package io.mosip.certify.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Collections;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * The CRL state an offline IACA needs and a CRL cannot be rebuilt without: for each IACA (keyed by its subject key
 * identifier, so the PKCS#12 and the {@code --pem-out} form of one IACA share one inventory) the last CRL number used
 * and every serial ever revoked with its original revocation date. Each {@code pki crl issue} lists the whole inventory,
 * so a CRL never drops an earlier revocation (RFC 5280 section 5: a complete CRL lists every unexpired revoked
 * certificate), and numbers only go up.
 *
 * <pre>
 * {
 *   "format" : "certify-cli/crl-state/1",
 *   "iacas" : {
 *     "3f2a…" : {
 *       "subject" : "CN=Lorem Ipsum Demo IACA,O=Lorem Ipsum Demo,ST=Karnataka,C=IN",
 *       "lastCrlNumber" : "7",
 *       "revoked" : [ { "serial" : "40a1…", "revokedAt" : "2026-11-13T09:12:44Z" } ]
 *     }
 *   }
 * }
 * </pre>
 *
 * <p>One inventory per IACA identity: the file is {@code iaca-<ski-hex>.crlstate.json} in the real directory of the IACA
 * keystore or PEM file (symbolic links resolved), or the file {@code --state} names. Every run for the IACA first takes
 * the identity lock {@code .<ski-hex>.crl.lock} in that directory (and in the {@code --state} directory when it is
 * another one), then discovers the state under the lock ({@link #discover}), so two copies of one IACA in one directory
 * ({@code a.p12}, {@code b.p12}, {@code iaca-key.pem}) find, create and update the same file and never start two
 * inventories. Writes then also hold the file's own lock ({@code <state>.lock}), so two IACAs sharing a {@code --state}
 * file are serialised too. A file under the round-2 name {@code <iaca-store>.crlstate.json} is still read and, when it
 * holds only this IACA, renamed to the canonical name under the lock.
 *
 * <p>Files are written atomically ({@code rw-------}). An empty or unreadable file is a hard error, never an empty
 * inventory: it is the only record of what was revoked. Discovery reads every {@code *.crlstate.json} in the directory,
 * so a corrupt state file of another IACA there blocks this one too (it fails safe: nothing is issued until the file is
 * restored or moved aside).
 */
final class CrlState {

    static final String FORMAT = "certify-cli/crl-state/1";
    static final String SUFFIX = ".crlstate.json";

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    /** IACA subject key identifier (lowercase hex) to its inventory, in insertion order. */
    private final Map<String, Inventory> iacas;

    private CrlState(Map<String, Inventory> iacas) {
        this.iacas = iacas;
    }

    static CrlState empty() {
        return new CrlState(new LinkedHashMap<>());
    }

    Inventory inventory(String keyId) {
        return iacas.get(keyId);
    }

    void put(String keyId, Inventory inventory) {
        iacas.put(keyId, inventory);
    }

    /** One IACA's last CRL number ({@code null} before its first CRL) and its revoked serials with their dates. */
    static final class Inventory {
        private final String subject;
        private BigInteger lastCrlNumber;
        private final SortedMap<BigInteger, Instant> revoked = new TreeMap<>();

        Inventory(String subject, BigInteger lastCrlNumber) {
            this.subject = subject;
            this.lastCrlNumber = lastCrlNumber;
        }

        BigInteger lastCrlNumber() {
            return lastCrlNumber;
        }

        void lastCrlNumber(BigInteger number) {
            this.lastCrlNumber = number;
        }

        SortedMap<BigInteger, Instant> revoked() {
            return Collections.unmodifiableSortedMap(revoked);
        }

        boolean isRevoked(BigInteger serial) {
            return revoked.containsKey(serial);
        }

        /** Records a revocation; an earlier date already recorded for the serial is kept. */
        void revoke(BigInteger serial, Instant at) {
            Instant date = at.truncatedTo(ChronoUnit.SECONDS);
            revoked.merge(serial, date, (existing, added) -> existing.isBefore(added) ? existing : added);
        }

        /**
         * Merges a CRL the IACA published: its entries (the earlier date wins for a serial known to both) and its CRL
         * number, which raises the last number when it is higher.
         */
        void importCrl(X509CRL crl, BigInteger number) {
            if (crl.getRevokedCertificates() != null) {
                for (X509CRLEntry entry : crl.getRevokedCertificates()) {
                    revoke(entry.getSerialNumber(), entry.getRevocationDate().toInstant());
                }
            }
            if (lastCrlNumber == null || number.compareTo(lastCrlNumber) > 0) {
                lastCrlNumber = number;
            }
        }
    }

    // ------------------------------------------------------------------ keys and paths

    /** The IACA's subject key identifier as lowercase hex; RFC 5280 method 1 when the extension is absent. */
    static String keyId(X509Certificate iaca) {
        try {
            byte[] extension = iaca.getExtensionValue("2.5.29.14");
            byte[] identifier = extension != null
                    ? SubjectKeyIdentifier.getInstance(JcaX509ExtensionUtils.parseExtensionValue(extension))
                            .getKeyIdentifier()
                    : new JcaX509ExtensionUtils().createSubjectKeyIdentifier(iaca.getPublicKey()).getKeyIdentifier();
            return HexFormat.of().formatHex(identifier);
        } catch (IOException | NoSuchAlgorithmException | RuntimeException e) {
            throw new IllegalArgumentException("cannot read the IACA subject key identifier: " + e.getMessage(), e);
        }
    }

    /** The canonical inventory file name of an IACA: {@code iaca-<ski-hex>.crlstate.json}. */
    static String canonicalName(String keyId) {
        return "iaca-" + keyId + SUFFIX;
    }

    /** The round-2 default name, {@code <iaca-store>.crlstate.json} next to the store; read and migrated, never created. */
    static Path legacyPath(Path iacaStore) {
        return iacaStore.resolveSibling(iacaStore.getFileName() + SUFFIX);
    }

    /** {@code .<ski-hex>.crl.lock} in {@code directory}: taken before this IACA's state there is discovered or created. */
    static Path identityLock(Path directory, String keyId) {
        return directory.resolve("." + keyId + ".crl.lock");
    }

    /** Where discovery found (or will create) the IACA's inventory; {@code migratedFrom} when a legacy file was renamed. */
    record Location(Path path, Path migratedFrom) {}

    /**
     * The inventory file of the IACA with {@code keyId}; the caller holds the identity locks of the IACA's directory and
     * of the {@code explicit} file's directory. Every {@code *.crlstate.json} in those directories is read, and the
     * files that record this IACA are its holders (canonical paths, so a symbolic link and its target count once).
     *
     * <ul>
     *   <li>{@code --state} given: that file when it is a holder or when there is none; refused when another file
     *       records the IACA, which would start a second inventory.</li>
     *   <li>One holder: that file; the legacy {@code <iaca-store>.crlstate.json} holding only this IACA is renamed to
     *       {@code iaca-<ski-hex>.crlstate.json} first.</li>
     *   <li>No holder: {@code iaca-<ski-hex>.crlstate.json} in the IACA's directory, for a first CRL.</li>
     *   <li>Two or more holders: refused, listing them; {@code --state} says which one is current.</li>
     * </ul>
     *
     * @param iacaStore the canonical (real) path of the IACA keystore or PEM file
     * @param explicit  the canonical {@code --state} path, or {@code null}
     */
    static Location discover(Path iacaStore, String keyId, Path explicit) throws IOException {
        Path home = iacaStore.getParent();
        Set<Path> directories = new LinkedHashSet<>();
        directories.add(home);
        if (explicit != null) {
            directories.add(explicit.getParent());
        }
        SortedSet<Path> holders = new TreeSet<>();
        for (Path directory : directories) {
            if (!Files.isDirectory(directory)) {
                continue;
            }
            try (DirectoryStream<Path> files = Files.newDirectoryStream(directory, "*" + SUFFIX)) {
                for (Path file : files) {
                    if (Files.isRegularFile(file) && holds(file, keyId)) {
                        holders.add(SecureFiles.canonical(file));
                    }
                }
            }
        }
        if (explicit != null) {
            // a --state of any name that records the IACA is the operator's choice among several holders
            if (holders.isEmpty() || holders.contains(explicit) || holds(explicit, keyId)) {
                return new Location(explicit, null);
            }
            throw new UsageException("--state " + explicit + " does not record this IACA, but " + list(holders)
                    + " does: a second file would start a second inventory and reuse CRL numbers; pass --state with"
                    + " that file");
        }
        if (holders.size() > 1) {
            throw new UsageException("the CRL state of this IACA is recorded in more than one file " + list(holders)
                    + "; pass --state <file> to say which one is current");
        }
        Path canonical = home.resolve(canonicalName(keyId));
        if (holders.isEmpty()) {
            return new Location(canonical, null);
        }
        Path holder = holders.first();
        if (holder.equals(legacyPath(iacaStore)) && !Files.exists(canonical, LinkOption.NOFOLLOW_LINKS)) {
            try (SecureFiles.Lock files = SecureFiles.lockAll(
                    List.of(SecureFiles.lockFile(holder), SecureFiles.lockFile(canonical)))) {
                CrlState legacy = read(holder);
                if (legacy != null && legacy.iacas.size() == 1 && legacy.inventory(keyId) != null
                        && !Files.exists(canonical, LinkOption.NOFOLLOW_LINKS)) {
                    SecureFiles.rename(holder, canonical);
                    return new Location(canonical, holder);
                }
            }
        }
        return new Location(holder, null);
    }

    private static String list(Collection<Path> paths) {
        return paths.stream().map(Path::toString).collect(Collectors.joining(", ", "[", "]"));
    }

    private static boolean holds(Path path, String keyId) throws IOException {
        CrlState state = read(path);
        return state != null && state.inventory(keyId) != null;
    }

    // ------------------------------------------------------------------ read and write

    /** The state at {@code path}, or {@code null} when the file does not exist. Empty or corrupt is an error. */
    static CrlState read(Path path) throws IOException {
        if (!Files.exists(path)) {
            return null;
        }
        byte[] bytes = Files.readAllBytes(path);
        if (new String(bytes, StandardCharsets.UTF_8).isBlank()) {
            throw corrupt(path, "the file is empty");
        }
        JsonNode root;
        try {
            root = MAPPER.readTree(bytes);
        } catch (IOException e) {
            throw corrupt(path, "not JSON: " + e.getMessage());
        }
        if (root == null || !root.isObject() || !FORMAT.equals(text(root, "format"))) {
            throw corrupt(path, "\"format\" is not " + FORMAT);
        }
        JsonNode iacas = root.get("iacas");
        if (iacas == null || !iacas.isObject()) {
            throw corrupt(path, "no \"iacas\" object");
        }
        Map<String, Inventory> inventories = new LinkedHashMap<>();
        for (Iterator<Map.Entry<String, JsonNode>> fields = iacas.fields(); fields.hasNext(); ) {
            Map.Entry<String, JsonNode> field = fields.next();
            String keyId = field.getKey();
            JsonNode node = field.getValue();
            if (!keyId.matches("[0-9a-f]{2,128}") || !node.isObject()) {
                throw corrupt(path, "the IACA entry \"" + keyId + "\" is not a key identifier with an object");
            }
            // every inventory the CLI writes has issued a CRL, so a missing number is damage, never "no CRL yet":
            // reading it as such would restart the sequence at 1 under revocations already published
            BigInteger last;
            JsonNode lastNode = node.get("lastCrlNumber");
            if (lastNode == null || lastNode.isNull()) {
                throw corrupt(path, "lastCrlNumber of " + keyId + " is missing");
            }
            try {
                if (!lastNode.isTextual() && !lastNode.isIntegralNumber()) {
                    throw new NumberFormatException(lastNode.getNodeType().toString());
                }
                last = new BigInteger(lastNode.asText());
            } catch (NumberFormatException e) {
                throw corrupt(path, "lastCrlNumber of " + keyId + " is not a decimal integer");
            }
            if (last.signum() < 0) {
                throw corrupt(path, "lastCrlNumber of " + keyId + " is negative");
            }
            Inventory inventory = new Inventory(text(node, "subject"), last);
            JsonNode revoked = node.get("revoked");
            if (revoked == null || !revoked.isArray()) {
                throw corrupt(path, "the IACA entry " + keyId + " has no \"revoked\" array");
            }
            for (JsonNode entry : revoked) {
                try {
                    BigInteger serial = new BigInteger(text(entry, "serial"), 16);
                    if (serial.signum() <= 0) {
                        throw new NumberFormatException("not positive");
                    }
                    if (inventory.isRevoked(serial)) {
                        throw corrupt(path, "the serial " + serial.toString(16) + " is listed twice for " + keyId);
                    }
                    inventory.revoked.put(serial, Instant.parse(text(entry, "revokedAt")));
                } catch (NumberFormatException | DateTimeParseException | NullPointerException e) {
                    throw corrupt(path, "a revoked entry of " + keyId + " is not {serial: hex, revokedAt: instant}");
                }
            }
            inventories.put(keyId, inventory);
        }
        return new CrlState(inventories);
    }

    /** Writes the state atomically, {@code rw-------}, replacing the previous file. */
    void write(Path path) throws IOException {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("format", FORMAT);
        ObjectNode iacasNode = root.putObject("iacas");
        iacas.forEach((keyId, inventory) -> {
            if (inventory.lastCrlNumber == null) {
                throw new IllegalStateException("the inventory of " + keyId + " has no CRL number to record");
            }
            ObjectNode node = iacasNode.putObject(keyId);
            node.put("subject", inventory.subject);
            node.put("lastCrlNumber", inventory.lastCrlNumber.toString());
            ArrayNode revoked = node.putArray("revoked");
            inventory.revoked.forEach((serial, at) -> revoked.addObject()
                    .put("serial", serial.toString(16))
                    .put("revokedAt", at.toString()));
        });
        byte[] bytes = (MAPPER.writeValueAsString(root) + System.lineSeparator()).getBytes(StandardCharsets.UTF_8);
        SecureFiles.write(path, bytes, SecureFiles.Visibility.SECRET, true);
    }

    /** The cRLNumber of a CRL; one without it cannot be placed in the sequence and is refused. */
    static BigInteger crlNumber(X509CRL crl) {
        byte[] extension = crl.getExtensionValue("2.5.29.20");
        if (extension == null) {
            throw new IllegalArgumentException("the CRL has no cRLNumber extension");
        }
        try {
            return ASN1Integer.getInstance(JcaX509ExtensionUtils.parseExtensionValue(extension)).getValue();
        } catch (IOException | RuntimeException e) {
            throw new IllegalArgumentException("the CRL's cRLNumber cannot be read: " + e.getMessage(), e);
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || !value.isTextual() ? null : value.asText();
    }

    private static IllegalStateException corrupt(Path path, String problem) {
        return new IllegalStateException("the CRL state file " + path + " is corrupt (" + problem + "); it is the only"
                + " record of this IACA's revocations and CRL numbers: restore it from a backup, or move it aside and"
                + " rebuild it with --base-crl <the last published CRL>");
    }
}
