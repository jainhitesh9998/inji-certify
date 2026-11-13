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
import java.util.ArrayList;
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
 * <p>One inventory per IACA identity, found through one authoritative slot: {@code iaca-<ski-hex>.crlstate.json} in
 * the <em>home</em> directory, the real directory of the IACA keystore or PEM file (symbolic links resolved) or, when
 * that directory is read-only (offline media, D3), the directory of {@code --state}. The slot holds the inventory
 * itself or, when {@code --state} keeps it elsewhere, a pointer ({@code {"format": "certify-cli/crl-state-pointer/1",
 * "iaca": "<ski>", "stateAt": "<real path>"}}) written under the identity lock on first use; discovery follows it, so a
 * later run without {@code --state} finds the same file, and a {@code --state} naming any other file is refused. Every
 * run first takes the identity lock {@code .<ski-hex>.crl.lock} in the home directory (and in the {@code --state}
 * directory when it is another one), then discovers under the lock ({@link #discover}): copies of one IACA
 * ({@code a.p12}, {@code b.p12}, {@code iaca-key.pem}) find, create and update the same file and never start two
 * inventories. Writes then also hold the file's own lock ({@code <state>.lock}), so two IACAs sharing a {@code --state}
 * file are serialised too. A file under the round-2 name {@code <iaca-store>.crlstate.json} is still read and, when it
 * holds only this IACA, renamed to the canonical name under the lock. Other files recording the IACA (copies, the
 * round-2 name next to the canonical one) are holders: the inventory in use must be at or ahead of every one of them.
 *
 * <p>Files are written atomically ({@code rw-------}). An empty or unreadable file is a hard error, never an empty
 * inventory: it is the only record of what was revoked. Discovery reads every {@code *.crlstate.json} in the directory,
 * so a corrupt state file of another IACA there blocks this one too (it fails safe: nothing is issued until the file is
 * restored or moved aside).
 */
final class CrlState {

    static final String FORMAT = "certify-cli/crl-state/1";
    static final String POINTER_FORMAT = "certify-cli/crl-state-pointer/1";
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

    /**
     * The home directory of the IACA's authoritative slot: the IACA's real directory when it is writable, else the
     * directory of {@code --state}; a read-only IACA directory without {@code --state} is refused (exit 1), since the
     * lock and the state must live where the CLI can write and every run must name the same place.
     */
    static Path home(Path iacaStore, Path explicit) {
        Path directory = iacaStore.getParent();
        if (Files.isWritable(directory)) {
            return directory;
        }
        if (explicit == null) {
            throw new UsageException("the IACA directory " + directory + " is read-only; pass --state <file> in a"
                    + " writable directory and use the same --state on every run");
        }
        return explicit.getParent();
    }

    /**
     * Where discovery found (or will create) the IACA's inventory. {@code migratedFrom} when a round-2 file was
     * renamed; {@code pointer}, the slot to write a pointer to {@code path} into once the run is about to record its
     * CRL; {@code otherHolders}, the other files recording the IACA, which the inventory must not be behind.
     */
    record Location(Path path, Path migratedFrom, Path pointer, List<Path> otherHolders) {}

    /** A pointer slot: the IACA it is for and the real path of the state file it names. */
    record Pointer(String keyId, Path stateAt) {}

    /**
     * The inventory file of the IACA with {@code keyId}; the caller holds the identity locks of {@code home} and of the
     * {@code explicit} file's directory.
     *
     * <ol>
     *   <li>The authority: the slot {@code iaca-<ski>.crlstate.json} in {@code home} (the state itself, or the file its
     *       pointer names, which must exist and record the IACA: a dangling pointer is a hard error, never a fresh
     *       start), and a pointer in the IACA's own directory when that is read-only. Two authorities that disagree
     *       are refused.</li>
     *   <li>The holders: every {@code *.crlstate.json} in the IACA's directory, {@code home} and the {@code --state}
     *       directory that records this IACA, the authority and the {@code --state} file (canonical paths, so a
     *       symbolic link and its target count once).</li>
     *   <li>{@code --state} given: refused when it is a pointer, or names another file than the authority (exit 1,
     *       naming both); otherwise used, with a pointer to it written into the empty slot.</li>
     *   <li>No {@code --state}: the authority; else the one holder (the round-2 name is renamed to the slot first,
     *       another name gets a pointer); two or more holders are refused until {@code --state} names one; none: the
     *       slot, for a first CRL.</li>
     * </ol>
     *
     * @param iacaStore the canonical (real) path of the IACA keystore or PEM file
     * @param explicit  the canonical {@code --state} path, or {@code null}
     * @param home      {@link #home}
     */
    static Location discover(Path iacaStore, String keyId, Path explicit, Path home) throws IOException {
        Path iacaDirectory = iacaStore.getParent();
        Path slot = home.resolve(canonicalName(keyId));
        // the authority, and what said so
        Map<Path, String> authorities = new LinkedHashMap<>();
        Set<Path> holders = new TreeSet<>();
        Set<Path> slots = new LinkedHashSet<>(List.of(slot, iacaDirectory.resolve(canonicalName(keyId))));
        for (Path candidate : slots) {
            Object entry = readEntry(candidate);
            if (entry instanceof Pointer pointer) {
                authorities.putIfAbsent(follow(candidate, pointer, keyId), "the pointer " + candidate);
            } else if (entry instanceof CrlState state) {
                if (state.inventory(keyId) == null) {
                    throw new IllegalStateException("the CRL state file " + candidate + " is named for this IACA but"
                            + " does not record it; restore it, or move it aside and rebuild with --base-crl <the last"
                            + " published CRL>");
                }
                if (candidate.equals(slot)) {
                    authorities.putIfAbsent(SecureFiles.canonical(candidate), "the state file " + candidate);
                } else {
                    holders.add(SecureFiles.canonical(candidate)); // the read-only IACA directory's own slot
                }
            }
        }
        if (authorities.size() > 1) {
            throw new UsageException("the CRL state of this IACA is claimed by " + authorities.entrySet().stream()
                    .map(e -> e.getKey() + " (" + e.getValue() + ")").collect(Collectors.joining(" and "))
                    + "; keep one: move the other pointer or state aside");
        }
        Path authority = authorities.isEmpty() ? null : authorities.keySet().iterator().next();
        Set<Path> directories = new LinkedHashSet<>(List.of(iacaDirectory, home));
        if (explicit != null) {
            directories.add(explicit.getParent());
        }
        for (Path directory : directories) {
            if (!Files.isDirectory(directory)) {
                continue;
            }
            try (DirectoryStream<Path> files = Files.newDirectoryStream(directory, "*" + SUFFIX)) {
                for (Path file : files) {
                    if (!Files.isRegularFile(file) || slots.contains(file)) {
                        continue;
                    }
                    Object entry = readEntry(file);
                    if (entry instanceof CrlState state && state.inventory(keyId) != null) {
                        holders.add(SecureFiles.canonical(file));
                    } else if (entry instanceof Pointer pointer && pointer.keyId().equals(keyId)) {
                        holders.add(follow(file, pointer, keyId)); // a copied pointer: its target is a holder
                    }
                }
            }
        }
        if (authority != null) {
            holders.add(authority);
        }
        Path chosen;
        Path migratedFrom = null;
        if (explicit != null) {
            Object entry = readEntry(explicit);
            if (entry instanceof Pointer pointer) {
                throw new UsageException("--state " + explicit + " is a CRL state pointer to " + pointer.stateAt()
                        + ", not a state; pass --state " + pointer.stateAt() + ", or omit --state");
            }
            if (authority != null && !authority.equals(explicit)) {
                throw new UsageException("--state " + explicit + " is not the CRL state of this IACA: " + authority
                        + " is (" + authorities.get(authority) + "). Pass --state " + authority + " or omit --state;"
                        + " to rebuild the inventory in " + explicit + " instead, move " + slot + " aside and pass"
                        + " --state " + explicit + " --base-crl <the last CRL this IACA published>");
            }
            if (entry instanceof CrlState state && state.inventory(keyId) != null) {
                holders.add(explicit);
            }
            chosen = explicit;
        } else if (authority != null) {
            chosen = authority;
        } else if (holders.size() > 1) {
            throw new UsageException("the CRL state of this IACA is recorded in more than one file " + list(holders)
                    + "; pass --state <file> to say which one is current (it must be at or ahead of the others), and"
                    + " move the stale copies aside");
        } else if (holders.size() == 1) {
            Path holder = holders.iterator().next();
            chosen = holder;
            if (holder.equals(legacyPath(iacaStore)) && home.equals(iacaDirectory)
                    && !Files.exists(slot, LinkOption.NOFOLLOW_LINKS)) {
                try (SecureFiles.Lock files = SecureFiles.lockAll(
                        List.of(SecureFiles.lockFile(holder), SecureFiles.lockFile(slot)))) {
                    CrlState legacy = read(holder);
                    if (legacy != null && legacy.iacas.size() == 1 && legacy.inventory(keyId) != null
                            && !Files.exists(slot, LinkOption.NOFOLLOW_LINKS)) {
                        SecureFiles.rename(holder, slot);
                        holders.remove(holder);
                        holders.add(slot);
                        chosen = slot;
                        migratedFrom = holder;
                    }
                }
            }
        } else {
            chosen = slot;
        }
        Path pointer = chosen.equals(slot) || Files.exists(slot, LinkOption.NOFOLLOW_LINKS) ? null : slot;
        List<Path> others = new ArrayList<>(holders);
        others.remove(chosen);
        return new Location(chosen, migratedFrom, pointer, others);
    }

    /** The real path a pointer names; it must exist and record the IACA, or discovery stops (fails closed). */
    private static Path follow(Path file, Pointer pointer, String keyId) throws IOException {
        if (!pointer.keyId().equals(keyId)) {
            throw new IllegalStateException("the CRL state pointer " + file + " is for the IACA " + pointer.keyId()
                    + ", not for this one (" + keyId + "); move it aside");
        }
        Path target = pointer.stateAt();
        if (!Files.exists(target)) {
            throw new IllegalStateException("the CRL state pointer " + file + " names " + target + ", which does not"
                    + " exist (is the medium that holds it mounted?): this IACA's revocation inventory is there."
                    + " Restore " + target + " from a backup; if it is lost, move " + file + " aside and rebuild the"
                    + " inventory with --state <file> --base-crl <the last CRL this IACA published>. If this IACA has"
                    + " never published a CRL (a first run that stopped between writing the pointer and the"
                    + " inventory), move " + file + " aside and run again with --initial");
        }
        Path real = SecureFiles.canonical(target);
        Object entry = readEntry(real);
        if (!(entry instanceof CrlState state) || state.inventory(keyId) == null) {
            throw new IllegalStateException("the CRL state pointer " + file + " names " + real + ", which does not"
                    + " record this IACA; restore it, or move " + file + " aside and rebuild the inventory with"
                    + " --state <file> --base-crl <the last CRL this IACA published>");
        }
        return real;
    }

    private static String list(Collection<Path> paths) {
        return paths.stream().map(Path::toString).collect(Collectors.joining(", ", "[", "]"));
    }

    /** Writes the pointer {@code slot -> stateAt} ({@code rw-------}); the slot must not exist (CREATE_NEW). */
    static void writePointer(Path slot, String keyId, Path stateAt) throws IOException {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("format", POINTER_FORMAT);
        root.put("iaca", keyId);
        root.put("stateAt", stateAt.toString());
        byte[] bytes = (MAPPER.writeValueAsString(root) + System.lineSeparator()).getBytes(StandardCharsets.UTF_8);
        SecureFiles.write(slot, bytes, SecureFiles.Visibility.SECRET, false);
    }

    // ------------------------------------------------------------------ read and write

    /** The state at {@code path}, or {@code null} when the file does not exist. Empty, corrupt or a pointer is an error. */
    static CrlState read(Path path) throws IOException {
        Object entry = readEntry(path);
        if (entry instanceof Pointer pointer) {
            throw new IllegalStateException(path + " is a CRL state pointer to " + pointer.stateAt() + ", not a CRL"
                    + " state");
        }
        return (CrlState) entry;
    }

    /**
     * The file at {@code path}: a {@link CrlState}, a {@link Pointer}, or {@code null} when it does not exist. Empty or
     * corrupt is an error, never an empty inventory.
     */
    static Object readEntry(Path path) throws IOException {
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
        if (root != null && root.isObject() && POINTER_FORMAT.equals(text(root, "format"))) {
            String keyId = text(root, "iaca");
            String stateAt = text(root, "stateAt");
            if (keyId == null || !keyId.matches("[0-9a-f]{2,128}") || stateAt == null
                    || !Path.of(stateAt).isAbsolute()) {
                throw corrupt(path, "a pointer needs \"iaca\" (a key identifier) and an absolute \"stateAt\"");
            }
            return new Pointer(keyId, Path.of(stateAt));
        }
        if (root == null || !root.isObject() || !FORMAT.equals(text(root, "format"))) {
            throw corrupt(path, "\"format\" is not " + FORMAT + " or " + POINTER_FORMAT);
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
