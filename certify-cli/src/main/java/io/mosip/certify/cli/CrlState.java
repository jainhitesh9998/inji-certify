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
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

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
 * <p>The file lives next to the IACA keystore as {@code <iaca-store>.crlstate.json}, written atomically
 * ({@code rw-------}) under the lock of {@link SecureFiles#lock}. An empty or unreadable file is a hard error, never an
 * empty inventory: it is the only record of what was revoked.
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

    /** {@code <iaca-store>.crlstate.json}, next to the IACA keystore or PEM file. */
    static Path defaultPath(Path iacaStore) {
        return iacaStore.resolveSibling(iacaStore.getFileName() + SUFFIX);
    }

    /**
     * The state file for this IACA: {@code explicit} when given; else the one file in the IACA store's directory
     * ({@code <iaca-store>.crlstate.json} first, then any other {@code *.crlstate.json}) that already holds this IACA's
     * inventory, so the {@code .p12} and the PEM form of one IACA find the same record; else the default path for a
     * first CRL. Two files holding the same IACA are refused: the operator says which one with {@code --state}.
     */
    static Path locate(Path iacaStore, String keyId, Path explicit) throws IOException {
        if (explicit != null) {
            return explicit;
        }
        Path preferred = defaultPath(iacaStore);
        Path canonicalPreferred = SecureFiles.canonical(preferred);
        List<Path> holders = new ArrayList<>();
        if (holds(preferred, keyId)) {
            holders.add(preferred);
        }
        // listed under the name the caller used (not the canonical one), so a found file is reported as given
        Path directory = preferred.toAbsolutePath().getParent();
        if (Files.isDirectory(directory)) {
            try (DirectoryStream<Path> siblings = Files.newDirectoryStream(directory, "*" + SUFFIX)) {
                for (Path sibling : siblings) {
                    if (Files.isRegularFile(sibling) && !SecureFiles.canonical(sibling).equals(canonicalPreferred)
                            && holds(sibling, keyId)) {
                        holders.add(sibling);
                    }
                }
            }
        }
        if (holders.size() > 1) {
            throw new UsageException("the CRL state of this IACA is recorded in more than one file " + holders
                    + "; pass --state <file> to say which one is current");
        }
        return holders.isEmpty() ? preferred : holders.get(0);
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
            BigInteger last;
            JsonNode lastNode = node.get("lastCrlNumber");
            try {
                last = lastNode == null || lastNode.isNull() ? null : new BigInteger(lastNode.asText());
            } catch (NumberFormatException e) {
                throw corrupt(path, "lastCrlNumber of " + keyId + " is not a decimal integer");
            }
            if (last != null && last.signum() < 0) {
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
            ObjectNode node = iacasNode.putObject(keyId);
            node.put("subject", inventory.subject);
            if (inventory.lastCrlNumber == null) {
                node.putNull("lastCrlNumber");
            } else {
                node.put("lastCrlNumber", inventory.lastCrlNumber.toString());
            }
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
