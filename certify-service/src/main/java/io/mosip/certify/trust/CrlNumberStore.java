package io.mosip.certify.trust;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The last cRLNumber issued per IACA, for the CRLs dev mode signs (docs/design/20-mdl-issuer.md M-08). RFC 5280 5.2.3
 * requires the number to increase with every CRL an issuer publishes; a number derived from the clock alone repeats
 * after a restart within the same second and decreases after the clock is set back, so the last number is kept and the
 * next one is always larger. Keyed by the SHA-256 of the IACA certificate, so an anchor whose id changes keeps its
 * sequence.
 */
public interface CrlNumberStore {

    /** The last number recorded for {@code iaca}; zero when none was. */
    BigInteger last(X509Certificate iaca);

    /** Records {@code number} as the last one issued for {@code iaca}, durably before it returns. */
    void record(X509Certificate iaca, BigInteger number) throws IOException;

    /** The file the numbers are kept in; empty for a store held in memory. */
    default java.util.Optional<Path> location() {
        return java.util.Optional.empty();
    }

    /** Numbers kept for this process only: for tests, and an x509-file keystore without a file. */
    static CrlNumberStore inMemory() {
        Map<String, BigInteger> numbers = new ConcurrentHashMap<>();
        return new CrlNumberStore() {
            @Override
            public BigInteger last(X509Certificate iaca) {
                return numbers.getOrDefault(fingerprint(iaca), BigInteger.ZERO);
            }

            @Override
            public void record(X509Certificate iaca, BigInteger number) {
                numbers.merge(fingerprint(iaca), number, BigInteger::max);
            }
        };
    }

    /**
     * A properties file, {@code <sha256 of the IACA>=<last cRLNumber>}, written whole to a temporary file in the same
     * directory and moved over the previous one atomically, so a crash leaves either the old or the new numbers and
     * never a torn file. A file that cannot be read refuses startup: issuing a number the store cannot vouch for would
     * be exactly the reuse it exists to prevent.
     */
    static CrlNumberStore file(Path path) {
        return new FileStore(path);
    }

    /** The store dev mode keeps next to the x509-file keystore: {@code <keystore>.crl-numbers}. */
    static Path nextTo(Path keystore) {
        return keystore.resolveSibling(keystore.getFileName() + ".crl-numbers");
    }

    static String fingerprint(X509Certificate iaca) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(iaca.getEncoded()));
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException("Cannot encode the IACA " + iaca.getSubjectX500Principal(), e);
        }
    }

    final class FileStore implements CrlNumberStore {

        private final Path path;
        private final Map<String, BigInteger> numbers = new TreeMap<>();

        FileStore(Path path) {
            this.path = path.toAbsolutePath();
            if (Files.exists(this.path)) {
                Properties stored = new Properties();
                try (Reader reader = Files.newBufferedReader(this.path, StandardCharsets.ISO_8859_1)) {
                    stored.load(reader);
                    for (String key : stored.stringPropertyNames()) {
                        BigInteger number = new BigInteger(stored.getProperty(key).trim());
                        if (number.signum() < 0) {
                            throw new NumberFormatException("negative number " + number);
                        }
                        numbers.put(key, number);
                    }
                } catch (IOException | RuntimeException e) {
                    throw new IllegalStateException("Cannot read the dev-mode CRL numbers " + this.path + " (" + e.getMessage()
                            + "); restore it, or delete it to number the next CRLs from the clock again (safe unless the"
                            + " clock was set back)", e);
                }
            }
        }

        @Override
        public synchronized BigInteger last(X509Certificate iaca) {
            return numbers.getOrDefault(fingerprint(iaca), BigInteger.ZERO);
        }

        @Override
        public synchronized void record(X509Certificate iaca, BigInteger number) throws IOException {
            Map<String, BigInteger> next = new TreeMap<>(numbers);
            next.merge(fingerprint(iaca), number, BigInteger::max);
            Path directory = path.getParent();
            Files.createDirectories(directory);
            Path temporary = Files.createTempFile(directory, path.getFileName().toString(), ".tmp");
            try {
                try (Writer writer = Files.newBufferedWriter(temporary, StandardCharsets.ISO_8859_1)) {
                    writer.write("# Last cRLNumber of each dev-mode IACA CRL, by the SHA-256 of the IACA certificate"
                            + " (RFC 5280 5.2.3: numbers only increase). Written by Inji Certify; do not edit.\n");
                    for (Map.Entry<String, BigInteger> entry : next.entrySet()) {
                        writer.write(entry.getKey() + "=" + entry.getValue() + "\n");
                    }
                }
                try {
                    Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING);
                }
            } finally {
                Files.deleteIfExists(temporary);
            }
            numbers.clear();
            numbers.putAll(next);
        }

        Path path() {
            return path;
        }

        @Override
        public java.util.Optional<Path> location() {
            return java.util.Optional.of(path);
        }
    }
}
