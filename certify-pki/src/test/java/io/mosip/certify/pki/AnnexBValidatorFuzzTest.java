package io.mosip.certify.pki;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Seeded mutation fuzzing of the validator: every certificate or CRL a JCA provider (the JDK's or BouncyCastle's) will
 * construct from a mutated encoding must come back as a list of violations, never as an exception.
 *
 * <p>The baselines are fixed DER files written once by the production builders (P-256 and P-521: an IACA, a Document
 * Signer issued by it, and a CRL revoking the Document Signer) under {@code src/test/resources/io/mosip/certify/pki/fuzz},
 * and every mutant comes from a {@link Random} with a fixed seed per object, provider and curve, so a run is the same
 * on every machine and a failure names the mutant to reproduce it. A mutant flips a bit in, or overwrites, one to three
 * octets of the baseline. Each loadable IACA mutant is validated on its own and as the issuer of the baseline DS and
 * CRL; each DS mutant as a DS and as an IACA; each CRL mutant against the baseline IACA.
 *
 * <p>Two properties are asserted: no validation throws, and no object whose encoding differs from its baseline passes
 * its own profile (a changed octet breaks the signature, the encoding or a rule). The encoding compared is the object's
 * own {@code getEncoded()}: BouncyCastle's provider re-encodes what it parsed to DER, so a mutant that only turned a DER
 * octet into its BER equivalent (a BOOLEAN {@code FF} into {@code 01}) comes back as the original certificate, which
 * rightly passes; the JDK keeps the mutated octets, and the signature over them fails.
 *
 * <p>{@value #DEFAULT_MUTANTS} mutants per object, provider and curve run with the suite; set
 * {@code -Dpki.fuzz.mutants=2000} for a longer run.
 */
class AnnexBValidatorFuzzTest {

    static final int DEFAULT_MUTANTS = 300;

    private static final int MUTANTS = Integer.getInteger("pki.fuzz.mutants", DEFAULT_MUTANTS);

    private static final long SEED = 0x18013_5L;

    private record Baseline(String curve, byte[] iaca, byte[] ds, byte[] crl) {}

    private record Provider(String name, CertificateFactory factory) {}

    private record Failure(String label, Throwable thrown, byte[] mutant) {
        @Override
        public String toString() {
            StackTraceElement at = null;
            for (StackTraceElement element : thrown.getStackTrace()) {
                if (element.getClassName().startsWith("io.mosip")) {
                    at = element;
                    break;
                }
            }
            return label + ": " + thrown + " at " + at + "\n    mutant " + Base64.getEncoder().encodeToString(mutant);
        }
    }

    @TestFactory
    Stream<DynamicTest> noMutantMakesTheValidatorThrow() {
        List<DynamicTest> tests = new ArrayList<>();
        int curveIndex = 0;
        for (Baseline baseline : List.of(baseline("p256"), baseline("p521"))) {
            int providerIndex = 0;
            for (Provider provider : providers()) {
                long seed = SEED + 100L * curveIndex + 10L * providerIndex;
                tests.add(DynamicTest.dynamicTest(baseline.curve() + " " + provider.name() + " IACA",
                        () -> fuzzIaca(baseline, provider, new Random(seed))));
                tests.add(DynamicTest.dynamicTest(baseline.curve() + " " + provider.name() + " DS",
                        () -> fuzzDs(baseline, provider, new Random(seed + 1))));
                tests.add(DynamicTest.dynamicTest(baseline.curve() + " " + provider.name() + " CRL",
                        () -> fuzzCrl(baseline, provider, new Random(seed + 2))));
                providerIndex++;
            }
            curveIndex++;
        }
        return tests.stream();
    }

    /** The baselines conform, so the mutants start from objects that reach every check. */
    @Test
    void theBaselinesConform() {
        for (String curve : List.of("p256", "p521")) {
            Baseline baseline = baseline(curve);
            for (Provider provider : providers()) {
                X509Certificate iaca = certificate(provider, baseline.iaca());
                X509Certificate ds = certificate(provider, baseline.ds());
                X509CRL crl = crl(provider, baseline.crl());
                assertEquals(List.of(), AnnexBValidator.validateIaca(iaca), curve + " " + provider.name());
                assertEquals(List.of(), AnnexBValidator.validateDs(ds, iaca), curve + " " + provider.name());
                assertEquals(List.of(), AnnexBValidator.validateCrl(crl, iaca, crl.getThisUpdate().toInstant()),
                        curve + " " + provider.name());
            }
        }
    }

    /** The IACA the third-round reviewers found throwing: its issuer country carries a primitive SET tag. */
    @Test
    void theReviewersThrowingIacaIsReported() {
        X509Certificate iaca = certificate(providers().get(0), resource("reviewer-throwing-iaca.der"));
        assertEquals(List.of("IACA_ENCODING_INVALID"), AnnexBValidator.ruleIds(AnnexBValidator.validateIaca(iaca)));
        Baseline baseline = baseline("p256");
        X509Certificate ds = certificate(providers().get(0), baseline.ds());
        assertEquals(List.of("IACA_ENCODING_INVALID"), AnnexBValidator.ruleIds(AnnexBValidator.validateDs(ds, iaca)));
    }

    private static void fuzzIaca(Baseline baseline, Provider provider, Random random) {
        X509Certificate ds = certificate(provider, baseline.ds());
        X509CRL crl = crl(provider, baseline.crl());
        Instant at = crl.getThisUpdate().toInstant();
        List<Failure> failures = new ArrayList<>();
        int loaded = 0;
        for (int i = 0; i < MUTANTS; i++) {
            byte[] mutant = mutate(baseline.iaca(), random);
            X509Certificate iaca = loadCertificate(provider, mutant);
            if (iaca == null) {
                continue;
            }
            loaded++;
            runOwn(failures, "validateIaca(mutant)", baseline.iaca(), mutant, encoded(iaca),
                    () -> AnnexBValidator.validateIaca(iaca));
            run(failures, "validateDs(ds, mutant)", mutant, () -> AnnexBValidator.validateDs(ds, iaca));
            run(failures, "validateCrl(crl, mutant)", mutant, () -> AnnexBValidator.validateCrl(crl, iaca, at));
        }
        report(baseline.curve() + " " + provider.name() + " IACA", loaded, failures);
    }

    private static void fuzzDs(Baseline baseline, Provider provider, Random random) {
        X509Certificate iaca = certificate(provider, baseline.iaca());
        List<Failure> failures = new ArrayList<>();
        int loaded = 0;
        for (int i = 0; i < MUTANTS; i++) {
            byte[] mutant = mutate(baseline.ds(), random);
            X509Certificate ds = loadCertificate(provider, mutant);
            if (ds == null) {
                continue;
            }
            loaded++;
            runOwn(failures, "validateDs(mutant, iaca)", baseline.ds(), mutant, encoded(ds),
                    () -> AnnexBValidator.validateDs(ds, iaca));
            run(failures, "validateIaca(mutant)", mutant, () -> AnnexBValidator.validateIaca(ds));
        }
        report(baseline.curve() + " " + provider.name() + " DS", loaded, failures);
    }

    private static void fuzzCrl(Baseline baseline, Provider provider, Random random) {
        X509Certificate iaca = certificate(provider, baseline.iaca());
        Instant at = crl(provider, baseline.crl()).getThisUpdate().toInstant();
        List<Failure> failures = new ArrayList<>();
        int loaded = 0;
        for (int i = 0; i < MUTANTS; i++) {
            byte[] mutant = mutate(baseline.crl(), random);
            X509CRL crl = loadCrl(provider, mutant);
            if (crl == null) {
                continue;
            }
            loaded++;
            runOwn(failures, "validateCrl(mutant, iaca)", baseline.crl(), mutant, encoded(crl),
                    () -> AnnexBValidator.validateCrl(crl, iaca, at));
            run(failures, "validateCrl(mutant, iaca, now)", mutant, () -> AnnexBValidator.validateCrl(crl, iaca));
        }
        report(baseline.curve() + " " + provider.name() + " CRL", loaded, failures);
    }

    private static void report(String label, int loaded, List<Failure> failures) {
        System.out.println("fuzz " + label + ": " + MUTANTS + " mutants, " + loaded + " loadable, "
                + failures.size() + " failures (throws or a changed encoding accepted)");
        assertTrue(loaded > 0, label + ": no mutant could be constructed, so nothing was fuzzed");
        assertTrue(failures.isEmpty(), () -> label + ": " + failures.size() + " validations failed, first "
                + failures.subList(0, Math.min(5, failures.size())));
    }

    private static void run(List<Failure> failures, String label, byte[] mutant,
                            Supplier<List<AnnexBValidator.Violation>> validation) {
        try {
            validation.get();
        } catch (Throwable thrown) {
            failures.add(new Failure(label, thrown, mutant));
        }
    }

    /** As {@link #run}, and an object whose own encoding differs from the baseline must not pass its own profile. */
    private static void runOwn(List<Failure> failures, String label, byte[] baseline, byte[] mutant, byte[] encoded,
                               Supplier<List<AnnexBValidator.Violation>> validation) {
        try {
            if (validation.get().isEmpty() && !java.util.Arrays.equals(baseline, encoded)) {
                failures.add(new Failure(label, new AssertionError("a changed encoding passes its own profile"), mutant));
            }
        } catch (Throwable thrown) {
            failures.add(new Failure(label, thrown, mutant));
        }
    }

    /** One to three octets of the baseline, each with one bit flipped or overwritten with a random octet. */
    static byte[] mutate(byte[] baseline, Random random) {
        byte[] mutant = baseline.clone();
        int changes = 1 + random.nextInt(3);
        for (int i = 0; i < changes; i++) {
            int position = random.nextInt(mutant.length);
            if (random.nextBoolean()) {
                mutant[position] ^= (byte) (1 << random.nextInt(8));
            } else {
                mutant[position] = (byte) random.nextInt(256);
            }
        }
        return mutant;
    }

    /** The object's own encoding, or {@code null} when the provider cannot produce one (then it differs). */
    private static byte[] encoded(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] encoded(X509CRL crl) {
        try {
            return crl.getEncoded();
        } catch (Exception e) {
            return null;
        }
    }

    private static List<Provider> providers() {
        try {
            return List.of(new Provider("JDK", CertificateFactory.getInstance("X.509")),
                    new Provider("BC", CertificateFactory.getInstance("X.509", BadCerts.BC)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509Certificate loadCertificate(Provider provider, byte[] der) {
        try {
            return (X509Certificate) provider.factory().generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception | Error e) {
            return null;
        }
    }

    private static X509CRL loadCrl(Provider provider, byte[] der) {
        try {
            return (X509CRL) provider.factory().generateCRL(new ByteArrayInputStream(der));
        } catch (Exception | Error e) {
            return null;
        }
    }

    private static X509Certificate certificate(Provider provider, byte[] der) {
        X509Certificate certificate = loadCertificate(provider, der);
        if (certificate == null) {
            throw new IllegalStateException(provider.name() + " cannot load a baseline certificate");
        }
        return certificate;
    }

    private static X509CRL crl(Provider provider, byte[] der) {
        X509CRL crl = loadCrl(provider, der);
        if (crl == null) {
            throw new IllegalStateException(provider.name() + " cannot load the baseline CRL");
        }
        return crl;
    }

    private static Baseline baseline(String curve) {
        return new Baseline(curve, resource(curve + "-iaca.der"), resource(curve + "-ds.der"), resource(curve + "-crl.der"));
    }

    private static byte[] resource(String name) {
        try (InputStream in = AnnexBValidatorFuzzTest.class.getResourceAsStream("fuzz/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing test resource fuzz/" + name);
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
