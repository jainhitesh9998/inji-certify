package io.mosip.certify.signing;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The one table that maps the four algorithm vocabularies Certify meets: JOSE names, COSE identifiers,
 * legacy Linked Data signature suites, and Data Integrity cryptosuites. Replaces the mapping property
 * {@code mosip.certify.credential-config.credential-signing-alg-values-supported}, the COSE map in
 * {@code CredentialConfigurationServiceImpl} and danubetech's {@code findCryptosuitesForJwsAlgorithm}.
 */
public final class AlgorithmRegistry {

    /** Legacy LD suite name to algorithm. */
    private static final Map<String, SignatureAlgorithm> LD_SUITES = new LinkedHashMap<>();
    /** Data Integrity cryptosuite name to algorithm. */
    private static final Map<String, SignatureAlgorithm> CRYPTOSUITES = new LinkedHashMap<>();

    static {
        LD_SUITES.put("RsaSignature2018", SignatureAlgorithm.RS256);
        LD_SUITES.put("Ed25519Signature2018", SignatureAlgorithm.EdDSA);
        LD_SUITES.put("Ed25519Signature2020", SignatureAlgorithm.EdDSA);
        LD_SUITES.put("EcdsaKoblitzSignature2016", SignatureAlgorithm.ES256K);
        LD_SUITES.put("EcdsaSecp256k1Signature2019", SignatureAlgorithm.ES256K);
        LD_SUITES.put("EcdsaSecp256r1Signature2019", SignatureAlgorithm.ES256);

        CRYPTOSUITES.put("ecdsa-rdfc-2019", SignatureAlgorithm.ES256);
        CRYPTOSUITES.put("ecdsa-jcs-2019", SignatureAlgorithm.ES256);
        CRYPTOSUITES.put("ecdsa-sd-2023", SignatureAlgorithm.ES256);
        CRYPTOSUITES.put("eddsa-rdfc-2022", SignatureAlgorithm.EdDSA);
        CRYPTOSUITES.put("eddsa-jcs-2022", SignatureAlgorithm.EdDSA);
    }

    private AlgorithmRegistry() {}

    public static Optional<SignatureAlgorithm> byJose(String joseName) {
        return SignatureAlgorithm.fromJose(joseName);
    }

    public static Optional<SignatureAlgorithm> byCose(int coseId) {
        return SignatureAlgorithm.fromCose(coseId);
    }

    /** Resolves either a legacy LD suite name or a Data Integrity cryptosuite name. */
    public static Optional<SignatureAlgorithm> bySuite(String suiteOrCryptosuite) {
        if (suiteOrCryptosuite == null) {
            return Optional.empty();
        }
        SignatureAlgorithm alg = LD_SUITES.get(suiteOrCryptosuite);
        if (alg == null) {
            alg = CRYPTOSUITES.get(suiteOrCryptosuite);
        }
        return Optional.ofNullable(alg);
    }

    public static boolean isLegacyLdSuite(String name) {
        return LD_SUITES.containsKey(name);
    }

    public static boolean isDataIntegrityCryptosuite(String name) {
        return CRYPTOSUITES.containsKey(name);
    }

    public static List<String> ldSuitesFor(SignatureAlgorithm alg) {
        return LD_SUITES.entrySet().stream().filter(e -> e.getValue() == alg).map(Map.Entry::getKey).toList();
    }

    public static List<String> cryptosuitesFor(SignatureAlgorithm alg) {
        return CRYPTOSUITES.entrySet().stream().filter(e -> e.getValue() == alg).map(Map.Entry::getKey).toList();
    }

    public static Map<String, SignatureAlgorithm> ldSuites() {
        return Collections.unmodifiableMap(LD_SUITES);
    }

    public static Map<String, SignatureAlgorithm> cryptosuites() {
        return Collections.unmodifiableMap(CRYPTOSUITES);
    }
}
