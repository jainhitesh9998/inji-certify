package io.mosip.certify.format.ldpvc;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.verifier.DataIntegrityProofLdVerifier;
import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.verifier.EcdsaSecp256k1Signature2019LdVerifier;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;
import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier;
import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.FormatConfig;
import io.mosip.certify.spi.FormatException;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;
import io.mosip.certify.spi.TenantContext;
import io.mosip.certify.spi.UnsignedCredential;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.URI;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Every proof the formatter adds is verified by danubetech's verifiers against the dev keys' public parts. */
class LdpVcFormatterTest {

    static { Security.addProvider(new BouncyCastleProvider()); }

    /** The contexts certify-service ships, then danubetech's bundled security and Data Integrity contexts. */
    static final DocumentLoader LOADER = new DocumentLoader() {
        final Map<String, String> local = Map.of(
                "https://www.w3.org/2018/credentials/v1", "/contexts/credentials-v1.jsonld",
                "https://www.w3.org/ns/credentials/v2", "/contexts/credentials-v2.jsonld",
                "https://w3id.org/security/suites/ed25519-2020/v1", "/contexts/security-v1.jsonld");

        @Override
        public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {
            String resource = local.get(url.toString());
            if (resource != null) {
                try (InputStream in = LdpVcFormatterTest.class.getResourceAsStream(resource)) {
                    return JsonDocument.of(in);
                } catch (Exception e) {
                    throw new JsonLdError(com.apicatalog.jsonld.JsonLdErrorCode.LOADING_DOCUMENT_FAILED, e);
                }
            }
            try {
                return LDSecurityContexts.DOCUMENT_LOADER.loadDocument(url, options);
            } catch (JsonLdError e) {
                return DataIntegrityContexts.DOCUMENT_LOADER.loadDocument(url, options);
            }
        }
    };

    static final JcaKeyProvider KEYS = JcaKeyProvider.devMode();
    static final IssuanceContext CONTEXT = new IssuanceContext(TenantContext.DEFAULT, null, List.of(), ProtocolVersion.OID4VCI_1_0, "c",
            Instant.parse("2026-09-18T10:00:00Z"), Map.of());
    final LdpVcFormatter formatter = new LdpVcFormatter(LOADER);

    static Map<String, Object> vc11() {
        return Map.of("@context", List.of("https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/ed25519-2020/v1"),
                "type", List.of("VerifiableCredential"), "issuer", "did:web:issuer.example",
                "issuanceDate", "2026-09-18T10:00:00.000Z", "credentialSubject", Map.of("id", "did:jwk:abc"));
    }

    static Map<String, Object> vc20() {
        return Map.of("@context", List.of("https://www.w3.org/ns/credentials/v2"), "type", List.of("VerifiableCredential"),
                "issuer", "did:web:issuer.example", "validFrom", "2026-09-18T10:00:00.000Z", "credentialSubject", Map.of("id", "did:jwk:abc"));
    }

    SigningContext signing(String alias, SignatureAlgorithm alg, String suite) {
        SigningKey key = KEYS.resolve(KeyRef.parse("jca:" + alias)).withAlgorithm(alg);
        return new SigningContext(new SigningConfig(key.ref(), alg, suite, null, null, "did:web:issuer.example"), key, KEYS);
    }

    IssuedCredential issue(Map<String, Object> document, SigningContext signing) {
        CredentialConfiguration configuration = new CredentialConfiguration(null, "c", "s", "ldp_vc", null, null, signing.config(), null, null, null, null, null);
        UnsignedCredential unsigned = formatter.build(ClaimSet.of(document), configuration, CONTEXT, HolderBinding.did("did:jwk:abc", "jwt"));
        return formatter.sign(unsigned, signing, CONTEXT);
    }

    static JsonLDObject jsonLd(IssuedCredential issued) {
        JsonLDObject jsonLd = JsonLDObject.fromJsonObject(issued.credential() instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of());
        jsonLd.setDocumentLoader(LOADER);
        return jsonLd;
    }

    static byte[] ed25519Raw(SigningKey key) {
        byte[] spki = key.descriptor().publicKey().getEncoded();
        return Arrays.copyOfRange(spki, spki.length - 32, spki.length);
    }

    @Test
    void ed25519Signature2020VerifiesWithDanubetech() throws Exception {
        SigningContext signing = signing("dev-eddsa", SignatureAlgorithm.EdDSA, "Ed25519Signature2020");
        IssuedCredential issued = issue(vc11(), signing);

        Map<?, ?> proof = (Map<?, ?>) ((Map<?, ?>) issued.credential()).get("proof");
        assertEquals("Ed25519Signature2020", proof.get("type"));
        assertEquals("did:web:issuer.example#dev-eddsa", proof.get("verificationMethod"));
        assertEquals("assertionMethod", proof.get("proofPurpose"));
        assertEquals("2026-09-18T10:00:00Z", proof.get("created"), "created is the credential's issuanceDate in UTC");
        assertTrue(proof.get("proofValue").toString().startsWith("z"));
        assertTrue(new Ed25519Signature2020LdVerifier(ed25519Raw(signing.key())).verify(jsonLd(issued)));
        assertEquals("ldp_vc", issued.format());
    }

    @Test
    void rsaSignature2018DetachedJwsVerifiesWithDanubetech() throws Exception {
        SigningContext signing = signing("dev-rs256", SignatureAlgorithm.RS256, "RsaSignature2018");
        IssuedCredential issued = issue(vc11(), signing);
        Map<?, ?> proof = (Map<?, ?>) ((Map<?, ?>) issued.credential()).get("proof");
        assertTrue(proof.get("jws").toString().contains(".."), "detached payload");
        assertTrue(new RsaSignature2018LdVerifier((RSAPublicKey) signing.key().descriptor().publicKey()).verify(jsonLd(issued)));
    }

    @Test
    void ecdsaSecp256k1Signature2019VerifiesWithDanubetechAndJca() throws Exception {
        SigningContext signing = signing("dev-es256k", SignatureAlgorithm.ES256K, "EcdsaSecp256k1Signature2019");
        IssuedCredential issued = issue(vc11(), signing);
        ByteVerifier jca = new ByteVerifier(JWSAlgorithm.ES256K) {
            @Override
            protected boolean verify(byte[] content, byte[] signature) throws java.security.GeneralSecurityException {
                Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
                verifier.initVerify(signing.key().descriptor().publicKey());
                verifier.update(content);
                try {
                    return verifier.verify(com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToDER(signature));
                } catch (com.nimbusds.jose.JOSEException e) {
                    throw new java.security.SignatureException(e);
                }
            }
        };
        assertTrue(new EcdsaSecp256k1Signature2019LdVerifier(jca).verify(jsonLd(issued)));
    }

    @Test
    void eddsaRdfc2022DataIntegrityVerifiesWithDanubetech() throws Exception {
        SigningContext signing = signing("dev-eddsa", SignatureAlgorithm.EdDSA, "eddsa-rdfc-2022");
        IssuedCredential issued = issue(vc20(), signing);
        Map<?, ?> proof = (Map<?, ?>) ((Map<?, ?>) issued.credential()).get("proof");
        assertEquals("DataIntegrityProof", proof.get("type"));
        assertEquals("eddsa-rdfc-2022", proof.get("cryptosuite"));
        assertTrue(new DataIntegrityProofLdVerifier(new Ed25519_EdDSA_PublicKeyVerifier(ed25519Raw(signing.key()))).verify(jsonLd(issued)));
    }

    @Test
    void metadataFragmentAndConfigParsing() {
        FormatConfig config = formatter.parseConfig(Map.of("context", "https://www.w3.org/2018/credentials/v1", "credentialType", "FarmerCredential,VerifiableCredential"));
        assertEquals("https://www.w3.org/2018/credentials/v1|FarmerCredential,VerifiableCredential", config.selectorKey());
        CredentialConfiguration configuration = new CredentialConfiguration(null, "c", "s", "ldp_vc", config, null,
                SigningConfig.of(KeyRef.parse("jca:dev-eddsa"), SignatureAlgorithm.EdDSA), null, null, null, null, null);
        Map<String, Object> fragment = formatter.metadataFragment(configuration, ProtocolVersion.OID4VCI_1_0);
        assertEquals("ldp_vc", fragment.get("format"));
        assertEquals(Map.of("@context", List.of("https://www.w3.org/2018/credentials/v1"), "type", List.of("FarmerCredential", "VerifiableCredential")), fragment.get("credential_definition"));
        assertTrue(formatter.handles("ldp_vc"));
    }

    @Test
    void suiteMustBeKnown() {
        FormatException none = assertThrows(FormatException.class, () -> issue(vc11(), signing("dev-eddsa", SignatureAlgorithm.EdDSA, null)));
        assertEquals(LdpVcFormatter.ERROR_UNSUPPORTED_SUITE, none.getErrorCode());
        FormatException unknown = assertThrows(FormatException.class, () -> issue(vc11(), signing("dev-eddsa", SignatureAlgorithm.EdDSA, "NoSuchSuite2030")));
        assertEquals(LdpVcFormatter.ERROR_UNSUPPORTED_SUITE, unknown.getErrorCode());
    }
}
