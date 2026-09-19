package io.mosip.certify.proof;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** did:web holder keys: DID to URL, the verification method by id, publicKeyJwk and publicKeyMultibase, failures. */
class DIDwebProofManagerTest {

    static final String ED25519_MULTIBASE = "z6MktwAJhFN5fDccQ8k1nDtcTAhaW6YuvVcV5xmjKXH9E6zi";

    @Test
    void mapsTheDidToTheDocumentUrl() {
        assertEquals(URI.create("https://wallet.example/.well-known/did.json"), DIDwebProofManager.documentUrl("did:web:wallet.example"));
        assertEquals(URI.create("https://wallet.example/users/alice/did.json"), DIDwebProofManager.documentUrl("did:web:wallet.example:users:alice"));
        assertEquals(URI.create("https://localhost:8443/.well-known/did.json"), DIDwebProofManager.documentUrl("did:web:localhost%3A8443"));
        assertThrows(IllegalArgumentException.class, () -> DIDwebProofManager.documentUrl("did:web:"));
    }

    @Test
    void resolvesAPublicKeyJwkByVerificationMethodId() throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        String kid = "did:web:wallet.example:users:alice#key-1";
        DIDwebProofManager manager = new DIDwebProofManager(documents(Map.of("https://wallet.example/users/alice/did.json",
                document("did:web:wallet.example:users:alice", "{\"id\":\"" + kid + "\",\"type\":\"JsonWebKey2020\",\"publicKeyJwk\":" + holder.toPublicJWK().toJSONString() + "}"))));
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(kid).build();
        Optional<JWK> key = manager.getKeyFromHeader(header);
        assertTrue(key.isPresent());
        assertEquals(holder.toPublicJWK().computeThumbprint(), key.get().computeThumbprint());
        assertEquals(kid, key.get().getKeyID(), "kid set so the JWS key selector matches the header");
        assertEquals(Optional.of(kid), manager.getDID(header));
    }

    @Test
    void resolvesAPublicKeyMultibaseAndRelativeFragmentIds() throws Exception {
        String kid = "did:web:wallet.example#ed";
        DIDwebProofManager manager = new DIDwebProofManager(documents(Map.of("https://wallet.example/.well-known/did.json",
                document("did:web:wallet.example", "{\"id\":\"#ed\",\"type\":\"Ed25519VerificationKey2020\",\"publicKeyMultibase\":\"" + ED25519_MULTIBASE + "\"}"))));
        Optional<JWK> key = manager.getKeyFromHeader(new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(kid).build());
        assertTrue(key.isPresent());
        assertEquals("OKP", key.get().getKeyType().getValue());
        assertEquals(kid, key.get().getKeyID());
    }

    @Test
    void answersEmptyForUnknownMethodsMismatchedDocumentsAndFetchFailures() throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        String method = "{\"id\":\"did:web:wallet.example#key-1\",\"type\":\"JsonWebKey2020\",\"publicKeyJwk\":" + holder.toPublicJWK().toJSONString() + "}";
        DIDwebProofManager known = new DIDwebProofManager(documents(Map.of("https://wallet.example/.well-known/did.json", document("did:web:wallet.example", method))));
        assertTrue(known.getKeyFromHeader(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("did:web:wallet.example#key-2").build()).isEmpty(), "unknown fragment");
        DIDwebProofManager mismatched = new DIDwebProofManager(documents(Map.of("https://wallet.example/.well-known/did.json", document("did:web:other.example", method))));
        assertTrue(mismatched.getKeyFromHeader(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("did:web:wallet.example#key-1").build()).isEmpty(), "document id differs");
        DIDwebProofManager unreachable = new DIDwebProofManager(url -> { throw new IOException("connection refused"); });
        assertTrue(unreachable.getKeyFromHeader(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("did:web:wallet.example#key-1").build()).isEmpty(), "fetch failure");
        assertTrue(unreachable.getKeyFromHeader(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("did:key:z6Mk").build()).isEmpty(), "not a did:web");
        assertTrue(unreachable.getDID(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("did:key:z6Mk").build()).isEmpty());
    }

    private static String document(String id, String verificationMethod) {
        return "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"id\":\"" + id + "\",\"verificationMethod\":[" + verificationMethod + "]}";
    }

    private static DidDocumentFetcher documents(Map<String, String> byUrl) {
        return url -> {
            String document = byUrl.get(url.toString());
            if (document == null) {
                throw new IOException("404 " + url);
            }
            return document;
        };
    }
}
