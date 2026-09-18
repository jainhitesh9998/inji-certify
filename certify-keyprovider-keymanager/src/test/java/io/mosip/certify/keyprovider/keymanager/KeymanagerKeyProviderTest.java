package io.mosip.certify.keyprovider.keymanager;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import io.mosip.certify.signing.JwsEnvelope;
import io.mosip.certify.signing.JwsHeaderPolicy;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.KeyRequirement;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.signing.SigningKey;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.calls;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class KeymanagerKeyProviderTest {

    static final Instant NOW = Instant.parse("2026-09-18T12:00:00Z");
    static final KeymanagerAlias ED = new KeymanagerAlias("CERTIFY_VC_SIGN_ED25519", "ED25519_SIGN");
    static final KeymanagerAlias R1 = new KeymanagerAlias("CERTIFY_VC_SIGN_EC_R1", "EC_SECP256R1_SIGN");
    static final KeymanagerAlias K1 = new KeymanagerAlias("CERTIFY_VC_SIGN_EC_K1", "EC_SECP256K1_SIGN");
    static final KeymanagerAlias RSA = new KeymanagerAlias("CERTIFY_VC_SIGN_RSA", "");

    KeymanagerStandIn keymanager;
    MutableClock clock;
    KeymanagerKeyProvider provider;
    String edExpiredKid, edCurrentKid;

    @BeforeEach
    void setUp() {
        keymanager = new KeymanagerStandIn();
        clock = new MutableClock(NOW);
        edExpiredKid = keymanager.addKey(ED, SignatureAlgorithm.EdDSA, KeymanagerStandIn.at("2024-01-01T00:00:00Z"), KeymanagerStandIn.at("2025-01-01T00:00:00Z"));
        edCurrentKid = keymanager.addKey(ED, SignatureAlgorithm.EdDSA, KeymanagerStandIn.at("2025-01-01T00:00:00Z"), KeymanagerStandIn.at("2027-01-01T00:00:00Z"));
        keymanager.addKey(R1, SignatureAlgorithm.ES256, KeymanagerStandIn.at("2025-01-01T00:00:00Z"), KeymanagerStandIn.at("2027-01-01T00:00:00Z"));
        keymanager.addKey(K1, SignatureAlgorithm.ES256K, KeymanagerStandIn.at("2025-01-01T00:00:00Z"), KeymanagerStandIn.at("2027-01-01T00:00:00Z"));
        keymanager.addKey(RSA, SignatureAlgorithm.RS256, KeymanagerStandIn.at("2025-01-01T00:00:00Z"), KeymanagerStandIn.at("2027-01-01T00:00:00Z"));
        provider = new KeymanagerKeyProvider(keymanager.keymanagerService, keymanager.signatureService, List.of(ED, R1, RSA), clock, Duration.ofMinutes(1));
    }

    static JWSVerifier verifierFor(SigningKey key) throws Exception {
        JWK jwk = key.descriptor().toJwk();
        if (jwk instanceof RSAKey rsa) return new RSASSAVerifier(rsa);
        if (jwk instanceof ECKey ec) {
            ECDSAVerifier verifier = new ECDSAVerifier(ec);
            verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
            return verifier;
        }
        return new Ed25519Verifier((OctetKeyPair) jwk);
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, names = {"EdDSA", "ES256", "ES256K", "RS256", "PS256"})
    void jwsSignedThroughKeymanagerVerifiesWithNimbus(SignatureAlgorithm alg) throws Exception {
        KeymanagerAlias alias = switch (alg) { case EdDSA -> ED; case ES256 -> R1; case ES256K -> K1; default -> RSA; };
        SigningKey key = provider.resolve(alias.toKeyRef()).withAlgorithm(alg);
        String payload = "{\"iss\":\"https://issuer.example\",\"alg\":\"" + alg.joseName() + "\"}";

        String compact = JwsEnvelope.sign(payload, JwsHeaderPolicy.compact("JWT"), key, provider);

        JWSObject jws = JWSObject.parse(compact);
        assertEquals(alg.joseName(), jws.getHeader().getAlgorithm().getName());
        assertEquals(key.kid(), jws.getHeader().getKeyID());
        assertTrue(jws.verify(verifierFor(key)), "keymanager-signed JWS must verify with the published key for " + alg);
        assertEquals(payload, jws.getPayload().toString());
    }

    @Test
    void resolvePicksTheLatestExpiringValidCertificate() {
        SigningKey key = provider.resolve(ED.toKeyRef());

        assertEquals(edCurrentKid, key.kid());
        assertEquals(SignatureAlgorithm.EdDSA, key.algorithm());
        assertEquals(KeymanagerKeyProvider.PURPOSE_VC_SIGNING, key.descriptor().purpose());
        assertEquals(Instant.parse("2027-01-01T00:00:00Z"), key.descriptor().notAfter());
        assertEquals(1, key.chain().leafFirst().size());
    }

    @Test
    void versionPinsAKeyIdEvenWhenExpired() {
        SigningKey key = provider.resolve(new KeyRef("keymanager", ED.toString(), edExpiredKid));
        assertEquals(edExpiredKid, key.kid());
        assertThrows(SigningException.class, () -> provider.resolve(new KeyRef("keymanager", ED.toString(), "NOPE")));
    }

    @Test
    void noValidCertificateIsAnError() {
        clock.set(Instant.parse("2030-01-01T00:00:00Z"));
        assertThrows(SigningException.class, () -> provider.resolve(ED.toKeyRef()));
        assertThrows(SigningException.class, () -> provider.resolve(KeyRef.parse("keymanager:CERTIFY_VC_SIGN_NONE/NONE")));
    }

    @Test
    void refusesForeignRefsUnsupportedAndMismatchedAlgorithms() {
        SigningKey ed = provider.resolve(ED.toKeyRef());
        assertThrows(SigningException.class, () -> provider.resolve(KeyRef.parse("jca:dev-es256")));
        assertThrows(SigningException.class, () -> provider.signRaw(new byte[]{1}, ed, SignatureAlgorithm.ES384));
        assertThrows(SigningException.class, () -> provider.signRaw(new byte[]{1}, ed, SignatureAlgorithm.ES256));
        assertThrows(SigningException.class, () -> ed.withAlgorithm(SignatureAlgorithm.ES256));
        assertTrue(!provider.supportedAlgorithms().contains(SignatureAlgorithm.ES384));
    }

    @Test
    void publicKeysCoverKnownAliasesAndHonourFilters() {
        List<PublicKeyDescriptor> all = provider.publicKeys(KeyFilter.ALL);
        assertEquals(4, all.size(), "two Ed25519 certificates, one ES256, one RSA; K1 is not a known alias");

        List<PublicKeyDescriptor> valid = provider.publicKeys(new KeyFilter(null, null, NOW));
        assertEquals(3, valid.size());
        assertTrue(valid.stream().noneMatch(d -> d.kid().equals(edExpiredKid)));

        assertEquals(List.of(SignatureAlgorithm.ES256), provider.publicKeys(new KeyFilter(null, SignatureAlgorithm.ES256, null)).stream().map(PublicKeyDescriptor::algorithm).toList());
    }

    @Test
    void certificatesAreCachedForTheTtlAndEvictable() {
        provider.resolve(ED.toKeyRef());
        provider.resolve(ED.toKeyRef());
        verify(keymanager.keymanagerService, times(1)).getAllCertificates(eq(ED.applicationId()), eq(Optional.of(ED.referenceId())));

        clock.set(NOW.plus(Duration.ofMinutes(2)));
        provider.resolve(ED.toKeyRef());
        verify(keymanager.keymanagerService, times(2)).getAllCertificates(eq(ED.applicationId()), eq(Optional.of(ED.referenceId())));

        provider.evict();
        provider.resolve(ED.toKeyRef());
        verify(keymanager.keymanagerService, times(3)).getAllCertificates(eq(ED.applicationId()), eq(Optional.of(ED.referenceId())));
    }

    @Test
    void ensureKeysReproducesTheHistoricalInitKeysCalls() {
        provider.ensureKeys(List.of(
                new KeyRequirement("CERTIFY_VC_SIGN_RSA", SignatureAlgorithm.RS256, "vc-signing"),
                new KeyRequirement("CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", SignatureAlgorithm.EdDSA, "vc-signing")));

        InOrder order = inOrder(keymanager.keymanagerService);
        ArgumentCaptor<KeyPairGenerateRequestDto> rsa = ArgumentCaptor.forClass(KeyPairGenerateRequestDto.class);
        order.verify(keymanager.keymanagerService, calls(1)).generateMasterKey(eq("certificate"), rsa.capture());
        assertEquals("CERTIFY_VC_SIGN_RSA", rsa.getValue().getApplicationId());
        assertEquals("", rsa.getValue().getReferenceId());
        assertEquals(Boolean.FALSE, rsa.getValue().getForce());

        ArgumentCaptor<KeyPairGenerateRequestDto> store = ArgumentCaptor.forClass(KeyPairGenerateRequestDto.class);
        order.verify(keymanager.keymanagerService, calls(1)).generateMasterKey(eq("certificate"), store.capture());
        assertEquals("CERTIFY_VC_SIGN_ED25519", store.getValue().getApplicationId());
        assertEquals("", store.getValue().getReferenceId());

        ArgumentCaptor<KeyPairGenerateRequestDto> ec = ArgumentCaptor.forClass(KeyPairGenerateRequestDto.class);
        order.verify(keymanager.keymanagerService, calls(1)).generateECSignKey(eq("certificate"), ec.capture());
        assertEquals("CERTIFY_VC_SIGN_ED25519", ec.getValue().getApplicationId());
        assertEquals("ED25519_SIGN", ec.getValue().getReferenceId());
        order.verifyNoMoreInteractions();
    }

    @Test
    void aliasGrammarRoundTrips() {
        assertEquals(ED, KeymanagerAlias.parse("CERTIFY_VC_SIGN_ED25519/ED25519_SIGN"));
        assertEquals(RSA, KeymanagerAlias.parse("CERTIFY_VC_SIGN_RSA"));
        assertEquals("keymanager:CERTIFY_VC_SIGN_RSA", RSA.toKeyRef().toString());
        assertEquals("keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", ED.toKeyRef().toString());
        assertEquals(ED, KeymanagerAlias.of(KeyRef.parse("keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN@ABC")));
        assertThrows(IllegalArgumentException.class, () -> KeymanagerAlias.parse("/REF"));
    }

    static final class MutableClock extends Clock {
        private Instant now;
        MutableClock(Instant now) { this.now = now; }
        void set(Instant instant) { now = instant; }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
