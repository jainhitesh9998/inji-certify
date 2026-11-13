package io.mosip.certify.status;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.upokecenter.cbor.CBORObject;
import io.mosip.certify.signing.CoseEnvelope;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.security.Signature;
import java.time.Duration;
import java.util.List;

import static io.mosip.certify.status.StatusListTestKeys.DSC;
import static io.mosip.certify.status.StatusListTestKeys.EXPIRED;
import static io.mosip.certify.status.StatusListTestKeys.EXPIRED_KEYS;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;

/**
 * M-11d: the endpoint's one-format-per-list rule (owner decision D-M11-2, draft-ietf-oauth-status-list sections 8.1-8.2)
 * and the statuses of the CWT branch (D-M11-7).
 *
 * <p>What this test proves, item by item:
 * <ul>
 *   <li>a {@code TokenStatusList} (JWT) row answers exactly as before the change for every {@code Accept} — the stored
 *   JWT bytes, {@code 200}, {@code application/statuslist+jwt} — pinned here against the stored document so a byte of
 *   movement fails;</li>
 *   <li>a {@code TokenStatusListCwt} row answers {@code 200} + {@code application/statuslist+cwt} + the raw CWT for
 *   every {@code Accept}, {@code application/statuslist+jwt} included (one format per list, never negotiated), and the
 *   body verifies with Authlete COSE and plain JCA against the signing certificate (the independent verifier runs as
 *   conformance samples: this module's classpath cannot carry Multipaz, see the M-11d section "Where the independent
 *   check runs");</li>
 *   <li>{@code HEAD} answers the same status and headers with no body;</li>
 *   <li>a retired CWT list is {@code 410} with no {@code Retry-After} and no body, once its own {@code exp} has
 *   passed;</li>
 *   <li>a CWT list whose pinned signer is gone, or whose renewal the signer policy refuses, is {@code 503} with
 *   {@code Retry-After} — never an old body;</li>
 *   <li>an unknown id is {@code 404}.</li>
 * </ul>
 */
class TokenStatusListControllerCwtTest {

    static final List<String> ACCEPTS = List.of(TokenStatusListService.MEDIA_TYPE, TokenStatusListService.MEDIA_TYPE_CWT,
            "application/json", "text/html", "*/*", "");

    @Test
    void aJwtRowAnswersTheStoredJwtForEveryAccept() throws Exception {
        TokenStatusListCwtServiceTest.Fixture fixture = new TokenStatusListCwtServiceTest.Fixture();
        TokenStatusListService lists = fixture.lists(TokenStatusListCwtServiceTest.T0);
        TokenStatusListService.Entry entry = lists.allocate("revocation");
        String listId = fixture.listId(entry);
        String stored = fixture.rows.get(listId).getVcDocument();
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new TokenStatusListController(lists)).build();

        for (String accept : ACCEPTS) {
            var request = get("/credentials/token-status-list/" + listId);
            if (!accept.isEmpty()) {
                request = request.accept(accept);
            }
            MvcResult result = mvc.perform(request).andReturn();
            assertEquals(200, result.getResponse().getStatus(), accept);
            assertEquals(TokenStatusListService.MEDIA_TYPE, result.getResponse().getContentType(), accept);
            assertEquals(stored, result.getResponse().getContentAsString(), "the stored JWT, byte for byte, for " + accept);
        }

        // HEAD keeps the GET mapping's status and headers; the servlet container discards the body, MockMvc does not
        MvcResult head = mvc.perform(head("/credentials/token-status-list/" + listId)).andReturn();
        assertEquals(200, head.getResponse().getStatus());
        assertEquals(TokenStatusListService.MEDIA_TYPE, head.getResponse().getContentType());
    }

    @Test
    void aCwtRowAnswersTheCwtForEveryAcceptIncludingJwt() throws Exception {
        TokenStatusListCwtServiceTest.Fixture fixture = new TokenStatusListCwtServiceTest.Fixture();
        TokenStatusListService lists = fixture.lists(TokenStatusListCwtServiceTest.T0);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        String listId = fixture.listId(entry);
        byte[] stored = TokenStatusListCwtServiceTest.TokenStatusListCwtBase.token(
                fixture.rows.get(listId).getVcDocument());
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new TokenStatusListController(lists)).build();

        for (String accept : ACCEPTS) {
            var request = get("/credentials/token-status-list/" + listId);
            if (!accept.isEmpty()) {
                request = request.accept(accept);
            }
            MvcResult result = mvc.perform(request).andReturn();
            assertEquals(200, result.getResponse().getStatus(), accept);
            assertEquals(TokenStatusListService.MEDIA_TYPE_CWT, result.getResponse().getContentType(),
                    "one format per list: the Accept is disregarded (D-M11-2), for " + accept);
            assertArrayEquals(stored, result.getResponse().getContentAsByteArray(), accept);
            assertVerified(result.getResponse().getContentAsByteArray());
        }

        MvcResult head = mvc.perform(head("/credentials/token-status-list/" + listId)
                .accept(TokenStatusListService.MEDIA_TYPE)).andReturn();
        assertEquals(200, head.getResponse().getStatus());
        assertEquals(TokenStatusListService.MEDIA_TYPE_CWT, head.getResponse().getContentType(),
                "HEAD answers the list's own type even when the client asked for JWT");
    }

    @Test
    void aRetiredCwtListIs410WithoutRetryAfter() throws Exception {
        TokenStatusListCwtServiceTest.Fixture fixture = new TokenStatusListCwtServiceTest.Fixture();
        TokenStatusListCwtServiceTest.MutableClock clock = new TokenStatusListCwtServiceTest.MutableClock(
                TokenStatusListCwtServiceTest.T0);
        fixture.clock = clock;
        TokenStatusListService lists = fixture.lists(clock);
        String listId = "a-retired-cwt-list";
        byte[] token = TokenStatusListCwtServiceTest.TokenStatusListCwtBase.storedToken(
                TokenStatusListCwtServiceTest.URI(listId), TokenStatusListCwtServiceTest.T0.minus(Duration.ofHours(2)),
                TokenStatusListCwtServiceTest.T0.plus(Duration.ofMinutes(30)), new byte[128],
                StatusListTestKeys.key("expired", EXPIRED_KEYS, EXPIRED));
        fixture.rows.put(listId, fixture.row(listId, TokenStatusListService.TYPE_CWT,
                TokenStatusListCwtServiceTest.TokenStatusListCwtBase.envelope(new TokenStatusListService.SignerBinding(
                        TokenStatusListService.SIGNER_DOCUMENT, "x509-file:mdl-dsc", StatusListSigners.x5tS256(EXPIRED)),
                        token)));
        fixture.documents.put(listId, fixture.rows.get(listId).getVcDocument());
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new TokenStatusListController(lists)).build();

        MvcResult beforeExp = mvc.perform(get("/credentials/token-status-list/" + listId)).andReturn();
        assertEquals(200, beforeExp.getResponse().getStatus(), "a retired list is served as stored while its exp holds");
        assertArrayEquals(token, beforeExp.getResponse().getContentAsByteArray());

        clock.advance(Duration.ofMinutes(31));
        MvcResult gone = mvc.perform(get("/credentials/token-status-list/" + listId)
                .accept(TokenStatusListService.MEDIA_TYPE_CWT)).andReturn();
        assertEquals(410, gone.getResponse().getStatus());
        assertNull(gone.getResponse().getHeader(HttpHeaders.RETRY_AFTER),
                "asking again cannot help: no Retry-After on a retired list (D-M11-7)");
        assertEquals(0, gone.getResponse().getContentAsByteArray().length);
    }

    @Test
    void aCwtListWhoseSignerIsGoneIs503WithRetryAfter() throws Exception {
        TokenStatusListCwtServiceTest.Fixture fixture = new TokenStatusListCwtServiceTest.Fixture();
        TokenStatusListCwtServiceTest.MutableClock clock = new TokenStatusListCwtServiceTest.MutableClock(
                TokenStatusListCwtServiceTest.T0);
        fixture.clock = clock;
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        fixture.switching.available.set(false);
        clock.advance(TokenStatusListCwtServiceTest.TTL.multipliedBy(2));
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new TokenStatusListController(lists)).build();

        MvcResult refused = mvc.perform(get("/credentials/token-status-list/" + fixture.listId(entry))).andReturn();
        assertEquals(503, refused.getResponse().getStatus());
        assertEquals(Long.toString(TokenStatusListCwtServiceTest.BACKOFF.getSeconds()),
                refused.getResponse().getHeader(HttpHeaders.RETRY_AFTER));
        assertEquals(0, refused.getResponse().getContentAsByteArray().length, "never an old body");
    }

    @Test
    void aPolicyRefusalAtRenewalIs503WithRetryAfter() throws Exception {
        TokenStatusListCwtServiceTest.Fixture fixture = new TokenStatusListCwtServiceTest.Fixture();
        TokenStatusListCwtServiceTest.MutableClock clock = new TokenStatusListCwtServiceTest.MutableClock(
                TokenStatusListCwtServiceTest.T0);
        fixture.clock = clock;
        TokenStatusListService lists = fixture.lists(clock);
        TokenStatusListService.Entry entry = lists.allocateCwt("revocation", fixture.dsc());
        fixture.registry.crl.set(StatusListTestKeys.crl(TokenStatusListCwtServiceTest.T0.minus(Duration.ofHours(1)),
                TokenStatusListCwtServiceTest.T0.plus(Duration.ofDays(1)), DSC.getSerialNumber()));
        fixture.registry.enforced.set(true);
        clock.advance(TokenStatusListCwtServiceTest.TTL.multipliedBy(2));
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new TokenStatusListController(lists)).build();

        MvcResult refused = mvc.perform(get("/credentials/token-status-list/" + fixture.listId(entry))).andReturn();
        assertEquals(503, refused.getResponse().getStatus());
        assertEquals(Long.toString(TokenStatusListCwtServiceTest.BACKOFF.getSeconds()),
                refused.getResponse().getHeader(HttpHeaders.RETRY_AFTER),
                "a revoked signer is the back-off and 503, never an unsigned or old-exp body");
    }

    @Test
    void anUnknownListIs404AndABitstringRowIsNotServed() throws Exception {
        TokenStatusListCwtServiceTest.Fixture fixture = new TokenStatusListCwtServiceTest.Fixture();
        TokenStatusListService lists = fixture.lists(TokenStatusListCwtServiceTest.T0);
        fixture.rows.put("bitstring", fixture.row("bitstring", "BitstringStatusListCredential", "{}"));
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new TokenStatusListController(lists)).build();
        assertEquals(404, mvc.perform(get("/credentials/token-status-list/no-such-list")).andReturn().getResponse().getStatus());
        assertEquals(404, mvc.perform(get("/credentials/token-status-list/bitstring")).andReturn().getResponse().getStatus());
    }

    /** Authlete COSE and plain JCA accept the served token's signature against the certificate its x5chain names. */
    static void assertVerified(byte[] body) throws Exception {
        CBORItem item = new CBORDecoder(body).next();
        assertTrue(item instanceof CBORTaggedItem, "a Status List Token is tag 18 (TSL section 5.2)");
        CBORTaggedItem tagged = (CBORTaggedItem) item;
        assertEquals(18L, tagged.getTagNumber().longValue());
        assertEquals(DSC, TokenStatusListCwt.decode(body).x5chain().get(0));
        COSESign1 sign1 = COSESign1.build(tagged.getTagContent());
        assertEquals(TokenStatusListCwt.MEDIA_TYPE,
                sign1.getProtectedHeader().getParameters().get(CoseEnvelope.LABEL_TYP));
        assertEquals(List.of(DSC), sign1.getProtectedHeader().getX5Chain(), "the signer chain without the IACA");
        assertTrue(new COSEVerifier(DSC.getPublicKey()).verify(sign1), "Authlete COSE accepts the signature");

        CBORObject cose = CBORObject.DecodeFromBytes(body).UntagOne();
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(DSC.getPublicKey());
        verifier.update(CoseEnvelope.sigStructure(cose.get(0).GetByteString(), new byte[0], cose.get(2).GetByteString()));
        assertTrue(verifier.verify(ECDSA.transcodeSignatureToDER(cose.get(3).GetByteString())),
                "plain JCA verifies SHA256withECDSA over Sig_structure");
    }

    static {
        if (!DSC.getNotAfter().toInstant().isAfter(TokenStatusListCwtServiceTest.T0)) {
            throw new IllegalStateException("the fixture Document Signer must outlive the test instants");
        }
    }
}
