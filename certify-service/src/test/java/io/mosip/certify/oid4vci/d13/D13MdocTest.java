package io.mosip.certify.oid4vci.d13;

import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class D13MdocTest {

    @Test
    void wrapsIssuerSignedInADocumentWithATaggedIssuerAuth() {
        byte[] issuerAuth = CBORObject.NewArray().Add(new byte[] {1}).Add(CBORObject.NewMap()).Add(new byte[] {2}).Add(new byte[] {3}).EncodeToBytes();
        CBORObject issuerSigned = CBORObject.NewMap()
                .Add("nameSpaces", CBORObject.NewMap().Add("org.iso.18013.5.1", CBORObject.NewArray()))
                .Add("issuerAuth", CBORObject.DecodeFromBytes(issuerAuth));
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(issuerSigned.EncodeToBytes());

        CBORObject document = CBORObject.DecodeFromBytes(Base64.getUrlDecoder().decode(D13Mdoc.wrapDocument(encoded, "org.iso.18013.5.1.mDL")));
        assertEquals("[\"docType\", \"issuerSigned\"]", document.getKeys().toString());
        assertEquals("org.iso.18013.5.1.mDL", document.get("docType").AsString());
        CBORObject wrapped = document.get("issuerSigned").get("issuerAuth");
        assertTrue(wrapped.isTagged());
        assertEquals(18, wrapped.getMostOuterTag().ToInt32Checked());
        assertArrayEquals(issuerAuth, wrapped.Untag().EncodeToBytes(), "the COSE_Sign1 bytes are unchanged under the tag");
        assertFalse(issuerSigned.get("issuerAuth").isTagged(), "the core's IssuerSigned stays untagged");
        assertThrows(IllegalArgumentException.class, () -> D13Mdoc.wrapDocument(Base64.getUrlEncoder().encodeToString(CBORObject.NewMap().EncodeToBytes()), "x"));
    }
}
