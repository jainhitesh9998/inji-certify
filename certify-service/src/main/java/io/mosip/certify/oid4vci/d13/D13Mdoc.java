package io.mosip.certify.oid4vci.d13;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.List;

/**
 * The 0.14.0 mDoc wire shape: a Document {@code {docType, issuerSigned}} whose {@code issuerAuth} carries the
 * COSE_Sign1 tag 18, around the bare IssuerSigned the core produces. The MSO itself is left as the core signs it
 * (tag 24 around the payload, {@code signed} in validityInfo: both required by ISO/IEC 18013-5 and absent in 0.14.0;
 * see docs/design/wp/P0-02-notes.md and the decision log).
 */
final class D13Mdoc {

    static final long COSE_SIGN1_TAG = 18;

    private D13Mdoc() {}

    static String wrapDocument(String issuerSignedBase64Url, String docType) {
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(issuerSignedBase64Url);
            List<DataItem> items = new CborDecoder(new ByteArrayInputStream(bytes)).decode();
            if (items.isEmpty() || !(items.get(0) instanceof Map issuerSigned)) {
                throw new IllegalArgumentException("IssuerSigned is not a CBOR map");
            }
            DataItem issuerAuth = issuerSigned.get(new UnicodeString("issuerAuth"));
            if (issuerAuth == null) {
                throw new IllegalArgumentException("IssuerSigned carries no issuerAuth");
            }
            issuerAuth.setTag(COSE_SIGN1_TAG);
            Map document = new Map();
            document.put(new UnicodeString("docType"), new UnicodeString(docType));
            document.put(new UnicodeString("issuerSigned"), issuerSigned);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            new CborEncoder(out).encode(document);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(out.toByteArray());
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Could not wrap the mDoc as a Document: " + e.getMessage(), e);
        }
    }
}
