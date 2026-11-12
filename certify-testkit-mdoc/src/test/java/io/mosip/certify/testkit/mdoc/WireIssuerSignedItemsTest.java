/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The CBOR framing matrix of the raw-slice scanner (RFC 8949 3): every argument width, definite and indefinite maps,
 * arrays and strings, and the malformed inputs that must be refused rather than read past the end or zero-padded.
 */
class WireIssuerSignedItemsTest {

    static final String NS = "org.iso.18013.5.1";

    // ---- well-formed framing -----------------------------------------------------------------------------------

    @Test
    void definiteFramingWithImmediateLengths() {
        byte[] first = tag24(item(7, "family_name"), 0);
        byte[] second = tag24(item(3, "given_name"), 0);
        byte[] cbor = map(entry("issuerAuth", text("x")), entry("nameSpaces", map(entry(NS, array(first, second)))));

        List<WireIssuerSignedItems.Item> items = WireIssuerSignedItems.scan(cbor);
        assertEquals(2, items.size());
        assertArrayEquals(first, items.get(0).raw(), "the exact received bytes, tag and length head included");
        assertEquals(7, items.get(0).digestId());
        assertEquals("family_name", items.get(0).identifier());
        assertEquals(NS, items.get(0).namespace());
        assertArrayEquals(second, items.get(1).raw());
        assertEquals(1, items.get(1).index());
    }

    @ParameterizedTest(name = "a {0}-byte bstr length head is sliced as received")
    @ValueSource(ints = {1, 2, 4, 8})
    void everyLengthWidthIsSlicedAsReceived(int width) {
        // a short item under a deliberately wide (non-preferred) length head: the slice must keep the head's bytes
        byte[] wide = tag24(item(1, "birth_date"), width);
        byte[] cbor = map(entry("nameSpaces", map(entry(NS, array(wide)))));
        WireIssuerSignedItems.Item item = WireIssuerSignedItems.scan(cbor).get(0);
        assertArrayEquals(wide, item.raw());
        assertEquals("birth_date", item.identifier());
    }

    @Test
    void largeValuesUnderTwoAndFourByteHeadsAreSkipped() {
        byte[] big = new byte[70_000]; // needs a 4-byte length head
        Arrays.fill(big, (byte) 0x41);
        byte[] medium = new byte[300]; // needs a 2-byte length head
        byte[] cbor = map(entry("issuerAuth", bytes(big)), entry("status", text(new String(medium, StandardCharsets.ISO_8859_1))),
                entry("nameSpaces", map(entry(NS, array(tag24(item(2, "portrait"), 0))))));
        assertEquals("portrait", WireIssuerSignedItems.scan(cbor).get(0).identifier());
    }

    @Test
    void indefiniteMapsArraysAndStringsAreWalked() {
        byte[] first = tag24(item(1, "a"), 0);
        byte[] second = tag24(item(2, "b"), 0);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xbf); // indefinite IssuerSigned map, as Multipaz accepts
        // issuerAuth: an indefinite bstr of two chunks
        out.writeBytes(text("issuerAuth"));
        out.write(0x5f);
        out.writeBytes(bytes(new byte[] {1, 2}));
        out.writeBytes(bytes(new byte[] {3}));
        out.write(0xff);
        // the key nameSpaces itself as an indefinite tstr of two chunks
        out.write(0x7f);
        out.writeBytes(text("name"));
        out.writeBytes(text("Spaces"));
        out.write(0xff);
        // indefinite nameSpaces map holding an indefinite namespace array
        out.write(0xbf);
        out.writeBytes(text(NS));
        out.write(0x9f);
        out.writeBytes(first);
        out.writeBytes(second);
        out.write(0xff);
        out.write(0xff);
        out.write(0xff);

        List<WireIssuerSignedItems.Item> items = WireIssuerSignedItems.scan(out.toByteArray());
        assertEquals(2, items.size());
        assertArrayEquals(first, items.get(0).raw());
        assertArrayEquals(second, items.get(1).raw());
    }

    @Test
    void theDocumentValueIsSlicedWithoutReencoding() {
        byte[] issuerSigned = map(entry("nameSpaces", map(entry(NS, array(tag24(item(1, "a"), 2))))));
        byte[] document = map(entry("docType", text("org.iso.18013.5.1.mDL")), entry("issuerSigned", issuerSigned));
        assertArrayEquals(issuerSigned, WireIssuerSignedItems.valueOf(document, "issuerSigned"));
        assertNull(WireIssuerSignedItems.valueOf(document, "deviceSigned"));
    }

    // ---- malformed input is refused --------------------------------------------------------------------------

    @Test
    void aTruncatedStringIsRefusedNotZeroPadded() {
        byte[] cbor = concat(new byte[] {(byte) 0xa1}, text("issuerAuth"), new byte[] {0x4a, 1, 2, 3, 4, 5}); // 10 declared, 5 present
        assertRefused(cbor, "declares 10 byte(s) but only 5 remain");
    }

    @Test
    void anEightByteLengthBeyondTwoToTheSixtyThreeIsRefused() {
        byte[] cbor = concat(new byte[] {(byte) 0xa1}, text("issuerAuth"),
                new byte[] {0x5b, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0});
        assertRefused(cbor, "declares 18446744073709551615 byte(s)");
    }

    @Test
    void aFourByteLengthBeyondTheInputIsRefused() {
        byte[] cbor = concat(new byte[] {(byte) 0xa1}, text("issuerAuth"), new byte[] {0x5a, 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0});
        assertRefused(cbor, "declares 2147483647 byte(s) but only 1 remain");
    }

    @Test
    void anArrayCountBeyondTheInputIsRefused() {
        byte[] cbor = concat(new byte[] {(byte) 0xa1}, text("nameSpaces"), new byte[] {(byte) 0xa1}, text(NS),
                new byte[] {(byte) 0x9b, 0x10, 0, 0, 0, 0, 0, 0, 0});
        assertRefused(cbor, "entries but only 0 byte(s) remain");
    }

    @Test
    void aTruncatedHeadIsRefused() {
        byte[] cbor = concat(new byte[] {(byte) 0xa1}, text("issuerAuth"), new byte[] {0x59, 0x01});
        assertRefused(cbor, "truncated CBOR head");
    }

    @Test
    void trailingBytesAreRefused() {
        assertRefused(concat(map(entry("issuerAuth", text("x"))), new byte[] {0x00}), "trailing byte");
    }

    @Test
    void reservedAdditionalInformationIsRefused() {
        assertRefused(concat(new byte[] {(byte) 0xa1}, text("issuerAuth"), new byte[] {0x1c}), "reserved CBOR additional information 28");
    }

    @Test
    void aBreakWhereAValueBelongsIsRefused() {
        assertRefused(concat(new byte[] {(byte) 0xbf}, text("issuerAuth"), new byte[] {(byte) 0xff}), "unexpected break");
    }

    @Test
    void anIndefiniteStringWithAForeignChunkIsRefused() {
        assertRefused(concat(new byte[] {(byte) 0xa1}, text("issuerAuth"), new byte[] {0x5f}, text("x"), new byte[] {(byte) 0xff}),
                "RFC 8949 3.2.3");
    }

    @Test
    void anUnterminatedIndefiniteArrayIsRefused() {
        assertRefused(concat(new byte[] {(byte) 0xa1}, text("nameSpaces"), new byte[] {(byte) 0xa1}, text(NS),
                new byte[] {(byte) 0x9f}, tag24(item(1, "a"), 0)), "not terminated");
    }

    @Test
    void nestingBeyondTheLimitIsRefusedWithoutBlowingTheStack() {
        byte[] deep = new byte[100_000];
        Arrays.fill(deep, (byte) 0x81); // [[[[...
        assertRefused(concat(new byte[] {(byte) 0xa1}, text("issuerAuth"), deep), "nested deeper than");
    }

    @Test
    void aDuplicateNameSpacesKeyIsRefused() {
        byte[] namespaces = map(entry(NS, array(tag24(item(1, "a"), 0))));
        assertRefused(map(entry("nameSpaces", namespaces), entry("nameSpaces", namespaces)), "twice");
    }

    @Test
    void anItemWithoutTag24IsRefused() {
        assertRefused(map(entry("nameSpaces", map(entry(NS, array(bytes(item(1, "a"))))))), "not wrapped in tag 24");
    }

    // ---- CBOR building blocks ----------------------------------------------------------------------------------

    static void assertRefused(byte[] cbor, String message) {
        AssertionError error = assertThrows(AssertionError.class, () -> WireIssuerSignedItems.scan(cbor));
        assertTrue(error.getMessage().contains(message), "expected \"" + message + "\" in: " + error.getMessage());
    }

    /** The head of a CBOR item; {@code width} 0 is the preferred encoding, 1/2/4/8 force that many argument bytes. */
    static byte[] head(int major, long argument, int width) {
        if (width == 0) {
            if (argument < 24) {
                return new byte[] {(byte) ((major << 5) | argument)};
            }
            width = argument < 0x100 ? 1 : argument < 0x10000 ? 2 : argument < 0x100000000L ? 4 : 8;
        }
        int additional = switch (width) {
            case 1 -> 24;
            case 2 -> 25;
            case 4 -> 26;
            default -> 27;
        };
        byte[] head = new byte[1 + width];
        head[0] = (byte) ((major << 5) | additional);
        for (int i = 0; i < width; i++) {
            head[width - i] = (byte) (argument >>> (8 * i));
        }
        return head;
    }

    static byte[] text(String value) {
        byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
        return concat(head(3, utf8.length, 0), utf8);
    }

    static byte[] bytes(byte[] value) {
        return concat(head(2, value.length, 0), value);
    }

    static byte[] array(byte[]... items) {
        return concat(head(4, items.length, 0), concat(items));
    }

    static byte[][] entry(String key, byte[] value) {
        return new byte[][] {text(key), value};
    }

    static byte[] map(byte[][]... entries) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(head(5, entries.length, 0));
        for (byte[][] entry : entries) {
            out.writeBytes(entry[0]);
            out.writeBytes(entry[1]);
        }
        return out.toByteArray();
    }

    /** An IssuerSignedItem map with what the scanner reads: digestID and elementIdentifier. */
    static byte[] item(int digestId, String identifier) {
        return map(entry("digestID", head(0, digestId, 0)), entry("elementIdentifier", text(identifier)));
    }

    /** #6.24(bstr) around {@code content}, the bstr length head in the given width. */
    static byte[] tag24(byte[] content, int width) {
        return concat(new byte[] {(byte) 0xd8, 0x18}, head(2, content.length, width), content);
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}
