/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

import org.multipaz.cbor.Cbor;
import org.multipaz.cbor.DataItem;
import org.multipaz.cbor.Tagged;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The {@code IssuerSignedItem} entries of an {@code IssuerSigned} <b>as they arrived</b>, one raw byte slice each.
 *
 * <p>ISO/IEC 18013-5 9.1.2.5 hashes the bytes of the {@code Tagged(24, bstr)} wrapper, so a verifier that re-encodes
 * the parsed item is checking its own encoder rather than the credential: a non-preferred integer encoding such as
 * {@code 18 00} for {@code 0} disappears on re-encoding, and a credential whose {@code valueDigests} no longer cover
 * the bytes on the wire would still pass. {@code IssuerSignedItem.calculateDigest} re-encodes, so it cannot be the
 * primary oracle; this scanner is. The parsed item (digestID, elementIdentifier) is read out of the same slice, so
 * the identifier and the hashed bytes cannot disagree.
 *
 * <p>The scanner walks the CBOR framing only (RFC 8949 3): definite and indefinite maps, arrays and strings, every
 * argument width. It interprets nothing except the keys it needs ({@code nameSpaces}, the namespace names,
 * {@code digestID}, {@code elementIdentifier}). Offsets and lengths are {@code long} and every slice is checked against
 * the end of the input, so a truncated or oversized length is an error and never a zero-padded copy.
 */
final class WireIssuerSignedItems {

    /** One {@code Tagged(24, bstr)} entry: the exact received bytes and the metadata read out of them. */
    record Item(String namespace, int index, byte[] raw, long digestId, String identifier) {}

    /** Deeper nesting than this is refused rather than risking the stack; an IssuerSigned needs fewer than ten. */
    static final int MAX_DEPTH = 256;

    private static final int MAJOR_BYTES = 2;
    private static final int MAJOR_TEXT = 3;
    private static final int MAJOR_ARRAY = 4;
    private static final int MAJOR_MAP = 5;
    private static final int MAJOR_TAG = 6;
    private static final int INDEFINITE = 31;

    private WireIssuerSignedItems() {}

    static List<Item> scan(byte[] cbor) {
        List<Item> items = new ArrayList<>();
        long[] namespaces = mapValue(cbor, "nameSpaces", "IssuerSigned");
        if (namespaces != null) {
            scanNamespaces(cbor, namespaces[0], items);
        }
        return items;
    }

    /**
     * The raw bytes of the value under the text key {@code key} of the top-level map, or null when the map has no such
     * key. Used to take the {@code issuerSigned} of a draft-13 {@code Document} exactly as it arrived.
     */
    static byte[] valueOf(byte[] cbor, String key) {
        long[] range = mapValue(cbor, key, "the top-level CBOR item");
        return range == null ? null : Arrays.copyOfRange(cbor, (int) range[0], (int) range[1]);
    }

    /** {start, end} of the value under {@code key} in the top-level map, after checking the whole input is that map. */
    private static long[] mapValue(byte[] cbor, String key, String what) {
        Cursor top = header(cbor, 0);
        require(top.major == MAJOR_MAP, what + " is not a CBOR map");
        long[] found = null;
        long position = top.next;
        for (long i = 0; top.indefinite() || i < top.count(cbor, 0); i++) {
            if (top.indefinite() && isBreak(cbor, position)) {
                position++;
                break;
            }
            long valueOffset = skip(cbor, position, 1);
            long end = skip(cbor, valueOffset, 1);
            if (header(cbor, position).major == MAJOR_TEXT && key.equals(text(cbor, position, what + " key"))) {
                require(found == null, what + " carries the key " + key + " twice");
                found = new long[] {valueOffset, end};
            }
            position = end;
        }
        require(position == cbor.length, what + " is followed by " + (cbor.length - position) + " trailing byte(s)");
        return found;
    }

    private static void scanNamespaces(byte[] cbor, long offset, List<Item> items) {
        Cursor namespaces = header(cbor, offset);
        require(namespaces.major == MAJOR_MAP, "IssuerSigned.nameSpaces is not a CBOR map");
        long position = namespaces.next;
        for (long i = 0; namespaces.indefinite() || i < namespaces.count(cbor, offset); i++) {
            if (namespaces.indefinite() && isBreak(cbor, position)) {
                return;
            }
            String namespace = text(cbor, position, "namespace key");
            long arrayOffset = skip(cbor, position, 2);
            Cursor array = header(cbor, arrayOffset);
            require(array.major == MAJOR_ARRAY, "namespace " + namespace + " is not a CBOR array");
            long element = array.next;
            for (long index = 0; array.indefinite() || index < array.count(cbor, arrayOffset); index++) {
                if (array.indefinite() && isBreak(cbor, element)) {
                    break;
                }
                long end = skip(cbor, element, 3);
                items.add(decodeItem(namespace, (int) index, Arrays.copyOfRange(cbor, (int) element, (int) end)));
                element = end;
            }
            position = skip(cbor, arrayOffset, 2);
        }
    }

    private static Item decodeItem(String namespace, int index, byte[] raw) {
        DataItem decoded = Cbor.INSTANCE.decode(raw);
        if (!(decoded instanceof Tagged tagged)) {
            throw new AssertionError("IssuerSignedItem " + index + " in " + namespace
                    + " is not wrapped in tag 24 (ISO/IEC 18013-5 9.1.2.5)");
        }
        require(tagged.getTagNumber() == Tagged.ENCODED_CBOR,
                "IssuerSignedItem " + index + " in " + namespace + " carries tag " + tagged.getTagNumber() + ", not 24");
        DataItem item = Cbor.INSTANCE.decode(tagged.getTaggedItem().getAsBstr());
        require(item.getMajorType() == org.multipaz.cbor.MajorType.MAP,
                "IssuerSignedItem " + index + " in " + namespace + " is not a CBOR map");
        DataItem digestId = item.getOrNull("digestID");
        require(digestId != null, "IssuerSignedItem " + index + " in " + namespace + " has no digestID");
        DataItem identifier = item.getOrNull("elementIdentifier");
        require(identifier != null, "IssuerSignedItem " + index + " in " + namespace + " has no elementIdentifier");
        return new Item(namespace, index, raw, digestId.getAsNumber(), identifier.getAsTstr());
    }

    /**
     * A CBOR head: major type, additional information, the argument and where the content starts. The argument of an
     * 8-byte head is unsigned; a value of 2^63 or more reads back negative here and is refused wherever it is used
     * as a length or a count.
     */
    private record Cursor(int major, int additional, long argument, long next) {

        boolean indefinite() {
            return additional == INDEFINITE;
        }

        /** The entry count of a definite array or map, checked against what is left: every entry needs a byte. */
        long count(byte[] cbor, long offset) {
            require(argument >= 0 && argument <= cbor.length - next, "CBOR " + (major == MAJOR_ARRAY ? "array" : "map")
                    + " at offset " + offset + " declares " + Long.toUnsignedString(argument)
                    + " entries but only " + (cbor.length - next) + " byte(s) remain");
            return argument;
        }
    }

    private static Cursor header(byte[] cbor, long offset) {
        require(offset >= 0 && offset < cbor.length, "CBOR item at offset " + offset + " runs past the end of the input ("
                + cbor.length + " bytes)");
        int initial = cbor[(int) offset] & 0xff;
        int major = initial >>> 5;
        int additional = initial & 0x1f;
        long next = offset + 1;
        long argument;
        switch (additional) {
            case 24, 25, 26, 27 -> {
                int size = 1 << (additional - 24);
                require(cbor.length - next >= size, "truncated CBOR head at offset " + offset + ": the argument needs "
                        + size + " byte(s), " + (cbor.length - next) + " remain");
                argument = 0;
                for (int i = 0; i < size; i++) {
                    argument = (argument << 8) | (cbor[(int) (next + i)] & 0xffL);
                }
                next += size;
            }
            case 28, 29, 30 -> throw new AssertionError("reserved CBOR additional information " + additional
                    + " at offset " + offset + " (RFC 8949 3)");
            case INDEFINITE -> {
                require(major == MAJOR_BYTES || major == MAJOR_TEXT || major == MAJOR_ARRAY || major == MAJOR_MAP
                        || major == 7, "major type " + major + " cannot be indefinite-length (offset " + offset + ")");
                argument = -1;
            }
            default -> argument = additional;
        }
        return new Cursor(major, additional, argument, next);
    }

    /** The end offset of the item starting at {@code offset}, without interpreting it. */
    private static long skip(byte[] cbor, long offset, int depth) {
        require(depth <= MAX_DEPTH, "CBOR nested deeper than " + MAX_DEPTH + " levels at offset " + offset);
        Cursor cursor = header(cbor, offset);
        switch (cursor.major) {
            case 0, 1 -> {
                return cursor.next;
            }
            case MAJOR_BYTES, MAJOR_TEXT -> {
                if (!cursor.indefinite()) {
                    return within(cbor, cursor, offset);
                }
                long position = cursor.next;
                while (!isBreak(cbor, position)) {
                    Cursor chunk = header(cbor, position);
                    require(chunk.major == cursor.major && !chunk.indefinite(), "indefinite-length string at offset "
                            + offset + " carries a chunk at offset " + position + " that is not a definite string of "
                            + "the same major type (RFC 8949 3.2.3)");
                    position = within(cbor, chunk, position);
                }
                return position + 1;
            }
            case MAJOR_ARRAY, MAJOR_MAP -> {
                int perEntry = cursor.major == MAJOR_ARRAY ? 1 : 2;
                long position = cursor.next;
                for (long i = 0; cursor.indefinite() || i < cursor.count(cbor, offset); i++) {
                    if (cursor.indefinite() && isBreak(cbor, position)) {
                        return position + 1;
                    }
                    for (int k = 0; k < perEntry; k++) {
                        position = skip(cbor, position, depth + 1);
                    }
                }
                return position;
            }
            case MAJOR_TAG -> {
                return skip(cbor, cursor.next, depth + 1);
            }
            default -> {
                require(!cursor.indefinite(), "unexpected break (0xff) at offset " + offset);
                return cursor.next; // major type 7: half, single and double floats read their bytes in the head
            }
        }
    }

    /** The end of a definite string, refused unless it lies inside the input. */
    private static long within(byte[] cbor, Cursor cursor, long offset) {
        require(cursor.argument >= 0 && cursor.argument <= cbor.length - cursor.next, "CBOR string at offset " + offset
                + " declares " + Long.toUnsignedString(cursor.argument) + " byte(s) but only "
                + (cbor.length - cursor.next) + " remain");
        return cursor.next + cursor.argument;
    }

    private static boolean isBreak(byte[] cbor, long position) {
        require(position < cbor.length, "indefinite-length item not terminated before the end of the input");
        return (cbor[(int) position] & 0xff) == 0xff;
    }

    /** A text string, definite or indefinite, decoded as strict UTF-8. */
    private static String text(byte[] cbor, long offset, String what) {
        Cursor cursor = header(cbor, offset);
        require(cursor.major == MAJOR_TEXT, what + " at offset " + offset + " is not a CBOR text string");
        skip(cbor, offset, 1); // bounds and chunk structure
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        if (!cursor.indefinite()) {
            bytes.write(cbor, (int) cursor.next, (int) cursor.argument);
        } else {
            long position = cursor.next;
            while (!isBreak(cbor, position)) {
                Cursor chunk = header(cbor, position);
                bytes.write(cbor, (int) chunk.next, (int) chunk.argument);
                position = chunk.next + chunk.argument;
            }
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes.toByteArray())).toString();
        } catch (CharacterCodingException e) {
            throw new AssertionError(what + " at offset " + offset + " is not valid UTF-8");
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
