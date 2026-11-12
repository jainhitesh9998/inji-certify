/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

import org.multipaz.cbor.Cbor;
import org.multipaz.cbor.DataItem;
import org.multipaz.cbor.Tagged;

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
 * <p>The scanner walks the CBOR framing only; it does not interpret anything except the keys it needs
 * ({@code nameSpaces}, the namespace names, {@code digestID}, {@code elementIdentifier}).
 */
final class WireIssuerSignedItems {

    /** One {@code Tagged(24, bstr)} entry: the exact received bytes and the metadata read out of them. */
    record Item(String namespace, int index, byte[] raw, long digestId, String identifier) {}

    private WireIssuerSignedItems() {}

    static List<Item> scan(byte[] cbor) {
        List<Item> items = new ArrayList<>();
        int start = 0;
        Cursor top = header(cbor, start);
        require(top.major == 5 && top.length >= 0, "IssuerSigned is not a definite-length CBOR map");
        int position = top.next;
        for (long i = 0; i < top.length; i++) {
            String key = text(cbor, position, "IssuerSigned map key");
            int valueOffset = skip(cbor, position);
            if ("nameSpaces".equals(key)) {
                scanNamespaces(cbor, valueOffset, items);
            }
            position = skip(cbor, valueOffset);
        }
        return items;
    }

    private static void scanNamespaces(byte[] cbor, int offset, List<Item> items) {
        Cursor namespaces = header(cbor, offset);
        require(namespaces.major == 5, "IssuerSigned.nameSpaces is not a CBOR map");
        int position = namespaces.next;
        long entries = namespaces.length >= 0 ? namespaces.length : Long.MAX_VALUE;
        for (long i = 0; i < entries; i++) {
            if (namespaces.length < 0 && (cbor[position] & 0xff) == 0xff) {
                return;
            }
            String namespace = text(cbor, position, "namespace key");
            int arrayOffset = skip(cbor, position);
            Cursor array = header(cbor, arrayOffset);
            require(array.major == 4, "namespace " + namespace + " is not a CBOR array");
            int element = array.next;
            long count = array.length >= 0 ? array.length : Long.MAX_VALUE;
            for (int index = 0; index < count; index++) {
                if (array.length < 0 && (cbor[element] & 0xff) == 0xff) {
                    break;
                }
                int end = skip(cbor, element);
                items.add(decodeItem(namespace, index, Arrays.copyOfRange(cbor, element, end)));
                element = end;
            }
            position = skip(cbor, arrayOffset);
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

    private record Cursor(int major, long length, int next) {}

    private static Cursor header(byte[] cbor, int offset) {
        require(offset < cbor.length, "CBOR item at offset " + offset + " runs past the end of the credential");
        int initial = cbor[offset] & 0xff;
        int major = initial >> 5;
        int additional = initial & 0x1f;
        int next = offset + 1;
        long length;
        switch (additional) {
            case 24 -> {
                require(next + 1 <= cbor.length, "truncated CBOR header at offset " + offset);
                length = cbor[next] & 0xffL;
                next += 1;
            }
            case 25 -> {
                require(next + 2 <= cbor.length, "truncated CBOR header at offset " + offset);
                length = ((cbor[next] & 0xffL) << 8) | (cbor[next + 1] & 0xffL);
                next += 2;
            }
            case 26 -> {
                require(next + 4 <= cbor.length, "truncated CBOR header at offset " + offset);
                length = unsigned(cbor, next, 4);
                next += 4;
            }
            case 27 -> {
                require(next + 8 <= cbor.length, "truncated CBOR header at offset " + offset);
                length = unsigned(cbor, next, 8);
                next += 8;
            }
            case 28, 29, 30 -> throw new IllegalArgumentException("reserved CBOR additional information " + additional);
            case 31 -> length = -1;
            default -> length = additional;
        }
        return new Cursor(major, length, next);
    }

    private static long unsigned(byte[] cbor, int offset, int size) {
        long value = 0;
        for (int i = 0; i < size; i++) {
            value = (value << 8) | (cbor[offset + i] & 0xffL);
        }
        return value;
    }

    /** The end offset of the item starting at {@code offset}, without interpreting it. */
    private static int skip(byte[] cbor, int offset) {
        Cursor cursor = header(cbor, offset);
        int position = cursor.next;
        switch (cursor.major) {
            case 0, 1 -> {
                return position;
            }
            case 2, 3 -> {
                if (cursor.length >= 0) {
                    return position + (int) cursor.length;
                }
                while ((cbor[position] & 0xff) != 0xff) {
                    position = skip(cbor, position);
                }
                return position + 1;
            }
            case 4 -> {
                if (cursor.length >= 0) {
                    for (long i = 0; i < cursor.length; i++) {
                        position = skip(cbor, position);
                    }
                    return position;
                }
                while ((cbor[position] & 0xff) != 0xff) {
                    position = skip(cbor, position);
                }
                return position + 1;
            }
            case 5 -> {
                if (cursor.length >= 0) {
                    for (long i = 0; i < cursor.length; i++) {
                        position = skip(cbor, skip(cbor, position));
                    }
                    return position;
                }
                while ((cbor[position] & 0xff) != 0xff) {
                    position = skip(cbor, skip(cbor, position));
                }
                return position + 1;
            }
            case 6 -> {
                return skip(cbor, position);
            }
            default -> {
                return position; // major type 7: half, single and double floats read their bytes in the header
            }
        }
    }

    private static String text(byte[] cbor, int offset, String what) {
        Cursor cursor = header(cbor, offset);
        require(cursor.major == 3 && cursor.length >= 0, what + " is not a definite-length CBOR text string");
        return new String(cbor, cursor.next, (int) cursor.length, StandardCharsets.UTF_8);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
