/*
 * A small CBOR decoder (RFC 8949) for the offer page: enough to read an ISO/IEC 18013-5 IssuerSigned structure - maps,
 * arrays, integers, byte strings, text strings, tags and the simple values - with no dependency outside this repository.
 * Tag 24 (encoded CBOR data item) is decoded one level further, so an IssuerSignedItem arrives as its own map; tag 1
 * (epoch-based date/time) resolves to an ISO instant, tags 2 and 3 (positive and negative bignum) resolve to a BigInt,
 * while tag 0 (tdate, an RFC 3339 text string) and tag 1004 (full-date) print as the string they carry.
 *
 * Byte ranges (`Cbor.spans`) come from the input's own offsets, never from a re-encoding, and a tag is transparent to
 * them: `#6.24(item)` and `#6.18([...])` are walked like the item they carry, so a tagged COSE_Sign1 keeps the ranges of
 * its own array elements. `Cbor.tagged` reports a tag by its numeric value, whatever head carries it (`d8 18` and the
 * non-preferred `d9 00 18` are both tag 24) and returns the tagged item's content bytes unchanged.
 *
 * Integers are exact. A value that fits a JavaScript number (|n| <= Number.MAX_SAFE_INTEGER) decodes to a number;
 * anything larger, in either direction, decodes to a BigInt so no digit is silently lost, and the page renders it as the
 * decimal string it is (String(bigint) is exact). Map keys are rendered in one stable form that cannot collide: an
 * integer key is its decimal digits, a byte-string key is h'..' hex, an array key is [..] and a map key is {..}.
 * A data item with bytes left over after it - at the top level or inside tag-24 content - is malformed and throws.
 *
 * Test vectors (verified with `node` against this file; run `node -e` with a Uint8Array of the bytes):
 *   hex 7f6268696121ff              -> "hi!"        (indefinite-length text string, one chunk)
 *   bytes [0x82,0x7f,0x61,0x61,0x61,0x62,0xff,0x01] -> ["ab", 1]  (indefinite text, two chunks, inside an array)
 *   bytes [0xbf,0x7f,0x61,0x61,0xff,0x01,0xff]      -> {"a": 1}    (indefinite map with an indefinite key; null-proto map)
 *   bytes [0xa1,0x69,'_','_','p','r','o','t','o','_','_',0x01] -> an own "__proto__" key, Object.prototype untouched
 *   bytes [0x7f,0x01,0xff]          -> throws       (a text-string chunk that is not a text string)
 *   bytes [0x9f]                    -> throws       (unexpected end of input, never a hang)
 *   bytes a2 01 61 61 61 31 61 62   -> throws       (keys 1 and "1" render alike: ambiguous, never overwritten)
 *   bytes [0xf9]                    -> throws       (truncated half float)
 *   bytes [0x1f] / [0xff] / [0x7c]  -> throws       (indefinite integer, stray break, reserved additional information)
 *   hex 1b0020000000000001          -> 9007199254740993n  (2^53+1: a BigInt, not 9007199254740992)
 *   hex 3b0020000000000001          -> -9007199254740994n (below Number.MIN_SAFE_INTEGER)
 *   hex c249010000000000000000      -> 18446744073709551616n (tag 2 bignum: 2^64)
 *   hex c349010000000000000000      -> -18446744073709551617n (tag 3 bignum: -1 - 2^64)
 *   bytes [0xa2,0x01,0x61,0x61,0x41,0x01,0x61,0x62] -> {"1": "a", "h'01'": "b"}  (integer and byte-string keys differ)
 *   hex 0102                        -> throws       (trailing bytes after the top-level item)
 *   hex d818420102                  -> throws       (trailing bytes inside tag-24 content)
 *   hex d8184101                    -> 1            (tag 24 around exactly one item)
 */
var Cbor = (function () {
  "use strict";

  var MAX_SAFE = 9007199254740991n; // Number.MAX_SAFE_INTEGER
  var HEX = "0123456789abcdef";

  function Reader(bytes) {
    this.bytes = bytes;
    this.offset = 0;
    // byte ranges (P5-03a): when `found` is set, every array element and map value down to `limit` levels below the
    // root is recorded as it is decoded, so a range is the input's own offsets and nothing is re-encoded
    this.found = null;
    this.limit = 0;
    this.path = [];
  }
  Reader.prototype.byte = function () {
    if (this.offset >= this.bytes.length) throw new Error("CBOR: unexpected end of input");
    return this.bytes[this.offset++];
  };
  Reader.prototype.peek = function () {
    if (this.offset >= this.bytes.length) throw new Error("CBOR: unexpected end of input");
    return this.bytes[this.offset];
  };
  Reader.prototype.take = function (count) {
    if (typeof count !== "number") throw new Error("CBOR: length " + String(count) + " is too large to read");
    if (count < 0) throw new Error("CBOR: negative length " + count);
    if (this.offset + count > this.bytes.length) throw new Error("CBOR: unexpected end of input");
    var slice = this.bytes.subarray(this.offset, this.offset + count);
    this.offset += count;
    return slice;
  };
  /** An unsigned argument of {@code count} bytes: a number when exact, a BigInt when it would lose digits. */
  Reader.prototype.uint = function (count) {
    if (count === 0) return 0;
    var value = 0n;
    for (var i = 0; i < count; i++) value = value * 256n + BigInt(this.byte());
    return value <= MAX_SAFE ? Number(value) : value;
  };
  Reader.prototype.done = function () {
    return this.offset === this.bytes.length;
  };

  function argument(reader, major, additional) {
    if (additional < 24) return additional;
    if (additional === 24) return reader.uint(1);
    if (additional === 25) return reader.uint(2);
    if (additional === 26) return reader.uint(4);
    if (additional === 27) return reader.uint(8);
    if (additional === 31) {
      // only a string, array or map may be indefinite; an integer or a tag with it is malformed (RFC 8949 3.2.1)
      if (major === 2 || major === 3 || major === 4 || major === 5) return -1;
      throw new Error("CBOR: indefinite length is not allowed for major type " + major);
    }
    // 28-30 are reserved and never valid
    throw new Error("CBOR: reserved additional information " + additional);
  }

  /** One definite-length string chunk of an indefinite-length string, whose type and length are checked. */
  function stringChunk(reader, major, label) {
    var initial = reader.byte();
    if (initial >> 5 !== major) throw new Error("CBOR: indefinite-length " + label + " chunk must be a definite-length " + label);
    var length = argument(reader, major, initial & 31);
    if (length < 0) throw new Error("CBOR: indefinite-length " + label + " chunk must be definite-length");
    return reader.take(length);
  }

  function float(reader, additional) {
    var width = additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
    if (width && reader.offset + width > reader.bytes.length) throw new Error("CBOR: unexpected end of input");
    var view = new DataView(reader.bytes.buffer, reader.bytes.byteOffset + reader.offset);
    if (additional === 25) {
      var half = view.getUint16(0);
      reader.take(2);
      var sign = (half & 0x8000) ? -1 : 1, exponent = (half >> 10) & 0x1f, mantissa = half & 0x3ff;
      if (exponent === 0) return sign * mantissa * Math.pow(2, -24);
      if (exponent === 31) return mantissa === 0 ? sign * Infinity : NaN;
      return sign * (1 + mantissa / 1024) * Math.pow(2, exponent - 15);
    }
    if (additional === 26) {
      var single = view.getFloat32(0);
      reader.take(4);
      return single;
    }
    if (additional === 27) {
      var double = view.getFloat64(0);
      reader.take(8);
      return double;
    }
    throw new Error("CBOR: unsupported simple value " + additional);
  }

  function hex(bytes) {
    var text = "";
    for (var i = 0; i < bytes.length; i++) text += HEX[bytes[i] >> 4] + HEX[bytes[i] & 15];
    return text;
  }

  /** The magnitude of a byte string, as a BigInt (tags 2 and 3). */
  function magnitude(bytes) {
    var value = 0n;
    for (var i = 0; i < bytes.length; i++) value = value * 256n + BigInt(bytes[i]);
    return value;
  }

  /**
   * One stable string for a map key. Integer keys are their decimal digits, byte strings are h'..', arrays and maps are
   * bracketed forms of their own keys, so no two distinct keys render alike (the byte string 0x01 is h'01', never 1).
   */
  function keyOf(key) {
    if (typeof key === "string") return key;
    if (key === null) return "null";
    if (key === undefined) return "undefined";
    if (key instanceof Uint8Array) return "h'" + hex(key) + "'";
    if (Array.isArray(key)) {
      var items = [];
      for (var i = 0; i < key.length; i++) items.push(keyOf(key[i]));
      return "[" + items.join(",") + "]";
    }
    if (typeof key === "object") {
      var names = Object.keys(key).sort();
      var entries = [];
      for (var k = 0; k < names.length; k++) entries.push(keyOf(names[k]) + ":" + keyOf(key[names[k]]));
      return "{" + entries.join(",") + "}";
    }
    return String(key); // numbers, BigInts, booleans
  }

  /**
   * One data item. With a recording reader ({@code reader.found} set) the item's `[start, end)` is appended under the
   * path it was reached by, down to {@code reader.limit} levels below the root. `record` is passed false for a map's
   * key and a tag's content: neither is a value of the container the caller asked about (a tag adds no level, RFC 8949
   * 3.4), so neither gets an entry of its own.
   */
  function decode(reader, record) {
    var start = reader.offset;
    var level = reader.path.length;
    var value = decodeValue(reader);
    if (record !== false && reader.found !== null && level > 0 && level <= reader.limit) {
      reader.found.push({ path: reader.path.slice(), start: start, end: reader.offset });
    }
    return value;
  }

  function decodeValue(reader) {
    var initial = reader.byte();
    var major = initial >> 5;
    var additional = initial & 31;
    var length;
    switch (major) {
      case 0:
        return argument(reader, major, additional);
      case 1:
        var magnitudeArg = argument(reader, major, additional);
        return typeof magnitudeArg === "bigint" ? -1n - magnitudeArg : -1 - magnitudeArg;
      case 2:
        length = argument(reader, major, additional);
        if (length < 0) { // indefinite: concatenate the definite-length byte-string chunks
          var chunks = [];
          while (reader.peek() !== 0xff) chunks.push(stringChunk(reader, 2, "byte string"));
          reader.byte();
          var total = 0;
          chunks.forEach(function (chunk) { total += chunk.length; });
          var joined = new Uint8Array(total), at = 0;
          chunks.forEach(function (chunk) { joined.set(chunk, at); at += chunk.length; });
          return joined;
        }
        return reader.take(length);
      case 3:
        length = argument(reader, major, additional);
        if (length < 0) { // indefinite: concatenate the definite-length text-string chunks
          var parts = [];
          while (reader.peek() !== 0xff) {
            parts.push(new TextDecoder("utf-8").decode(stringChunk(reader, 3, "text string")));
          }
          reader.byte();
          return parts.join("");
        }
        return new TextDecoder("utf-8").decode(reader.take(length));
      case 4:
        length = argument(reader, major, additional);
        var items = [];
        var element = function () { // the path follows the recursion, so a recorded range knows where it is
          reader.path.push(items.length);
          items.push(decode(reader));
          reader.path.pop();
        };
        if (length < 0) {
          while (reader.peek() !== 0xff) element();
          reader.byte();
          return items;
        }
        if (typeof length !== "number") throw new Error("CBOR: array length " + String(length) + " is too large to read");
        for (var i = 0; i < length; i++) element();
        return items;
      case 5:
        length = argument(reader, major, additional);
        // no prototype: a decoded "__proto__" key is data, not an assignment to Object.prototype
        var map = Object.create(null);
        var put = function () {
          var rendered = keyOf(decode(reader, false)); // a key is not a value: it gets no range entry
          // RFC 8949 5.6: duplicate keys make a map invalid; keys that only render alike (1 and "1") are refused too, never overwritten
          if (Object.prototype.hasOwnProperty.call(map, rendered)) throw new Error("CBOR: duplicate or ambiguous map key " + rendered);
          reader.path.push(rendered);
          map[rendered] = decode(reader);
          reader.path.pop();
        };
        if (length < 0) {
          while (reader.peek() !== 0xff) put();
          reader.byte();
          return map;
        }
        if (typeof length !== "number") throw new Error("CBOR: map length " + String(length) + " is too large to read");
        for (var k = 0; k < length; k++) put();
        return map;
      case 6:
        var tag = argument(reader, major, additional);
        var tagged = decode(reader, false); // the tagged value is the item at this path, not a child of it
        if (tag === 24) { // embedded CBOR: exactly one data item, no padding around it
          if (!(tagged instanceof Uint8Array)) throw new Error("CBOR: tag 24 content is not a byte string");
          return decodeItem(tagged);
        }
        if (tag === 2 || tag === 3) { // bignum: an unsigned magnitude in big-endian bytes, exact as a BigInt
          if (!(tagged instanceof Uint8Array)) throw new Error("CBOR: tag " + tag + " content is not a byte string");
          return tag === 2 ? magnitude(tagged) : -1n - magnitude(tagged);
        }
        if (tag === 1 && typeof tagged === "number") return new Date(tagged * 1000).toISOString(); // epoch-based date/time
        return tagged; // tag 0 (tdate, a tstr), 1004 (full-date) and any other tag: the value is what the page prints
      case 7:
        if (additional === 31) throw new Error("CBOR: unexpected break outside an indefinite-length item");
        if (additional === 20) return false;
        if (additional === 21) return true;
        if (additional === 22) return null;
        if (additional === 23) return undefined;
        return float(reader, additional);
      default:
        throw new Error("CBOR: unsupported major type " + major);
    }
  }

  /** Decodes exactly one data item from {@code bytes}: anything left over means the input is not just that item. */
  function decodeItem(bytes) {
    var reader = new Reader(bytes);
    var item = decode(reader);
    if (!reader.done()) {
      throw new Error("CBOR: " + (bytes.length - reader.offset) + " trailing byte(s) after the data item");
    }
    return item;
  }

  /* ---------------------------------------------------------------- byte ranges (P5-03a) */

  /**
   * The decoded item and the `[start, end)` range of every array element and map value down to {@code depth} levels
   * below the root (the root's own children are depth 1). The ranges are recorded by `decode` as it reads, so they are
   * the input's own offsets: nothing is re-encoded, and a definite- or an indefinite-length item is read the same way.
   * Each entry is `{path, start, end}`, the path being the rendered map keys and array indexes from the root.
   */
  function ranges(bytes, depth) {
    var reader = new Reader(bytes);
    reader.found = [];
    reader.limit = typeof depth === "number" ? depth : 0;
    var value = decode(reader);
    if (!reader.done()) {
      throw new Error("CBOR: " + (bytes.length - reader.offset) + " trailing byte(s) after the data item");
    }
    return { value: value, ranges: reader.found };
  }

  /**
   * The tag of the data item at {@code offset}: `{tag, content, end}` - the tag by its numeric value however the head
   * encodes it (RFC 8949 3.1: `d8 18` and the non-preferred `d9 00 18` are both tag 24), the exact bytes of the tagged
   * item's content, and the offset just past the whole item. `null` when the item is not tagged. The bytes are never
   * changed, so a reader can require the tag and still carry the item exactly as it arrived.
   */
  function tagOf(bytes, offset) {
    var at = offset === undefined ? 0 : offset;
    var reader = new Reader(bytes.subarray(at));
    var initial = reader.byte();
    if (initial >> 5 !== 6) return null;
    var tag = argument(reader, 6, initial & 31);
    var contentStart = reader.offset;
    decode(reader, false); // exactly the tagged item's content, with the decoder's own rules
    return { tag: tag, content: reader.bytes.subarray(contentStart, reader.offset), end: at + reader.offset };
  }

  /* ---------------------------------------------------------------- encoding (RFC 8949 4.1, preferred) */

  /** A tagged value: `Cbor.Tagged(24, itemBytes)` is `#6.24(bstr .cbor item)` (callable with or without `new`). */
  function Tagged(tag, value) {
    if (!(this instanceof Tagged)) return new Tagged(tag, value);
    if (typeof tag !== "number" || !Number.isSafeInteger(tag) || tag < 0) throw new Error("CBOR: a tag is a non-negative integer");
    this.tag = tag;
    this.value = value;
  }

  /** Bytes emitted verbatim; refused unless they are exactly one well-formed data item (with or without `new`). */
  function Raw(input) {
    if (!(this instanceof Raw)) return new Raw(input);
    var bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    decodeItem(bytes);
    this.bytes = bytes;
  }

  var UTF8 = null;

  function utf8(text) {
    if (UTF8 === null) UTF8 = new TextEncoder();
    return UTF8.encode(text);
  }

  /** One head: the major type and its argument in the shortest form that holds it (RFC 8949 4.1). */
  function head(major, argument) {
    var value = typeof argument === "bigint" ? argument : BigInt(argument);
    var bits = major << 5;
    if (value < 24n) return Uint8Array.of(bits | Number(value));
    if (value < 256n) return Uint8Array.of(bits | 24, Number(value));
    if (value < 65536n) return Uint8Array.of(bits | 25, Number(value >> 8n), Number(value & 255n));
    if (value < 4294967296n) {
      return Uint8Array.of(bits | 26, Number((value >> 24n) & 255n), Number((value >> 16n) & 255n),
        Number((value >> 8n) & 255n), Number(value & 255n));
    }
    if (value < 18446744073709551616n) {
      var out = new Uint8Array(9);
      out[0] = bits | 27;
      for (var i = 8; i >= 1; i--) {
        out[i] = Number(value & 255n);
        value >>= 8n;
      }
      return out;
    }
    throw new Error("CBOR: the argument " + String(argument) + " does not fit a head");
  }

  /** The big-endian magnitude of a bignum, with no leading zero (RFC 8949 3.4.3). */
  function magnitudeBytes(magnitude) {
    var hex = magnitude.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function encodeInto(value, parts) {
    if (value === null) { parts.push(Uint8Array.of(0xf6)); return; }
    if (value === true) { parts.push(Uint8Array.of(0xf5)); return; }
    if (value === false) { parts.push(Uint8Array.of(0xf4)); return; }
    if (value === undefined) throw new Error("CBOR: undefined cannot be encoded");
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value)) {
        throw new Error("CBOR: " + String(value) + " is not a safe integer (only integers can be encoded)");
      }
      parts.push(value >= 0 ? head(0, value) : head(1, -1 - value));
      return;
    }
    if (typeof value === "bigint") {
      var magnitude = value >= 0n ? value : -1n - value;
      if (magnitude < 18446744073709551616n) {
        parts.push(head(value >= 0n ? 0 : 1, magnitude));
      } else { // a bignum: tag 2 for positive, tag 3 for negative (RFC 8949 3.4.3)
        parts.push(head(6, value >= 0n ? 2 : 3));
        var bytes = magnitudeBytes(magnitude);
        parts.push(head(2, bytes.length));
        parts.push(bytes);
      }
      return;
    }
    if (typeof value === "string") {
      var text = utf8(value);
      parts.push(head(3, text.length));
      parts.push(text);
      return;
    }
    if (value instanceof Uint8Array) {
      parts.push(head(2, value.length));
      parts.push(value);
      return;
    }
    if (value instanceof Raw) { parts.push(value.bytes); return; }
    if (value instanceof Tagged) {
      parts.push(head(6, value.tag));
      encodeInto(value.value, parts);
      return;
    }
    if (Array.isArray(value)) {
      parts.push(head(4, value.length));
      for (var i = 0; i < value.length; i++) encodeInto(value[i], parts);
      return;
    }
    if (value instanceof Map) {
      parts.push(head(5, value.size));
      value.forEach(function (member, key) {
        encodeInto(key, parts);
        encodeInto(member, parts);
      });
      return;
    }
    if (typeof value === "object") {
      // plan 4.3: a map is a `Map` and nothing else. A plain object would encode under key names the caller did not
      // choose and an order ISO/IEC 18013-5's CDDL does not give it, so it is refused rather than guessed at.
      throw new Error("CBOR: only Map encodes as a map, not " + Object.prototype.toString.call(value));
    }
    throw new Error("CBOR: cannot encode a " + typeof value);
  }

  return {
    /** Decodes one data item from a Uint8Array (or an ArrayBuffer). */
    decode: function (input) {
      var bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
      return decodeItem(bytes);
    },

    /**
     * The decoded item and the byte range of every array element and map value down to {@code depth} levels below the
     * root, as `{path, start, end}` entries. Nothing is re-encoded: the ranges are the input's own offsets.
     */
    spans: function (input, depth) {
      var bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
      return ranges(bytes, depth);
    },

    /**
     * The tag of the data item at {@code offset} of {@code input}, by numeric value, with the exact bytes of its content
     * and the offset just past the whole tagged item: `{tag, content, end}`. `null` when the item is not tagged.
     */
    tagged: function (input, offset) {
      var bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
      return tagOf(bytes, offset);
    },

    /** Encodes one value in the preferred serialization (RFC 8949 4.1). */
    encode: function (value) {
      var parts = [];
      encodeInto(value, parts);
      var total = 0;
      parts.forEach(function (part) { total += part.length; });
      var out = new Uint8Array(total);
      var at = 0;
      parts.forEach(function (part) { out.set(part, at); at += part.length; });
      return out;
    },

    /** A tagged value (`Cbor.Tagged(24, itemBytes)`). */
    Tagged: Tagged,

    /** Bytes emitted verbatim; the constructor refuses anything that is not exactly one data item. */
    Raw: Raw
  };
})();
