/*
 * A small CBOR decoder (RFC 8949) for the offer page: enough to read an ISO/IEC 18013-5 IssuerSigned structure - maps,
 * arrays, integers, byte strings, text strings, tags and the simple values - with no dependency outside this repository.
 * Tag 24 (encoded CBOR data item) is decoded one level further, so an IssuerSignedItem arrives as its own map; tag 1
 * (epoch-based date/time) resolves to an ISO instant, tags 2 and 3 (positive and negative bignum) resolve to a BigInt,
 * while tag 0 (tdate, an RFC 3339 text string) and tag 1004 (full-date) print as the string they carry.
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

  function decode(reader) {
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
        if (length < 0) {
          while (reader.peek() !== 0xff) items.push(decode(reader));
          reader.byte();
          return items;
        }
        if (typeof length !== "number") throw new Error("CBOR: array length " + String(length) + " is too large to read");
        for (var i = 0; i < length; i++) items.push(decode(reader));
        return items;
      case 5:
        length = argument(reader, major, additional);
        // no prototype: a decoded "__proto__" key is data, not an assignment to Object.prototype
        var map = Object.create(null);
        var put = function () {
          var key = decode(reader);
          map[keyOf(key)] = decode(reader);
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
        var tagged = decode(reader);
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

  return {
    /** Decodes one data item from a Uint8Array (or an ArrayBuffer). */
    decode: function (input) {
      var bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
      return decodeItem(bytes);
    }
  };
})();
