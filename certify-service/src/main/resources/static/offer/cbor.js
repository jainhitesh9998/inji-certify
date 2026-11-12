/*
 * A small CBOR decoder (RFC 8949) for the offer page: enough to read an ISO/IEC 18013-5 IssuerSigned structure - maps,
 * arrays, integers, byte strings, text strings, tags and the simple values - with no dependency outside this repository.
 * Tag 24 (encoded CBOR data item) is decoded one level further, so an IssuerSignedItem arrives as its own map; tag 1
 * (epoch-based date/time) resolves to an ISO instant, while tag 0 (tdate, an RFC 3339 text string) and tag 1004
 * (full-date) print as the string they carry.
 *
 * Test vectors (verified with `node` against this file; run `node -e` with a Uint8Array of the bytes):
 *   hex 7f6268696121ff              -> "hi!"        (indefinite-length text string, one chunk)
 *   bytes [0x82,0x7f,0x61,0x61,0x61,0x62,0xff,0x01] -> ["ab", 1]  (indefinite text, two chunks, inside an array)
 *   bytes [0xbf,0x7f,0x61,0x61,0xff,0x01,0xff]      -> {"a": 1}    (indefinite map with an indefinite key; null-proto map)
 *   bytes [0xa1,0x69,'_','_','p','r','o','t','o','_','_',0x01] -> an own "__proto__" key, Object.prototype untouched
 *   bytes [0x7f,0x01,0xff]          -> throws       (a text-string chunk that is not a text string)
 *   bytes [0x9f]                    -> throws       (unexpected end of input, never a hang)
 *   bytes [0x1f] / [0xff] / [0x7c]  -> throws       (indefinite integer, stray break, reserved additional information)
 */
var Cbor = (function () {
  "use strict";

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
    if (count < 0) throw new Error("CBOR: negative length " + count);
    if (this.offset + count > this.bytes.length) throw new Error("CBOR: unexpected end of input");
    var slice = this.bytes.subarray(this.offset, this.offset + count);
    this.offset += count;
    return slice;
  };
  Reader.prototype.uint = function (count) {
    var value = 0;
    for (var i = 0; i < count; i++) value = value * 256 + this.byte();
    return value;
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

  function decode(reader) {
    var initial = reader.byte();
    var major = initial >> 5;
    var additional = initial & 31;
    var length;
    switch (major) {
      case 0:
        return argument(reader, major, additional);
      case 1:
        return -1 - argument(reader, major, additional);
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
        for (var i = 0; i < length; i++) items.push(decode(reader));
        return items;
      case 5:
        length = argument(reader, major, additional);
        // no prototype: a decoded "__proto__" key is data, not an assignment to Object.prototype
        var map = Object.create(null);
        var put = function () {
          var key = decode(reader);
          map[typeof key === "string" ? key : String(key)] = decode(reader);
        };
        if (length < 0) {
          while (reader.peek() !== 0xff) put();
          reader.byte();
          return map;
        }
        for (var k = 0; k < length; k++) put();
        return map;
      case 6:
        var tag = argument(reader, major, additional);
        var tagged = decode(reader);
        if (tag === 24 && tagged instanceof Uint8Array) return decode(new Reader(tagged)); // embedded CBOR
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

  return {
    /** Decodes one data item from a Uint8Array (or an ArrayBuffer). */
    decode: function (input) {
      var bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
      return decode(new Reader(bytes));
    }
  };
})();
