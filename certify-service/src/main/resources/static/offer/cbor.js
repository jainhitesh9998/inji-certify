/*
 * A small CBOR decoder (RFC 8949) for the offer page: enough to read an ISO/IEC 18013-5 IssuerSigned structure - maps,
 * arrays, integers, byte strings, text strings, tags and the simple values - with no dependency outside this repository.
 * Tag 24 (encoded CBOR data item) is decoded one level further, so an IssuerSignedItem arrives as its own map;
 * full-date (1004) and tdate (0) tags resolve to a string and an ISO instant so the page can print them.
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
  Reader.prototype.take = function (count) {
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

  function argument(reader, additional) {
    if (additional < 24) return additional;
    if (additional === 24) return reader.uint(1);
    if (additional === 25) return reader.uint(2);
    if (additional === 26) return reader.uint(4);
    if (additional === 27) return reader.uint(8);
    if (additional === 31) return -1; // indefinite length
    throw new Error("CBOR: reserved additional information " + additional);
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
        return argument(reader, additional);
      case 1:
        return -1 - argument(reader, additional);
      case 2:
        length = argument(reader, additional);
        if (length < 0) { // indefinite: concatenate the chunks
          var chunks = [];
          while (reader.bytes[reader.offset] !== 0xff) chunks.push(decode(reader));
          reader.byte();
          var total = 0;
          chunks.forEach(function (chunk) { total += chunk.length; });
          var joined = new Uint8Array(total), at = 0;
          chunks.forEach(function (chunk) { joined.set(chunk, at); at += chunk.length; });
          return joined;
        }
        return reader.take(length);
      case 3:
        length = argument(reader, additional);
        return new TextDecoder("utf-8").decode(reader.take(length));
      case 4:
        length = argument(reader, additional);
        var items = [];
        if (length < 0) {
          while (reader.bytes[reader.offset] !== 0xff) items.push(decode(reader));
          reader.byte();
          return items;
        }
        for (var i = 0; i < length; i++) items.push(decode(reader));
        return items;
      case 5:
        length = argument(reader, additional);
        var map = {};
        var put = function () {
          var key = decode(reader);
          map[typeof key === "string" ? key : String(key)] = decode(reader);
        };
        if (length < 0) {
          while (reader.bytes[reader.offset] !== 0xff) put();
          reader.byte();
          return map;
        }
        for (var k = 0; k < length; k++) put();
        return map;
      case 6:
        var tag = argument(reader, additional);
        var tagged = decode(reader);
        if (tag === 24 && tagged instanceof Uint8Array) return decode(new Reader(tagged)); // embedded CBOR
        if (tag === 0 && typeof tagged === "number") return new Date(tagged * 1000).toISOString(); // tdate
        if (tag === 1 && typeof tagged === "number") return new Date(tagged * 1000).toISOString(); // epoch datetime
        return tagged; // 1004 full-date and any other tag: the value is what the page prints
      case 7:
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
