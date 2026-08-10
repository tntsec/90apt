(function (global) {
  'use strict';

  var Cmd = {
    SYNC: 0x434e5953,
    CNXN: 0x4e584e43,
    AUTH: 0x48545541,
    OPEN: 0x4e45504f,
    OKAY: 0x59414b4f,
    CLSE: 0x45534c43,
    WRTE: 0x45545257
  };

  var AuthType = {
    TOKEN: 1,
    SIGNATURE: 2,
    RSAPUBLICKEY: 3
  };

  var VERSION = 0x01000000;
  var MAXDATA = 4096;
  var HEADER_SIZE = 24;
  var AUTH_TOKEN_SIZE = 20;

  var CRC32_TABLE = (function () {
    var table = new Uint32Array(256);
    for (var i = 0; i < 256; i++) {
      var c = i;
      for (var k = 0; k < 8; k++) {
        c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[i] = c >>> 0;
    }
    return table;
  })();

  function crc32(data) {
    var c = 0xffffffff;
    for (var i = 0; i < data.length; i++) {
      c = CRC32_TABLE[(c ^ data[i]) & 0xff] ^ (c >>> 8);
    }
    return (c ^ 0xffffffff) >>> 0;
  }

  function buildPacket(command, arg0, arg1, payload) {
    payload = payload || new Uint8Array(0);
    var msg = new Uint8Array(HEADER_SIZE + payload.length);
    var dv = new DataView(msg.buffer);
    dv.setUint32(0, command, true);
    dv.setUint32(4, arg0 >>> 0, true);
    dv.setUint32(8, arg1 >>> 0, true);
    dv.setUint32(12, payload.length, true);
    dv.setUint32(16, crc32(payload), true);
    dv.setUint32(20, (command ^ 0xffffffff) >>> 0, true);
    msg.set(payload, HEADER_SIZE);
    return msg;
  }

  function parsePacket(header, payload) {
    var dv = new DataView(header.buffer, header.byteOffset, HEADER_SIZE);
    return {
      command: dv.getUint32(0, true),
      arg0: dv.getUint32(4, true),
      arg1: dv.getUint32(8, true),
      length: dv.getUint32(12, true),
      checksum: dv.getUint32(16, true),
      magic: dv.getUint32(20, true),
      payload: payload
    };
  }

  var encoder = new TextEncoder();
  var decoder = new TextDecoder();

  function textEncode(str) {
    return encoder.encode(str);
  }

  function textDecode(bytes) {
    return decoder.decode(bytes);
  }

  function concatBytes(a, b) {
    var out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  global.WebADB = Object.assign(global.WebADB || {}, {
    Cmd: Cmd,
    AuthType: AuthType,
    VERSION: VERSION,
    MAXDATA: MAXDATA,
    HEADER_SIZE: HEADER_SIZE,
    AUTH_TOKEN_SIZE: AUTH_TOKEN_SIZE,
    crc32: crc32,
    buildPacket: buildPacket,
    parsePacket: parsePacket,
    textEncode: textEncode,
    textDecode: textDecode,
    concatBytes: concatBytes
  });
})(window);
