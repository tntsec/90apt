(function (global) {
  'use strict';

  var STORAGE_KEY = 'webadb.adb.key.v1';
  var KEY_SIZE_BITS = 2048;
  var KEY_SIZE_BYTES = KEY_SIZE_BITS / 8;
  var MODULUS_WORDS = KEY_SIZE_BITS / 32;
  var PUBKEY_BLOB_SIZE = 524;
  var AUTH_TOKEN_SIZE = 20;
  var POW2_32 = 1n << 32n;
  var DIGEST_INFO_SHA1 = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];

  function base64UrlToBytes(b64u) {
    var b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function bytesToBase64(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function bytesToBigInt(bytes) {
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
      hex += ((bytes[i] >>> 4) & 0xf).toString(16);
      hex += (bytes[i] & 0xf).toString(16);
    }
    return BigInt('0x' + hex);
  }

  function bigIntToBytes(n, length) {
    var bytes = new Uint8Array(length);
    var value = n;
    for (var i = length - 1; i >= 0; i--) {
      bytes[i] = Number(value & 0xffn);
      value >>= 8n;
    }
    return bytes;
  }

  function bigIntToLeWords(n, wordCount) {
    var words = new Uint32Array(wordCount);
    var value = n;
    for (var i = 0; i < wordCount; i++) {
      words[i] = Number(value & 0xffffffffn);
      value >>= 32n;
    }
    return words;
  }

  function modPow(base, exp, mod) {
    var result = 1n;
    var b = base % mod;
    var e = exp;
    while (e > 0n) {
      if (e & 1n) result = (result * b) % mod;
      b = (b * b) % mod;
      e >>= 1n;
    }
    return result;
  }

  function modInverse(a, mod) {
    var t = 0n;
    var newt = 1n;
    var r = mod;
    var newr = a;
    while (newr !== 0n) {
      var q = r / newr;
      var tmpT = t;
      t = newt;
      newt = tmpT - q * newt;
      var tmpR = r;
      r = newr;
      newr = tmpR - q * newr;
    }
    if (r > 1n) throw new Error('无法计算模逆');
    if (t < 0n) t += mod;
    return t;
  }

  function sha1(data) {
    return crypto.subtle.digest('SHA-1', data).then(function (buf) {
      return new Uint8Array(buf);
    });
  }

  function loadKey() {
    try {
      var raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      var jwk = JSON.parse(raw);
      if (jwk && jwk.kty === 'RSA') return jwk;
      return null;
    } catch (e) {
      return null;
    }
  }

  function getOrCreateKey(comment) {
    var existing = loadKey();
    if (existing) return Promise.resolve(existing);
    return crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: KEY_SIZE_BITS,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-1'
      },
      true,
      ['sign', 'verify']
    ).then(function (keyPair) {
      return crypto.subtle.exportKey('jwk', keyPair.privateKey);
    }).then(function (jwk) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(jwk));
      return jwk;
    });
  }

  function signToken(token, jwk) {
    if (token.length !== AUTH_TOKEN_SIZE) {
      return Promise.reject(new Error('AUTH token 长度异常：' + token.length));
    }
    // adbd 调用 RSA_sign(NID_sha1, token, ...) 时把 20 字节 token 本身当作
    // SHA-1 摘要处理（不重新哈希），因此 PKCS#1 v1.5 填充内容为
    // "DigestInfo(SHA1) || token"，然后做 m^d mod n。
    var em = new Uint8Array(KEY_SIZE_BYTES);
    em[0] = 0x00;
    em[1] = 0x01;
    var idx = 2;
    var tLen = DIGEST_INFO_SHA1.length + token.length;
    while (idx < em.length - 1 - tLen) em[idx++] = 0xff;
    em[idx++] = 0x00;
    for (var i = 0; i < DIGEST_INFO_SHA1.length; i++) em[idx++] = DIGEST_INFO_SHA1[i];
    em.set(token, idx);

    var n = bytesToBigInt(base64UrlToBytes(jwk.n));
    var d = bytesToBigInt(base64UrlToBytes(jwk.d));
    var m = bytesToBigInt(em);
    var signature = modPow(m, d, n);
    return Promise.resolve(bigIntToBytes(signature, KEY_SIZE_BYTES));
  }

  function buildPublicKeyBlob(jwk, comment) {
    var n = bytesToBigInt(base64UrlToBytes(jwk.n));
    var e = bytesToBigInt(base64UrlToBytes(jwk.e));
    var words = bigIntToLeWords(n, MODULUS_WORDS);
    var rr = bigIntToLeWords(modPow(1n << 4096n, 1n, n), MODULUS_WORDS);
    var n0inv = (POW2_32 - modInverse(BigInt(words[0]), POW2_32)) % POW2_32;

    var buf = new Uint8Array(PUBKEY_BLOB_SIZE);
    var dv = new DataView(buf.buffer);
    dv.setUint32(0, MODULUS_WORDS, true);
    dv.setUint32(4, Number(n0inv), true);
    for (var i = 0; i < MODULUS_WORDS; i++) dv.setUint32(8 + i * 4, words[i], true);
    for (var j = 0; j < MODULUS_WORDS; j++) dv.setUint32(264 + j * 4, rr[j], true);
    dv.setUint32(520, Number(e), true);

    return bytesToBase64(buf) + ' ' + comment + '\0';
  }

  global.WebADB = Object.assign(global.WebADB || {}, {
    Crypto: {
      getOrCreateKey: getOrCreateKey,
      signToken: signToken,
      buildPublicKeyBlob: buildPublicKeyBlob,
      sha1: sha1
    }
  });
})(window);
