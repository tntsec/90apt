const FuncConfigCrypto = (() => {
    const BLOCK_SIZE = 16;
    const PREFIX_SIZE = 16;
    const LENGTH_FIELD_SIZE = 4;
    const HEADER_SIZE = PREFIX_SIZE + LENGTH_FIELD_SIZE;

    const PRESETS = {
        '7.1.7': {
            key: 'Jbga21autoj7ZAsF',
            iv: 'Jbga21autoj7ZAsF',
            prefix: 'J451640)$n?2\\\x10q\x1b'
        },
        '7.5': {
            key: 'Jbga21autoj7ZAsF',
            iv: 'Jbga21autoj7ZAsF',
            prefix: '1234567812345678'
        },
        '8.1': {
            key: 'Yqwr31autou4PbNM',
            iv: '1234567812345678',
            prefix: '9zxc46abc7o28l4t'
        },
        '8.5': {
            key: 'Yqwr31autou4PbNM',
            iv: '1234567812345678',
            prefix: '9zxc46abc7o28l4t'
        },
        '9.1': {
            key: 'Yqwr31autou4PbNM',
            iv: '1234567812345678',
            prefix: '9zxc46abc7o28l4t'
        },
        '9.5': {
            key: 'Yqwr31autou4PbNM',
            iv: '1234567812345678',
            prefix: '9zxc46abc7o28l4t'
        }
    };

    function getPreset(version) {
        return PRESETS[version] || null;
    }

    function getPresetVersions() {
        return Object.keys(PRESETS);
    }

    function utf8ByteLength(str) {
        return new TextEncoder().encode(str).length;
    }

    function toBytes(value) {
        if (typeof value === 'string') return new TextEncoder().encode(value);
        if (value instanceof Uint8Array) return value;
        return new Uint8Array(value);
    }

    // KEY / IV 按「字节」而非「字符」校验：16 个中文字符是 48 字节，必须拒绝
    function assertKeyAndIv(key, iv) {
        const keyLen = utf8ByteLength(key);
        if (keyLen !== 16) {
            throw new Error('KEY 必须为 16 字节（当前 ' + keyLen + ' 字节）');
        }
        const ivLen = utf8ByteLength(iv);
        if (ivLen !== 16) {
            throw new Error('IV 必须为 16 字节（当前 ' + ivLen + ' 字节）');
        }
    }

    function assertPrefix(prefix) {
        const bytes = typeof prefix === 'string' ? utf8ByteLength(prefix) : (prefix ? prefix.length : 0);
        if (bytes !== PREFIX_SIZE) {
            throw new Error('数据填充（Prefix）必须为 16 字节（当前 ' + bytes + ' 字节）');
        }
    }

    function wordArrayToUint8Array(wordArray) {
        const byteLength = typeof wordArray.sigBytes === 'number'
            ? wordArray.sigBytes
            : wordArray.words.length * 4;
        const u8 = new Uint8Array(byteLength);
        for (let i = 0; i < byteLength; i++) {
            u8[i] = (wordArray.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        }
        return u8;
    }

    function decrypt(fileData, key, iv) {
        assertKeyAndIv(key, iv);

        if (fileData.length === 0) {
            throw new Error('文件为空');
        }
        if (fileData.length % BLOCK_SIZE !== 0) {
            throw new Error('密文长度不是 16 的整数倍（当前 ' + fileData.length + ' 字节），文件可能已损坏或并非 .dat');
        }

        const wordArray = CryptoJS.lib.WordArray.create(fileData);
        const decrypted = CryptoJS.AES.decrypt(
            { ciphertext: wordArray },
            CryptoJS.enc.Utf8.parse(key),
            {
                iv: CryptoJS.enc.Utf8.parse(iv),
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.NoPadding
            }
        );

        const u8 = wordArrayToUint8Array(decrypted);

        if (u8.length < HEADER_SIZE) {
            throw new Error('数据长度不足');
        }

        const plainLen = new DataView(u8.buffer, u8.byteOffset, u8.byteLength).getUint32(PREFIX_SIZE, true);

        if (plainLen <= 0 || plainLen > u8.length - HEADER_SIZE) {
            throw new Error('数据长度异常 (plainLen=' + plainLen + ', available=' + (u8.length - HEADER_SIZE) + ')，请确认所选版本与文件是否匹配');
        }

        return u8.slice(HEADER_SIZE, HEADER_SIZE + plainLen);
    }

    function encrypt(fileData, key, iv, prefix) {
        assertKeyAndIv(key, iv);
        assertPrefix(prefix);

        const prefixBytes = toBytes(prefix);
        const plainLen = fileData.length;
        const lenBytes = new ArrayBuffer(LENGTH_FIELD_SIZE);
        new DataView(lenBytes).setUint32(0, plainLen, true);
        const lenU8 = new Uint8Array(lenBytes);

        const toEncrypt = new Uint8Array(prefixBytes.length + lenU8.length + fileData.length);
        toEncrypt.set(prefixBytes, 0);
        toEncrypt.set(lenU8, prefixBytes.length);
        toEncrypt.set(fileData, prefixBytes.length + lenU8.length);

        // 补齐到 16 字节整数倍；恰好对齐时会再补满一整块，解密端读长度字段故不受影响
        const padLen = BLOCK_SIZE - (toEncrypt.length % BLOCK_SIZE);
        const paddedData = new Uint8Array(toEncrypt.length + padLen);
        paddedData.set(toEncrypt);

        const wordArray = CryptoJS.lib.WordArray.create(paddedData);
        const encrypted = CryptoJS.AES.encrypt(
            wordArray,
            CryptoJS.enc.Utf8.parse(key),
            {
                iv: CryptoJS.enc.Utf8.parse(iv),
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.NoPadding
            }
        );

        return wordArrayToUint8Array(encrypted.ciphertext);
    }

    // 分块转换，避免大文件时 String.fromCharCode(...codes) 触发调用栈上限
    function asciiCodesToString(codes) {
        const CHUNK = 8192;
        let out = '';
        for (let i = 0; i < codes.length; i += CHUNK) {
            out += String.fromCharCode.apply(null, codes.slice(i, i + CHUNK));
        }
        return out;
    }

    function decryptToJSON(fileData, key, iv) {
        const decryptedBytes = decrypt(fileData, key, iv);
        let text = new TextDecoder('utf-8').decode(decryptedBytes);

        // 部分文件把内容存成逗号分隔的 ASCII 码
        if (/^[\d,\s]+$/.test(text.trim())) {
            const asciiCodes = text.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
            text = asciiCodesToString(asciiCodes);
        }

        return text;
    }

    function encryptFromJSON(jsonText, key, iv, prefix) {
        return encrypt(new TextEncoder().encode(jsonText), key, iv, prefix);
    }

    return {
        BLOCK_SIZE,
        PREFIX_SIZE,
        LENGTH_FIELD_SIZE,
        HEADER_SIZE,
        PRESETS,
        getPreset,
        getPresetVersions,
        utf8ByteLength,
        decrypt,
        encrypt,
        decryptToJSON,
        encryptFromJSON
    };
})();
