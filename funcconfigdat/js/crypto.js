const FuncConfigCrypto = (() => {
    const PRESETS = {
        '7.1.7': {
            key: 'Jbga21autoj7ZAsF',
            iv: 'Jbga21autoj7ZAsF',
            prefix: 'J451640)$n?2\x10q\x1b'
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

    function decrypt(fileData, key, iv) {
        if (key.length !== 16 || iv.length !== 16) {
            throw new Error('KEY 和 IV 必须为 16 字节');
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

        if (u8.length < 20) {
            throw new Error('解密失败：数据长度不足');
        }

        const plainLen = new DataView(u8.buffer, u8.byteOffset, u8.byteLength).getUint32(16, true);

        if (plainLen <= 0 || plainLen > u8.length - 20) {
            throw new Error('解密失败：数据长度异常 (plainLen=' + plainLen + ', available=' + (u8.length - 20) + ')');
        }

        return u8.slice(20, 20 + plainLen);
    }

    function encrypt(fileData, key, iv, prefix) {
        if (key.length !== 16 || iv.length !== 16) {
            throw new Error('KEY 和 IV 必须为 16 字节');
        }
        if (prefix.length !== 16) {
            throw new Error('数据填充（prefix）必须为 16 字节');
        }

        const plainLen = fileData.length;
        const lenBytes = new ArrayBuffer(4);
        new DataView(lenBytes).setUint32(0, plainLen, true);

        const prefixBytes = new TextEncoder().encode(prefix);
        const lenU8 = new Uint8Array(lenBytes);

        const toEncrypt = new Uint8Array(prefixBytes.length + lenU8.length + fileData.length);
        toEncrypt.set(prefixBytes, 0);
        toEncrypt.set(lenU8, prefixBytes.length);
        toEncrypt.set(fileData, prefixBytes.length + lenU8.length);

        const blockSize = 16;
        const padLen = blockSize - (toEncrypt.length % blockSize);
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

    function wordArrayToUint8Array(wordArray) {
        const u8 = new Uint8Array(wordArray.words.length * 4);
        for (let i = 0; i < wordArray.words.length; i++) {
            const word = wordArray.words[i];
            u8[i * 4] = (word >> 24) & 0xff;
            u8[i * 4 + 1] = (word >> 16) & 0xff;
            u8[i * 4 + 2] = (word >> 8) & 0xff;
            u8[i * 4 + 3] = word & 0xff;
        }
        return u8;
    }

    function decryptToJSON(fileData, key, iv) {
        const decryptedBytes = decrypt(fileData, key, iv);
        let text = new TextDecoder('utf-8').decode(decryptedBytes);

        // Some files store content as comma-separated ASCII codes
        if (/^[\d,\s]+$/.test(text.trim())) {
            const asciiCodes = text.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
            text = String.fromCharCode(...asciiCodes);
        }

        return text;
    }

    function encryptFromJSON(jsonText, key, iv, prefix) {
        const encoded = new TextEncoder().encode(jsonText);
        return encrypt(encoded, key, iv, prefix);
    }

    return {
        PRESETS,
        getPreset,
        getPresetVersions,
        decrypt,
        encrypt,
        decryptToJSON,
        encryptFromJSON
    };
})();
