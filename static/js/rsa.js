function bigModPow(base, exponent, modulus) {
    base = BigInt(base);
    exponent = BigInt(exponent);
    modulus = BigInt(modulus);

    if (modulus === 1n) return 0n;

    let result = 1n;
    base = base % modulus;

    while (exponent > 0n) {
        if (exponent % 2n === 1n) {
            result = (result * base) % modulus;
        }
        exponent = exponent / 2n;
        base = (base * base) % modulus;
    }
    return result;
}

// Sunucudan gelen {value: "...", n: "..."} nesnesini BigInt'e çevirir.
function parseRSAKey(keyObj) {
    if (!keyObj) return null;
    return { value: BigInt(keyObj.value), n: BigInt(keyObj.n) };
}

// n'in byte cinsinden uzunluğu (Python _byte_length ile birebir eşleşir).
function rsaByteLength(bigIntN) {
    return Math.ceil(bigIntN.toString(2).length / 8);
}

// Bir BigInt'i, tam olarak `length` byte uzunluğunda büyük-endian bir
// Uint8Array'e çevirir (gerekirse baştan sıfırla doldurur).
function bigIntToBytes(num, length) {
    let hex = num.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    const raw = [];
    for (let i = 0; i < hex.length; i += 2) {
        raw.push(parseInt(hex.substr(i, 2), 16));
    }
    const bytes = new Uint8Array(length);
    // sağa yasla (soldaki eksik byte'lar zaten 0x00 kalır)
    bytes.set(raw, length - raw.length);
    return bytes;
}

// Büyük-endian bir Uint8Array'i BigInt'e çevirir.
function bytesToBigInt(bytes) {
    let hex = '';
    for (const b of bytes) hex += b.toString(16).padStart(2, '0');
    return hex.length ? BigInt('0x' + hex) : 0n;
}

// Kriptografik olarak güvenli, SIFIR OLMAYAN rastgele byte'lar üretir
// (PKCS#1 v1.5 kuralı: dolgu byte'ları asla 0x00 olamaz).
function randomNonZeroBytes(length) {
    const out = new Uint8Array(length);
    let filled = 0;
    while (filled < length) {
        const chunk = new Uint8Array(length - filled);
        window.crypto.getRandomValues(chunk);
        for (const b of chunk) {
            if (b !== 0) out[filled++] = b;
        }
    }
    return out;
}

// Metni UTF-8 byte'lara çevirip PKCS#1 v1.5 benzeri rastgele dolgu ile
// bloklara böler, her bloğu ayrı ayrı şifreler. Dönüş: ondalık string dizisi.
function rsaEncrypt(text, publicKey) {
    if (!publicKey) {
        console.error("RSA public key eksik.");
        return [];
    }
    const nBytes = rsaByteLength(publicKey.n);
    const maxBlock = nBytes - 11; // 3 byte başlık + en az 8 byte dolgu (PKCS#1 v1.5)
    if (maxBlock <= 0) {
        console.error("RSA key is too small to block this message.");
        return [];
    }

    const data = new TextEncoder().encode(text);
    const blocks = [];
    if (data.length === 0) {
        blocks.push(new Uint8Array(0));
    } else {
        for (let i = 0; i < data.length; i += maxBlock) {
            blocks.push(data.slice(i, i + maxBlock));
        }
    }

    return blocks.map(chunk => {
        const psLen = nBytes - 3 - chunk.length;
        const ps = randomNonZeroBytes(psLen);

        const padded = new Uint8Array(nBytes);
        padded[0] = 0x00;
        padded[1] = 0x02;
        padded.set(ps, 2);
        padded[2 + psLen] = 0x00;
        padded.set(chunk, 3 + psLen);

        const m = bytesToBigInt(padded);
        const c = bigModPow(m, publicKey.value, publicKey.n);
        return c.toString();
    });
}

// encrypt() ile üretilmiş ondalık string dizisini çözüp orijinal metni döner.
function rsaDecrypt(cipherBlocks, privateKey) {
    if (!cipherBlocks || !privateKey) {
        console.error("Missing encrypted data or RSA key.");
        return "[Corrupted or Missing Encrypted Data]";
    }
    try {
        const nBytes = rsaByteLength(privateKey.n);
        const chunks = [];
        let totalLen = 0;

        for (const cStr of cipherBlocks) {
            const c = BigInt(cStr);
            const m = bigModPow(c, privateKey.value, privateKey.n);
            const mb = bigIntToBytes(m, nBytes);

            if (mb[0] !== 0x00 || mb[1] !== 0x02) {
                throw new Error("Invalid PKCS#1 padding (wrong key or corrupted data).");
            }
            let sepIndex = -1;
            for (let i = 2; i < mb.length; i++) {
                if (mb[i] === 0x00) { sepIndex = i; break; }
            }
            if (sepIndex === -1) {
                throw new Error("Padding terminator not found (corrupted data).");
            }
            const chunk = mb.slice(sepIndex + 1);
            chunks.push(chunk);
            totalLen += chunk.length;
        }

        const full = new Uint8Array(totalLen);
        let offset = 0;
        for (const c of chunks) { full.set(c, offset); offset += c.length; }

        return new TextDecoder().decode(full);
    } catch (e) {
        console.error("RSA decryption error:", e);
        return "[Could Not Decrypt - Invalid Key]";
    }
}