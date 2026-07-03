// aes.js — İstemci tarafı AES-GCM şifreleme.
//
// Anahtar, oda şifresi (roomPassword) + sunucudan join_confirmed ile
// gelen odaya özel 'aes_salt' (etkin salt) birlikte PBKDF2'ye verilerek
// türetilir. Sunucu tarafında bu salt, .env'deki AES_KEY (gizli pepper)
// ile HMAC üzerinden imzalanmış durumdadır (bkz. ciphers/aes_utils.py).

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

let currentAESKeyHex = null;

async function deriveAESKey(roomPassword, saltHex) {
    const enc = new TextEncoder();
    const saltBytes = hexToBytes(saltHex);

    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(roomPassword),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    const aesKey = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,   // Demo için true
        ["encrypt", "decrypt"]
    );

    const rawKey = await window.crypto.subtle.exportKey("raw", aesKey);

    const hex = Array.from(new Uint8Array(rawKey))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");

    currentAESKeyHex = hex;

    console.log("AES Key:", hex);

    return aesKey;
}

async function encryptData(plainText, aesKey) {
    const enc = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, aesKey, enc.encode(plainText)
    );
    const ciphertextBase64 = btoa(String.fromCharCode.apply(null, new Uint8Array(encrypted)));
    const ivBase64 = btoa(String.fromCharCode.apply(null, iv));
    return { ciphertext: ciphertextBase64, iv: ivBase64 };
}

async function decryptData(ciphertextBase64, ivBase64, aesKey) {
    if (!ciphertextBase64 || !ivBase64 || !aesKey) {
        console.error("Eksik şifreli veri, IV veya anahtar.");
        return "[Şifreli Veri Bozuk veya Eksik]";
    }
    try {
        const ciphertext = new Uint8Array(atob(ciphertextBase64).split("").map(c => c.charCodeAt(0)));
        const iv = new Uint8Array(atob(ivBase64).split("").map(c => c.charCodeAt(0)));
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv }, aesKey, ciphertext
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        console.error("Deşifre hatası:", e);
        return "[Şifre Çözülemedi - Geçersiz Anahtar]";
    }
}