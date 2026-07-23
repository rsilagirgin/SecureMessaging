function e2eeBufToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function e2eeBase64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

// Kullanıcının kendi RSA-OAEP anahtar çiftini üretir. extractable=true
// SADECE public key'in dışa aktarılabilmesi için gerekli; private key
// zaten bu fonksiyonun dışına (sunucuya/ağa) hiç gönderilmiyor.
async function generateE2EEKeyPair() {
    return await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]), // 65537
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );
}

// Public key'i sunucuya gönderilebilecek JSON-uyumlu bir biçime (JWK) çevirir.
async function exportE2EEPublicKey(publicKey) {
    return await window.crypto.subtle.exportKey("jwk", publicKey);
}

// Sunucudan/başka bir kullanıcıdan gelen JWK public key'i, şifreleme için
// kullanılabilir bir CryptoKey nesnesine çevirir.
async function importE2EEPublicKey(jwk) {
    return await window.crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
    );
}

// Metni rastgele bir AES-256-GCM oturum anahtarıyla şifreler, sonra o
// anahtarı `recipientsPublicKeys` içindeki HERKESİN public key'i ile ayrı
// ayrı sarar. recipientsPublicKeys: { username: CryptoKey(public) }
// Dönüş: { iv, ciphertext, keys: { username: sarılmışAnahtar(base64) } }
// (Gönderenin kendi mesajını daha sonra çözebilmesi için recipientsPublicKeys
// içine kendi public key'ini de eklemesi gerekir — çağıran taraf sorumludur.)
async function e2eeEncryptMessage(text, recipientsPublicKeys) {
    const usernames = Object.keys(recipientsPublicKeys || {});
    if (usernames.length === 0) {
        throw new Error("No recipient's public key was found in the room.");
    }

    // 1) Tek seferlik (ephemeral) AES-256-GCM oturum anahtarı
    const sessionKey = await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true, // dışa aktarılabilir olmalı ki RSA ile sarabilelim
        ["encrypt", "decrypt"]
    );
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // 2) Mesajı oturum anahtarıyla şifrele
    const enc = new TextEncoder();
    const ciphertextBuf = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        sessionKey,
        enc.encode(text)
    );

    // 3) Oturum anahtarının ham (raw) baytlarını al, her alıcı için RSA-OAEP ile sar
    const rawSessionKey = await window.crypto.subtle.exportKey("raw", sessionKey);

    const wrappedKeys = {};
    for (const username of usernames) {
        const theirPublicKey = recipientsPublicKeys[username];
        const wrapped = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            theirPublicKey,
            rawSessionKey
        );
        wrappedKeys[username] = e2eeBufToBase64(wrapped);
    }

    return {
        iv: e2eeBufToBase64(iv),
        ciphertext: e2eeBufToBase64(ciphertextBuf),
        keys: wrappedKeys,
    };
}

// encrypt tarafında üretilen paketi çözer.
// payload: { iv, ciphertext, keys }  |  myUsername: kendi kullanıcı adın
// myPrivateKey: SADECE kendi tarayıcında üretilen, hiç paylaşılmamış private key.
async function e2eeDecryptMessage(payload, myUsername, myPrivateKey) {
    if (!payload || !payload.keys || !myPrivateKey) {
        return "[Corrupted or Missing Encrypted Data]";
    }

    const myWrappedKey = payload.keys[myUsername];
    if (!myWrappedKey) {
        // Bu, GERÇEK E2EE'nin doğal bir sonucudur: bu mesaj gönderildiğinde
        // henüz odada değildin (public key'in dağıtım listesinde yoktu),
        // bu yüzden senin için şifrelenmiş bir anahtar zarfı hiç üretilmedi.
        // Sunucu bile bunu "geriye dönük" düzeltemez, çünkü private key'i yok.
        return "[🔒 This message was sent before you joined the room and cannot be decrypted]";
    }

    try {
        const rawSessionKey = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            myPrivateKey,
            e2eeBase64ToBuf(myWrappedKey)
        );
        const sessionKey = await window.crypto.subtle.importKey(
            "raw",
            rawSessionKey,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );
        const plainBuf = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: e2eeBase64ToBuf(payload.iv) },
            sessionKey,
            e2eeBase64ToBuf(payload.ciphertext)
        );
        return new TextDecoder().decode(plainBuf);
    } catch (e) {
        console.error("E2EE decryption error:", e);
        return "[Could Not Decrypt - Invalid Key]";
    }
}