// akis.js — 🪪 AKİS kartı ile şifrelenen odalar (istemci tarafı).
//
// TASARIM: e2ee.js ile AYNI zarflama (envelope) yöntemi kullanılır:
// rastgele bir AES-256-GCM oturum anahtarı üretilir, mesaj bu anahtarla
// şifrelenir, sonra oturum anahtarı odadaki HERKESİN kartının GERÇEK RSA
// public key'i ile (PKCS#1 v1.5 — bkz. rsa.js: rsaEncrypt) ayrı ayrı sarılır.
//
// FARK: normal RSA/E2EE modlarının aksine burada private key tarayıcıda
// DEĞİL, kullanıcının fiziksel AKİS kartındadır ve karttan asla çıkmaz.
// Bu yüzden şifre çözme JS içinde yapılamaz; tarayıcı sunucudan
// 'akis_decrypt_request' ile kartın (o an açık PIN oturumuyla) sarılı
// anahtarı çözmesini ister (bkz. app.py + ciphers/akis_pkcs11.py ->
// decrypt_with_card, PKCS#11 C_Decrypt). Kart çıkarılır/oturum kapanırsa
// bu istek başarısız olur ve mesaj çözülemez — yani odayı SADECE o an
// kartıyla giriş yapmış olanlar okuyabilir.

function akisBufToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function akisBase64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

// recipientsAkisPublicKeys: { username: {value: BigInt, n: BigInt} } (rsa.js -> parseRSAKey ile parse edilmiş)
async function akisEncryptMessage(text, recipientsAkisPublicKeys) {
    const usernames = Object.keys(recipientsAkisPublicKeys || {});
    if (usernames.length === 0) {
        throw new Error("No AKIS card public key was found in the room yet.");
    }

    // 1) Tek seferlik AES-256-GCM oturum anahtarı
    const sessionKey = await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
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

    // 3) Oturum anahtarının ham baytlarını al, base64'e çevir (rsaEncrypt
    // metin bekler; base64 tamamen ASCII olduğu için kayıpsız taşınır),
    // ve her alıcının kartının GERÇEK public key'i ile sar.
    const rawSessionKey = await window.crypto.subtle.exportKey("raw", sessionKey);
    const sessionKeyB64 = akisBufToBase64(rawSessionKey);

    const wrappedKeys = {};
    for (const username of usernames) {
        const theirPublicKey = recipientsAkisPublicKeys[username];
        wrappedKeys[username] = rsaEncrypt(sessionKeyB64, theirPublicKey);
    }

    return {
        iv: akisBufToBase64(iv),
        ciphertext: akisBufToBase64(ciphertextBuf),
        keys: wrappedKeys,
    };
}

// payload: { iv, ciphertext, keys } | myUsername: kendi (benzersiz) kullanıcı adın.
// Şifre çözme, kartın fiziksel olarak takılı olduğu backend üzerinden yapılır.
async function akisDecryptMessage(payload, myUsername) {
    if (!payload || !payload.keys) {
        return "[Corrupted or Missing Encrypted Data]";
    }

    const myWrappedKey = payload.keys[myUsername];
    if (!myWrappedKey) {
        // Bu mesaj gönderildiğinde henüz odada (kart public key'i dağıtım
        // listesinde) değildin, bu yüzden senin için sarılmış bir anahtar
        // zarfı hiç üretilmedi.
        return "[🔒 This message was sent before you joined the room and cannot be decrypted]";
    }

    try {
        const ackResult = await new Promise((resolve) => {
            socket.emit('akis_decrypt_request', { blocks: myWrappedKey }, (response) => {
                resolve(response);
            });
        });

        if (!ackResult || !ackResult.success) {
            const reason = (ackResult && ackResult.msg) || "No response from server.";
            console.error("AKIS decryption error:", reason);
            return `[🪪 Could not decrypt with card: ${reason}]`;
        }

        const rawKeyBuf = akisBase64ToBuf(ackResult.key_b64);
        const sessionKey = await window.crypto.subtle.importKey(
            "raw",
            rawKeyBuf,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );
        const plainBuf = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: akisBase64ToBuf(payload.iv) },
            sessionKey,
            akisBase64ToBuf(payload.ciphertext)
        );
        return new TextDecoder().decode(plainBuf);
    } catch (e) {
        console.error("AKIS decryption error:", e);
        return "[Could Not Decrypt - Invalid Key]";
    }
}