// caesar.js — İstemci tarafı Caesar Cipher (kaydırmalı şifre) mantığı.
//
// Kaydırma (shift) değeri backend tarafından oda kurulurken üretilir
// (bkz. ciphers/caesar.py -> generate_caesar_shift) ve odaya katılan
// istemciye join_confirmed olayıyla gönderilir (data.shift).

ALPHABET = (
   ' 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZÇĞİÖŞÜabcdefghijklmnopqrstuvwxyzçğıöşü.,!?:;\'"-()\n'
)


function caesarEncrypt(text, shift) {
    let result = "";
    for (let char of text) {
        let index = ALPHABET.indexOf(char);
        result += index === -1 ? char : ALPHABET[(index + shift) % ALPHABET.length];
    }
    return result;
}

function caesarDecrypt(text, shift) {
    let result = "";
    for (let char of text) {
        let index = ALPHABET.indexOf(char);
        if (index === -1) {
            result += char;
        } else {
            let newIndex = index - shift;
            if (newIndex < 0) newIndex += ALPHABET.length;
            result += ALPHABET[newIndex];
        }
    }
    return result;
}