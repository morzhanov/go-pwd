const crypto = require('crypto');

function deriveKey(secret) {
    return crypto.createHash('sha256').update(secret).digest();
}

function encryptPK(text, secret) {
    const key = deriveKey(secret);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cfb', key, iv);
    let encrypted = cipher.update(Buffer.from(text, 'utf8'));
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    // Combine IV and encrypted text
    const encryptedData = Buffer.concat([iv, encrypted]);

    // Return base64 encoded string
    console.log(encryptedData.toString('base64'));
}

encryptPK("pk", "2133352");
