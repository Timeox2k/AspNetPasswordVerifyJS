const crypto = require('crypto');

function createPasswordHash(password, salt) {
    const saltBuffer = Buffer.from(salt, 'base64');
    const passwordBuffer = Buffer.from(password, 'utf16le');
    const passwordWithSaltBuffer = Buffer.concat([saltBuffer, passwordBuffer]);
    const hash = crypto.createHash('sha1').update(passwordWithSaltBuffer).digest('base64');
    return hash;
}

function verifyPassword(password, hashedPassword, salt) {
    const hashVerify = createPasswordHash(password, salt);
    return { storedHash: hashedPassword, generatedHash: hashVerify };
}

const userInputPassword = 'ENTER THE PASSWORD HERE';
const storedHashedPassword = 'ENTER THE HASHED PASSWORD HERE';
const salt = 'ENTER THE SALT HERE';

const hashes = verifyPassword(userInputPassword, storedHashedPassword, salt);
console.log(`Stored Hash: ${hashes.storedHash}`);
console.log(`Generated Hash: ${hashes.generatedHash}`);
