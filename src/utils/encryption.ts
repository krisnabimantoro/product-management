import crypto from "crypto";

// Function to ensure the key is 32 bytes long
const ensureKeyLength = (key: string): Buffer => {
  if (key.length !== 32) {
    throw new Error("Key length must be 32 bytes.");
  }
  return Buffer.from(key);
};

export const encrypt = (key: string, plainText: string): string => {
  const iv = crypto.randomBytes(16);
  const validKey = ensureKeyLength(key);
  const cipher = crypto.createCipheriv("aes-256-ctr", validKey, iv);
  let encrypted = cipher.update(plainText);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return `${iv.toString("hex")}:${encrypted.toString("hex")}`;
};

export const decrypt = (key: string, encryptedText: string): string => {
  const textParts = encryptedText.split(":");
  const ivHex = textParts.shift();
  const iv = ivHex ? Buffer.from(ivHex, "hex") : Buffer.alloc(0);
  const validKey = ensureKeyLength(key);
  const encryptedBuffer = Buffer.from(textParts.join(":"), "hex");
  const decipher = crypto.createDecipheriv("aes-256-ctr", validKey, iv);
  let decrypted = decipher.update(encryptedBuffer);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
};
