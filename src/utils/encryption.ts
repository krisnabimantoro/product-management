import crypto from "crypto";

const ensureKeyLength = (key: string): Buffer => {
  if (key.length !== 32) {
    throw new Error("Key length must be 32 bytes.");
  }
  return Buffer.from(key);
};

export const encrypt = (key: string, plainText: string): string => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-ctr", Buffer.from(key), iv);
  let encrypted = cipher.update(plainText);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return `${iv.toString("hex")}:${encrypted.toString("hex")}`;
};

export const decrypt = (key: string, plainText: string) => {
  const textParts = plainText.split(":");
  const ivHex = textParts.shift();
  const iv = ivHex ? Buffer.from(ivHex, "hex") : Buffer.alloc(0);
  const encryptedText = Buffer.from(textParts.join(":"), "hex");
  const decipher = crypto.createDecipheriv("aes-256-ctr", Buffer.from(key), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
};
