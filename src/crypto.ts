import crypto from "crypto";

export function generateRandomHexString(length:number): string {
  const randomBytes = crypto.randomBytes(length/2);
  return randomBytes.toString("hex");
}
