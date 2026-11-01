import { createHash, randomBytes } from "node:crypto";

export function createPkcePair() {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: s256(verifier) };
}

export function s256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}
