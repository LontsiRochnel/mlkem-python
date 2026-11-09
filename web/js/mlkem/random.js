export function randomBytes(length) {
  const bytes = new Uint8Array(length);

  const candidate =
    typeof globalThis !== "undefined" && globalThis.crypto && typeof globalThis.crypto.getRandomValues === "function" ? globalThis.crypto : null;

  if (candidate) {
    candidate.getRandomValues(bytes);
    return bytes;
  }

  try {
    const nodeCrypto = Function("return require('node:crypto').webcrypto")();
    nodeCrypto.getRandomValues(bytes);
    return bytes;
  } catch {
    throw new Error("crypto.getRandomValues n'est pas disponible");
  }
}
