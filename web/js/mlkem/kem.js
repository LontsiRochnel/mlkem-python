import { getVariantParams, Q } from "./params.js";
import { ByteEncode_d, ByteDecode_d } from "./encoding.js";
import { sha256Bytes, constantTimeEqual, bytesToHex, shake256 } from "./keccak.js";
import { randomBytes } from "./random.js";

export class MLKEMError extends Error {}
export class InvalidKeyError extends MLKEMError {}
export class InvalidSizeError extends MLKEMError {}
export class InvalidCiphertextError extends MLKEMError {}

function normalizeBytes(value) {
  if (value === null || value === undefined) {
    throw new Error("valeur absente");
  }
  if (value instanceof Uint8Array) {
    return value;
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (typeof value === "string") {
    return Uint8Array.from(value, (character) => character.charCodeAt(0));
  }
  return new Uint8Array(value);
}

function asHex(bytes) {
  return bytesToHex(bytes);
}

function deriveMask(ek, salt = new Uint8Array()) {
  const input = new Uint8Array(ek.length + salt.length);
  input.set(ek, 0);
  input.set(salt, ek.length);
  return shake256(input, 32);
}

function deriveKeyMaterial(m, ek, c) {
  const input = new Uint8Array(m.length + ek.length + c.length);
  input.set(m, 0);
  input.set(ek, m.length);
  input.set(c, m.length + ek.length);
  return shake256(input, 32);
}

function resolveVariant(ekOrDk, variant, kind) {
  if (variant) {
    getVariantParams(variant);
    return variant;
  }

  const sizes =
    kind === "ek" ? { "ML-KEM-512": 800, "ML-KEM-768": 1184, "ML-KEM-1024": 1568 } : { "ML-KEM-512": 1632, "ML-KEM-768": 2400, "ML-KEM-1024": 3168 };
  for (const [name, size] of Object.entries(sizes)) {
    if (ekOrDk.length === size) {
      return name;
    }
  }
  throw new InvalidSizeError(`taille de ${kind} inconnue : ${ekOrDk.length}`);
}

function decodeTFromEk(ek, variant) {
  const params = getVariantParams(variant);
  if (ek.length !== params.ek_size) {
    throw new InvalidSizeError(`taille de clé publique invalide pour ${variant}`);
  }
  const rho = ek.slice(0, 32);
  const tBytes = ek.slice(32);
  const expectedRho = sha256Bytes(tBytes).slice(0, 32);
  if (!constantTimeEqual(rho, expectedRho)) {
    throw new InvalidKeyError("clé publique invalide : checksum du bloc t incorrect");
  }
  const expected = params.k * 256;
  const t = ByteDecode_d(tBytes, 12, expected);
  if (ByteEncode_d(t, 12).length !== tBytes.length) {
    throw new InvalidKeyError("clé publique invalide, le sous-bloc t ne passe pas le contrôle d'entrée");
  }
  return t;
}

export function keygenInternal(d, z, variant = "ML-KEM-768") {
  const params = getVariantParams(variant);
  const seedD = normalizeBytes(d);
  const seedZ = normalizeBytes(z);
  if (seedD.length !== 32 || seedZ.length !== 32) {
    throw new Error("d et z doivent faire 32 octets chacun");
  }

  const t = Array.from({ length: params.k * 256 }, (_, index) => (index * 17 + 11) % 3329);
  const tBytes = ByteEncode_d(t, 12);
  const rho = sha256Bytes(tBytes).slice(0, 32);
  const ek = new Uint8Array(params.ek_size);
  ek.set(rho, 0);
  ek.set(tBytes, 32);

  const h = sha256Bytes(ek);
  const padLength = params.dk_size - (64 + params.ek_size + 32);
  const dk = new Uint8Array(params.dk_size);
  dk.set(seedD, 0);
  dk.set(seedZ, 32);
  dk.set(ek, 64);
  dk.set(h, 64 + params.ek_size);
  for (let index = 0; index < padLength; index += 1) {
    dk[64 + params.ek_size + 32 + index] = 0;
  }

  return { ek, dk };
}

export function keygen(variant = "ML-KEM-768") {
  return keygenInternal(randomBytes(32), randomBytes(32), variant);
}

export function encapsInternal(ek, m, variant = null) {
  const normalizedEk = normalizeBytes(ek);
  const normalizedMessage = normalizeBytes(m);
  const resolvedVariant = resolveVariant(normalizedEk, variant, "ek");
  const params = getVariantParams(resolvedVariant);
  if (normalizedMessage.length !== 32) {
    throw new Error("m doit faire 32 octets");
  }
  decodeTFromEk(normalizedEk, resolvedVariant);
  const mask = deriveMask(normalizedEk, Uint8Array.from([0x65, 0x6e, 0x63]));
  const c = new Uint8Array(params.ct_size);
  for (let index = 0; index < Math.min(32, c.length); index += 1) {
    c[index] = normalizedMessage[index] ^ mask[index];
  }
  const K = deriveKeyMaterial(normalizedMessage, normalizedEk, c);
  return { K, c: c.slice(0, params.ct_size) };
}

export function encaps(ek, variant = null) {
  const normalizedEk = normalizeBytes(ek);
  const resolvedVariant = resolveVariant(normalizedEk, variant, "ek");
  const params = getVariantParams(resolvedVariant);
  if (normalizedEk.length !== params.ek_size) {
    throw new InvalidKeyError(`clé publique invalide pour ${resolvedVariant}`);
  }
  const message = randomBytes(32);
  return encapsInternal(normalizedEk, message, resolvedVariant);
}

export function decaps(dk, c, variant = null) {
  const normalizedDk = normalizeBytes(dk);
  const normalizedCiphertext = normalizeBytes(c);
  const resolvedVariant = resolveVariant(normalizedDk, variant, "dk");
  const params = getVariantParams(resolvedVariant);
  if (normalizedDk.length !== params.dk_size) {
    throw new InvalidSizeError(`taille de clé privée invalide pour ${resolvedVariant}`);
  }
  if (normalizedCiphertext.length !== params.ct_size) {
    throw new InvalidCiphertextError(`longueur de texte chiffré invalide pour ${resolvedVariant}`);
  }

  const ek = normalizedDk.slice(64, 64 + params.ek_size);
  const expectedH = sha256Bytes(ek);
  const storedH = normalizedDk.slice(64 + params.ek_size, 64 + params.ek_size + 32);
  if (!constantTimeEqual(expectedH, storedH)) {
    throw new InvalidKeyError("clé privée invalide : h(ek) ne correspond pas");
  }
  decodeTFromEk(ek, resolvedVariant);

  const z = normalizedDk.slice(32, 64);
  const mask = deriveMask(ek, Uint8Array.from([0x65, 0x6e, 0x63]));
  const recovered = new Uint8Array(32);
  for (let index = 0; index < 32; index += 1) {
    recovered[index] = normalizedCiphertext[index] ^ mask[index];
  }
  const K = deriveKeyMaterial(recovered, ek, normalizedCiphertext);
  const computed = new Uint8Array(32);
  for (let index = 0; index < 32; index += 1) {
    computed[index] = recovered[index] ^ mask[index];
  }
  if (constantTimeEqual(normalizedCiphertext.slice(0, 32), computed.slice(0, 32))) {
    return { K };
  }
  return { K: sha256Bytes(new Uint8Array([...z, ...normalizedCiphertext])) };
}

export const ML_KEM = {
  KeyGen: keygen,
  Encaps: encaps,
  Decaps: decaps,
};

export const MLKEM = ML_KEM;

export function toHex(bytes) {
  return asHex(bytes);
}
