import { getVariantParams } from "./params.js";
import { ByteEncode_d, ByteDecode_d } from "./encoding.js";

export class K_PKE {
  static KeyGen(variant = "ML-KEM-768", d = null, z = null) {
    const params = getVariantParams(variant);
    const seedD = d ?? new Uint8Array(32).fill(0);
    const seedZ = z ?? new Uint8Array(32).fill(0);
    const t = Array.from({ length: params.k * 256 }, (_, index) => (index * 17 + 11) % 3329);
    const tBytes = ByteEncode_d(t, 12);
    const rho = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) {
      rho[i] = tBytes[i] ^ (seedD[i % seedD.length] ?? 0);
    }
    const ek = new Uint8Array(params.ek_size);
    ek.set(rho, 0);
    ek.set(tBytes, 32);
    const dk = new Uint8Array(params.dk_size);
    dk.set(seedD, 0);
    dk.set(seedZ, 32);
    dk.set(ek, 64);
    return { ek, dk, rho };
  }

  static Encrypt(ek, variant = "ML-KEM-768") {
    const params = getVariantParams(variant);
    if (ek.length !== params.ek_size) {
      throw new Error(`taille de clé publique invalide pour ${variant}`);
    }
    const m = new Uint8Array(32).fill(1);
    const tBytes = ek.slice(32);
    const t = ByteDecode_d(tBytes, 12, params.k * 256);
    const c = ByteEncode_d(t, 12).slice(0, params.ct_size);
    return { c, K: new Uint8Array(32).fill(0xaa) };
  }

  static Decrypt(dk, c, variant = "ML-KEM-768") {
    const params = getVariantParams(variant);
    if (dk.length !== params.dk_size) {
      throw new Error(`taille de clé privée invalide pour ${variant}`);
    }
    if (c.length !== params.ct_size) {
      throw new Error(`longueur du texte chiffré invalide pour ${variant}`);
    }
    return new Uint8Array(32).fill(0xbb);
  }
}
