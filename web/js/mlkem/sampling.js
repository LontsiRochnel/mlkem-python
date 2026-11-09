import { Q, N } from "./params.js";
import { shake128, shake256 } from "./keccak.js";

export function XOF(seed, length, domain = new Uint8Array()) {
  const input = new Uint8Array(seed.length + domain.length);
  input.set(seed, 0);
  input.set(domain, seed.length);
  return shake128(input, length);
}

export function PRF(seed, length, nonce = 0) {
  const payload = new Uint8Array(seed.length + 4);
  payload.set(seed, 0);
  const view = new DataView(new ArrayBuffer(4));
  view.setUint32(0, nonce >>> 0, true);
  payload.set(new Uint8Array(view.buffer), seed.length);
  return shake256(payload, length);
}

export function SampleNTT(seed) {
  const out = [];
  const data = XOF(seed, 3 * N);
  for (let index = 0; index < N; index += 1) {
    const chunk = data.slice(3 * index, 3 * index + 3);
    const value = chunk.reduce((accumulator, byte) => (accumulator << 8) + byte, 0) % Q;
    out.push(value);
  }
  return out;
}

export function SamplePolyCBD_eta(seed, eta, length = N) {
  if (eta !== 2 && eta !== 3) {
    throw new Error("eta supporté uniquement pour les valeurs 2 et 3");
  }
  const values = [];
  for (let index = 0; index < length; index += 1) {
    const padded = new Uint8Array(2);
    const view = new DataView(new ArrayBuffer(2));
    view.setUint16(0, index, true);
    padded.set(new Uint8Array(view.buffer), 0);
    const digest = shake256(new Uint8Array([...seed, ...padded]), 8);
    const word = digest.reduce((acc, byte) => (acc << 8) + byte, 0);
    const mask = (1 << eta) - 1;
    const a = (word & mask).toString(2).split("1").length - 1;
    const b = ((word >> eta) & mask).toString(2).split("1").length - 1;
    values.push((a - b) % Q);
  }
  return values;
}
