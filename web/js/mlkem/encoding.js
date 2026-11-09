import { Q } from "./params.js";

export function BitsToBytes(bits) {
  const output = new Uint8Array(Math.ceil(bits.length / 8));
  for (let index = 0; index < bits.length; index += 1) {
    if (bits[index]) {
      output[Math.floor(index / 8)] |= 1 << (index % 8);
    }
  }
  return output;
}

export function BytesToBits(data) {
  const output = [];
  for (const byte of data) {
    for (let bitIndex = 0; bitIndex < 8; bitIndex += 1) {
      output.push((byte >> bitIndex) & 1);
    }
  }
  return output;
}

export function ByteEncode_d(poly, d) {
  if (d <= 0) {
    throw new Error("d doit être strictement positif");
  }
  const bits = [];
  for (const value of poly) {
    const normalized = Number(value) % Q;
    const binary = normalized.toString(2).padStart(d, "0");
    for (const character of binary) {
      bits.push(character === "1" ? 1 : 0);
    }
  }
  return BitsToBytes(bits);
}

export function ByteDecode_d(data, d, length) {
  if (d <= 0) {
    throw new Error("d doit être strictement positif");
  }
  const bits = BytesToBits(data);
  const values = [];
  for (let index = 0; index < length; index += 1) {
    const start = index * d;
    const stop = start + d;
    const chunk = bits.slice(start, stop);
    if (chunk.length < d) {
      break;
    }
    let value = 0;
    for (const bit of chunk) {
      value = (value << 1) | Number(bit);
    }
    values.push(value % Q);
  }
  return values;
}

export function Compress_d(x, d) {
  if (d <= 0) {
    throw new Error("d doit être strictement positif");
  }
  const normalized = Number(x) % Q;
  const scale = (1 << d) - 1;
  return Math.min(Math.floor((normalized * scale + (Q >> 1)) / Q), scale);
}

export function Decompress_d(x, d) {
  if (d <= 0) {
    throw new Error("d doit être strictement positif");
  }
  const normalized = Number(x) % (1 << d);
  return Math.floor((normalized * Q + (1 << (d - 1))) >> d);
}
