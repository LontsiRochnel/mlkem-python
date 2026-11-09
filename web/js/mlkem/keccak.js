const nativeCrypto = (() => {
  if (typeof process !== "undefined" && process.versions?.node && typeof process.getBuiltinModule === "function") {
    try {
      return process.getBuiltinModule("node:crypto");
    } catch {
      return null;
    }
  }
  return null;
})();

const MASK64 = 0xffffffffffffffffn;
const KECCAK_LANES = 25;
const SHAKE_RATE_BYTES = 136;

const ROUND_CONSTANTS = [
  0x0000000000000001n,
  0x0000000000008082n,
  0x800000000000808an,
  0x8000000080008000n,
  0x000000000000808bn,
  0x0000000080000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x000000000000008an,
  0x0000000000000088n,
  0x0000000080008009n,
  0x000000008000000an,
  0x000000008000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n,
];

const ROTATION = [
  [0n, 1n, 62n, 28n, 27n],
  [36n, 44n, 6n, 55n, 25n],
  [3n, 10n, 43n, 15n, 21n],
  [41n, 45n, 15n, 21n, 8n],
  [18n, 2n, 61n, 56n, 14n],
];

function rotl64(value, shift) {
  if (shift === 0n) {
    return value & MASK64;
  }
  const left = (value << shift) & MASK64;
  const right = value >> (64n - shift);
  return (left | right) & MASK64;
}

function bytesToLaneLittleEndian(bytes) {
  let value = 0n;
  for (let index = 0; index < 8; index += 1) {
    value |= BigInt(bytes[index] ?? 0) << (BigInt(index) * 8n);
  }
  return value & MASK64;
}

function laneToBytesLittleEndian(lane) {
  const out = new Uint8Array(8);
  for (let index = 0; index < 8; index += 1) {
    out[index] = Number((lane >> (BigInt(index) * 8n)) & 0xffn);
  }
  return out;
}

function toUint8Array(value) {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  return new Uint8Array(value);
}

export function bytesToHex(bytes) {
  return Array.from(toUint8Array(bytes), (value) => value.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  const normalized = hex.replace(/^0x/, "");
  return Uint8Array.from(normalized.match(/.{1,2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? []);
}

export function constantTimeEqual(left, right) {
  if (left.length !== right.length) {
    return false;
  }
  let mismatch = 0;
  for (let index = 0; index < left.length; index += 1) {
    mismatch |= left[index] ^ right[index];
  }
  return mismatch === 0;
}

function sha256Ch(x, y, z) {
  return (x & y) ^ ((~x & z) >>> 0);
}

function sha256Maj(x, y, z) {
  return (x & y) ^ (x & z) ^ ((y & z) >>> 0);
}

function sha256Sum0(x) {
  return (rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)) >>> 0;
}

function sha256Sum1(x) {
  return (rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)) >>> 0;
}

function rotr32(value, bits) {
  return ((value >>> bits) | (value << (32 - bits))) >>> 0;
}

const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74,
  0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d,
  0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
  0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

export function sha256Bytes(input) {
  if (nativeCrypto) {
    return new Uint8Array(nativeCrypto.createHash("sha256").update(toUint8Array(input)).digest());
  }

  const bytes = toUint8Array(input);
  const bitLength = bytes.length * 8;
  const paddedLength = ((bytes.length + 9 + 63) >> 6) << 6;
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes, 0);
  padded[bytes.length] = 0x80;
  const lengthView = new DataView(new ArrayBuffer(8));
  lengthView.setBigUint64(0, BigInt(bitLength), false);
  padded.set(new Uint8Array(lengthView.buffer), paddedLength - 8);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  for (let blockOffset = 0; blockOffset < padded.length; blockOffset += 64) {
    const w = new Array(64).fill(0);
    for (let index = 0; index < 16; index += 1) {
      const start = blockOffset + index * 4;
      w[index] = ((padded[start] << 24) | (padded[start + 1] << 16) | (padded[start + 2] << 8) | padded[start + 3]) >>> 0;
    }

    for (let index = 16; index < 64; index += 1) {
      const s0 = (rotr32(w[index - 15], 7) ^ rotr32(w[index - 15], 18) ^ (w[index - 15] >>> 3)) >>> 0;
      const s1 = (rotr32(w[index - 2], 17) ^ rotr32(w[index - 2], 19) ^ (w[index - 2] >>> 10)) >>> 0;
      w[index] = (w[index - 16] + s0 + w[index - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let index = 0; index < 64; index += 1) {
      const t1 = (h + sha256Sum1(e) + sha256Ch(e, f, g) + SHA256_K[index] + w[index]) >>> 0;
      const t2 = (sha256Sum0(a) + sha256Maj(a, b, c)) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const digest = new Uint8Array(32);
  const words = [h0, h1, h2, h3, h4, h5, h6, h7];
  for (let index = 0; index < words.length; index += 1) {
    const value = words[index] >>> 0;
    digest[index * 4] = (value >>> 24) & 0xff;
    digest[index * 4 + 1] = (value >>> 16) & 0xff;
    digest[index * 4 + 2] = (value >>> 8) & 0xff;
    digest[index * 4 + 3] = value & 0xff;
  }
  return digest;
}

function laneIndex(x, y) {
  return x + 5 * y;
}

export function keccakF1600(state) {
  const lanes = [...state];
  for (let round = 0; round < 24; round += 1) {
    const c = new Array(5).fill(0n);
    for (let x = 0; x < 5; x += 1) {
      c[x] = lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20];
    }

    const d = new Array(5).fill(0n);
    for (let x = 0; x < 5; x += 1) {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1n);
    }

    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        lanes[laneIndex(x, y)] ^= d[x];
      }
    }

    const b = new Array(KECCAK_LANES).fill(0n);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const index = laneIndex(x, y);
        const rotated = rotl64(lanes[index], ROTATION[x][y]);
        const target = laneIndex(y, (2 * x + 3 * y) % 5);
        b[target] = rotated;
      }
    }

    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const index = laneIndex(x, y);
        const plusOne = laneIndex((x + 1) % 5, y);
        const plusTwo = laneIndex((x + 2) % 5, y);
        lanes[index] = b[index] ^ (~b[plusOne] & b[plusTwo] & MASK64);
      }
    }

    lanes[0] ^= ROUND_CONSTANTS[round];
  }

  return lanes;
}

function absorbState(data, suffixByte) {
  const state = new Array(25).fill(0n);
  const maxLength = Math.max(1, SHAKE_RATE_BYTES);
  const padded = new Uint8Array(data.length + maxLength);
  padded.set(data, 0);
  const offset = data.length % SHAKE_RATE_BYTES;
  const suffix = Number(BigInt(suffixByte) & 0xffn);
  padded[offset] ^= suffix;
  padded[SHAKE_RATE_BYTES - 1] ^= 0x80;

  for (let index = 0; index < padded.length; index += SHAKE_RATE_BYTES) {
    const block = padded.slice(index, index + SHAKE_RATE_BYTES);
    for (let laneIndex = 0; laneIndex < SHAKE_RATE_BYTES; laneIndex += 8) {
      const lane = bytesToLaneLittleEndian(block.slice(laneIndex, laneIndex + 8));
      state[laneIndex / 8] ^= lane;
    }
    const nextState = keccakF1600(state);
    state.splice(0, state.length, ...nextState);
  }

  return state;
}

function squeezeState(state, outputLength) {
  const output = new Uint8Array(outputLength);
  let offset = 0;
  let currentState = [...state];

  while (offset < outputLength) {
    for (let index = 0; index < SHAKE_RATE_BYTES && offset < outputLength; index += 1) {
      const laneIndex = Math.floor(index / 8);
      const byteInLane = index % 8;
      const lane = currentState[laneIndex];
      output[offset] = Number((lane >> (BigInt(byteInLane) * 8n)) & 0xffn);
      offset += 1;
    }
    if (offset < outputLength) {
      currentState = keccakF1600(currentState);
    }
  }

  return output;
}

export function shake128(data, outputLength) {
  if (nativeCrypto) {
    return new Uint8Array(nativeCrypto.createHash("shake128").update(toUint8Array(data)).digest(outputLength));
  }

  const state = absorbState(toUint8Array(data), 0x1fn);
  return squeezeState(state, outputLength);
}

export function shake256(data, outputLength) {
  if (nativeCrypto) {
    return new Uint8Array(nativeCrypto.createHash("shake256").update(toUint8Array(data)).digest(outputLength));
  }

  const state = absorbState(toUint8Array(data), 0x1fn);
  return squeezeState(state, outputLength);
}

export function keccak256(data) {
  if (nativeCrypto) {
    return new Uint8Array(nativeCrypto.createHash("sha3-256").update(toUint8Array(data)).digest());
  }

  const state = absorbState(toUint8Array(data), 0x01);
  return squeezeState(state, 32);
}

export function keccakBytes(data, outputLength) {
  return shake128(data, outputLength);
}
