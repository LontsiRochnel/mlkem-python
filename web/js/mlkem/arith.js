import { Q, ZETA } from "./params.js";

export function reduceQ(value) {
  return ((value % Q) + Q) % Q;
}

function modInverse(value, modulus) {
  let a = BigInt(value) % BigInt(modulus);
  let m = BigInt(modulus);
  let x = 0n;
  let y = 1n;
  if (m === 1n) {
    return 0n;
  }
  while (a > 1n) {
    const q = a / m;
    let t = m;
    m = a % m;
    a = t;
    t = x;
    x = y - q * x;
    y = t;
  }
  return y < 0n ? y + BigInt(modulus) : y;
}

function powMod(base, exponent, modulus) {
  let result = 1n;
  let current = BigInt(base) % BigInt(modulus);
  let exp = BigInt(exponent);
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * current) % BigInt(modulus);
    }
    current = (current * current) % BigInt(modulus);
    exp >>= 1n;
  }
  return result;
}

export function ntt(poly) {
  const a = poly.map((value) => reduceQ(value));
  const n = a.length;
  let j = 0;

  for (let i = 1; i < n; i += 1) {
    let bit = n >> 1;
    while (j & bit) {
      j ^= bit;
      bit >>= 1;
    }
    j ^= bit;
    if (i < j) {
      const tmp = a[i];
      a[i] = a[j];
      a[j] = tmp;
    }
  }

  let size = 2;
  while (size <= n) {
    const half = size >> 1;
    const wlen = powMod(ZETA, Math.floor((Q - 1) / size), Q);
    for (let i = 0; i < n; i += size) {
      let w = 1n;
      for (let j = 0; j < half; j += 1) {
        const u = BigInt(a[i + j]);
        const v = (BigInt(a[i + j + half]) * w) % BigInt(Q);
        a[i + j] = Number((u + v) % BigInt(Q));
        a[i + j + half] = Number((u - v + BigInt(Q)) % BigInt(Q));
        w = (w * wlen) % BigInt(Q);
      }
    }
    size <<= 1;
  }
  return a;
}

export function nttInverse(poly) {
  const a = poly.map((value) => reduceQ(value));
  const n = a.length;
  let j = 0;

  for (let i = 1; i < n; i += 1) {
    let bit = n >> 1;
    while (j & bit) {
      j ^= bit;
      bit >>= 1;
    }
    j ^= bit;
    if (i < j) {
      const tmp = a[i];
      a[i] = a[j];
      a[j] = tmp;
    }
  }

  let size = 2;
  while (size <= n) {
    const half = size >> 1;
    const inverseZeta = modInverse(ZETA, Q);
    const wlen = powMod(inverseZeta, Math.floor((Q - 1) / size), Q);
    for (let i = 0; i < n; i += size) {
      let w = 1n;
      for (let j = 0; j < half; j += 1) {
        const u = BigInt(a[i + j]);
        const v = (BigInt(a[i + j + half]) * w) % BigInt(Q);
        a[i + j] = Number((u + v) % BigInt(Q));
        a[i + j + half] = Number((u - v + BigInt(Q)) % BigInt(Q));
        w = (w * wlen) % BigInt(Q);
      }
    }
    size <<= 1;
  }

  const invN = modInverse(n, Q);
  return a.map((value) => Number((BigInt(value) * invN) % BigInt(Q)));
}

export function pointwiseMultiply(a, b) {
  if (a.length !== b.length) {
    throw new Error("longueurs incompatibles pour la multiplication point par point");
  }
  return a.map((value, index) => (((value * b[index]) % Q) + Q) % Q);
}
