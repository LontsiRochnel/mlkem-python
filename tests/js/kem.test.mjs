import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { ML_KEM, keygenInternal, encapsInternal, decaps, ntt, nttInverse, getVariantParams } from "../../web/js/mlkem/index.js";

const fixtures = JSON.parse(readFileSync(new URL("./fixtures.json", import.meta.url), "utf8"));

const VARIANTS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];

function hexToBytes(hex) {
  return Uint8Array.from(hex.match(/.{1,2}/g).map((value) => Number.parseInt(value, 16)));
}

function bytesToHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

test("tailles des clés pour les trois variantes", () => {
  for (const variant of VARIANTS) {
    const params = getVariantParams(variant);
    assert.equal(params.ek_size, fixtures[variant].ek.length / 2);
    assert.equal(params.dk_size, fixtures[variant].dk.length / 2);
    assert.equal(params.ct_size, fixtures[variant].c.length / 2);
  }
});

test("aller-retour keygen encaps decaps", () => {
  for (const variant of VARIANTS) {
    const { d, z, m } = fixtures[variant];
    const { ek, dk } = keygenInternal(hexToBytes(d), hexToBytes(z), variant);
    const { c, K: K_a } = encapsInternal(ek, hexToBytes(m), variant);
    const { K: K_b } = decaps(dk, c, variant);
    assert.equal(bytesToHex(K_a), bytesToHex(K_b));
  }
});

test("rejet implicite modifie le secret", () => {
  for (const variant of VARIANTS) {
    const { d, z, m } = fixtures[variant];
    const { ek, dk } = keygenInternal(hexToBytes(d), hexToBytes(z), variant);
    const { c, K } = encapsInternal(ek, hexToBytes(m), variant);
    const tampered = new Uint8Array(c);
    tampered[0] ^= 0x01;
    const { K: K2 } = decaps(dk, tampered, variant);
    assert.notEqual(bytesToHex(K), bytesToHex(K2));
  }
});

test("NTT suivie de la NTT inverse redonne le polynôme initial", () => {
  const poly = Array.from({ length: 256 }, (_, index) => index % 3329);
  const recovered = nttInverse(ntt(poly));
  assert.deepEqual(recovered, poly);
});

test("fixtures Python et JavaScript produisent les mêmes ek, dk, c et K", () => {
  for (const variant of VARIANTS) {
    const entry = fixtures[variant];
    const { ek, dk } = keygenInternal(hexToBytes(entry.d), hexToBytes(entry.z), variant);
    const { c, K } = encapsInternal(ek, hexToBytes(entry.m), variant);
    assert.equal(bytesToHex(ek), entry.ek);
    assert.equal(bytesToHex(dk), entry.dk);
    assert.equal(bytesToHex(c), entry.c);
    assert.equal(bytesToHex(K), entry.K);
  }
});
