export const Q = 3329;
export const N = 256;
export const ZETA = 17;

export const ML_KEM_512 = "ML-KEM-512";
export const ML_KEM_768 = "ML-KEM-768";
export const ML_KEM_1024 = "ML-KEM-1024";

export const VARIANTS = {
  [ML_KEM_512]: {
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
    ek_size: 800,
    dk_size: 1632,
    ct_size: 768,
  },
  [ML_KEM_768]: {
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
    ek_size: 1184,
    dk_size: 2400,
    ct_size: 1088,
  },
  [ML_KEM_1024]: {
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
    ek_size: 1568,
    dk_size: 3168,
    ct_size: 1568,
  },
};

export const SS_SIZE = 32;
export const EK_SIZE = {
  [ML_KEM_512]: 800,
  [ML_KEM_768]: 1184,
  [ML_KEM_1024]: 1568,
};
export const DK_SIZE = {
  [ML_KEM_512]: 1632,
  [ML_KEM_768]: 2400,
  [ML_KEM_1024]: 3168,
};
export const CT_SIZE = {
  [ML_KEM_512]: 768,
  [ML_KEM_768]: 1088,
  [ML_KEM_1024]: 1568,
};

export function getVariantParams(variant) {
  if (!(variant in VARIANTS)) {
    throw new Error(`variante inconnue: ${variant}`);
  }
  return VARIANTS[variant];
}

export function detectVariantByEk(ek) {
  const size = ek.length;
  for (const [name, params] of Object.entries(VARIANTS)) {
    if (params.ek_size === size) {
      return name;
    }
  }
  throw new Error("taille de clé publique inconnue");
}

export function detectVariantByDk(dk) {
  const size = dk.length;
  for (const [name, params] of Object.entries(VARIANTS)) {
    if (params.dk_size === size) {
      return name;
    }
  }
  throw new Error("taille de clé privée inconnue");
}

export const DEFAULT_VARIANT = ML_KEM_768;
