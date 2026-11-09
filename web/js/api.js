import { DEFAULT_VARIANT, keygen, encaps, decaps, getVariantParams } from "./mlkem/index.js";

const mlkemApi = {
  async params() {
    const variants = {};
    for (const [name, params] of Object.entries(
      getVariantParams("ML-KEM-768")
        ? {
            "ML-KEM-512": getVariantParams("ML-KEM-512"),
            "ML-KEM-768": getVariantParams("ML-KEM-768"),
            "ML-KEM-1024": getVariantParams("ML-KEM-1024"),
          }
        : {},
    )) {
      variants[name] = params;
    }
    return variants;
  },

  async keygen(variant = DEFAULT_VARIANT) {
    return keygen(variant);
  },

  async encaps(ek, variant = DEFAULT_VARIANT) {
    return encaps(ek, variant);
  },

  async decaps(dk, c, variant = DEFAULT_VARIANT) {
    return decaps(dk, c, variant);
  },
};

window.mlkemApi = mlkemApi;
window.mlkem = { ...mlkemApi };
