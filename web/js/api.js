async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let payload = {};
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (error) {
      payload = { error: text };
    }
  }

  if (!response.ok) {
    const message = payload.error || payload.message || "Erreur serveur";
    throw new Error(message);
  }

  return payload;
}

const mlkemApi = {
  async params() {
    return fetchJson("/v1/params");
  },

  async keygen(variant = "ML-KEM-768") {
    return fetchJson("/v1/keygen", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ variant }),
    });
  },

  async encaps(ek, variant = "ML-KEM-768") {
    return fetchJson("/v1/encaps", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ek, variant }),
    });
  },

  async decaps(dk, c, variant = "ML-KEM-768") {
    return fetchJson("/v1/decaps", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ dk, c, variant }),
    });
  },
};
