const app = {
  state: {
    params: {},
    history: mlkemStorage.loadHistory(),
    keys: mlkemStorage.loadKeys(),
  },
};

function addHistory(entry) {
  app.state.history.unshift(entry);
  app.state.history = app.state.history.slice(0, 10);
  mlkemStorage.saveHistory(app.state.history);
  renderHistory(app.state.history);
}

function syncKeysToStorage() {
  const ek = document.getElementById("public-key").value.trim();
  const dk = document.getElementById("private-key").value.trim();
  const variant = document.getElementById("variant-select").value;
  const payload = { ek, dk, variant };
  mlkemStorage.saveKeys(payload);
  renderStoredKeys(payload);
}

async function loadParams() {
  try {
    const params = await mlkemApi.params();
    app.state.params = params;
    const select = document.getElementById("variant-select");
    select.innerHTML = Object.keys(params)
      .filter((name) => name !== "sizes")
      .map((name) => `<option value="${name}">${name}</option>`)
      .join("");

    const savedVariant = app.state.keys.variant || "ML-KEM-768";
    if (Object.hasOwn(params, savedVariant)) {
      select.value = savedVariant;
    }
    setStatus("Paramètres chargés.", "info");
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function generateKeys() {
  const variant = document.getElementById("variant-select").value;
  try {
    const payload = await mlkemApi.keygen(variant);
    document.getElementById("public-key").value = payload.ek;
    document.getElementById("private-key").value = payload.dk;
    document.getElementById("encaps-pubkey").value = payload.ek;
    document.getElementById("decaps-privkey").value = payload.dk;
    const keys = { ek: payload.ek, dk: payload.dk, variant };
    mlkemStorage.saveKeys(keys);
    renderStoredKeys(keys);
    setStatus(`Clés générées pour ${variant}.`, "success");
    addHistory(`Clés générées (${variant})`);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function encapsulate() {
  const variant = document.getElementById("variant-select").value;
  const ek = document.getElementById("encaps-pubkey").value.trim();
  const publicKeyInput = document.getElementById("public-key");
  const privateKeyInput = document.getElementById("private-key");
  try {
    const payload = await mlkemApi.encaps(ek, variant);
    document.getElementById("ciphertext").value = payload.c;
    document.getElementById("shared-secret-a").value = payload.K;
    document.getElementById("decaps-ciphertext").value = payload.c;
    if (publicKeyInput && !publicKeyInput.value.trim()) publicKeyInput.value = ek;
    if (privateKeyInput && !privateKeyInput.value.trim()) privateKeyInput.value = "";
    setStatus("Session encapsulée avec succès.", "success");
    addHistory(`Encapsulation (${variant})`);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function decapsulate() {
  const variant = document.getElementById("variant-select").value;
  const dk = document.getElementById("decaps-privkey").value.trim();
  const c = document.getElementById("decaps-ciphertext").value.trim();
  try {
    const payload = await mlkemApi.decaps(dk, c, variant);
    document.getElementById("shared-secret-b").value = payload.K;
    setStatus("Décapsulation réussie.", "success");
    addHistory(`Décapsulation (${variant})`);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

function bindEvents() {
  document.getElementById("refresh-params").addEventListener("click", loadParams);
  document.getElementById("generate-keys").addEventListener("click", generateKeys);
  document.getElementById("encapsulate").addEventListener("click", encapsulate);
  document.getElementById("decapsulate").addEventListener("click", decapsulate);

  ["public-key", "private-key"].forEach((id) => {
    document.getElementById(id).addEventListener("input", syncKeysToStorage);
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  syncFromStorage();
  await loadParams();
  renderStoredKeys(app.state.keys);
  renderHistory(app.state.history);
});
