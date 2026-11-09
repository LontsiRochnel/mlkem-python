const app = {
  state: {
    params: {},
    history: window.mlkemStorage.loadHistory(),
    keys: window.mlkemStorage.loadKeys(),
  },
};

function bytesToText(value) {
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  return Base64.bytesToBase64(value);
}

function textToBytes(value) {
  const raw = String(value ?? "").trim();
  if (!raw) {
    return new Uint8Array();
  }
  return Base64.base64ToBytes(raw);
}

function addHistory(entry) {
  app.state.history.unshift(entry);
  app.state.history = app.state.history.slice(0, 10);
  window.mlkemStorage.saveHistory(app.state.history);
  renderHistory(app.state.history);
}

function syncKeysToStorage() {
  const ek = document.getElementById("public-key").value.trim();
  const dk = document.getElementById("private-key").value.trim();
  const variant = document.getElementById("variant-select").value;
  const payload = { ek, dk, variant };
  window.mlkemStorage.saveKeys(payload);
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
    const ekText = bytesToText(payload.ek);
    const dkText = bytesToText(payload.dk);
    document.getElementById("public-key").value = ekText;
    document.getElementById("private-key").value = dkText;

    const encapsPubKey = document.getElementById("encaps-pubkey");
    const decapsPrivKey = document.getElementById("decaps-privkey");
    if (encapsPubKey) encapsPubKey.value = ekText;
    if (decapsPrivKey) decapsPrivKey.value = dkText;

    const keys = { ek: ekText, dk: dkText, variant };
    window.mlkemStorage.saveKeys(keys);
    app.state.keys = keys;
    renderStoredKeys(keys);
    setStatus(`Clés générées pour ${variant}.`, "success");
    addHistory(`Clés générées (${variant})`);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function encapsulate() {
  const variant = document.getElementById("variant-select")?.value || app.state.keys.variant || "ML-KEM-768";
  const ek = textToBytes(document.getElementById("encaps-pubkey").value);
  const publicKeyInput = document.getElementById("public-key");
  const privateKeyInput = document.getElementById("private-key");
  try {
    const payload = await mlkemApi.encaps(ek, variant);
    document.getElementById("ciphertext").value = bytesToText(payload.c);
    document.getElementById("shared-secret-a").value = bytesToText(payload.K);
    document.getElementById("decaps-ciphertext").value = bytesToText(payload.c);
    if (publicKeyInput && !publicKeyInput.value.trim()) publicKeyInput.value = bytesToText(ek);
    if (privateKeyInput && !privateKeyInput.value.trim()) privateKeyInput.value = "";
    setStatus("Session encapsulée avec succès.", "success");
    addHistory(`Encapsulation (${variant})`);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function decapsulate() {
  const variant = document.getElementById("variant-select")?.value || app.state.keys.variant || "ML-KEM-768";
  const dk = textToBytes(document.getElementById("decaps-privkey").value);
  const c = textToBytes(document.getElementById("decaps-ciphertext").value);
  try {
    const payload = await mlkemApi.decaps(dk, c, variant);
    document.getElementById("shared-secret-b").value = bytesToText(payload.K);
    setStatus("Décapsulation réussie.", "success");
    addHistory(`Décapsulation (${variant})`);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

function bindEvents() {
  const refreshParamsButton = document.getElementById("refresh-params");
  if (refreshParamsButton) {
    refreshParamsButton.addEventListener("click", loadParams);
  }

  const generateKeysButton = document.getElementById("generate-keys");
  if (generateKeysButton) {
    generateKeysButton.addEventListener("click", generateKeys);
  }

  const encapsulateButton = document.getElementById("encapsulate");
  if (encapsulateButton) {
    encapsulateButton.addEventListener("click", encapsulate);
  }

  const decapsulateButton = document.getElementById("decapsulate");
  if (decapsulateButton) {
    decapsulateButton.addEventListener("click", decapsulate);
  }

  ["public-key", "private-key"].forEach((id) => {
    const input = document.getElementById(id);
    if (input) {
      input.addEventListener("input", syncKeysToStorage);
    }
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  syncFromStorage();
  await loadParams();
  renderStoredKeys(app.state.keys);
  renderHistory(app.state.history);
});
