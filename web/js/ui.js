function setStatus(message, tone = "info") {
  const statusNode = document.getElementById("status");
  if (!statusNode) return;
  statusNode.textContent = message;
  statusNode.className = `status ${tone}`;
}

function renderStoredKeys(keys) {
  const container = document.getElementById("stored-keys");
  if (!container) return;
  if (!keys || !keys.ek || !keys.dk) {
    container.textContent = "Aucune clé pour le moment.";
    return;
  }

  container.textContent = JSON.stringify(
    {
      variant: keys.variant || "ML-KEM-768",
      ek: keys.ek.slice(0, 40) + (keys.ek.length > 40 ? "…" : ""),
      dk: keys.dk.slice(0, 40) + (keys.dk.length > 40 ? "…" : ""),
    },
    null,
    2,
  );
}

function renderHistory(history) {
  const list = document.getElementById("history-list");
  if (!list) return;
  if (!history.length) {
    list.innerHTML = "<li>Aucun événement récent.</li>";
    return;
  }

  list.innerHTML = history
    .slice(0, 10)
    .map((item) => `<li>${item}</li>`)
    .join("");
}

function syncFromStorage() {
  const keys = window.mlkemStorage.loadKeys();
  const history = window.mlkemStorage.loadHistory();
  const publicKey = document.getElementById("public-key");
  const privateKey = document.getElementById("private-key");
  const encapsPub = document.getElementById("encaps-pubkey");
  const decapsPriv = document.getElementById("decaps-privkey");

  if (publicKey && keys.ek) publicKey.value = keys.ek;
  if (privateKey && keys.dk) privateKey.value = keys.dk;
  if (encapsPub && keys.ek) encapsPub.value = keys.ek;
  if (decapsPriv && keys.dk) decapsPriv.value = keys.dk;

  renderStoredKeys(keys);
  renderHistory(history);
}
