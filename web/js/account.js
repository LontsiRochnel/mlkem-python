document.addEventListener("DOMContentLoaded", () => {
  const keys = mlkemStorage.loadKeys();
  const history = mlkemStorage.loadHistory();

  const keysNode = document.getElementById("account-keys");
  const historyNode = document.getElementById("account-history");

  if (!keys || !keys.ek || !keys.dk) {
    keysNode.textContent = "Aucune clé pour le moment.";
  } else {
    keysNode.textContent = JSON.stringify(
      {
        variant: keys.variant || "ML-KEM-768",
        ek: keys.ek.slice(0, 40) + (keys.ek.length > 40 ? "…" : ""),
        dk: keys.dk.slice(0, 40) + (keys.dk.length > 40 ? "…" : ""),
      },
      null,
      2,
    );
  }

  if (!history.length) {
    historyNode.innerHTML = "<li>Aucun événement récent.</li>";
  } else {
    historyNode.innerHTML = history
      .slice(0, 10)
      .map((item) => `<li>${item}</li>`)
      .join("");
  }
});
