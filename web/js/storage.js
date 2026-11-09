const mlkemStorage = (() => {
  const KEYS_KEY = "mlkem.keys";
  const HISTORY_KEY = "mlkem.history";

  function safeRead(key, fallback) {
    try {
      const raw = window.sessionStorage.getItem(key);
      if (raw === null) return fallback;
      return JSON.parse(raw);
    } catch (error) {
      window.sessionStorage.removeItem(key);
      return fallback;
    }
  }

  function safeWrite(key, value) {
    try {
      window.sessionStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
      console.warn("sessionStorage unavailable", error);
    }
  }

  function loadKeys() {
    return safeRead(KEYS_KEY, {});
  }

  function saveKeys(value) {
    safeWrite(KEYS_KEY, value);
  }

  function loadHistory() {
    return safeRead(HISTORY_KEY, []);
  }

  function saveHistory(value) {
    safeWrite(HISTORY_KEY, value);
  }

  return {
    loadKeys,
    saveKeys,
    loadHistory,
    saveHistory,
  };
})();
