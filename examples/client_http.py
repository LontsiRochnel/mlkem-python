"""Client HTTP pédagogique pour Alice et Bob via le serveur ML-KEM.

Le script appelle l'API HTTP exposée par le serveur local et montre le flux
Alice/Bob sans exposer la logique de chiffrement interne.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request

SERVER_URL = "http://127.0.0.1:8000"


def http_json(method: str, path: str, payload: dict | None = None) -> dict:
    """Envoie une requête JSON vers le serveur HTTP local."""
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        f"{SERVER_URL}{path}", data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            error_json = json.loads(body)
            raise RuntimeError(
                f"HTTP {exc.code}: {error_json.get('error', 'unknown error')}"
            ) from exc
        except json.JSONDecodeError:
            raise RuntimeError(f"HTTP {exc.code}: {body}") from exc


def main() -> None:
    """Démontre le scénario complet Alice/Bob via HTTP."""
    print("[Bob] Génération de la paire de clés")
    keygen_response = http_json("POST", "/v1/keygen", {"variant": "ML-KEM-768"})
    ek = base64.b64decode(keygen_response["ek"])
    dk = base64.b64decode(keygen_response["dk"])
    print(f"[Bob] ek={len(ek)} octets, dk={len(dk)} octets")

    print("[Alice] Encapsulation du secret partagé")
    enc_response = http_json(
        "POST", "/v1/encaps", {"ek": keygen_response["ek"], "variant": "ML-KEM-768"}
    )
    K_a = base64.b64decode(enc_response["K"])
    c = base64.b64decode(enc_response["c"])
    print(f"[Alice] K_A={len(K_a)} octets, c={len(c)} octets")

    print("[Bob] Décapsulation du secret partagé")
    dec_response = http_json(
        "POST",
        "/v1/decaps",
        {"dk": keygen_response["dk"], "c": enc_response["c"], "variant": "ML-KEM-768"},
    )
    K_b = base64.b64decode(dec_response["K"])
    print(f"[Bob] K_B={len(K_b)} octets")

    print(f"[Resultat] K_A == K_B ? {K_a == K_b}")
    print(
        "[Note] Ensuite, K sert de clé symétrique pour un chiffrement symétrique ou un AEAD."
    )


if __name__ == "__main__":
    main()
