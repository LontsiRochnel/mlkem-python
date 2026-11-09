"""Serveur HTTP pédagogique pour exposer l'API ML-KEM.

Le serveur ne stocke pas d'état et appelle uniquement l'API publique de
`mlkem`, sans modifier le comportement des modules mathématiques ou de
cryptographie déjà présents. Il sert uniquement à exposer ML-KEM sur HTTP pour
l'enseignement et les tests.

Remarque de sécurité : dans un déploiement réel, la clé privée `dk` ne doit
jamais être envoyée à un serveur sans protection. Cette exposition HTTP est
strictement pédagogique et sans TLS ni authentification.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from . import decaps, encaps, keygen
from .errors import InvalidCiphertextError, InvalidKeyError, InvalidSizeError
from .params import (
    CT_SIZE,
    DK_SIZE,
    EK_SIZE,
    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024,
    SS_SIZE,
    VARIANTS,
)

LOGGER = logging.getLogger(__name__)
MAX_BODY_SIZE = 16 * 1024


class HTTPJSONError(Exception):
    """Erreur de requête HTTP sérialisable en JSON."""

    def __init__(self, status_code: int, message: str, error_type: str):
        self.status_code = status_code
        self.message = message
        self.error_type = error_type


def _b64encode(data: bytes) -> str:
    """Encode des octets en base64 standard."""
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: Any, field_name: str) -> bytes:
    """Décode une entrée Base64 standard dédiée au JSON HTTP."""
    if not isinstance(value, str):
        raise HTTPJSONError(
            400, f"field '{field_name}' must be a base64 string", "ValueError"
        )
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise HTTPJSONError(
            400, f"field '{field_name}' is not valid base64", "ValueError"
        ) from exc


def _read_json_object(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    """Lit un corps JSON et vérifie qu'il s'agit d'un objet JSON valide."""
    if handler.headers.get("Content-Length") is None:
        raise HTTPJSONError(
            411,
            "Content-Length header is required for POST requests",
            "MissingContentLength",
        )
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError as exc:
        raise HTTPJSONError(
            400, "Content-Length header is invalid", "ValueError"
        ) from exc
    if length > MAX_BODY_SIZE:
        raise HTTPJSONError(413, "request body exceeds 16 KiB", "PayloadTooLarge")
    raw = handler.rfile.read(length)
    if not raw:
        raise HTTPJSONError(400, "request body is empty", "ValueError")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPJSONError(
            400, "request body is not valid JSON", "ValueError"
        ) from exc
    if not isinstance(payload, dict):
        raise HTTPJSONError(400, "JSON body must be an object", "ValueError")
    return payload


class MLKEMHTTPHandler(BaseHTTPRequestHandler):
    """Handler HTTP pour exposer les fonctions publiques ML-KEM.

    Route attendue : `POST /v1/keygen`, `POST /v1/encaps`, `POST /v1/decaps`.
    Le corps est un objet JSON et les octets sont encodés en base64 standard.
    Les codes d'erreur possibles sont 400, 404, 405, 411, 413 et 500.
    """

    server_version = "mlkem-http/0.1.0"

    def do_GET(self) -> None:  # noqa: N802
        """Traite une requête HTTP GET.

        Routes supportées : `/health`, `/v1/params` et les fichiers statiques du
        dossier `web/`. Les codes de succès sont 200. Les erreurs renvoient un
        objet JSON avec `error` et `type`.
        """
        try:
            if self.path in {"/v1/keygen", "/v1/encaps", "/v1/decaps"}:
                self._send_json_error(
                    405, "method not allowed", "MethodNotAllowed", allow="POST"
                )
                return
            if self.path == "/health":
                self._send_json({"status": "ok"}, status_code=200)
                return
            if self.path == "/v1/params":
                self._send_json(_params_payload(), status_code=200)
                return
            static_file = _resolve_static_file(self.path)
            if static_file is not None:
                self._send_static_file(static_file)
                return
            raise HTTPJSONError(404, "route not found", "NotFound")
        except HTTPJSONError as exc:
            self._send_json_error(
                exc.status_code,
                exc.message,
                exc.error_type,
                allow=getattr(exc, "allow", None),
            )
        except Exception:  # pragma: no cover - guard against unexpected errors
            LOGGER.exception("Unhandled GET error")
            self._send_json_error(500, "internal server error", "InternalServerError")

    def do_POST(self) -> None:  # noqa: N802
        """Traite une requête HTTP POST.

        En entrée, le corps JSON contient des champs de type `variant`, `ek`, `dk`
        ou `c`. Les octets sont représentés en base64. Les réponses sont en JSON
        avec les mêmes données encodées en base64.
        """
        try:
            if self.path in {"/health", "/v1/params"}:
                self._send_json_error(
                    405, "method not allowed", "MethodNotAllowed", allow="GET"
                )
                return
            if self.path == "/v1/keygen":
                payload = _read_json_object(self)
                variant = payload.get("variant", "ML-KEM-768")
                if not isinstance(variant, str):
                    raise HTTPJSONError(
                        400, "field 'variant' must be a string", "ValueError"
                    )
                ek, dk = keygen(variant)
                self._send_json(
                    {"ek": _b64encode(ek), "dk": _b64encode(dk)}, status_code=200
                )
                return
            if self.path == "/v1/encaps":
                payload = _read_json_object(self)
                ek_b64 = payload.get("ek")
                if ek_b64 is None:
                    raise HTTPJSONError(400, "missing field 'ek'", "ValueError")
                variant = payload.get("variant")
                ek = _b64decode(ek_b64, "ek")
                K, c = encaps(ek, variant)
                self._send_json(
                    {"K": _b64encode(K), "c": _b64encode(c)}, status_code=200
                )
                return
            if self.path == "/v1/decaps":
                payload = _read_json_object(self)
                dk_b64 = payload.get("dk")
                c_b64 = payload.get("c")
                if dk_b64 is None:
                    raise HTTPJSONError(400, "missing field 'dk'", "ValueError")
                if c_b64 is None:
                    raise HTTPJSONError(400, "missing field 'c'", "ValueError")
                variant = payload.get("variant")
                dk = _b64decode(dk_b64, "dk")
                c = _b64decode(c_b64, "c")
                K = decaps(dk, c, variant)
                self._send_json({"K": _b64encode(K)}, status_code=200)
                return
            raise HTTPJSONError(404, "route not found", "NotFound")
        except InvalidSizeError as exc:
            self._send_json_error(400, str(exc), "InvalidSizeError")
        except InvalidKeyError as exc:
            self._send_json_error(400, str(exc), "InvalidKeyError")
        except InvalidCiphertextError as exc:
            self._send_json_error(400, str(exc), "InvalidCiphertextError")
        except HTTPJSONError as exc:
            self._send_json_error(
                exc.status_code,
                exc.message,
                exc.error_type,
                allow=getattr(exc, "allow", None),
            )
        except Exception:  # pragma: no cover - guard against unexpected errors
            LOGGER.exception("Unhandled POST error")
            self._send_json_error(500, "internal server error", "InternalServerError")

    def do_DELETE(self) -> None:  # noqa: N802
        """Retourne une erreur HTTP par défaut pour une méthode non supportée."""
        self._send_json_error(
            405, "method not allowed", "MethodNotAllowed", allow="GET, POST"
        )

    def do_PUT(self) -> None:  # noqa: N802
        """Retourne une erreur HTTP par défaut pour une méthode non supportée."""
        self._send_json_error(
            405, "method not allowed", "MethodNotAllowed", allow="GET, POST"
        )

    def do_PATCH(self) -> None:  # noqa: N802
        """Retourne une erreur HTTP par défaut pour une méthode non supportée."""
        self._send_json_error(
            405, "method not allowed", "MethodNotAllowed", allow="GET, POST"
        )

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        """Journalise uniquement la méthode, la route et le code HTTP retourné."""
        code = args[1] if len(args) >= 2 else "-"
        LOGGER.info("%s %s -> %s", self.command, self.path, code)

    def _send_json(self, payload: dict[str, Any], status_code: int) -> None:
        """Envoie un objet JSON avec le bon en-tête HTTP."""
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_static_file(self, file_path: Path) -> None:
        """Envoie un fichier statique avec le bon type MIME."""
        suffix = file_path.suffix.lower()
        mime_types = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
        }
        content_type = mime_types.get(suffix, "application/octet-stream")
        content = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_json_error(
        self,
        status_code: int,
        message: str,
        error_type: str,
        allow: str | None = None,
    ) -> None:
        """Envoie une réponse JSON structurée pour une erreur HTTP."""
        payload = {"error": message, "type": error_type}
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status_code)
        if allow is not None:
            self.send_header("Allow", allow)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _params_payload() -> dict[str, Any]:
    """Construit le payload de paramètres public pour `/v1/params`."""
    payload: dict[str, Any] = {}
    for name in (ML_KEM_512, ML_KEM_768, ML_KEM_1024):
        params = VARIANTS[name]
        payload[name] = {
            "k": params["k"],
            "eta1": params["eta1"],
            "eta2": params["eta2"],
            "du": params["du"],
            "dv": params["dv"],
            "ek_size": params["ek_size"],
            "dk_size": params["dk_size"],
            "ct_size": params["ct_size"],
            "ss_size": SS_SIZE,
        }
    payload["sizes"] = {
        "EK_SIZE": EK_SIZE,
        "DK_SIZE": DK_SIZE,
        "CT_SIZE": CT_SIZE,
        "SS_SIZE": SS_SIZE,
    }
    return payload


def _static_root() -> Path:
    """Retourne le dossier racine des fichiers statiques du projet."""
    return (Path(__file__).resolve().parent.parent / "web").resolve()


def _resolve_static_file(request_path: str) -> Path | None:
    """Résout un chemin statique sans permettre le parcours de répertoire."""
    root = _static_root()
    raw_path = unquote(urlsplit(request_path).path)
    if raw_path in {"", "/"}:
        return root / "index.html"
    relative = raw_path.lstrip("/")
    if not relative:
        return root / "index.html"
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate


def create_server(host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    """Crée le serveur HTTP en mode multithreadé pour le projet pédagogique."""
    return ThreadingHTTPServer((host, port), MLKEMHTTPHandler)


def main(argv: list[str] | None = None) -> None:
    """Point d'entrée CLI pour lancer le serveur HTTP ML-KEM.

    Args:
        argv (list[str] | None): arguments de ligne de commande.

    Returns:
        None: le serveur tourne jusqu'à arrêt manuel.

    Correspondance FIPS 203 : aucune ; le serveur n'implémente pas un
    algorithme cryptographique, il délègue uniquement aux fonctions publiques de
    l'API ML-KEM.
    """
    parser = argparse.ArgumentParser(description="Serveur HTTP pédagogique pour ML-KEM")
    parser.add_argument(
        "--host", default="127.0.0.1", help="hostname à écouter, par défaut 127.0.0.1"
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="port TCP à écouter, par défaut 8000"
    )
    args = parser.parse_args(argv)

    if args.host == "0.0.0.0":
        print(
            "[WARNING] 0.0.0.0 binds the server on all network interfaces; this is only for local testing. No TLS or authentication is enabled."
        )

    server = create_server(args.host, args.port)
    print(f"Serving ML-KEM on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping ML-KEM server")
    finally:
        server.server_close()
