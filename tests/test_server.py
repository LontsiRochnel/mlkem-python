"""Tests du serveur HTTP ML-KEM."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

from mlkem.server import create_server


def _request_json(method: str, url: str, payload: dict | None = None):
    """Fait une requête HTTP et retourne un objet JSON si possible."""
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8")
            return response.status, response.headers, json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        return exc.code, exc.headers, json.loads(body)


def test_http_routes():
    """Vérifie les routes principales, le serveur statique et les erreurs HTTP attendues."""
    server = create_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        status, headers, payload = _request_json(
            "GET", f"http://127.0.0.1:{server.server_address[1]}/health"
        )
        assert status == 200
        assert payload == {"status": "ok"}

        status, headers, payload = _request_json(
            "GET", f"http://127.0.0.1:{server.server_address[1]}/healthz"
        )
        assert status == 200
        assert payload == {"status": "ok"}

        status, headers, payload = _request_json(
            "GET", f"http://127.0.0.1:{server.server_address[1]}/v1/params"
        )
        assert status == 200
        assert "ML-KEM-768" in payload
        assert payload["ML-KEM-768"]["ek_size"] == 1184

        root_req = urllib.request.Request(
            f"http://127.0.0.1:{server.server_address[1]}/", method="GET"
        )
        with urllib.request.urlopen(root_req, timeout=10) as response:
            assert response.status == 200
            assert "<html" in response.read().decode("utf-8").lower()
            assert response.headers.get_content_type() == "text/html"
            assert (
                response.headers.get("Content-Security-Policy") == "default-src 'self'"
            )
            assert response.headers.get("X-Content-Type-Options") == "nosniff"
            assert response.headers.get("X-Frame-Options") == "DENY"
            assert response.headers.get("Referrer-Policy") == "no-referrer"

        css_req = urllib.request.Request(
            f"http://127.0.0.1:{server.server_address[1]}/css/style.css", method="GET"
        )
        with urllib.request.urlopen(css_req, timeout=10) as response:
            assert response.status == 200
            assert response.headers.get_content_type() == "text/css"

        bad_req = urllib.request.Request(
            f"http://127.0.0.1:{server.server_address[1]}/../pyproject.toml",
            method="GET",
        )
        try:
            urllib.request.urlopen(bad_req, timeout=10)
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
        else:
            raise AssertionError("expected 404 for directory traversal attempt")

        status, headers, payload = _request_json(
            "POST",
            f"http://127.0.0.1:{server.server_address[1]}/v1/keygen",
            {"variant": "ML-KEM-768"},
        )
        assert status == 200
        assert headers.get("Content-Security-Policy") == "default-src 'self'"
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("Referrer-Policy") == "no-referrer"
        assert headers.get("Cache-Control") == "no-store"
        assert "ek" in payload and "dk" in payload
        ek_b64 = payload["ek"]
        dk_b64 = payload["dk"]

        status, headers, payload = _request_json(
            "POST",
            f"http://127.0.0.1:{server.server_address[1]}/v1/encaps",
            {"ek": ek_b64, "variant": "ML-KEM-768"},
        )
        assert status == 200
        assert "K" in payload and "c" in payload
        c_b64 = payload["c"]

        status, headers, payload = _request_json(
            "POST",
            f"http://127.0.0.1:{server.server_address[1]}/v1/decaps",
            {"dk": dk_b64, "c": c_b64, "variant": "ML-KEM-768"},
        )
        assert status == 200
        assert "K" in payload

        status, headers, payload = _request_json(
            "GET", f"http://127.0.0.1:{server.server_address[1]}/nope"
        )
        assert status == 404
        assert "error" in payload

        status, headers, payload = _request_json(
            "GET", f"http://127.0.0.1:{server.server_address[1]}/v1/keygen"
        )
        assert status == 405
        assert payload["type"] == "MethodNotAllowed"

        status, headers, payload = _request_json(
            "POST",
            f"http://127.0.0.1:{server.server_address[1]}/v1/encaps",
            {"ek": "%%%"},
        )
        assert status == 400
        assert "error" in payload

        req = urllib.request.Request(
            f"http://127.0.0.1:{server.server_address[1]}/v1/decaps",
            data=json.dumps({"dk": "", "c": ""}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
