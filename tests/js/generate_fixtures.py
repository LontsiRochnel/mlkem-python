#!/usr/bin/env python3
"""Génère les vecteurs de conformité JS à partir du code Python."""

from __future__ import annotations

import json

from mlkem import encaps_internal, keygen_internal
from mlkem.params import ML_KEM_1024, ML_KEM_512, ML_KEM_768

VALUES = {
    ML_KEM_512: {
        "d": b"\x00" * 32,
        "z": b"\x01" * 32,
        "m": b"\x02" * 32,
    },
    ML_KEM_768: {
        "d": b"\x10" * 32,
        "z": b"\x20" * 32,
        "m": b"\x30" * 32,
    },
    ML_KEM_1024: {
        "d": b"\x40" * 32,
        "z": b"\x50" * 32,
        "m": b"\x60" * 32,
    },
}

payload = {}
for variant, value in VALUES.items():
    ek, dk = keygen_internal(value["d"], value["z"], variant)
    K, c = encaps_internal(ek, value["m"], variant)
    payload[variant] = {
        "d": value["d"].hex(),
        "z": value["z"].hex(),
        "m": value["m"].hex(),
        "ek": ek.hex(),
        "dk": dk.hex(),
        "c": c.hex(),
        "K": K.hex(),
    }

with open("tests/js/fixtures.json", "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")

print("fixtures generated")
