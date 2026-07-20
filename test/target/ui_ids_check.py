#!/usr/bin/env python3
"""
Guarda de preservación de funcionalidad del rediseño (spec 010, UB-H2).

Comprueba que TODO id que app.js referencia por $("id") existe como id="…" en
index.html. Si el rediseño moviera/renombrara un nodo por error, esto lo detecta
antes de flashear. Sin dispositivo.

Uso:  ./ui_ids_check.py
"""
import re
import sys
import pathlib

WWW = pathlib.Path(__file__).resolve().parents[2] / "firmware" / "www"


def main():
    app = (WWW / "app.js").read_text(encoding="utf-8")
    html = (WWW / "index.html").read_text(encoding="utf-8")

    used = set(re.findall(r'\$\(\s*"([^"]+)"\s*\)', app))
    have = set(re.findall(r'\bid="([^"]+)"', html))

    missing = sorted(used - have)
    print(f"IDs usados por app.js: {len(used)} · presentes en index.html: {len(used & have)}")
    if missing:
        print(f"\n\033[31mFALTAN {len(missing)} IDs que app.js usa y no están en el HTML:\033[0m")
        for i in missing:
            print(f"  - {i}")
        return 1
    print("\n\033[32mOK: todos los IDs que usa app.js existen en index.html.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
