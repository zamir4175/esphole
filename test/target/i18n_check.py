#!/usr/bin/env python3
"""
Chequeo de completitud de las traducciones (spec 009, IK-01..03).

Análisis estático de firmware/www/: comprueba que TODA clave usada en la interfaz
(data-i18n / data-i18n-ph en index.html, t("…") en app.js) existe en el diccionario
de i18n.js con 'en' y 'es' NO vacíos. Avisa de claves del diccionario no usadas
(huérfanas). Sale ≠0 si falta alguna clave o alguna entrada está incompleta.

No necesita el dispositivo. Uso:  ./i18n_check.py
"""
import re
import sys
import pathlib

WWW = pathlib.Path(__file__).resolve().parents[2] / "firmware" / "www"


def read(name):
    return (WWW / name).read_text(encoding="utf-8")


def dict_keys(js):
    """Claves del diccionario I18N y si tienen en/es no vacíos.
    Entradas de una línea: "clave": { en: "…", es: "…" }, """
    entries = {}
    pat = re.compile(
        r'"([^"]+)"\s*:\s*\{\s*en\s*:\s*"((?:[^"\\]|\\.)*)"\s*,\s*'
        r'es\s*:\s*"((?:[^"\\]|\\.)*)"\s*\}')
    for m in pat.finditer(js):
        key, en, es = m.group(1), m.group(2), m.group(3)
        entries[key] = (en.strip() != "", es.strip() != "")
    return entries


def used_html(html):
    return set(re.findall(r'data-i18n(?:-ph)?="([^"]+)"', html))


def strip_comments(js):
    """Quita comentarios // y /* */ respetando cadenas (para no confundir
    ejemplos en comentarios ni un // dentro de una URL con un comentario)."""
    out = []
    i, n = 0, len(js)
    while i < n:
        c = js[i]
        if c in "\"'":
            q = c
            out.append(c)
            i += 1
            while i < n:
                out.append(js[i])
                if js[i] == "\\":
                    i += 1
                    if i < n:
                        out.append(js[i])
                        i += 1
                    continue
                if js[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if c == "/" and i + 1 < n and js[i + 1] == "/":
            while i < n and js[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and js[i + 1] == "*":
            i += 2
            while i + 1 < n and not (js[i] == "*" and js[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def used_js(js):
    return set(re.findall(r'\bt\(\s*["\']([^"\']+)["\']', strip_comments(js)))


def main():
    i18n = read("i18n.js")
    html = read("index.html")
    app = read("app.js")
    theme = (WWW / "theme.js").exists() and read("theme.js") or ""

    D = dict_keys(i18n)
    # t("…") aparece en app.js, theme.js y también en i18n.js (p. ej. el título)
    used = used_html(html) | used_js(app) | used_js(i18n) | used_js(theme)

    missing = sorted(used - set(D))                      # usadas sin entrada
    incompleta = sorted(k for k in D if not (D[k][0] and D[k][1]))  # sin en/es
    orphan = sorted(set(D) - used)                       # en dict, no usadas

    print(f"Diccionario: {len(D)} claves · Usadas: {len(used)}")
    ok = True
    if missing:
        ok = False
        print(f"\n\033[31mFALTAN {len(missing)} claves usadas sin traducir:\033[0m")
        for k in missing:
            print(f"  - {k}")
    if incompleta:
        ok = False
        print(f"\n\033[31m{len(incompleta)} entradas sin 'en'/'es' no vacíos:\033[0m")
        for k in incompleta:
            print(f"  - {k}")
    if orphan:
        print(f"\n\033[33mAviso: {len(orphan)} claves huérfanas (en el diccionario, no usadas):\033[0m")
        for k in orphan:
            print(f"  - {k}")

    if ok and not missing and not incompleta:
        print("\n\033[32mOK: todas las claves usadas tienen traducción en/es no vacía.\033[0m")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
