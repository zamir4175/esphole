#!/usr/bin/env python3
"""
Genera la partición de lista de bloqueo del ESPHole (T027).

Descarga una lista en formato HOSTS, extrae los dominios, replica la
normalización+inversión del módulo `domain` del firmware, ordena (orden de
bytes == strcmp), poda subdominios redundantes (la coincidencia por sufijo
ya los cubre, FR-015) y emite el formato de partición:

    magic "EBL1" | count u32 LE | entradas invertidas NUL-terminadas

Flashear con:
    python -m esptool --chip esp32s3 -p PUERTO write-flash 0x420000 blocklist.bin
"""
import re
import struct
import sys
import urllib.request

URL_DEFAULT = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
LABEL_RE = re.compile(r"[a-z0-9_-]+")
EXCLUIR = {"localhost", "localhost.localdomain", "local", "broadcasthost",
           "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
           "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"}

# topes del firmware (data-model §3 / app_main)
BLOB_CAP = 5 * 1024 * 1024 + 200 * 1024
INDEX_CAP = 200_000


def invertir(dominio: str):
    """Réplica de domain_normalize_invert: None si el dominio es inválido."""
    d = dominio.lower().rstrip(".")
    if not d or len(d) > 253:
        return None
    labels = d.split(".")
    for l in labels:
        if not 0 < len(l) <= 63 or not LABEL_RE.fullmatch(l):
            return None
    return ".".join(reversed(labels))


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else URL_DEFAULT
    salida = sys.argv[2] if len(sys.argv) > 2 else "blocklist.bin"

    print(f"descargando {url} …")
    with urllib.request.urlopen(url, timeout=60) as r:
        texto = r.read().decode("utf-8", errors="replace")

    dominios = set()
    invalidos = 0
    for linea in texto.splitlines():
        linea = linea.split("#", 1)[0].strip()
        if not linea:
            continue
        partes = linea.split()
        # formato HOSTS: "0.0.0.0 dominio" (o solo dominio, formato lista plana)
        dominio = partes[1] if len(partes) >= 2 else partes[0]
        if dominio in EXCLUIR:
            continue
        inv = invertir(dominio)
        if inv is None:
            invalidos += 1
            continue
        dominios.add(inv)

    orden = sorted(dominios)  # orden de bytes ASCII == strcmp

    # poda: si una entrada previa es prefijo en límite de etiqueta, la
    # coincidencia por sufijo del firmware ya cubre a la actual
    podadas = []
    for inv in orden:
        if podadas:
            prev = podadas[-1]
            if inv.startswith(prev) and (len(inv) == len(prev) or inv[len(prev)] == "."):
                continue
        podadas.append(inv)

    if len(podadas) > INDEX_CAP:
        print(f"AVISO: {len(podadas)} entradas > tope {INDEX_CAP}; se truncan "
              f"(el firmware haría lo mismo de forma determinista)")
        podadas = podadas[:INDEX_CAP]

    blob = b"".join(e.encode() + b"\0" for e in podadas)
    if len(blob) > BLOB_CAP:
        print(f"ERROR: blob {len(blob)} B > tope {BLOB_CAP} B")
        return 1

    with open(salida, "wb") as f:
        f.write(b"EBL1")
        f.write(struct.pack("<I", len(podadas)))
        f.write(blob)

    print(f"{salida}: {len(podadas)} dominios ({len(dominios) - len(podadas)} "
          f"podados, {invalidos} inválidos), blob {len(blob) / 1048576:.2f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
