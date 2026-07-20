#!/usr/bin/env bash
# Tests de host de los módulos puros (research.md R3).
#
# IMPORTANTE: NO ejecutar con el entorno de ESP-IDF activado — su PATH antepone
# binutils cruzados sin prefijo (xtensa/riscv) y rompen al gcc del host
# ("as: unrecognized option '--64'"). Este script usa cmake/ninja/ctest de la
# instalación de IDF por ruta absoluta, con el PATH del sistema intacto.
set -euo pipefail

IDF_ROOT="${HOME}/.espressif"
VENV_BIN="${IDF_ROOT}/tools/python/v6.0.1/venv/bin"
NINJA="${IDF_ROOT}/tools/ninja/1.12.1/ninja"
export IDF_PATH="${IDF_PATH:-${IDF_ROOT}/v6.0.1/esp-idf}"

HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${HERE}/build"

"${VENV_BIN}/cmake" -S "${HERE}" -B "${BUILD}" -G Ninja \
    -DCMAKE_MAKE_PROGRAM="${NINJA}" -DCMAKE_BUILD_TYPE=Debug
"${VENV_BIN}/cmake" --build "${BUILD}"
"${VENV_BIN}/ctest" --test-dir "${BUILD}" --output-on-failure "$@"
