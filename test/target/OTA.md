# Guion de prueba — OTA de firmware (spec 005)

Cubre OB-01..OB-10 del contrato (`specs/005-ota-firmware/contracts/ota-api.md`).
OTA es HW: toda la verificación es on-target (curl + reinicio + observación de ranura).

`IP` = ESPHole (por defecto `192.168.1.10`) · `PC` = esta máquina en la LAN (`192.168.1.20:8000`).

## Migración de particiones (una sola vez)

Habilitar OTA cambió la tabla de particiones (dos ranuras + otadata). Exige un reflasheo
completo por USB, que borra NVS (admin/Wi-Fi) y la partición de lista:

```bash
cd firmware
idf.py -p /dev/ttyACM0 erase-flash
idf.py reconfigure && idf.py build && idf.py -p /dev/ttyACM0 flash
# opcional: reflashear la lista real a su nuevo offset, o re-descargarla por la web (spec 004)
python -m esptool --chip esp32s3 -p /dev/ttyACM0 write-flash 0x420000 ../blocklist.bin
```

Arranca desde `ota_0`; el log muestra `otaupd: firmware confirmado, ranura ota_0 (válido)`.

## Servir la imagen de firmware

OTA **exige https** por defecto. Para probar en la LAN con un `http.server`, se compila con
el opt-in de desarrollo `CONFIG_ESPHOLE_OTA_ALLOW_INSECURE_HTTP=y` (nunca en producción) y
se sirve `firmware/build/esphole.bin`:

```bash
cd firmware/build && python3 -m http.server 8000 --bind 0.0.0.0
```

En producción, la URL es una release https (p. ej. un asset de GitHub); no hace falta opt-in.

## Automatizado — OB-01..OB-07

```bash
./test/target/api_ota.py     # setup + curl contra el dispositivo
```

| OB | Qué comprueba |
|----|----|
| OB-01 | `GET /api/firmware` → versión en ejecución + ranura (`ota_0`/`ota_1`) |
| OB-02 | Sin sesión → 401 |
| OB-03 | `POST update` con esquema no soportado (`ftp://`) → 400 |
| OB-06 | Imagen inválida (200 pero no es una app) → `error`, firmware intacto, sin reinicio |
| OB-07 | Descarga fallida (404/host caído) → `error`, misma ranura |
| OB-04 | Imagen válida → `downloading` → reinicio en la **otra** ranura |
| OB-05 | Tras un reset físico sigue en la ranura nueva (confirmada, no revierte) |

## Automatizado — OB-08/09/10 (rollback provocado, aislamiento)

Requiere una imagen de **autotest** que aborta al arrancar a prueba (fuerza el rollback):

```bash
cd firmware
# 1) imagen mala:
idf.py menuconfig  # ESPHole → activar "Imagen de autotest: aborta al arrancar a prueba"
#   (o: añadir CONFIG_ESPHOLE_OTA_SELFTEST_PANIC=y a sdkconfig)
idf.py build && cp build/esphole.bin build/bad.bin
# 2) restaurar la imagen buena:
#   quitar el flag y: idf.py build
# 3) servir build/ y ejecutar:
./test/target/ota_rollback.py
```

| OB | Qué comprueba |
|----|----|
| OB-08 | OTA a `bad.bin` → arranca a prueba → aborta → el bootloader **revierte** a la ranura buena anterior (misma ranura y versión que antes) |
| OB-09 | Segunda OTA mientras hay una en curso → 409 |
| OB-10 | `dig` martillando durante la descarga OTA → 0 fallos (la escritura va a la ranura inactiva; la resolución no se degrada) |

> El timer de gracia (`OTA_VALIDATE_TIMEOUT_MS`, 120 s) cubre además un firmware que
> **cuelga** (sin pánico) antes de confirmarse: reinicia y el bootloader revierte.

## Manual — navegador (UI, O05)

1. `http://IP/` → login → sección **Firmware**: versión en ejecución y ranura.
2. Pegar la URL https del `.bin` y pulsar **Actualizar firmware** → barra de progreso
   (leído/total) → "Reiniciando…" → la página se recarga en la versión nueva.

## Regresión de las specs 001-004

Tras la migración de particiones, confirmar que nada se rompió:

```bash
./test/target/conformance.sh IP     # 001/002 (DNS): 17 PASS / 0 FAIL
./test/target/api_smoke.py           # 003 (API/web): TODO VERDE
./test/target/api_lists.py           # 004 (listas): TODO VERDE (necesita lista previa en la partición)
```
