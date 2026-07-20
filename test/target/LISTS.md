# Guion de prueba — actualización de la lista desde URL (spec 004)

Cubre LB-01..LB-09 del contrato (`specs/004-listas-desde-url/contracts/list-update-api.md`).
La mayoría se automatiza con `api_lists.py`; el resto es manual (navegador, reinicio).

`IP` = dirección del ESPHole (por defecto `192.168.1.10`).

## Preparación

Estado **SETUP** (sin admin) y una lista previa en la partición (para verificar el
fail-open y la restauración). Para dejar SETUP sin borrar la partición de la lista:

```bash
python -m esptool -p /dev/ttyACM0 --after hard-reset erase-region 0x9000 0x6000
```

(borra solo NVS; la partición `blocklist` (0x410000) conserva la lista actual, que hace de
"lista previa"). Las credenciales Wi-Fi las repone el override Kconfig.

## Automatizado — LB-01/02/05/06/03/09

```bash
./test/target/api_lists.py            # IP y PASSWORD por defecto
```

Verifica, contra el dispositivo real:

| LB | Qué comprueba |
|----|----|
| LB-01 | `GET /api/blocklist` → URL configurada + conteo de la lista activa |
| LB-02 | Sin sesión → 401 |
| LB-05 | `PUT` con esquema no soportado (`ftp://`) → 400; URL previa intacta |
| LB-06 | `POST update` con host que no resuelve → termina en `error`; la **lista previa sigue activa** (mismo conteo, `dig` sigue bloqueando) |
| LB-03 | `POST update` con la StevenBlack → aplica; conteo grande; `dig doubleclick.net`→0.0.0.0, `dig example.com`→resuelve |
| LB-09 | **Aislamiento:** `dig` martillando durante la descarga → 0 fallos, p95 típico <150 ms (la resolución no se degrada) |

> Nota: el conteo on-device es mayor que el de `tools/gen_blocklist.py` (p. ej. ~76k vs
> ~42k) porque el dispositivo **no poda subdominios redundantes**; el bloqueo es idéntico
> (la coincidencia por sufijo los cubre), solo usa algo más de memoria.

## Manual — LB-08 (persistencia) y LB-04 (otra URL)

- **LB-08 (persistencia tras reinicio):** tras una actualización exitosa, reiniciar el
  dispositivo y observar el log de arranque:
  ```
  I (…) bl_load: lista ACTIVA: <N> dominios en <ms> ms (truncados 0)
  ```
  `<N>` debe ser el conteo de la lista descargada (no re-descarga). `dig` sigue bloqueando.
- **LB-04 (otra fuente):** `PUT /api/blocklist {"url":"https://otra/…/hosts"}` y actualizar;
  tras reiniciar, `GET /api/blocklist` muestra la URL nueva (persistió en NVS).

## Manual — navegador (UI, L15)

1. `http://IP/` → login → panel.
2. Sección **Lista de bloqueo**: muestra el conteo y la URL (editable).
3. Pulsar **Actualizar lista** → barra de progreso por polling (descargando → procesando →
   guardando) → conteo nuevo. Con una URL inválida, muestra el error y conserva la anterior.

## Regresión de las specs 001/002/003

La ruta DNS solo cambia por el flip de `blocklist.state` durante la ventana. Confirmar:

```bash
./test/target/conformance.sh IP     # specs 001/002 (DNS): 17 PASS / 0 FAIL
./test/target/api_smoke.py           # spec 003 (API/web): TODO VERDE
```
