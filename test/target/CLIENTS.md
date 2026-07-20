# Verificación on-target — registro de clientes (spec 008)

Contrato: `specs/008-clientes/contracts/clients-behavior.md` (CT-01..08).

**Seguro:** usa sondas `dig @IP` dirigidas — **no** configura el host como resolvedor.
El propio host aparece como un cliente al hacer `dig`. El script deja los contadores
reiniciados al terminar.

## Automatizado

```sh
./clients_safe.py [IP] [PASSWORD]     # defecto 192.168.1.10 / changeme
```

Cubre CT-01..06 y CT-08 (dig + `/api/clients` con sesión). Resultado esperado:
**12 PASS / 0 FALL**.

CT-07 (efímero) se comprueba aparte reiniciando el dispositivo y leyendo
`/api/clients` **antes** de hacer ninguna consulta (debe estar vacío).

## Casos (evidencia — P-V/P-VII)

| ID | Qué demuestra | Evidencia observada |
|----|---------------|---------------------|
| CT-01 | Endpoints bajo sesión | `GET`/`DELETE /api/clients` sin cookie → 401 |
| CT-02 | Reinicio | `DELETE` → `GET` da `[]` |
| CT-03 | El cliente aparece al consultar | tras `dig`, el IP del host con `total≥1`, `blocked=0` |
| CT-04 | Se cuenta el bloqueo | `dig doubleclick.net` → `blocked≥1` |
| CT-05 | Acumulación | repetir `dig` → `total` sube; `visto_s` pequeño |
| CT-06 | Reinicio + reaparición | `DELETE` vacía; nuevo `dig` reaparece desde cero |
| CT-07 | Efímero | reinicio del dispositivo → `/api/clients` vacío (sin dig) |
| CT-08 | Aislamiento | bajo flood: bloqueo→0.0.0.0 al instante, web→200 |

## Regresión base

El conteo por cliente es aditivo y pasivo; la ruta DNS base no cambia:

```sh
./conformance.sh [IP]     # 17 PASS / 0 FAIL esperado
```

## Nota de la ejecución de referencia (2026-07-20, 192.168.1.10)

- `clients_safe.py` → **12 PASS / 0 FALL**; el host (`192.168.1.20`) aparece con
  `total`/`blocked` correctos y `visto_s` reciente.
- CT-07 → tabla vacía tras reinicio (efímero).
- `conformance.sh` → 17 PASS / 0 FAIL (base intacta); host → 18/18.
