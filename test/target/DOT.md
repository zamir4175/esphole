# Verificación on-target — upstream DoT (spec 007)

Contrato: `specs/007-dot-upstream/contracts/dot-behavior.md` (OT-01..09).

**Seguro:** estas pruebas solo cambian el *upstream* de ESPHole (activan/desactivan
DoT y ajustan los SNI); **no** tocan la LAN del usuario. El script restaura el
estado por defecto (DoT off, SNI por defecto) al terminar.

## Automatizado

```sh
./dot_safe.py [IP] [PASSWORD]     # defecto 192.168.1.10 / changeme
```

Cubre OT-01..07 y OT-09 mediante `dig @IP` + la API `/api/dot` con sesión
(challenge-response PBKDF2, igual que `api_smoke.py`). Resultado esperado:
**14 PASS / 0 FALL**.

OT-08 (aislamiento) va aparte porque necesita concurrencia de shell:

```sh
IP=192.168.1.10
# (activar DoT vía la web o dot_safe) y luego:
for i in $(seq 1 40); do dig @$IP +short flood$i.example.com >/dev/null & done
dig @$IP +short doubleclick.net        # ruta rápida: debe dar 0.0.0.0 al instante
curl -s -o /dev/null -w '%{http_code}' http://$IP/api/challenge   # web: 200
wait
```

## Casos (evidencia, no afirmaciones — P-V/P-I/P-X)

| ID | Qué demuestra | Evidencia observada |
|----|---------------|---------------------|
| OT-01 | DoT off por defecto; reenvío UDP en claro | `enabled=false`; `dig example.com` resuelve |
| OT-02 | Endpoints protegidos por sesión | `GET /api/dot` sin cookie → 401 |
| OT-03 | DoT activo resuelve por TLS | `dig` resuelve; `connected=true`, `served≥1` |
| OT-04 | El bloqueo es previo al reenvío | `doubleclick.net` → 0.0.0.0 con DoT activo |
| OT-05 | Caché delante del reenvío | 2ª consulta resuelve (sin contactar al resolvedor) |
| OT-06 | **Fail-closed (privacidad)** | Todos los SNI inválidos → **SERVFAIL**, cero respuesta en claro; `servfail≥1`, `connected=false`, `last_error` poblado |
| OT-07 | Failover entre resolvedores cifrados | SNI[0] inválido, resto válido → sigue resolviendo |
| OT-08 | Aislamiento (la ruta rápida no se cuelga) | Bajo flood de forwards DoT: bloqueo→0.0.0.0 al instante, web→200; `dropped>0` (cola acotada, FR-007) |
| OT-09 | Volver a UDP; persiste | `enabled=false` → `dig` resuelve por UDP; el estado persiste |

## Regresión base

Con DoT **off** la ruta DNS base (UDP) no cambia:

```sh
./conformance.sh [IP]     # 17 PASS / 0 FAIL esperado (specs 001/002)
```

## Mejoras de arranque/robustez (2026-07-20)

- **Pre-calentamiento con failover:** al activar DoT, la tarea abre la conexión TLS
  de inmediato buscando un resolvedor VIVO (salta primarios caídos) → la primera
  consulta real no paga handshake ni failover, y el panel muestra `connected=true`
  en ~3 s sin necesidad de una consulta previa.
- **Reintento del mismo resolvedor antes de failover:** si una consulta falla
  REUSANDO una conexión viva (cierre por inactividad del resolvedor), reconecta al
  mismo y reintenta una vez; así un corte por inactividad no rebota a otro
  resolvedor (que costaría otro handshake).
- **Cortacircuitos fail-closed:** cuando un ciclo encuentra TODOS los resolvedores
  caídos, las consultas siguientes hacen SERVFAIL **al instante** (sin re-intentar
  handshakes ni bloquear la tarea con un sleep); se rearma tras el backoff.
- **Join fiable de la tarea:** `net_dot_stop` espera a que la tarea salga de verdad
  (semáforo), evitando que un *reload* rápido cree una segunda tarea compitiendo por
  la conexión/cola. Timeout de handshake bajado a 2.5 s (failover más ágil).

## Nota de la ejecución de referencia (2026-07-20, 192.168.1.10)

- `dot_safe.py` → **15 PASS / 0 FALL** (incluye la 2ª consulta SERVFAIL inmediato
  del cortacircuitos).
- OT-06 fail-closed confirmado: `status=SERVFAIL`, sin respuesta; `servfail≥1`,
  `last_error="conexion x.invalid.test (…) fallo"`.
- OT-07 failover resuelve (SNI[0] inválido, resto válido).
- OT-08: ruta rápida (bloqueo→0.0.0.0) y web (200) vivas bajo flood de 40 forwards.
- `conformance.sh` → 17 PASS / 0 FAIL (base intacta); host → 17/17.
