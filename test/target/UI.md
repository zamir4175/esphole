# Verificación — rediseño de UX/UI (spec 010)

Contratos: `specs/010-ui-redesign/contracts/{design-tokens.md,ui-behavior.md}` (DT/UB).

100% frontend: no toca firmware/DNS/API. Verificación automática (estática) + manual (navegador).

## Automatizado (sin dispositivo)

```sh
python3 test/target/i18n_check.py    # completitud i18n (incluye menú/tema/hero)
python3 test/target/ui_ids_check.py  # TODO $("id") de app.js existe en index.html (FR-008)
node    test/target/i18n_logic.js    # lógica i18n (defecto EN, cambio, {0}, fallbacks)
```
Esperado: los tres en verde.

## Manual (navegador real)

Abrir `http://<IP>/` (ventana privada para partir de cero).

### Tema — DT-01..07
| ID | Paso | Esperado |
|----|------|----------|
| DT-01/02 | 1ª carga sin `esphole_theme` | sigue al **sistema** (oscuro o claro) |
| DT-03 | pulsar ☀/🌙 | cambia al instante; persiste al recargar; `data-theme` fijado |
| DT-04 | `localStorage.esphole_theme='zz'` + recargar | cae a auto (sistema) |
| DT-05 | leer texto en ambos temas | contraste legible (AA) |
| DT-06 | cards / salud | color por categoría/estado **+ etiqueta** (no solo color) |
| DT-07 | anillo del hero | refleja el % bloqueado; `reduce` desactiva la animación |

### Navegación / responsive — UB-01..06
| ID | Paso | Esperado |
|----|------|----------|
| UB-01 | carga autenticada | Dashboard (hero + salud/clientes/caché); ítem activo |
| UB-02 | pulsar un ítem del menú | solo esa sección; `#hash`; ítem activo |
| UB-03 | recargar con `#dhcp` | abre DHCP directamente |
| UB-04 | `#zzz` | abre Dashboard |
| UB-05 | viewport móvil | menú en ☰ (plegable); sin scroll horizontal; tablas con scroll |
| UB-06 | setup/login (sin sesión) | centrado, estilo nuevo, **sin** sidebar |

### Funcionalidad preservada — UB-07..13 (repetir flujos)
- Login desafío-respuesta → entra.
- Guardar upstreams / vaciar caché → mismo efecto y mensajes.
- Actualizar lista / firmware → barra de estado, recarga.
- Activar/ajustar DHCP y DoT → mismos endpoints/resultados.
- Ver/reiniciar clientes; cambio de contraseña; logout → funcionan.
- Conmutar EN|ES → toda la interfaz (incl. menú/tema) traduce.

## Nota de referencia (2026-07-20, 192.168.1.10)
- `i18n_check.py` 109/109; `ui_ids_check.py` 51/51 IDs; `i18n_logic.js` 9/9.
- El dispositivo sirve `theme.js`/`i18n.js`; hero, sidebar (7 secciones) y conmutadores presentes.
- Sin cambios de firmware: `conformance.sh`/`dot_safe.py`/`clients_safe.py` siguen aplicando igual.
