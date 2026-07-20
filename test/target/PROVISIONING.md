# Guion de prueba manual — Aprovisionamiento (spec 002)

Los casos del portal necesitan un **cliente Wi-Fi real** (móvil o portátil), por lo que
no se automatizan. Este guion cubre PB-01..PB-10 del contrato de comportamiento.

## Preparación

Para probar el portal hay que **desactivar el override de desarrollo** (si no, el
dispositivo conecta directo y nunca abre el AP — FR-013):

```bash
# vaciar las credenciales compiladas
sed -i 's/CONFIG_ESPHOLE_WIFI_SSID=.*/CONFIG_ESPHOLE_WIFI_SSID=""/' firmware/sdkconfig
sed -i 's/CONFIG_ESPHOLE_WIFI_PASSWORD=.*/CONFIG_ESPHOLE_WIFI_PASSWORD=""/' firmware/sdkconfig
source ~/.espressif/tools/activate_idf_v6.0.1.sh
cd firmware && idf.py reconfigure && idf.py build && idf.py -p /dev/ttyACM0 flash monitor
```

> Nota: `idf.py` cachea `sdkconfig.h`. Si el override no cambia, ejecuta
> `idf.py reconfigure` y confirma con
> `grep ESPHOLE_WIFI_SSID build/config/sdkconfig.h` antes de compilar.

Al terminar las pruebas, restaura el override para uso normal (o deja el dispositivo
aprovisionado por el portal).

---

## PB-01 — Primer arranque sin credenciales → modo AP

1. Con override vacío y sin credenciales en NVS (`idf.py -p PORT erase-flash` primero si
   hiciera falta), arranca.
2. **Esperado (monitor):**
   ```
   W portal: === MODO APROVISIONAMIENTO ===
   W portal:   red:  ESPHole-XXXX
   W portal:   clave: <clave WPA2 única>
   W portal: portal activo en http://192.168.4.1/
   ```
3. Anota la red y la clave. ✔ si aparecen y el AP es visible desde el móvil.

## PB-02 — Portal cautivo automático

1. Conéctate con el móvil a `ESPHole-XXXX` usando la clave del monitor.
2. **Esperado:** el móvil abre solo la ventana del portal (iOS/Android detectan el
   portal cautivo). Si no salta solo, abre `http://192.168.4.1/`.

## PB-03 — Escaneo de redes

1. En el portal, el desplegable **Red** se puebla con las redes Wi-Fi cercanas
   (nombre + dBm), ordenadas por señal.
2. ✔ si tu red aparece en la lista.

## PB-04 — Guardar credenciales correctas → conecta

1. Elige tu red, escribe la contraseña correcta, pulsa **Guardar y conectar**.
2. **Esperado:** página "Credenciales guardadas"; el monitor muestra
   `provision: conectando…` → `IP obtenida: …` → `credenciales validadas`; el AP
   desaparece y arranca el DNS.
3. Verifica: `dig @<IP-del-esphole> doubleclick.net A` → `0.0.0.0`.

## PB-05 — Contraseña incorrecta → vuelve al portal

1. Repite PB-04 con una **contraseña equivocada**.
2. **Esperado:** tras ~30 s sin conectar, el monitor muestra `sin conexión en 30000 ms`
   y `=== MODO APROVISIONAMIENTO ===` de nuevo. El portal vuelve a estar disponible.

## PB-06 — Caída temporal de red validada → reintenta (no reabre el AP)

1. Con el dispositivo ya aprovisionado y funcionando, **reinicia tu router** (o apaga su
   Wi-Fi ~1 min).
2. **Esperado:** el monitor muestra reintentos de conexión; **no** aparece
   `=== MODO APROVISIONAMIENTO ===`. Al volver la red, reconecta solo.
3. ✔ si nunca reabrió el AP (Principio I).

## PB-07 — Factory reset con el botón BOOT

1. Con el dispositivo funcionando, **mantén pulsado BOOT ≥3 s**.
2. **Esperado:** `botón BOOT mantenido en operación: factory reset` y reinicio en modo AP
   (PB-01). Una pulsación **breve** no debe borrar nada.

## PB-08 — Persistencia entre reinicios

1. Aprovisionado y funcionando, **desenchufa y reenchufa** (o `idf.py -p PORT monitor`
   tras un reset).
2. **Esperado:** conecta directo sin portal (`provision: conectando…` → `IP obtenida`).

## PB-09 — Corte a mitad de guardado (atomicidad)

1. En PB-04, **corta la energía justo al pulsar Guardar** (difícil de cronometrar; repetir
   varias veces).
2. **Esperado:** al reiniciar, o las credenciales están completas y conecta, o se comporta
   como sin credenciales (portal). **Nunca** queda inservible (FR-006/C1: `provisioned`
   solo se sube tras validar, y `config_save_wifi` lo fija a 0 antes de escribir).

## PB-10 — Override de desarrollo

1. Restaura `CONFIG_ESPHOLE_WIFI_SSID`/`PASSWORD` con tus credenciales, `reconfigure`,
   `build`, `flash`.
2. **Esperado:** `override Kconfig: conexión directa a "<SSID>"` y conecta sin portal.

---

## Resultado (rellenar al ejecutar)

| Caso | Resultado | Notas |
|------|-----------|-------|
| PB-01 |  |  |
| PB-02 |  |  |
| PB-03 |  |  |
| PB-04 |  |  |
| PB-05 |  |  |
| PB-06 |  |  |
| PB-07 |  |  |
| PB-08 |  |  |
| PB-09 |  |  |
| PB-10 | ✔ (verificado en dev) | override conecta directo |

Verificado por el asistente hasta donde el hardware del host permite (su Wi-Fi está
soft-blocked, no puede asociarse al AP): modo AP levanta con identidad única real
(`ESPHole-9AE1`), portal HTTP y DNS cautivo activos sin crash; PB-10 (override) y la
regresión de la spec 001 confirmados con `dig`. PB-01..PB-09 requieren el cliente Wi-Fi.
