# Guion de prueba — API HTTP + interfaz web (spec 003)

Cubre AB-01..AB-13 del contrato (`specs/003-api-web/contracts/api-behavior.md`).
La mayoría se automatiza con `api_smoke.py`; unos pocos son manuales (navegador,
espera de TTL, botón físico).

`IP` = dirección del ESPHole en la LAN (por defecto `192.168.1.10`).

## Preparación

El dispositivo debe estar en estado **SETUP** (sin admin) para el guion completo.
Para dejarlo así sin reflashear la app:

```bash
python -m esptool -p /dev/ttyACM0 --after hard-reset erase-region 0x9000 0x6000
```

(borra solo la partición NVS; las credenciales Wi-Fi las repone el override
Kconfig de desarrollo en el arranque). Alternativa física: **factory reset** con
el botón BOOT ≥3 s.

## Automatizado — AB-01..AB-09 y AB-11

```bash
./test/target/api_smoke.py [IP] [PASSWORD]
```

Verifica, todo contra el dispositivo real:

| AB | Qué comprueba |
|----|----|
| AB-01 | `GET /api/status` sin sesión → 401 |
| AB-02 | `POST /api/setup` fija la credencial; el segundo setup → 409 |
| AB-03 | Login por **desafío-respuesta**: `GET /api/challenge` → `POST /api/login`; la contraseña **nunca** viaja (solo nonce+resp) |
| AB-04 | Nonce de un solo uso; resp incorrecta → 401 |
| AB-05 | `GET /api/status` con sesión → JSON con métricas, heap, uptime, salud |
| AB-06 | Resolver con `dig` sube los contadores (total y bloqueadas) |
| AB-08 | `PUT /api/config/upstreams` inválido → 400 y la config vigente no se corrompe |
| AB-09 | `GET`/`DELETE /api/cache`: muestra ocupación y la vacía |
| AB-11 | **Aislamiento (P-I):** 8 hilos martillando la web mientras `dig` resuelve; 30/30 consultas OK sin degradación (p95 típico <150 ms) |

La cripto del guion (PBKDF2-HMAC-SHA256 30k + HMAC del reto) es idéntica a la del
cliente del navegador (`firmware/www/app.js`) y a la del dispositivo
(`mbedtls_pkcs5_pbkdf2_hmac_ext`), así que un login correcto prueba la
interoperabilidad de las tres.

## Manual con navegador — AB-07 y flujo de UI

1. Abrir `http://IP/` en un navegador de la LAN.
2. **Setup:** si no hay admin, aparece «Configura tu contraseña». Crearla (≥8) →
   entra directo al panel.
3. **Login:** tras cerrar sesión (o expirar), «Entrar»; la contraseña se procesa
   en el navegador con PBKDF2 (~1 s) y no se envía. `crypto.subtle` no se usa
   (no existe en HTTP plano): SHA-256/HMAC/PBKDF2 van en JS puro.
4. **Dashboard:** tarjetas con auto-refresh cada 3 s; % bloqueado; salud de upstreams.
5. **AB-07:** en «Resolvedores upstream», cambiar la lista por IPs válidas y
   *Guardar y reiniciar*. El dispositivo responde «reiniciando», se reinicia y al
   volver `GET /api/config` muestra los nuevos. Con IPs inválidas → error y la
   config anterior intacta (AB-08).

   Equivalente por curl (con la cookie de sesión `esphole_session`):
   ```bash
   curl -s -X PUT http://IP/api/config/upstreams \
        -H 'Content-Type: application/json' -b "esphole_session=<TOKEN>" \
        -d '{"upstreams":["8.8.8.8","1.0.0.1"]}'
   # tras ~9 s: curl -s http://IP/api/config -b "esphole_session=<TOKEN>"
   ```

## Manual — casos límite

- **AB-10 (expiración de sesión):** con sesión válida, esperar > `WEBAPI_SESSION_TTL_S`
  (30 min) sin actividad y volver a `GET /api/status` → 401; re-login requerido.
  (La lógica de expiración está cubierta en host por AB-H3.)
- **AB-12 (partición www vacía):** flashear sin `www.bin` (o con partición sin
  formato). `GET /` → 404 «UI no instalada», pero la API sigue: `GET /api/status`
  con sesión responde igual (FR-011).
- **AB-13 (factory reset):** con admin fijado, mantener BOOT ≥3 s. Tras el reinicio,
  el primer acceso web vuelve a exigir crear contraseña (credencial borrada, FR-010).

## Regresión de las specs 001/002

La ruta DNS no se modifica. Confirmar que sigue verde:

```bash
./test/target/conformance.sh IP
```
