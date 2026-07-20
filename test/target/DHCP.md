# Guion de prueba — servidor DHCP opcional (spec 006)

Cubre DB-01..DB-09 y DB-M1/M2 del contrato
(`specs/006-servidor-dhcp/contracts/dhcp-behavior.md`). El grueso de la lógica se prueba en
**host**; en el dispositivo, lo que **no** sirve DHCP es automatizable; lo que **sí** enciende
el servidor se deja **manual** para no repartir concesiones en una LAN de producción sin querer.

`IP` = ESPHole (por defecto `192.168.1.10`).

> ⚠️ **Aviso:** activar el DHCP de ESPHole en una red donde el router también tiene DHCP
> activo puede entregar IPs a dispositivos reales. Hazlo solo cuando estés listo para
> **desactivar el DHCP del router**, idealmente en una red de pruebas.

## Host (el grueso — el riesgo real)

```bash
./test/host/run.sh   # incluye test_dhcp_wire (DW-01..09) y test_dhcp_lease (DL-01..10)
```

`dhcp_wire` (parseo/construcción de paquetes DHCP, basura acotada, fuzz bajo ASan) y
`dhcp_lease` (asignación, honrar-pedida, pool lleno, caducidad, release, decline) — cubren
DB-H1/H2.

## Automatizado seguro (no enciende el servidor)

```bash
./test/target/dhcp_safe.py [IP] [PASSWORD]
```

| DB | Qué |
|----|-----|
| DB-01 | `GET /api/dhcp` → `enabled=false` (off por defecto, P-X) |
| DB-02 | Sin sesión → 401 |
| DB-07 | `PUT` con rango inválido (inicio>fin) o IP malformada → 400; el DHCP **no** se activa |

## Manual — encender el servidor (hazlo tú, en red de pruebas)

**Antes:** desactiva el servidor DHCP de tu router.

1. **DB-03 (activar + auto-derivar):** en el panel web, sección **Servidor DHCP**, marca
   «Activar» y Guardar (o `PUT /api/dhcp {"enabled":"true"}`). `GET /api/dhcp` debe mostrar
   `enabled=true`, `gateway` = tu router, `dns` = la IP de ESPHole, y un rango dentro de tu
   subred (por defecto `.100–.200`). En el log serie: `net_dhcp: servidor DHCP activo en :67`.
2. **DB-04/05/06 (ciclo DHCP):** sonda de protocolo desde una máquina de la LAN (necesita
   privilegios para escuchar en el puerto 68):
   ```bash
   sudo ./test/target/dhcp_probe.py IP    # (si lo escribes) envía DISCOVER, valida OFFER/ACK
   ```
   o con `nmap --script broadcast-dhcp-discover`, o simplemente conectando un cliente real.
   Esperado: OFFER con IP del rango y **opción 6 (DNS) = ESPHole**; REQUEST→ACK; el mismo MAC
   recupera su IP (DB-06); la concesión aparece en `GET /api/dhcp`.
3. **DB-08 (apagar):** desmarca «Activar» y Guarda; el servidor deja de escuchar; persiste
   apagado tras reiniciar.
4. **DB-09 (aislamiento):** con el DHCP encendido y bajo peticiones, `dig @IP` sigue
   resolviendo con normalidad (el DHCP corre en su tarea, no toca la ruta DNS).

## Manual — cliente real end-to-end (DB-M1/M2)

Con el DHCP del router desactivado y el de ESPHole activo:

- **DB-M1:** conecta un equipo a la red. Debe obtener una IP del rango, el gateway correcto y
  **DNS = ESPHole**. Comprueba con `ipconfig /all` (Windows) o `nmcli`/`resolvectl` (Linux)
  que el DNS es la IP de ESPHole, y que `nslookup doubleclick.net` devuelve `0.0.0.0`
  (bloqueado) mientras un dominio normal resuelve.
- **DB-M2 (anti-duplicado):** deja un equipo con IP fija dentro del rango; ESPHole no debe
  entregar esa IP (sondeo ARP), o el cliente la declina y ESPHole la marca y ofrece otra.

## Regresión de las specs 001-005

```bash
./test/target/conformance.sh IP   # 001/002 (DNS): 16+ PASS / 0 FAIL
# 003/004/005: sus suites (api_smoke.py, api_lists.py, api_ota.py) borran NVS para partir de
# SETUP; el DHCP (006) es aditivo y off por defecto, no toca sus rutas. Correr solo si
# quieres re-verificarlas desde cero (cambian la contraseña de admin).
```
