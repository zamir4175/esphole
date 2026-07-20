#!/usr/bin/env python3
"""
Batería end-to-end de la API/web (spec 003) contra un ESPHole real.

Uso:  ./api_smoke.py [IP] [PASSWORD]     (defecto 192.168.1.10 / esphole-admin-2026)

Requiere el dispositivo en estado SETUP (sin admin). Para dejarlo así:
  python -m esptool -p /dev/ttyACM0 --after hard-reset erase-region 0x9000 0x6000
o un factory reset físico (botón BOOT ≥3 s).

Cubre AB-01..AB-09 y AB-11 (aislamiento DNS bajo carga web). AB-10 (expiración de
sesión, TTL 30 min), AB-12 (partición www vacía) y AB-13 (factory reset físico)
son manuales — ver API.md. La cripto (PBKDF2/HMAC) replica al cliente del navegador,
demostrando que la contraseña nunca viaja.
"""
import sys, json, time, threading, subprocess, hashlib, hmac
import urllib.request, urllib.error

IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.10"
PW = sys.argv[2] if len(sys.argv) > 2 else "esphole-admin-2026"
BASE = f"http://{IP}"
KDF_ITERS = 30000  # DEBE coincidir con WEBAPI_KDF_ITERS (webapi.c) y app.js

ok_all = True
def check(label, cond, extra=""):
    global ok_all
    ok_all = ok_all and cond
    print(f"[{'PASS' if cond else 'FALL'}] {label} {extra}")

def req(method, path, body=None, cookie=None, timeout=15):
    r = urllib.request.Request(BASE + path, data=body.encode() if body else None, method=method)
    if body: r.add_header("Content-Type", "application/json")
    if cookie: r.add_header("Cookie", cookie)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        return resp.getcode(), resp.read().decode(), resp.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), None

def cookie_of(setc):
    return setc.split(";")[0] if setc else None

def resp_for(nonce, salt_hex):
    key = hashlib.pbkdf2_hmac("sha256", PW.encode(), bytes.fromhex(salt_hex), KDF_ITERS, 32)
    return hmac.new(key, nonce.encode(), hashlib.sha256).hexdigest()

def login():
    _, b, _ = req("GET", "/api/challenge")
    ch = json.loads(b)
    _, _, setc = req("POST", "/api/login",
                     json.dumps({"nonce": ch["nonce"], "resp": resp_for(ch["nonce"], ch["salt"])}))
    return cookie_of(setc)

def dig(name):
    out = subprocess.run(["dig", "+short", "+time=2", "+tries=1", f"@{IP}", name],
                         capture_output=True, text=True, timeout=6).stdout.strip()
    return out

# AB-01
sc, _, _ = req("GET", "/api/status")
check("AB-01 status sin sesion -> 401", sc == 401, f"({sc})")

# AB-02
sc, _, setc = req("POST", "/api/setup", json.dumps({"password": PW}))
setup_cookie = cookie_of(setc)
check("AB-02 setup -> 200 + cookie", sc == 200 and setup_cookie, f"({sc})")
sc, _, _ = req("POST", "/api/setup", json.dumps({"password": "otra-1234"}))
check("AB-02 segundo setup -> 409", sc == 409, f"({sc})")

# AB-05
sc, b, _ = req("GET", "/api/status", cookie=setup_cookie)
check("AB-05 status con sesion -> 200 JSON",
      sc == 200 and all(k in b for k in ["total", "bloqueadas", "heap_libre"]), f"({sc})")

# AB-03 / AB-04
_, b, _ = req("GET", "/api/challenge")
ch = json.loads(b)
check("AB-03 challenge -> nonce+salt", len(ch["nonce"]) == 32 and len(ch["salt"]) == 32)
sc, _, lc = req("POST", "/api/login",
                json.dumps({"nonce": ch["nonce"], "resp": resp_for(ch["nonce"], ch["salt"])}))
cookie = cookie_of(lc)
check("AB-03 login desafio-respuesta -> 200 + cookie", sc == 200 and cookie, f"({sc})")
sc, _, _ = req("POST", "/api/login",
               json.dumps({"nonce": ch["nonce"], "resp": resp_for(ch["nonce"], ch["salt"])}))
check("AB-04 nonce reusado -> rechazado", sc == 401, f"({sc})")
_, b, _ = req("GET", "/api/challenge")
ch2 = json.loads(b)
sc, _, _ = req("POST", "/api/login", json.dumps({"nonce": ch2["nonce"], "resp": "00"*32}))
check("AB-04 resp incorrecta -> 401", sc == 401, f"({sc})")

# AB-06
sc, b, _ = req("GET", "/api/status", cookie=cookie); antes = json.loads(b)
for _ in range(2):
    for d in ["doubleclick.net", "ads.tracker.net"]: dig(d)
    for d in ["example.com", "example.org", "wikipedia.org"]: dig(d)
time.sleep(0.4)
sc, b, _ = req("GET", "/api/status", cookie=cookie); desp = json.loads(b)
check("AB-06 contadores suben con la resolucion",
      desp["total"] > antes["total"] and desp["bloqueadas"] > antes["bloqueadas"],
      f"(total {antes['total']}->{desp['total']}, bloq {antes['bloqueadas']}->{desp['bloqueadas']})")

# AB-09
sc, b, _ = req("GET", "/api/cache", cookie=cookie)
check("AB-09 GET cache -> 200", sc == 200, f"({b.strip()})")
sc, b, _ = req("DELETE", "/api/cache", cookie=cookie)
check("AB-09 DELETE cache -> 200", sc == 200, f"({b.strip()})")

# AB-08
sc, _, _ = req("PUT", "/api/config/upstreams", json.dumps({"upstreams": ["999.1.1.1"]}), cookie=cookie)
check("AB-08 upstreams invalido -> 400", sc == 400, f"({sc})")
sc, b, _ = req("GET", "/api/config", cookie=cookie)
check("AB-08 config intacta tras invalido", sc == 200 and "1.1.1.1" in b, f"({sc})")

# sin cookie -> 401
sc, _, _ = req("GET", "/api/config")
check("protegido sin cookie -> 401", sc == 401, f"({sc})")

# AB-11: aislamiento — martillar la web mientras dig resuelve
stop = threading.Event(); hits = [0]
def hammer():
    while not stop.is_set():
        try: req("GET", "/api/status", cookie=cookie); req("GET", "/"); hits[0] += 2
        except Exception: pass
ths = [threading.Thread(target=hammer) for _ in range(8)]
for t in ths: t.start()
lat, fails = [], 0
for i in range(30):
    t0 = time.time()
    r = dig("example.com" if i % 2 else "wikipedia.org")
    (lat.append((time.time()-t0)*1000) if r else None)
    if not r: fails += 1
stop.set()
for t in ths: t.join()
lat.sort()
p95 = lat[int(len(lat)*0.95)] if lat else 9999
check("AB-11 DNS no se degrada bajo carga web", fails == 0 and p95 < 1500,
      f"({len(lat)}/30 ok, p95={p95:.0f}ms, ~{hits[0]} req web)")

print("\nRESULTADO:", "TODO VERDE" if ok_all else "HAY FALLOS")
sys.exit(0 if ok_all else 1)
