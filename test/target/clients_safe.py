#!/usr/bin/env python3
"""
Verificación on-target del registro de clientes (spec 008, CT-01..08).

Seguro: usa sondas `dig @IP` dirigidas (NO configura este host como resolvedor).
El propio host aparece como cliente al hacer dig. Deja los contadores reiniciados
al terminar.

Uso:  ./clients_safe.py [IP] [PASSWORD]     (defecto 192.168.1.10 / changeme)
"""
import sys, json, time, hashlib, hmac, subprocess
import urllib.request

IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.10"
PW = sys.argv[2] if len(sys.argv) > 2 else "changeme"
KDF_ITERS = 30000
BASE = f"http://{IP}"

PASS = 0
FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[\033[32mPASS\033[0m] {label} {extra}")
    else:
        FAIL += 1
        print(f"[\033[31mFALL\033[0m] {label} {extra}")


def req(method, path, cookie=None, timeout=15):
    r = urllib.request.Request(BASE + path, method=method)
    if cookie:
        r.add_header("Cookie", cookie)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        return resp.getcode(), resp.read().decode(), resp.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), None


def login():
    _, b, _ = req("GET", "/api/challenge")
    ch = json.loads(b)
    key = hashlib.pbkdf2_hmac("sha256", PW.encode(), bytes.fromhex(ch["salt"]),
                              KDF_ITERS, 32)
    rp = hmac.new(key, ch["nonce"].encode(), hashlib.sha256).hexdigest()
    # /api/login necesita cuerpo JSON: lo mandamos con un request propio
    body = json.dumps({"nonce": ch["nonce"], "resp": rp}).encode()
    r = urllib.request.Request(BASE + "/api/login", method="POST", data=body)
    r.add_header("Content-Type", "application/json")
    resp = urllib.request.urlopen(r, timeout=15)
    setc = resp.headers.get("Set-Cookie")
    return setc.split(";")[0] if setc else None


def clients(cookie):
    sc, b, _ = req("GET", "/api/clients", cookie=cookie)
    return sc, (json.loads(b) if sc == 200 else None)


def dig(name):
    subprocess.run(["dig", f"@{IP}", "+time=4", "+tries=1", name, "A"],
                   capture_output=True, text=True)


def find_self(lst):
    """Devuelve la entrada del cliente con más consultas (este host es el único
    que sondea ahora mismo)."""
    return max(lst, key=lambda c: c["total"]) if lst else None


print(f"== Verificación de clientes contra {IP} ==")
cookie = login()
if not cookie:
    print("No se pudo iniciar sesión. Aborto.")
    sys.exit(1)

# CT-01: sin sesión -> 401
sc, _, _ = req("GET", "/api/clients")
check("CT-01  GET /api/clients sin sesión -> 401", sc == 401, f"({sc})")
sc, _, _ = req("DELETE", "/api/clients")
check("CT-01  DELETE /api/clients sin sesión -> 401", sc == 401, f"({sc})")

# CT-02: reset -> lista vacía
req("DELETE", "/api/clients", cookie=cookie)
sc, lst = clients(cookie)
check("CT-02  DELETE + GET -> lista vacía", sc == 200 and lst == [], f"({lst})")

# CT-03: dig -> el host aparece con total>=1, blocked=0
dig("example.com")
dig("example.net")
time.sleep(0.5)
sc, lst = clients(cookie)
me = find_self(lst)
check("CT-03  dig -> el cliente aparece con total>=1",
      me is not None and me["total"] >= 1, f"({me})")
check("CT-03  consultas no bloqueadas -> blocked=0", me and me["blocked"] == 0,
      f"(blocked={me['blocked'] if me else '?'})")

# CT-04: dig de dominio bloqueado -> blocked sube
antes = me["blocked"] if me else 0
antes_total = me["total"] if me else 0
dig("doubleclick.net")
time.sleep(0.5)
sc, lst = clients(cookie)
me = find_self(lst)
check("CT-04  dig de dominio bloqueado -> blocked>=1", me and me["blocked"] >= 1,
      f"(blocked={me['blocked'] if me else '?'})")

# CT-05: repetir -> total sube; visto reciente
dig("example.org")
time.sleep(0.5)
sc, lst = clients(cookie)
me2 = find_self(lst)
check("CT-05  repetir -> total sube", me2 and me2["total"] > antes_total,
      f"(total {antes_total} -> {me2['total'] if me2 else '?'})")
check("CT-05  visto reciente (<15 s)", me2 and me2["visto_s"] < 15,
      f"(visto_s={me2['visto_s'] if me2 else '?'})")

# CT-06: reset -> vacía; nuevo dig -> reaparece desde cero
req("DELETE", "/api/clients", cookie=cookie)
sc, lst = clients(cookie)
check("CT-06  reset -> vacía", lst == [], f"({lst})")
dig("iana.org")
time.sleep(0.5)
sc, lst = clients(cookie)
me = find_self(lst)
check("CT-06  tras reset, reaparece desde cero", me and me["total"] >= 1,
      f"({me})")

# CT-08: aislamiento — flood de forwards + ruta rápida (bloqueo) + web
import threading
def flood():
    for i in range(40):
        subprocess.run(["dig", f"@{IP}", "+time=4", "+tries=1", f"c{i}.example.com", "A"],
                       capture_output=True)
t = threading.Thread(target=flood)
t.start()
blk = subprocess.run(["dig", f"@{IP}", "+short", "+time=3", "+tries=1", "doubleclick.net", "A"],
                     capture_output=True, text=True).stdout.strip()
sc_web, _, _ = req("GET", "/api/challenge")
t.join()
check("CT-08  aislamiento: ruta rápida (bloqueo) viva bajo flood",
      blk.splitlines()[0] == "0.0.0.0" if blk else False, f"(blk={blk!r})")
check("CT-08  aislamiento: web viva bajo flood", sc_web == 200, f"({sc_web})")

# limpieza: dejar reiniciado
req("DELETE", "/api/clients", cookie=cookie)

print(f"\n== {PASS} PASS / {FAIL} FALL ==")
sys.exit(1 if FAIL else 0)
