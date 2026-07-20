#!/usr/bin/env python3
"""
Verificación on-target del upstream DoT (spec 007, OT-01..09).

Seguro: solo cambia el upstream de ESPHole (activa/desactiva DoT y ajusta SNI);
NO toca la LAN del usuario. Al terminar restaura el estado por defecto (DoT off,
SNI por defecto). La prueba clave es OT-06 (fail-closed): con DoT activo y todos
los resolvedores cifrados fallando, la consulta devuelve SERVFAIL — JAMÁS una
respuesta resuelta por texto plano.

Uso:  ./dot_safe.py [IP] [PASSWORD]     (defecto 192.168.1.10 / changeme)
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


def req(method, path, body=None, cookie=None, timeout=15):
    r = urllib.request.Request(BASE + path, method=method,
                               data=body.encode() if body else None)
    if cookie:
        r.add_header("Cookie", cookie)
    if body:
        r.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        return resp.getcode(), resp.read().decode(), resp.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), None


def cookie_of(setc):
    return setc.split(";")[0] if setc else None


def resp_for(nonce, salt_hex):
    key = hashlib.pbkdf2_hmac("sha256", PW.encode(), bytes.fromhex(salt_hex),
                              KDF_ITERS, 32)
    return hmac.new(key, nonce.encode(), hashlib.sha256).hexdigest()


def login():
    _, b, _ = req("GET", "/api/challenge")
    ch = json.loads(b)
    _, _, setc = req("POST", "/api/login",
                     json.dumps({"nonce": ch["nonce"],
                                 "resp": resp_for(ch["nonce"], ch["salt"])}))
    return cookie_of(setc)


def dig(name, rtype="A", timeout=4):
    """Devuelve (status, answers) de `dig @IP name rtype`."""
    out = subprocess.run(["dig", f"@{IP}", f"+time={timeout}", "+tries=1", name, rtype],
                         capture_output=True, text=True).stdout
    status = "?"
    for line in out.splitlines():
        if "status:" in line:
            status = line.split("status:")[1].split(",")[0].strip()
            break
    answers = []
    in_ans = False
    for line in out.splitlines():
        if line.startswith(";; ANSWER SECTION"):
            in_ans = True
            continue
        if in_ans:
            if line.strip() == "" or line.startswith(";;"):
                break
            parts = line.split()
            if len(parts) >= 5:
                answers.append(parts[-1])
    return status, answers


def get_dot(cookie):
    sc, b, _ = req("GET", "/api/dot", cookie=cookie)
    return sc, (json.loads(b) if sc == 200 else {})


def put_dot(cookie, enabled, sni=None):
    body = {"enabled": "true" if enabled else "false"}
    if sni is not None:
        body["sni"] = sni
    return req("PUT", "/api/dot", json.dumps(body), cookie=cookie)


print(f"== Verificación DoT contra {IP} ==")
cookie = login()
if not cookie:
    print("No se pudo iniciar sesión (¿password correcto?). Aborto.")
    sys.exit(1)

# OT-02: sin sesión -> 401
sc, _, _ = req("GET", "/api/dot")
check("OT-02  GET /api/dot sin sesión -> 401", sc == 401, f"({sc})")

# OT-01: DoT off por defecto; el reenvío es UDP en claro
sc, d = get_dot(cookie)
check("OT-01  GET /api/dot -> enabled=false (defecto)", sc == 200 and d.get("enabled") is False,
      f"(enabled={d.get('enabled')})")
st, ans = dig("example.com")
check("OT-01  dig example.com resuelve por UDP (DoT off)", st == "NOERROR" and len(ans) > 0,
      f"(status={st}, {len(ans)} resp)")

# OT-03: activar DoT (SNI por defecto) -> resuelve por DoT; connected=true
sc, _, _ = put_dot(cookie, True)
check("OT-03  PUT /api/dot {enabled:true} -> 200", sc == 200, f"({sc})")
time.sleep(1)
st, ans = dig("cloudflare.com")   # dispara la conexión TLS y resuelve
check("OT-03  dig resuelve con DoT activo", st == "NOERROR" and len(ans) > 0,
      f"(status={st}, {len(ans)} resp)")
time.sleep(1)
sc, d = get_dot(cookie)
check("OT-03  GET /api/dot -> connected=true", d.get("connected") is True,
      f"(connected={d.get('connected')}, active={d.get('active')}, served={d.get('served')}, err={d.get('last_error')})")

# OT-04: el bloqueo es previo al reenvío -> sigue bloqueando con DoT activo
st, ans = dig("doubleclick.net")
check("OT-04  dig doubleclick.net -> bloqueado (0.0.0.0) con DoT activo",
      "0.0.0.0" in ans, f"(resp={ans})")

# OT-05: 2ª consulta del mismo dominio -> caché (resuelve igual)
st2, ans2 = dig("cloudflare.com")
check("OT-05  repetición resuelve (caché)", st2 == "NOERROR" and len(ans2) > 0,
      f"(status={st2})")

# OT-07: failover -> SNI[0] inválido, resto válidos -> sigue resolviendo cifrado
sc, _, _ = put_dot(cookie, True,
                   ["invalid.esphole.test", "dns.quad9.net", "one.one.one.one", "dns.quad9.net"])
time.sleep(1)
st, ans = dig("mozilla.org")
check("OT-07  failover al siguiente resolvedor cifrado -> resuelve",
      st == "NOERROR" and len(ans) > 0, f"(status={st}, {len(ans)} resp)")

# OT-06: FAIL-CLOSED -> TODOS los SNI inválidos -> ningún resolvedor cifrado válido
#        -> SERVFAIL, jamás una respuesta en claro. El primer ciclo con TODO caído
#        recorre los N upstreams (unos segundos); el cortacircuitos hace instantáneas
#        las siguientes. Damos margen (+time=12) para observar ese SERVFAIL.
sc, _, _ = put_dot(cookie, True, ["x.invalid.test"] * 4)
time.sleep(1)
st, ans = dig("wikipedia.org", timeout=12)
check("OT-06  fail-closed: DoT roto -> SERVFAIL (NO cae a claro)",
      st == "SERVFAIL" and len(ans) == 0, f"(status={st}, resp={ans})")
# y ahora, con el cortacircuitos armado, una 2ª debe ser SERVFAIL inmediato
st2, ans2 = dig("example.org")
check("OT-06  cortacircuitos: 2ª consulta SERVFAIL inmediato (sin claro)",
      st2 == "SERVFAIL" and len(ans2) == 0, f"(status={st2}, resp={ans2})")
sc, d = get_dot(cookie)
check("OT-06  estado muestra el error / no conectado",
      d.get("connected") is False and d.get("servfail", 0) >= 1,
      f"(connected={d.get('connected')}, servfail={d.get('servfail')}, err={d.get('last_error')})")

# OT-09: desactivar -> vuelve a UDP en claro; resuelve; persiste
sc, _, _ = put_dot(cookie, False, ["one.one.one.one", "dns.quad9.net",
                                    "one.one.one.one", "dns.quad9.net"])
check("OT-09  PUT {enabled:false} -> 200", sc == 200, f"({sc})")
time.sleep(1)
st, ans = dig("example.net")
check("OT-09  dig resuelve por UDP tras desactivar", st == "NOERROR" and len(ans) > 0,
      f"(status={st}, {len(ans)} resp)")
sc, d = get_dot(cookie)
check("OT-09  GET /api/dot -> enabled=false (persistió)", d.get("enabled") is False,
      f"(enabled={d.get('enabled')})")

print(f"\n== {PASS} PASS / {FAIL} FALL ==")
sys.exit(1 if FAIL else 0)
