import sys, json, time, hashlib, hmac, subprocess, urllib.request, urllib.error

IP = "192.168.1.10"
PC = "192.168.1.20:8000"
BASE = f"http://{IP}"
PW = "esphole-admin-2026"
KDF = 30000

ok_all = True
def check(label, cond, extra=""):
    global ok_all; ok_all = ok_all and cond
    print(f"[{'PASS' if cond else 'FALL'}] {label} {extra}")

def req(method, path, body=None, cookie=None, timeout=15):
    r = urllib.request.Request(BASE+path, data=body.encode() if body else None, method=method)
    if body: r.add_header("Content-Type","application/json")
    if cookie: r.add_header("Cookie", cookie)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        return resp.getcode(), resp.read().decode(), resp.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), None

def cook(sc): return sc.split(";")[0] if sc else None

def login():
    # setup si SETUP, si no challenge-response
    scc,_,setc = req("POST","/api/setup", json.dumps({"password":PW}))
    if scc==200: return cook(setc)
    _,b,_ = req("GET","/api/challenge")
    ch = json.loads(b)
    key = hashlib.pbkdf2_hmac("sha256", PW.encode(), bytes.fromhex(ch["salt"]), KDF, 32)
    resp = hmac.new(key, ch["nonce"].encode(), hashlib.sha256).hexdigest()
    _,_,lc = req("POST","/api/login", json.dumps({"nonce":ch["nonce"],"resp":resp}))
    return cook(lc)

def wait_up(timeout=40):
    t0=time.time()
    while time.time()-t0<timeout:
        try:
            sc,_,_ = req("GET","/", timeout=3)
            if sc==200: return True
        except Exception: pass
        time.sleep(1)
    return False

cookie = login()
check("sesión", cookie is not None)

# OB-02 sin sesión
sc,_,_ = req("GET","/api/firmware")
check("OB-02 sin sesión -> 401", sc==401, f"({sc})")

# OB-01 versión + slot
sc,b,_ = req("GET","/api/firmware", cookie=cookie)
j = json.loads(b) if sc==200 else {}
slot0 = j.get("slot")
check("OB-01 GET firmware", sc==200 and slot0 in ("ota_0","ota_1"),
      f"(v={j.get('version')}, slot={slot0})")

# OB-03 esquema inválido
sc,_,_ = req("POST","/api/firmware/update", json.dumps({"url":"ftp://x/f.bin"}), cookie=cookie)
check("OB-03 esquema inválido -> 400", sc==400, f"({sc})")

def poll_ota(timeout):
    t0=time.time(); last=None
    while time.time()-t0<timeout:
        try:
            sc,b,_ = req("GET","/api/firmware", cookie=cookie, timeout=4)
            if sc==200:
                j=json.loads(b); last=j
                if not j.get("en_curso"): return j
        except Exception:
            return last  # probablemente reinició
        time.sleep(1)
    return last

# OB-07 descarga fallida (404) -> error, firmware intacto
sc,b,_ = req("POST","/api/firmware/update", json.dumps({"url":f"http://{PC}/nope.bin"}), cookie=cookie)
check("OB-07 update 404 -> 202", sc==202, f"({sc})")
j = poll_ota(30)
check("OB-07 termina en error", j and j.get("estado")=="error", f"({j.get('estado') if j else '?'}: {j.get('error') if j else ''})")
check("OB-07 sigue en la misma ranura", j and j.get("slot")==slot0)

# OB-06 imagen inválida (200 pero no es app) -> error, no reinicia
sc,_,_ = req("POST","/api/firmware/update", json.dumps({"url":f"http://{PC}/notanapp.bin"}), cookie=cookie)
check("OB-06 update imagen inválida -> 202", sc==202, f"({sc})")
j = poll_ota(30)
check("OB-06 termina en error (imagen inválida)", j and j.get("estado")=="error", f"({j.get('error') if j else '?'})")
check("OB-06 firmware intacto (misma ranura)", j and j.get("slot")==slot0)

# OB-04 actualización real -> descarga -> reinicio en la otra ranura
print(f"--- OB-04: OTA real desde http://{PC}/esphole.bin (ranura actual {slot0}) ---")
sc,b,_ = req("POST","/api/firmware/update", json.dumps({"url":f"http://{PC}/esphole.bin"}), cookie=cookie)
check("OB-04 update válido -> 202", sc==202, f"({sc})")
# poll durante la descarga hasta que reinicie (las peticiones empiezan a fallar)
t0=time.time(); vio_download=False
while time.time()-t0<90:
    try:
        sc,b,_ = req("GET","/api/firmware", cookie=cookie, timeout=3)
        if sc==200:
            j=json.loads(b)
            if j.get("estado")=="downloading": vio_download=True
            if j.get("estado")=="done": break
    except Exception:
        break  # reinició
    time.sleep(1)
check("OB-04 pasó por DOWNLOADING", vio_download)
print("    esperando reinicio en la ranura nueva…")
time.sleep(6)
up = wait_up(50)
check("OB-04 vuelve a estar accesible", up)
cookie = login()
sc,b,_ = req("GET","/api/firmware", cookie=cookie)
j = json.loads(b) if sc==200 else {}
slot1 = j.get("slot")
esperado = "ota_1" if slot0=="ota_0" else "ota_0"
check("OB-04/05 arrancó en la OTRA ranura", slot1==esperado, f"({slot0} -> {slot1})")

# OB-05 confirmación: un reset NO debe revertir (ranura confirmada válida)
print("    reset físico para comprobar que NO revierte (confirmada)…")
subprocess.run([sys.executable,"-m","esptool","-p","/dev/ttyACM0","--after","hard-reset","chip_id"],
               capture_output=True, timeout=30)
wait_up(50)
cookie = login()
sc,b,_ = req("GET","/api/firmware", cookie=cookie)
j = json.loads(b) if sc==200 else {}
check("OB-05 tras reset sigue en la ranura nueva (confirmada, no revierte)",
      j.get("slot")==esperado, f"(slot={j.get('slot')})")

print("\nRESULTADO:", "TODO VERDE" if ok_all else "HAY FALLOS")
sys.exit(0 if ok_all else 1)
