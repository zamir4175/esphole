import sys, json, time, threading, subprocess, hashlib, hmac, urllib.request, urllib.error

IP="192.168.1.10"; PC="192.168.1.20:8000"; BASE=f"http://{IP}"; PW="esphole-admin-2026"; KDF=30000
ok_all=True
def check(l,c,e=""):
    global ok_all; ok_all=ok_all and c; print(f"[{'PASS' if c else 'FALL'}] {l} {e}")
def req(m,p,body=None,cookie=None,timeout=15):
    r=urllib.request.Request(BASE+p,data=body.encode() if body else None,method=m)
    if body: r.add_header("Content-Type","application/json")
    if cookie: r.add_header("Cookie",cookie)
    try:
        rp=urllib.request.urlopen(r,timeout=timeout); return rp.getcode(),rp.read().decode(),rp.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e: return e.code,e.read().decode(),None
def cook(s): return s.split(";")[0] if s else None
def login():
    sc,_,setc=req("POST","/api/setup",json.dumps({"password":PW}))
    if sc==200: return cook(setc)
    _,b,_=req("GET","/api/challenge"); ch=json.loads(b)
    key=hashlib.pbkdf2_hmac("sha256",PW.encode(),bytes.fromhex(ch["salt"]),KDF,32)
    resp=hmac.new(key,ch["nonce"].encode(),hashlib.sha256).hexdigest()
    _,_,lc=req("POST","/api/login",json.dumps({"nonce":ch["nonce"],"resp":resp})); return cook(lc)
def wait_up(t=60):
    t0=time.time()
    while time.time()-t0<t:
        try:
            if req("GET","/",timeout=3)[0]==200: return True
        except Exception: pass
        time.sleep(1)
    return False
def dig(n):
    return subprocess.run(["dig","+short","+time=2","+tries=1",f"@{IP}",n],capture_output=True,text=True,timeout=6).stdout.strip()

cookie=login()
sc,b,_=req("GET","/api/firmware",cookie=cookie); j=json.loads(b)
slot0=j.get("slot"); ver0=j.get("version")
print(f"estado inicial: ranura {slot0}, versión {ver0}")

# OB-10: aislamiento — dig martillando durante la descarga de bad.bin
stop=threading.Event(); lat=[]; fails=[0]
def hammer():
    while not stop.is_set():
        t0=time.time(); r=dig("example.com" if int(t0)%2 else "google.com")
        (lat.append((time.time()-t0)*1000) if r else fails.__setitem__(0,fails[0]+1))
        time.sleep(0.25)
th=threading.Thread(target=hammer); th.start()

# OB-08: OTA a la imagen mala (aborta al arrancar a prueba → rollback)
sc,b,_=req("POST","/api/firmware/update",json.dumps({"url":f"http://{PC}/bad.bin"}),cookie=cookie)
check("OB-08 update bad.bin -> 202",sc==202,f"({sc})")
# OB-09: segunda petición mientras descarga -> 409
time.sleep(1.0)
sc2,_,_=req("POST","/api/firmware/update",json.dumps({"url":f"http://{PC}/esphole.bin"}),cookie=cookie)
check("OB-09 segunda OTA en curso -> 409",sc2==409,f"({sc2})")
# esperar a que descargue y reinicie (la conexión cae)
t0=time.time()
while time.time()-t0<90:
    try:
        s=req("GET","/api/firmware",cookie=cookie,timeout=3)
        if s[0]!=200: pass
    except Exception:
        break  # reinició en bad.bin
    time.sleep(1)
stop.set(); th.join()
# los digs contados son durante la descarga (antes del reinicio)
lat.sort(); p95=lat[int(len(lat)*0.95)] if lat else 9999
check("OB-10 DNS no se degrada durante la descarga OTA", fails[0]==0 and p95<1500,
      f"({len(lat)} digs, {fails[0]} fallos, p95={p95:.0f}ms)")

print("    imagen mala arrancó a prueba y abortó; esperando el rollback…")
time.sleep(8)
up=wait_up(70)
check("dispositivo accesible tras el rollback",up)
cookie=login()
sc,b,_=req("GET","/api/firmware",cookie=cookie); j=json.loads(b) if sc==200 else {}
check("OB-08 revirtió a la ranura buena anterior", j.get("slot")==slot0, f"(slot={j.get('slot')} esperado {slot0})")
check("OB-08 versión buena restaurada", j.get("version")==ver0, f"(v={j.get('version')})")
# estable: DNS resuelve
check("tras rollback DNS resuelve", dig("google.com") not in ("","0.0.0.0"))

print("\nRESULTADO:", "TODO VERDE" if ok_all else "HAY FALLOS")
sys.exit(0 if ok_all else 1)
