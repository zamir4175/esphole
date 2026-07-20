import sys, json, time, threading, subprocess, urllib.request, urllib.error

IP = "192.168.1.10"
BASE = f"http://{IP}"
PW = "esphole-admin-2026"
SB = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

ok_all = True
def check(label, cond, extra=""):
    global ok_all; ok_all = ok_all and cond
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

def dig(name):
    return subprocess.run(["dig","+short","+time=2","+tries=1",f"@{IP}",name],
                          capture_output=True,text=True,timeout=6).stdout.strip()

# --- sesión (SETUP) ---
sc, b, setc = req("POST","/api/setup", json.dumps({"password":PW}))
cookie = setc.split(";")[0] if setc else None
check("setup -> sesión", sc==200 and cookie, f"({sc})")

# LB-02: sin sesión -> 401
sc,_,_ = req("GET","/api/blocklist")
check("LB-02 sin sesión -> 401", sc==401, f"({sc})")

# LB-01: estado inicial (lista previa de la partición)
sc,b,_ = req("GET","/api/blocklist", cookie=cookie)
j = json.loads(b) if sc==200 else {}
count0 = j.get("count",0)
check("LB-01 GET blocklist", sc==200 and count0>0 and j.get("url","").startswith("http"),
      f"(count={count0}, url={j.get('url','')[:40]}…)")

# LB-05: URL inválida -> 400, url previa intacta
sc,_,_ = req("PUT","/api/blocklist", json.dumps({"url":"ftp://malo/x"}), cookie=cookie)
check("LB-05 PUT esquema inválido -> 400", sc==400, f"({sc})")
sc,b,_ = req("GET","/api/blocklist", cookie=cookie)
check("LB-05 url previa intacta", json.loads(b).get("url","").startswith("http"))

def poll(timeout):
    t0=time.time()
    while time.time()-t0 < timeout:
        sc,b,_ = req("GET","/api/blocklist", cookie=cookie)
        if sc==200:
            j=json.loads(b)
            if not j.get("en_curso"): return j
        time.sleep(2)
    return None

# LB-06: host que no resuelve -> ERROR, lista previa intacta
sc,b,_ = req("POST","/api/blocklist/update", json.dumps({"url":"https://noexiste.invalid/hosts"}), cookie=cookie)
check("LB-06 update host inválido -> 202", sc==202, f"({sc} {b.strip()})")
j = poll(40)
check("LB-06 termina en error", j is not None and j.get("estado")=="error", f"({j.get('estado') if j else 'timeout'}: {j.get('error') if j else ''})")
check("LB-06 lista previa intacta (count)", j is not None and j.get("count")==count0, f"(count={j.get('count') if j else '?'} vs {count0})")
check("LB-06 dig sigue bloqueando", dig("doubleclick.net")=="0.0.0.0")

# restaurar la URL por defecto para LB-03
req("PUT","/api/blocklist", json.dumps({"url":SB}), cookie=cookie)

# LB-03 + LB-09: actualización real desde StevenBlack, con dig martillando (aislamiento)
print("--- LB-03: actualizando desde StevenBlack (puede tardar ~1-2 min) ---")
stop=threading.Event(); lat=[]; fails=[0]
def hammer():
    while not stop.is_set():
        t0=time.time(); r=dig("example.com" if int(t0)%2 else "wikipedia.org")
        (lat.append((time.time()-t0)*1000) if r else fails.__setitem__(0,fails[0]+1))
        time.sleep(0.3)
th=threading.Thread(target=hammer); th.start()
sc,b,_ = req("POST","/api/blocklist/update", json.dumps({"url":SB}), cookie=cookie)
check("LB-03 update StevenBlack -> 202", sc==202, f"({sc})")
j = poll(180)
stop.set(); th.join()
check("LB-03 termina OK", j is not None and j.get("estado")=="ok", f"({j.get('estado') if j else 'timeout'})")
cnt = j.get("count") if j else 0
check("LB-03 count grande (~40k)", cnt>30000, f"(count={cnt})")
check("LB-03 dig doubleclick bloqueado", dig("doubleclick.net")=="0.0.0.0")
check("LB-03 dig example.com resuelve", dig("example.com") not in ("","0.0.0.0"))
lat.sort()
p95 = lat[int(len(lat)*0.95)] if lat else 9999
check("LB-09 DNS no se degrada durante la descarga", fails[0]==0 and p95<1500,
      f"({len(lat)} digs, {fails[0]} fallos, p95={p95:.0f}ms)")

print("\nRESULTADO:", "TODO VERDE" if ok_all else "HAY FALLOS")
print(f"(count final: {cnt})")
sys.exit(0 if ok_all else 1)
