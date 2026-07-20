import json,hashlib,hmac,urllib.request,urllib.error,sys
IP="192.168.1.10";BASE=f"http://{IP}";PW="esphole-admin-2026";KDF=30000
ok=True
def ck(l,c,e=""):
    global ok; ok=ok and c; print(f"[{'PASS' if c else 'FALL'}] {l} {e}")
def req(m,p,body=None,cookie=None):
    r=urllib.request.Request(BASE+p,data=body.encode() if body else None,method=m)
    if body:r.add_header("Content-Type","application/json")
    if cookie:r.add_header("Cookie",cookie)
    try:
        rp=urllib.request.urlopen(r,timeout=10);return rp.getcode(),rp.read().decode(),rp.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e:return e.code,e.read().decode(),None
def login():
    _,b,_=req("GET","/api/challenge");ch=json.loads(b)
    key=hashlib.pbkdf2_hmac("sha256",PW.encode(),bytes.fromhex(ch["salt"]),KDF,32)
    resp=hmac.new(key,ch["nonce"].encode(),hashlib.sha256).hexdigest()
    _,_,lc=req("POST","/api/login",json.dumps({"nonce":ch["nonce"],"resp":resp}))
    return lc.split(";")[0] if lc else None
c=login(); ck("login",c is not None)
# DB-01: off por defecto
sc,b,_=req("GET","/api/dhcp",cookie=c); j=json.loads(b)
ck("DB-01 DHCP off por defecto", sc==200 and j.get("enabled")==False, f"(enabled={j.get('enabled')})")
# DB-07: rango inválido (start>end) → 400, SIN activar el servidor
sc,b,_=req("PUT","/api/dhcp",json.dumps({"enabled":"true","pool_start":"192.168.1.200","pool_end":"192.168.1.100"}),cookie=c)
ck("DB-07 rango inválido -> 400", sc==400, f"({sc} {b.strip()})")
# IP malformada → 400
sc,_,_=req("PUT","/api/dhcp",json.dumps({"enabled":"true","pool_start":"999.1.1.1"}),cookie=c)
ck("DB-07 IP malformada -> 400", sc==400, f"({sc})")
# sigue apagado (no se activó nada)
sc,b,_=req("GET","/api/dhcp",cookie=c); j=json.loads(b)
ck("tras los 400 el DHCP sigue apagado", j.get("enabled")==False)
print("\nRESULTADO:", "TODO VERDE" if ok else "HAY FALLOS")
sys.exit(0 if ok else 1)
