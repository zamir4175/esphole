#!/usr/bin/env bash
# T028 — Batería de conformidad end-to-end contra el ESPHole real.
# Uso: ./conformance.sh [IP]   (defecto 192.168.1.10)
#
# Cubre los CB automatizables desde el host. Los que requieren manipular
# upstreams (CB-21/22/23/25), tráfico WAN (CB-41) o captura entre el
# dispositivo y el upstream (CB-34) quedan como MANUAL al final.
# El flood de rate-limit va EL ÚLTIMO: agota tokens del host.
set -u
IP="${1:-192.168.1.10}"
DIG="dig @$IP +time=4 +tries=1"
PASS=0; FAIL=0; SKIP=0

ok()   { PASS=$((PASS+1)); printf "  \e[32mPASS\e[0m %s\n" "$1"; }
bad()  { FAIL=$((FAIL+1)); printf "  \e[31mFAIL\e[0m %s — %s\n" "$1" "$2"; }
skip() { SKIP=$((SKIP+1)); printf "  \e[33mMANUAL\e[0m %s\n" "$1"; }

qtime() { grep -oP 'Query time: \K[0-9]+' <<<"$1"; }

echo "== ESPHole conformidad contra $IP =="

# ---------- CB-1x: bloqueo y resolución ----------
r=$($DIG doubleclick.net A)
if grep -q "0.0.0.0" <<<"$r" && grep -qP "doubleclick\.net\.\s+30\s+IN\s+A" <<<"$r" \
   && grep -q "flags: qr aa" <<<"$r"; then ok "CB-10 bloqueado A → 0.0.0.0, TTL 30, AA"
else bad "CB-10" "$(grep -E 'status|IN' <<<"$r" | head -2)"; fi

r=$($DIG doubleclick.net AAAA)
if grep -qP "IN\s+AAAA\s+::$" <<<"$r"; then ok "CB-11 bloqueado AAAA → ::"
else bad "CB-11" "sin :: en la respuesta"; fi

r=$($DIG ads.stats.doubleclick.net A)
grep -q "0.0.0.0" <<<"$r" && ok "CB-12 subdominio bloqueado" || bad "CB-12" "no bloqueado"

r=$($DIG notdoubleclick.net A)
if ! grep -q "0.0.0.0" <<<"$r" && grep -qE "status: (NOERROR|NXDOMAIN)" <<<"$r"; then
  ok "CB-13 sufijo solo textual NO bloqueado (reenviado)"
else bad "CB-13" "$(grep status <<<"$r")"; fi

r=$($DIG example.org A)
if grep -q "status: NOERROR" <<<"$r" && grep -qP "example\.org\.\s+\d+\s+IN\s+A\s+\d" <<<"$r" \
   && grep -q "flags: qr rd ra" <<<"$r"; then ok "CB-14+CB-35 permitido → respuesta íntegra, RD/RA"
else bad "CB-14" "$(grep -E 'status|flags' <<<"$r")"; fi

r=$($DIG doubleclick.net MX)
if grep -q "status: NOERROR" <<<"$r" && grep -q "ANSWER: 0" <<<"$r"; then
  ok "CB-15 bloqueado con tipo≠A/AAAA → NOERROR sin datos"
else bad "CB-15" "$(grep -E 'status|ANSWER' <<<"$r")"; fi

r=$($DIG gmail.com MX)
if grep -q "status: NOERROR" <<<"$r" && grep -qP "IN\s+MX\s+\d" <<<"$r"; then
  ok "CB-16 tipo no gestionado permitido → íntegro"
else bad "CB-16" "sin registros MX"; fi

# CB-17: QDCOUNT=2 bien formada → passthrough íntegro. (Con QDCOUNT=0 el
# upstream la DESCARTA —verificado contra 1.1.1.1— y no habría nada que relayar.)
r=$(python3 - "$IP" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
pkt = (bytes.fromhex("beef010000020000000000000161000001000101")
       + b"\x01b\x00\x00\x01\x00\x01")  # 2 preguntas: a. y b.
s.sendto(pkt, (sys.argv[1], 53))
try:
    d, _ = s.recvfrom(512)
    print("REPLY" if d[:2] == b"\xbe\xef" else "BADID")
except socket.timeout:
    print("TIMEOUT")
EOF
)
[ "$r" = "REPLY" ] && ok "CB-17 QDCOUNT≠1 reenviada íntegra (respuesta del upstream con nuestro ID)" \
                   || bad "CB-17" "$r"

# ---------- CB-24: errores del upstream se propagan ----------
r=$($DIG dominio-inexistente-esphole-t028.org A)
grep -q "status: NXDOMAIN" <<<"$r" && ok "CB-24 NXDOMAIN del upstream propagado" \
                                    || bad "CB-24" "$(grep status <<<"$r")"

# ---------- CB-5x: caché ----------
r1=$($DIG cache-test-t028.example.org A); t1=$(qtime "$r1")
r2=$($DIG cache-test-t028.example.org A); t2=$(qtime "$r2")
r3=$($DIG cache-test-t028.example.org A); t3=$(qtime "$r3")
tmin=$t2; [ -n "$t3" ] && [ "$t3" -lt "${tmin:-999}" ] && tmin=$t3
if [ -n "$tmin" ] && [ "$tmin" -le 25 ]; then
  ok "CB-50 acierto de caché (1ª ${t1} ms → repetida ${tmin} ms, sin upstream)"
else bad "CB-50" "repetida ${tmin:-?} ms"; fi

# CB-55: 30 consultas concurrentes idénticas no cacheadas → todas respondidas
r=$(python3 - "$IP" <<'EOF'
import socket, sys, threading
ip = sys.argv[1]; got = []
def q(i):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    name = b"\x08dedupe28\x07example\x03org\x00"
    pkt = i.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x01\x00\x01"
    s.sendto(pkt, (ip, 53))
    try:
        d, _ = s.recvfrom(1500)
        if d[:2] == i.to_bytes(2, "big"): got.append(i)
    except socket.timeout: pass
ts = [threading.Thread(target=q, args=(i,)) for i in range(1, 31)]
[t.start() for t in ts]; [t.join() for t in ts]
print(len(got))
EOF
)
if [ "${r:-0}" -ge 25 ]; then ok "CB-55 dedupe: $r/30 concurrentes idénticas respondidas (con su ID)"
else bad "CB-55" "solo $r/30 respondidas"; fi

# ---------- CB-3x: EDNS, TC y TCP ----------
r=$($DIG +bufsize=1232 google.com TXT)
if grep -q "status: NOERROR" <<<"$r" && ! grep -qP "flags:[^;]*\btc\b" <<<"$r"; then
  ok "CB-30 respuesta grande por UDP con EDNS (sin TC)"
else bad "CB-30" "$(grep flags <<<"$r" | head -1)"; fi

# CB-31: forzar TC con bufsize 512 en una respuesta >512 y reintentar por TCP
big=""
for cand in cloudflare.com google.com _dmarc.google.com; do
  n=$($DIG +tcp $cand TXT | grep -c "IN.TXT") || true
  sz=$($DIG +tcp $cand TXT | grep -oP 'MSG SIZE.*rcvd: \K[0-9]+')
  if [ -n "$sz" ] && [ "$sz" -gt 512 ]; then big=$cand; break; fi
done
if [ -n "$big" ]; then
  r=$($DIG +bufsize=512 +ignore $big TXT)
  rt=$($DIG +tcp $big TXT)
  if grep -qP "flags:[^;]*\btc\b" <<<"$r" && grep -q "status: NOERROR" <<<"$rt"; then
    ok "CB-31 TC=1 con payload 512 y respuesta completa por TCP ($big)"
  else bad "CB-31" "tc:$(grep -c tc <<<"$r") tcp:$(grep status <<<"$rt")"; fi
else skip "CB-31 (ningún candidato con respuesta >512 B ahora mismo)"; fi

r=$($DIG +tcp doubleclick.net A); r2=$($DIG +tcp example.org A)
if grep -q "0.0.0.0" <<<"$r" && grep -q "status: NOERROR" <<<"$r2"; then
  ok "CB-32 TCP: misma resolución (bloqueo + reenvío)"
else bad "CB-32" "tcp falló"; fi

# CB-33: tope de conexiones TCP concurrentes (4): la 5ª se cierra, las activas siguen
r=$(python3 - "$IP" <<'EOF'
import socket, sys
ip = sys.argv[1]
def conn():
    s = socket.socket(); s.settimeout(4); s.connect((ip, 53)); return s
def query(s, qid):
    name = b"\x0bdoubleclick\x03net\x00"
    m = qid.to_bytes(2,"big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x01\x00\x01"
    s.send(len(m).to_bytes(2,"big") + m)
    try:
        hdr = s.recv(2)
        if len(hdr) < 2: return "CLOSED"
        need = int.from_bytes(hdr,"big"); d = b""
        while len(d) < need: d += s.recv(need - len(d))
        return "ANSWER"
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        return "NONE"
cs = [conn() for _ in range(4)]
extra = conn()                     # 5ª: el firmware la cierra al aceptarla
quinta = query(extra, 99)
primera = query(cs[0], 1)          # las activas no se ven afectadas
print(f"{quinta}/{primera}")
for s in cs + [extra]:
    try: s.close()
    except OSError: pass
EOF
)
case "$r" in
  CLOSED/ANSWER|NONE/ANSWER) ok "CB-33 5ª conexión rechazada limpiamente; activas OK ($r)" ;;
  *) bad "CB-33" "$r" ;;
esac

# ---------- CB-40: malformadas ----------
r=$(python3 - "$IP" <<'EOF'
import socket, sys
ip = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.5)
for basura in (b"\x00", b"A"*13, bytes.fromhex("12340100000100000000000040") + b"x"*20):
    s.sendto(basura, (ip, 53))
    try:
        s.recvfrom(512); print("REPLIED"); sys.exit()
    except socket.timeout: pass
# y el servicio sigue vivo (con reintentos: la ráfaga puede dejar jitter Wi-Fi)
import time
name = b"\x0bdoubleclick\x03net\x00"
s.settimeout(3)
for intento in range(3):
    qid = (0x7700 + intento).to_bytes(2, "big")
    pkt = qid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x01\x00\x01"
    s.sendto(pkt, (ip, 53))
    try:
        d, _ = s.recvfrom(512)
        if d[:2] == qid:
            print("SILENT_ALIVE"); sys.exit()
    except socket.timeout:
        time.sleep(1)
print("DEAD")
EOF
)
[ "$r" = "SILENT_ALIVE" ] && ok "CB-40 malformadas descartadas en silencio; servicio vivo" \
                          || bad "CB-40" "$r"

# ---------- CB-42/43: rate limit (VA EL ÚLTIMO) ----------
r=$(python3 - "$IP" <<'EOF'
import socket, sys, time
ip = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.05)
name = b"\x0bdoubleclick\x03net\x00"
sent, answered = 300, 0
for i in range(sent):
    pkt = i.to_bytes(2,"big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x01\x00\x01"
    s.sendto(pkt, (ip, 53))
s.settimeout(0.3)
try:
    while True:
        s.recvfrom(512); answered += 1
except socket.timeout: pass
time.sleep(2.5)  # recarga: 2.5 s × 50/s
s.settimeout(3)
rec = "STUCK"
for intento in range(3):  # tolera jitter post-ráfaga
    qid = (0x5500 + intento).to_bytes(2, "big")
    pkt = qid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x01\x00\x01"
    s.sendto(pkt, (ip, 53))
    try:
        d, _ = s.recvfrom(512)
        if d[:2] == qid:
            rec = "RECOVERED"; break
    except socket.timeout:
        time.sleep(1.5)
print(f"{answered}/{sent} {rec}")
EOF
)
ans=${r%%/*}; rest=${r#* }
if [ "$ans" -lt 280 ] && [ "$ans" -ge 50 ] && [ "$rest" = "RECOVERED" ]; then
  ok "CB-42/43 flood limitado ($r): exceso descartado en silencio y recuperación"
else bad "CB-42/43" "$r"; fi

# ---------- manuales / diferidos ----------
skip "CB-20 lista CARGANDO ⇒ reenvío puro (verificado unitario + por orden de arranque)"
skip "CB-21/22/23 failover verificado a mano (primario 192.0.2.1: 1ª ~2.3s, tras 3 fallos CAIDO → secundario ~0.2s directo). Automatizable con la config API (spec 003)"
skip "CB-25 recuperación del primario tras backoff 30s (sondeo con tráfico real)"
skip "CB-26 desalojo de pendientes bajo flood sostenido (unitario)"
skip "CB-34 preservación del OPT hacia upstream (requiere captura en la ruta)"
skip "CB-41 origen WAN ignorado (requiere emitir desde fuera de la subred)"

echo
echo "== resultado: $PASS PASS, $FAIL FAIL, $SKIP manuales =="
exit $((FAIL > 0))
