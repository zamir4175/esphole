"use strict";
/*
 * ESPHole — cliente de la interfaz de administración.
 * El login es por desafío-respuesta: la contraseña NUNCA se envía. Se calcula
 * key = PBKDF2-HMAC-SHA256(pass, salt, ITERS) y resp = HMAC-SHA256(key, nonce),
 * igual que el dispositivo (mbedTLS). No se usa crypto.subtle porque solo existe
 * en contexto seguro (HTTPS/localhost) y aquí servimos HTTP plano en la LAN:
 * SHA-256, HMAC y PBKDF2 van en JS puro.
 */

/* DEBE coincidir con WEBAPI_KDF_ITERS del dispositivo (webapi.c). */
const KDF_ITERS = 30000;

/* ---- SHA-256 (FIPS 180-4), sobre Uint8Array ---- */
function sha256(msg) {
  const K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  let h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                           0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  const l = msg.length;
  const bitLen = l * 8;
  let total = l + 1;
  while (total % 64 !== 56) total++;
  total += 8;
  const buf = new Uint8Array(total);
  buf.set(msg);
  buf[l] = 0x80;
  // longitud en bits, 64-bit big-endian (l<2^29 ⇒ los 4 bytes altos son 0)
  buf[total-4] = (bitLen >>> 24) & 0xff;
  buf[total-3] = (bitLen >>> 16) & 0xff;
  buf[total-2] = (bitLen >>> 8) & 0xff;
  buf[total-1] = bitLen & 0xff;
  const w = new Uint32Array(64);
  const ror = (x,n) => (x >>> n) | (x << (32-n));
  for (let off=0; off<total; off+=64) {
    for (let i=0;i<16;i++)
      w[i] = (buf[off+i*4]<<24)|(buf[off+i*4+1]<<16)|(buf[off+i*4+2]<<8)|buf[off+i*4+3];
    for (let i=16;i<64;i++) {
      const s0 = ror(w[i-15],7)^ror(w[i-15],18)^(w[i-15]>>>3);
      const s1 = ror(w[i-2],17)^ror(w[i-2],19)^(w[i-2]>>>10);
      w[i] = (w[i-16]+s0+w[i-7]+s1)>>>0;
    }
    let a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (let i=0;i<64;i++) {
      const S1 = ror(e,6)^ror(e,11)^ror(e,25);
      const ch = (e&f)^(~e&g);
      const t1 = (hh+S1+ch+K[i]+w[i])>>>0;
      const S0 = ror(a,2)^ror(a,13)^ror(a,22);
      const maj = (a&b)^(a&c)^(b&c);
      const t2 = (S0+maj)>>>0;
      hh=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
    }
    h[0]=(h[0]+a)>>>0; h[1]=(h[1]+b)>>>0; h[2]=(h[2]+c)>>>0; h[3]=(h[3]+d)>>>0;
    h[4]=(h[4]+e)>>>0; h[5]=(h[5]+f)>>>0; h[6]=(h[6]+g)>>>0; h[7]=(h[7]+hh)>>>0;
  }
  const out = new Uint8Array(32);
  for (let i=0;i<8;i++) {
    out[i*4]=(h[i]>>>24)&0xff; out[i*4+1]=(h[i]>>>16)&0xff;
    out[i*4+2]=(h[i]>>>8)&0xff; out[i*4+3]=h[i]&0xff;
  }
  return out;
}

/* ---- HMAC-SHA256(key, msg) (RFC 2104) ---- */
function hmacSha256(key, msg) {
  if (key.length > 64) key = sha256(key);
  const k = new Uint8Array(64);
  k.set(key);
  const ipad = new Uint8Array(64), opad = new Uint8Array(64);
  for (let i=0;i<64;i++) { ipad[i]=k[i]^0x36; opad[i]=k[i]^0x5c; }
  const inner = sha256(concat(ipad, msg));
  return sha256(concat(opad, inner));
}

/* ---- PBKDF2-HMAC-SHA256, dkLen=32 (un solo bloque) ---- */
function pbkdf2Sha256(pass, salt, iters) {
  const blk = new Uint8Array(salt.length + 4);
  blk.set(salt); blk[salt.length + 3] = 1; // INT_32_BE(1)
  let u = hmacSha256(pass, blk);            // U1 = PRF(pass, salt‖1)
  const t = u.slice();
  for (let i = 1; i < iters; i++) {
    u = hmacSha256(pass, u);                 // Ui = PRF(pass, U(i-1))
    for (let j = 0; j < 32; j++) t[j] ^= u[j];
  }
  return t;
}

function concat(a, b) {
  const c = new Uint8Array(a.length + b.length);
  c.set(a); c.set(b, a.length);
  return c;
}
function hexToBytes(h) {
  const b = new Uint8Array(h.length/2);
  for (let i=0;i<b.length;i++) b[i] = parseInt(h.substr(i*2,2),16);
  return b;
}
function bytesToHex(b) {
  let s=""; for (let i=0;i<b.length;i++) s += b[i].toString(16).padStart(2,"0"); return s;
}
function strToBytes(s) { return new TextEncoder().encode(s); }

/* Nodo (test) o navegador */
if (typeof module !== "undefined" && module.exports) {
  module.exports = { sha256, hmacSha256, pbkdf2Sha256, hexToBytes, bytesToHex, strToBytes };
}

/* ================= UI (solo navegador) ================= */
if (typeof document !== "undefined") {
  const $ = (id) => document.getElementById(id);
  const show = (id) => {
    for (const s of ["setup","login","dash"]) $(s).hidden = (s !== id);
  };

  async function api(method, path, body) {
    const opt = { method, headers: {} };
    if (body) { opt.body = JSON.stringify(body); opt.headers["Content-Type"]="application/json"; }
    const r = await fetch(path, opt);
    let j = null;
    try { j = await r.json(); } catch (e) {}
    return { status: r.status, body: j };
  }

  async function checkState() {
    const st = await api("GET", "/api/status");
    if (st.status === 200) { startDash(); return; }
    const ch = await api("GET", "/api/challenge");
    if (ch.status === 409) show("setup"); else show("login");
  }

  // ---- setup ----
  $("setup-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const p = $("setup-pass").value, p2 = $("setup-pass2").value;
    const msg = $("setup-msg");
    if (p.length < 8) { msg.textContent = t("msg.min8"); return; }
    if (p !== p2) { msg.textContent = t("msg.pw_mismatch"); return; }
    msg.textContent = t("msg.creating");
    const r = await api("POST", "/api/setup", { password: p });
    if (r.status === 200) startDash();
    else msg.textContent = t("msg.error", (r.body && r.body.error) || r.status);
  });

  // ---- login ----
  $("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const p = $("login-pass").value;
    const msg = $("login-msg");
    msg.textContent = t("msg.signing_in");
    const ch = await api("GET", "/api/challenge");
    if (ch.status !== 200) { msg.textContent = t("msg.challenge_fail"); return; }
    const { nonce, salt } = ch.body;
    const key = pbkdf2Sha256(strToBytes(p), hexToBytes(salt), KDF_ITERS);
    const resp = bytesToHex(hmacSha256(key, strToBytes(nonce)));
    const r = await api("POST", "/api/login", { nonce, resp });
    if (r.status === 200) { $("login-pass").value=""; startDash(); }
    else msg.textContent = t("msg.wrong_pw");
  });

  // ---- dashboard ----
  let timer = null;
  const saludTxt = () => [t("health.ok"), t("health.susp"), t("health.down")];
  async function refresh() {
    const st = await api("GET", "/api/status");
    if (st.status === 401) { stopDash(); show("login"); return; }
    if (st.status !== 200) return;
    const s = st.body;
    const grid = $("cards");
    const card = (label,v,cls) => `<div class="card ${cls}"><div class="v">${v}</div><div class="t">${label}</div></div>`;
    grid.innerHTML =
      card(t("card.total"), s.total, "stat--queries") +
      card(t("card.blocked"), s.bloqueadas, "stat--blocked") +
      card(t("card.cache_hits"), s.cache_hits, "stat--cache") +
      card(t("card.forwarded"), s.reenviadas, "stat--forwarded") +
      card("SERVFAIL", s.servfail, "stat--servfail") +
      card(t("card.malformed"), s.malformadas, "stat--malformed") +
      card(t("card.heap"), (s.heap_libre/1024|0)+" KB", "stat--heap") +
      card(t("card.uptime"), fmtDur(s.uptime_s), "stat--uptime");
    const pct = s.total ? (100*s.bloqueadas/s.total).toFixed(1) : "0.0";
    $("blockpct").textContent = t("stat.block_pct", pct);
    // hero: anillo del sinkhole + números grandes
    $("hero-ring").style.setProperty("--pct", pct);
    $("hero-pct").textContent = pct + "%";
    $("hero-total").textContent = (s.total || 0).toLocaleString();
    $("hero-sub").textContent = t("hero.blocked_n", (s.bloqueadas || 0).toLocaleString());
    const SALUD = saludTxt();
    $("salud").innerHTML = (s.upstreams_salud||[]).slice(0, s.total!=null?undefined:0)
      .map((v,i)=>`<span class="dot d${v}" title="upstream ${i}">${SALUD[v]||v}</span>`).join(" ");
  }
  function fmtDur(x){const d=x/86400|0,h=(x%86400)/3600|0,m=(x%3600)/60|0;
    return d?`${d}d ${h}h`:h?`${h}h ${m}m`:`${m}m ${x%60}s`;}

  async function loadConfig() {
    const c = await api("GET", "/api/config");
    if (c.status === 200) $("upstreams").value = (c.body.upstreams||[]).join("\n");
    const ca = await api("GET", "/api/cache");
    if (ca.status === 200) $("cacheinfo").textContent =
      t("stat.cache_entries", ca.body.entradas, ca.body.capacidad);
  }

  $("save-upstreams").addEventListener("click", async () => {
    const list = $("upstreams").value.split(/\s+/).map(x=>x.trim()).filter(Boolean);
    const msg = $("cfg-msg");
    msg.textContent = t("msg.saving");
    const r = await api("PUT", "/api/config/upstreams", { upstreams: list });
    if (r.status === 200) {
      msg.textContent = t("msg.saved_reboot");
      stopDash();
      setTimeout(() => { location.reload(); }, 9000);
    } else {
      msg.textContent = t("msg.error", (r.body && r.body.error) || r.status);
    }
  });

  $("flush-cache").addEventListener("click", async () => {
    await api("DELETE", "/api/cache");
    loadConfig();
  });

  // ---- lista de bloqueo ----
  const luTxt = (e) => ({ downloading: t("lu.downloading"), building: t("lu.building"),
                   writing: t("lu.writing"), ok: "OK", error: t("lu.error"), idle: "" }[e]);
  function renderBl(b) {
    $("bl-count").textContent = t("bl.domains", (b.count || 0).toLocaleString());
    const el = $("bl-status");
    if (b.en_curso) {
      el.textContent = t("bl.updating") + " (" + (luTxt(b.estado) || b.estado) +
        (b.descargados ? ", " + Math.round(b.descargados / 1024) + " KB" : "") + ")";
    } else if (b.estado === "ok") {
      el.textContent = t("bl.ok");
    } else if (b.estado === "error") {
      el.textContent = t("bl.error", b.error || t("common.unknown"));
    } else {
      el.textContent = "";
    }
  }
  async function loadBlocklist() {
    const r = await api("GET", "/api/blocklist");
    if (r.status === 200) {
      if (document.activeElement !== $("bl-url")) $("bl-url").value = r.body.url || "";
      renderBl(r.body);
    }
  }
  $("bl-update").addEventListener("click", async () => {
    const url = $("bl-url").value.trim();
    $("bl-update").disabled = true;
    const r = await api("POST", "/api/blocklist/update", url ? { url } : undefined);
    if (r.status !== 202) {
      renderBl({ estado: "error", error: (r.body && r.body.error) || ("HTTP " + r.status) });
      $("bl-update").disabled = false;
      return;
    }
    const poll = setInterval(async () => {
      const s = await api("GET", "/api/blocklist");
      if (s.status !== 200) return;
      renderBl(s.body);
      if (!s.body.en_curso) { clearInterval(poll); $("bl-update").disabled = false; }
    }, 1500);
  });

  // ---- firmware / OTA ----
  const otaTxt = (e) => ({ downloading: t("lu.downloading"), done: t("ota.done"),
                   error: t("lu.error"), idle: "" }[e]);
  function renderFw(f) {
    $("fw-version").textContent = t("fw.version", f.version || "?", f.slot || "?");
    const el = $("fw-status");
    if (f.en_curso) {
      const pct = f.total ? Math.round(100 * f.leido / f.total) : 0;
      el.textContent = t("fw.updating") + " " + (otaTxt(f.estado) || f.estado) + (f.total ? ` ${pct}%` : "");
    } else if (f.estado === "error") {
      el.textContent = t("fw.error", f.error || "?");
    } else {
      el.textContent = "";
    }
  }
  async function loadFirmware() {
    const r = await api("GET", "/api/firmware");
    if (r.status === 200) {
      if (document.activeElement !== $("fw-url")) { /* no pisar edición */ }
      renderFw(r.body);
    }
  }
  $("fw-update").addEventListener("click", async () => {
    const url = $("fw-url").value.trim();
    if (!url) return;
    $("fw-update").disabled = true;
    const r = await api("POST", "/api/firmware/update", { url });
    if (r.status !== 202) {
      renderFw({ estado: "error", error: (r.body && r.body.error) || ("HTTP " + r.status) });
      $("fw-update").disabled = false;
      return;
    }
    const poll = setInterval(async () => {
      let s;
      try {
        s = await api("GET", "/api/firmware");
      } catch (e) {
        // la conexión cayó: el dispositivo se está reiniciando en la versión nueva
        clearInterval(poll);
        $("fw-status").textContent = t("fw.rebooting_new");
        setTimeout(() => location.reload(), 9000);
        return;
      }
      if (s.status !== 200) return;
      renderFw(s.body);
      if (s.body.estado === "error") {
        clearInterval(poll); $("fw-update").disabled = false;
      } else if (s.body.estado === "done") {
        clearInterval(poll);
        $("fw-status").textContent = t("fw.validated");
        setTimeout(() => location.reload(), 9000);
      }
    }, 1500);
  });

  // ---- cuenta: logout y cambio de contraseña ----
  $("logout").addEventListener("click", async () => {
    try { await api("POST", "/api/logout"); } catch (e) {}
    stopDash();
    location.reload();
  });
  $("pw-toggle").addEventListener("click", () => {
    $("pw-form").hidden = !$("pw-form").hidden;
  });
  $("pw-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const cur = $("pw-cur").value, np = $("pw-new").value, np2 = $("pw-new2").value;
    const msg = $("pw-msg");
    if (np.length < 8) { msg.textContent = t("pw.min8"); return; }
    if (np !== np2) { msg.textContent = t("pw.mismatch"); return; }
    msg.textContent = t("pw.changing");
    const ch = await api("GET", "/api/challenge");
    if (ch.status !== 200) { msg.textContent = t("pw.start_fail"); return; }
    // prueba de la contraseña ACTUAL por desafío-respuesta; la nueva se envía aparte
    const key = pbkdf2Sha256(strToBytes(cur), hexToBytes(ch.body.salt), KDF_ITERS);
    const resp = bytesToHex(hmacSha256(key, strToBytes(ch.body.nonce)));
    const r = await api("POST", "/api/password", { nonce: ch.body.nonce, resp, new_password: np });
    if (r.status === 200) {
      msg.textContent = t("pw.changed");
      stopDash();
      setTimeout(() => location.reload(), 1500);
    } else {
      msg.textContent = t("msg.error", (r.body && r.body.error) || ("HTTP " + r.status));
    }
  });

  // ---- DHCP ----
  $("dhcp-en").addEventListener("change", () => {
    $("dhcp-warn").hidden = !$("dhcp-en").checked;
  });
  function renderDhcp(d) {
    const f = document.activeElement;
    if (f !== $("dhcp-en")) $("dhcp-en").checked = !!d.enabled;
    $("dhcp-warn").hidden = !$("dhcp-en").checked;
    if (f !== $("dhcp-ps")) $("dhcp-ps").value = d.pool_start || "";
    if (f !== $("dhcp-pe")) $("dhcp-pe").value = d.pool_end || "";
    if (f !== $("dhcp-lt")) $("dhcp-lt").value = d.lease_time || "";
    const rows = d.leases || [];
    $("dhcp-leases").hidden = !d.enabled || rows.length === 0;
    const tb = $("dhcp-leases").querySelector("tbody");
    tb.textContent = "";
    // filas por DOM (textContent): el hostname lo pone el cliente ⇒ no innerHTML
    rows.forEach((l) => {
      const tr = document.createElement("tr");
      [l.ip, l.mac, l.hostname || ""].forEach((val) => {
        const td = document.createElement("td");
        td.textContent = val;
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    });
  }
  async function loadDhcp() {
    const r = await api("GET", "/api/dhcp");
    if (r.status === 200) renderDhcp(r.body);
  }
  $("dhcp-save").addEventListener("click", async () => {
    const body = {
      enabled: $("dhcp-en").checked ? "true" : "false",
      pool_start: $("dhcp-ps").value.trim(),
      pool_end: $("dhcp-pe").value.trim(),
      lease_time: $("dhcp-lt").value.trim(),
    };
    $("dhcp-msg").textContent = t("msg.saving");
    const r = await api("PUT", "/api/dhcp", body);
    if (r.status === 200) { $("dhcp-msg").textContent = t("msg.saved"); setTimeout(loadDhcp, 500); }
    else $("dhcp-msg").textContent = t("msg.error", (r.body && r.body.error) || ("HTTP " + r.status));
  });

  // ---- DoT (DNS cifrado) ----
  function renderDot(d) {
    const f = document.activeElement;
    if (f !== $("dot-en")) $("dot-en").checked = !!d.enabled;
    const sni = d.sni || [];
    for (let i = 0; i < 4; i++) {
      const el = $("dot-sni" + i);
      if (el && f !== el) el.value = sni[i] || "";
    }
    let s;
    if (!d.enabled) {
      s = t("dot.st_off");
    } else if (d.connected) {
      s = t("dot.st_connected", d.active, d.served || 0, d.servfail || 0, d.dropped || 0);
    } else {
      s = t("dot.st_connecting", d.servfail || 0) + (d.last_error ? " — " + d.last_error : "");
    }
    $("dot-estado").textContent = s;
  }
  async function loadDot() {
    const r = await api("GET", "/api/dot");
    if (r.status === 200) renderDot(r.body);
  }
  $("dot-save").addEventListener("click", async () => {
    const sni = [];
    for (let i = 0; i < 4; i++) {
      const v = $("dot-sni" + i).value.trim();
      if (v) sni.push(v);
    }
    const body = { enabled: $("dot-en").checked ? "true" : "false" };
    if (sni.length) body.sni = sni;
    $("dot-msg").textContent = t("msg.saving");
    const r = await api("PUT", "/api/dot", body);
    if (r.status === 200) { $("dot-msg").textContent = t("msg.saved"); setTimeout(loadDot, 500); }
    else $("dot-msg").textContent = t("msg.error", (r.body && r.body.error) || ("HTTP " + r.status));
  });

  // ---- Clientes ----
  function fmtAgo(s) {
    s = s | 0;
    if (s < 60) return t("time.ago_s", s);
    if (s < 3600) return t("time.ago_m", Math.floor(s / 60));
    return t("time.ago_h", Math.floor(s / 3600));
  }
  function renderClients(list) {
    const rows = list || [];
    $("clients-tabla").hidden = rows.length === 0;
    $("clients-vacio").hidden = rows.length !== 0;
    const tb = $("clients-tabla").querySelector("tbody");
    tb.textContent = "";
    // filas por DOM (textContent): la IP es un dato de red ⇒ no innerHTML
    rows.forEach((c) => {
      const tr = document.createElement("tr");
      [c.ip, String(c.total), String(c.blocked), fmtAgo(c.visto_s)].forEach((val) => {
        const td = document.createElement("td");
        td.textContent = val;
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    });
  }
  async function loadClients() {
    const r = await api("GET", "/api/clients");
    if (r.status === 200) renderClients(r.body);
  }
  $("clients-reset").addEventListener("click", async () => {
    $("clients-msg").textContent = t("msg.resetting");
    const r = await api("DELETE", "/api/clients");
    if (r.status === 200) { $("clients-msg").textContent = ""; loadClients(); }
    else $("clients-msg").textContent = t("msg.error", "HTTP " + r.status);
  });

  function startDash() { show("dash"); refresh(); loadConfig(); loadBlocklist(); loadFirmware(); loadDhcp(); loadDot(); loadClients(); timer = setInterval(() => { refresh(); loadDhcp(); loadDot(); loadClients(); }, 3000); }
  function stopDash() { if (timer) { clearInterval(timer); timer = null; } }

  // Al cambiar de idioma, repinta los paneles dinámicos si el dashboard está visible
  // (los textos estáticos ya los actualiza applyLang de i18n.js).
  document.addEventListener("esphole:lang", () => {
    if (!$("dash").hidden) {
      refresh(); loadConfig(); loadBlocklist(); loadFirmware(); loadDhcp(); loadDot(); loadClients();
    }
  });

  document.addEventListener("DOMContentLoaded", checkState);
}
