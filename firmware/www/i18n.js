"use strict";
/*
 * ESPHole — capa de internacionalización (spec 009).
 * Diccionario I18N: clave → {en, es}. Inglés por defecto. La elección se
 * recuerda en localStorage. El texto estático del HTML se marca con
 * data-i18n / data-i18n-ph; el dinámico (app.js) usa t("clave", ...args).
 * Contrato: specs/009-i18n/contracts/i18n-keys.md.
 */

/* Diccionario. Una entrada por texto visible; en/es no vacíos. Marcadores
 * posicionales {0}, {1}, … para valores dinámicos. (Se completa en I02/I03.) */
const I18N = {
  "app.title": { en: "ESPHole", es: "ESPHole" },

  // setup
  "setup.title":  { en: "Set your password", es: "Configura tu contraseña" },
  "setup.intro":  { en: "No admin yet. Create a password to protect the panel.", es: "Aún no hay administrador. Crea una contraseña para proteger el panel." },
  "setup.pass":   { en: "Password", es: "Contraseña" },
  "setup.pass2":  { en: "Repeat password", es: "Repite la contraseña" },
  "setup.submit": { en: "Create and sign in", es: "Crear y entrar" },

  // login
  "login.title":  { en: "Sign in", es: "Entrar" },
  "login.pass":   { en: "Password", es: "Contraseña" },
  "login.submit": { en: "Sign in", es: "Entrar" },
  "login.note":   { en: "Your password is never sent: challenge-response is used.", es: "La contraseña no se envía: se usa desafío-respuesta." },

  // account
  "account.title":    { en: "Account", es: "Cuenta" },
  "account.changepw": { en: "Change password", es: "Cambiar contraseña" },
  "account.logout":   { en: "Sign out", es: "Cerrar sesión" },
  "account.pw_cur":   { en: "Current password", es: "Contraseña actual" },
  "account.pw_new":   { en: "New password", es: "Nueva contraseña" },
  "account.pw_new2":  { en: "Repeat new one", es: "Repite la nueva" },
  "account.pw_save":  { en: "Save password", es: "Guardar contraseña" },

  // upstream resolvers
  "upstream.title": { en: "Upstream resolvers", es: "Resolvedores upstream" },
  "upstream.note":  { en: "One IP (v4 or v6) per line. Saving reboots the device.", es: "Una IP (v4 o v6) por línea. Guardar reinicia el dispositivo." },
  "upstream.save":  { en: "Save and reboot", es: "Guardar y reiniciar" },

  // blocklist
  "blocklist.title":  { en: "Blocklist", es: "Lista de bloqueo" },
  "blocklist.note":   { en: "List URL (HOSTS format). Update downloads and applies it; for ~1 min blocking is inactive (resolution keeps working).", es: "URL de la lista (formato HOSTS). Actualizar la descarga y aplica; durante ~1 min el bloqueo queda inactivo (la resolución sigue)." },
  "blocklist.update": { en: "Update list", es: "Actualizar lista" },

  // firmware
  "firmware.title":  { en: "Firmware", es: "Firmware" },
  "firmware.note":   { en: "https URL of the image (.bin). Update downloads, validates and reboots into the new version; if it doesn't boot well, it rolls back on its own.", es: "URL https de la imagen (.bin). Actualizar descarga, valida y reinicia en la versión nueva; si no arranca bien, vuelve sola a la anterior." },
  "firmware.update": { en: "Update firmware", es: "Actualizar firmware" },

  // DHCP
  "dhcp.title":      { en: "DHCP server", es: "Servidor DHCP" },
  "dhcp.note":       { en: "Hands out LAN IPs, serving ESPHole as DNS (automatic blocking for everyone). Optional.", es: "Reparte IPs a la LAN entregando ESPHole como DNS (bloqueo automático para todos). Opcional." },
  "dhcp.enable":     { en: "Enable DHCP server", es: "Activar servidor DHCP" },
  "dhcp.warn":       { en: "⚠️ You must disable your router's DHCP before enabling this one: there can't be two DHCP servers on the same network.", es: "⚠️ Debes desactivar el DHCP de tu router antes de activar este: no puede haber dos servidores DHCP en la misma red." },
  "dhcp.range_from": { en: "Range from", es: "Rango desde" },
  "dhcp.range_to":   { en: "Range to", es: "Rango hasta" },
  "dhcp.lease":      { en: "Lease (s)", es: "Concesión (s)" },
  "dhcp.col_name":   { en: "Name", es: "Nombre" },

  // DoT
  "dot.title":    { en: "Encrypted DNS (DoT)", es: "DNS cifrado (DoT)" },
  "dot.note":     { en: "Forwards your queries to the resolver over DNS over TLS (RFC 7858, port 853): nobody on the network sees which domains you look up. If the encrypted resolver fails, the query returns SERVFAIL (never falls back to plaintext). Optional.", es: "Reenvía tus consultas al resolvedor por DNS over TLS (RFC 7858, puerto 853): nadie en la red ve qué dominios consultas. Si el resolvedor cifrado falla, la consulta devuelve SERVFAIL (nunca cae a texto plano). Opcional." },
  "dot.enable":   { en: "Enable encrypted DNS (DoT)", es: "Activar DNS cifrado (DoT)" },
  "dot.sni_note": { en: "Hostname (SNI) for each upstream, in the same order as the resolvers. Must match the resolver's certificate.", es: "Hostname (SNI) de cada upstream, en el mismo orden que los resolvedores. Debe casar el certificado del resolvedor." },

  // clients
  "clients.title":       { en: "Clients", es: "Clientes" },
  "clients.note":        { en: "Devices (by IP) that have queried since the last boot: how many queries and how many blocked. Counters are ephemeral (reset on power-off).", es: "Dispositivos (por IP) que han consultado desde el último arranque: cuántas consultas y cuántas bloqueadas. Los contadores son efímeros (se reinician al apagar)." },
  "clients.reset":       { en: "Reset counters", es: "Reiniciar contadores" },
  "clients.col_queries": { en: "Queries", es: "Consultas" },
  "clients.col_blocked": { en: "Blocked", es: "Bloqueadas" },
  "clients.col_seen":    { en: "Seen", es: "Visto" },
  "clients.empty":       { en: "No clients registered yet.", es: "Aún no hay clientes registrados." },

  // cache
  "cache.title": { en: "Cache", es: "Caché" },
  "cache.flush": { en: "Flush cache", es: "Vaciar caché" },

  // upstream health
  "health.title": { en: "Upstream health", es: "Salud de upstreams" },

  // theme + nav (spec 010)
  "theme.toggle":   { en: "Toggle light/dark theme", es: "Cambiar tema claro/oscuro" },
  "nav.dashboard":  { en: "Dashboard", es: "Panel" },
  "nav.upstreams":  { en: "Upstreams", es: "Resolvedores" },
  "nav.blocklist":  { en: "Blocklist", es: "Lista" },
  "nav.firmware":   { en: "Firmware", es: "Firmware" },
  "nav.dhcp":       { en: "DHCP", es: "DHCP" },
  "nav.dot":        { en: "DoT", es: "DoT" },
  "nav.account":    { en: "Account", es: "Cuenta" },
  "hero.blocked_label": { en: "blocked", es: "bloqueado" },
  "hero.queries":       { en: "queries", es: "consultas" },
  "hero.blocked_n":     { en: "{0} blocked", es: "{0} bloqueadas" },

  // common
  "common.save":    { en: "Save", es: "Guardar" },
  "common.unknown": { en: "unknown", es: "desconocido" },

  // dashboard cards + stats
  "card.total":       { en: "Queries", es: "Consultas" },
  "card.blocked":     { en: "Blocked", es: "Bloqueadas" },
  "card.cache_hits":  { en: "Cache hits", es: "Aciertos de caché" },
  "card.forwarded":   { en: "Forwarded", es: "Reenviadas" },
  "card.malformed":   { en: "Malformed", es: "Malformadas" },
  "card.heap":        { en: "Free heap", es: "Heap libre" },
  "card.uptime":      { en: "Uptime", es: "Tiempo activo" },
  "stat.block_pct":   { en: "{0}% blocked", es: "{0}% bloqueado" },
  "stat.cache_entries": { en: "{0} / {1} entries", es: "{0} / {1} entradas" },

  // upstream health states
  "health.ok":   { en: "healthy", es: "sano" },
  "health.susp": { en: "suspect", es: "sospechoso" },
  "health.down": { en: "down", es: "caído" },

  // shared messages
  "msg.error":        { en: "Error: {0}", es: "Error: {0}" },
  "msg.saving":       { en: "Saving…", es: "Guardando…" },
  "msg.saved":        { en: "Saved.", es: "Guardado." },
  "msg.saved_reboot": { en: "Saved. The device is rebooting…", es: "Guardado. El dispositivo se reinicia…" },
  "msg.resetting":    { en: "Resetting…", es: "Reiniciando…" },
  "msg.min8":         { en: "At least 8 characters.", es: "Mínimo 8 caracteres." },
  "msg.pw_mismatch":  { en: "Passwords don't match.", es: "Las contraseñas no coinciden." },
  "msg.creating":     { en: "Creating…", es: "Creando…" },
  "msg.signing_in":   { en: "Signing in…", es: "Entrando…" },
  "msg.challenge_fail": { en: "Couldn't start the challenge.", es: "No se pudo iniciar el desafío." },
  "msg.wrong_pw":     { en: "Wrong password.", es: "Contraseña incorrecta." },

  // blocklist (dynamic)
  "lu.downloading": { en: "downloading", es: "descargando" },
  "lu.building":    { en: "processing", es: "procesando" },
  "lu.writing":     { en: "saving", es: "guardando" },
  "lu.error":       { en: "error", es: "error" },
  "bl.domains":     { en: "{0} domains", es: "{0} dominios" },
  "bl.updating":    { en: "Updating…", es: "Actualizando…" },
  "bl.ok":          { en: "Last update: OK.", es: "Última actualización: correcta." },
  "bl.error":       { en: "Error: {0}. Previous list kept.", es: "Error: {0}. Lista anterior conservada." },

  // firmware (dynamic)
  "ota.done":         { en: "ready", es: "listo" },
  "fw.version":       { en: "Version {0} · slot {1}", es: "Versión {0} · ranura {1}" },
  "fw.updating":      { en: "Updating…", es: "Actualizando…" },
  "fw.error":         { en: "Error: {0}. Previous firmware kept.", es: "Error: {0}. Firmware anterior conservado." },
  "fw.rebooting_new": { en: "Rebooting into the new version… the page will reload.", es: "Reiniciando en la versión nueva… la página se recargará." },
  "fw.validated":     { en: "Image validated. Rebooting… the page will reload.", es: "Imagen validada. Reiniciando… la página se recargará." },

  // change password (dynamic)
  "pw.min8":       { en: "The new one must be ≥8 characters.", es: "La nueva debe tener ≥8 caracteres." },
  "pw.mismatch":   { en: "The new one doesn't match.", es: "La nueva no coincide." },
  "pw.changing":   { en: "Changing…", es: "Cambiando…" },
  "pw.start_fail": { en: "Couldn't start.", es: "No se pudo iniciar." },
  "pw.changed":    { en: "Password changed. Sign in again…", es: "Contraseña cambiada. Vuelve a entrar…" },

  // DoT status (dynamic)
  "dot.st_off":        { en: "Off (plaintext UDP forwarding).", es: "Desactivado (reenvío UDP en claro)." },
  "dot.st_connected":  { en: "🔒 Connected (upstream {0}). Served: {1} · SERVFAIL: {2} · dropped: {3}", es: "🔒 Conectado (upstream {0}). Servidas: {1} · SERVFAIL: {2} · descartadas: {3}" },
  "dot.st_connecting": { en: "On, not connected yet. SERVFAIL: {0}", es: "Activado, sin conexión aún. SERVFAIL: {0}" },

  // relative time (dynamic)
  "time.ago_s": { en: "{0}s ago", es: "hace {0}s" },
  "time.ago_m": { en: "{0}m ago", es: "hace {0}m" },
  "time.ago_h": { en: "{0}h ago", es: "hace {0}h" },
};

/* Idioma activo: 'en' o 'es'; ausente/desconocido ⇒ 'en' (defecto, FR-002). */
function currentLang() {
  const l = localStorage.getItem("esphole_lang");
  return (l === "en" || l === "es") ? l : "en";
}

/* Traducción de 'clave' en el idioma activo; sustituye {0},{1},… por args.
 * Cae a 'en' si falta el idioma, y a la propia clave si falta la entrada. */
function t(key, ...args) {
  const e = I18N[key];
  let s = e ? (e[currentLang()] != null ? e[currentLang()] : e.en) : key;
  if (s == null) s = key;
  return String(s).replace(/\{(\d+)\}/g, (m, i) =>
    args[i] !== undefined ? String(args[i]) : m);
}

/* Cambia el idioma, lo persiste y lo aplica al instante (FR-003/004). */
function setLang(lang) {
  if (lang !== "en" && lang !== "es") lang = "en";
  localStorage.setItem("esphole_lang", lang);
  applyLang(lang);
}

/* Aplica el idioma a todo el DOM marcado + <html lang> + título; avisa a app.js
 * (evento) para repintar lo dinámico (FR-005/006). */
function applyLang(lang) {
  document.documentElement.lang = lang;
  document.title = t("app.title");
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.getAttribute("data-i18n"));
  });
  document.querySelectorAll("[data-i18n-ph]").forEach((el) => {
    el.setAttribute("placeholder", t(el.getAttribute("data-i18n-ph")));
  });
  document.querySelectorAll(".lang [data-lang]").forEach((b) => {
    b.classList.toggle("active", b.getAttribute("data-lang") === lang);
  });
  document.dispatchEvent(new Event("esphole:lang"));
}

/* Cablea el conmutador y pinta en el idioma recordado (sin parpadeo). */
function initLang() {
  const sw = document.querySelector(".lang");
  if (sw) {
    sw.addEventListener("click", (ev) => {
      const b = ev.target.closest("[data-lang]");
      if (b) setLang(b.getAttribute("data-lang"));
    });
  }
  applyLang(currentLang());
}

document.addEventListener("DOMContentLoaded", initLang);
