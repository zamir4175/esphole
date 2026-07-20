"use strict";
/*
 * ESPHole — tema claro/oscuro (spec 010). Por defecto sigue al sistema
 * (prefers-color-scheme); el conmutador ☀/🌙 fuerza uno (data-theme en <html>) y
 * lo recuerda (localStorage.esphole_theme). El router de secciones se añade abajo.
 * Contrato: specs/010-ui-redesign/contracts/design-tokens.md.
 */

/* Modo elegido: 'light'/'dark' si hay override; si no, 'auto'. */
function currentTheme() {
  const v = localStorage.getItem("esphole_theme");
  return (v === "light" || v === "dark") ? v : "auto";
}

/* Tema realmente visible: el override, o el del sistema cuando es 'auto'. */
function effectiveTheme() {
  const v = currentTheme();
  if (v !== "auto") return v;
  return (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches)
    ? "light" : "dark";
}

function markThemeBtn() {
  const btn = document.querySelector(".theme [data-theme-btn]");
  if (!btn) return;
  // muestra el icono del tema al que se cambiará
  btn.textContent = effectiveTheme() === "dark" ? "☀" : "🌙";
  btn.setAttribute("aria-label", (typeof t === "function") ? t("theme.toggle") : "Theme");
}

function applyTheme(mode) {
  const root = document.documentElement;
  if (mode === "light" || mode === "dark") {
    root.setAttribute("data-theme", mode);
    localStorage.setItem("esphole_theme", mode);
  } else { // auto
    root.removeAttribute("data-theme");
    localStorage.removeItem("esphole_theme");
  }
  markThemeBtn();
}

function initTheme() {
  applyTheme(currentTheme());
  const sw = document.querySelector(".theme");
  if (sw) {
    sw.addEventListener("click", (ev) => {
      if (!ev.target.closest("[data-theme-btn]")) return;
      applyTheme(effectiveTheme() === "dark" ? "light" : "dark"); // alterna el efectivo
    });
  }
  // si seguimos al sistema y este cambia, refresca el icono (el CSS ya reacciona)
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
      if (currentTheme() === "auto") markThemeBtn();
    });
  }
  // al cambiar de idioma, actualiza el aria-label del conmutador
  document.addEventListener("esphole:lang", markThemeBtn);
}

document.addEventListener("DOMContentLoaded", initTheme);

/* ================= router de secciones (por hash) ================= */
const VIEWS = ["dashboard", "upstreams", "blocklist", "firmware", "dhcp", "dot", "account"];

function currentView() {
  const h = location.hash.replace(/^#/, "");
  return VIEWS.includes(h) ? h : "dashboard";
}

function showView(id) {
  document.querySelectorAll("[data-view]").forEach((s) => {
    s.hidden = s.getAttribute("data-view") !== id;
  });
  document.querySelectorAll("[data-view-link]").forEach((a) => {
    a.classList.toggle("active", a.getAttribute("data-view-link") === id);
  });
  document.body.classList.remove("nav-open"); // cierra el menú móvil al navegar
}

function initRouter() {
  showView(currentView());
  window.addEventListener("hashchange", () => showView(currentView()));
  const tgl = document.getElementById("navtoggle");
  if (tgl) {
    tgl.addEventListener("click", () => document.body.classList.toggle("nav-open"));
  }
}

document.addEventListener("DOMContentLoaded", initRouter);
