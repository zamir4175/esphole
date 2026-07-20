// Test de lógica de la capa i18n (spec 009): defecto EN, cambio a ES,
// sustitución de {0}, y fallbacks. Sin navegador (stubs de document/localStorage).
// Uso:  node test/target/i18n_logic.js
const fs = require('fs'), vm = require('vm'), path = require('path');
const I18N_PATH = path.join(__dirname, '..', '..', 'firmware', 'www', 'i18n.js');
let store = {};
const ctx = {
  localStorage: { getItem: k => (k in store ? store[k] : null), setItem: (k,v)=>store[k]=String(v) },
  document: { documentElement:{}, title:"", querySelectorAll:()=>[], querySelector:()=>null,
              addEventListener:()=>{}, dispatchEvent:()=>{} },
  Event: function(n){ this.type=n; }, console,
};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(I18N_PATH,"utf8") +
  "\n;globalThis.__t=t;globalThis.__set=setLang;globalThis.__cur=currentLang;", ctx);
const t=ctx.__t, setLang=ctx.__set, cur=ctx.__cur;
let ok=0, bad=0;
const chk=(l,c)=>{ if(c){ok++;console.log("[PASS]",l)}else{bad++;console.log("[FALL]",l)} };
chk("defecto EN", cur()==="en");
chk("EN: login.title = Sign in", t("login.title")==="Sign in");
chk("EN: time.ago_s(5) = '5s ago'", t("time.ago_s",5)==="5s ago");
setLang("es");
chk("tras setLang(es) => es", cur()==="es");
chk("ES: login.title = Entrar", t("login.title")==="Entrar");
chk("ES: time.ago_s(5) = 'hace 5s'", t("time.ago_s",5)==="hace 5s");
chk("ES: dot.st_connected params", t("dot.st_connected",0,3,1,2)==="🔒 Conectado (upstream 0). Servidas: 3 · SERVFAIL: 1 · descartadas: 2");
chk("clave inexistente => la propia clave", t("no.existe")==="no.existe");
setLang("xx");
chk("idioma inválido => en", cur()==="en");
console.log(`\n${ok} PASS / ${bad} FALL`);
process.exit(bad?1:0);
