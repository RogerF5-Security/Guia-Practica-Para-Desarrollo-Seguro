/**
 * app.js — Lógica de la Guía Práctica de Desarrollo Seguro.
 *
 * Reglas de implementación (la página aplica lo que recomienda):
 *  - Sin innerHTML ni sinks de HTML: todo el DOM se construye con createElement/textContent
 *    (la CSP exige Trusted Types y no se crea ninguna política).
 *  - Sin recursos de terceros ni peticiones de red: los datos pegados por el usuario nunca salen del navegador.
 *  - Los valores sensibles detectados (secretos, cookies) se enmascaran en los reportes.
 */
import {
  GUIDES, GUIDE_BASE, RAW_BASE, PROFILES, CHECK_ITEMS, SCAN_RULES, SEV_LABEL,
  SAMPLE_HTTP, SAMPLE_CODE,
} from "./data.js";

/* =================================================================== Utilidades */

/** Crea un elemento con propiedades y nodos hijos (texto siempre como nodo de texto). */
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props ?? {})) {
    if (value == null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = value;
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
    else if (value === true) el.setAttribute(key, "");
    else el.setAttribute(key, String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child == null || child === false) continue;
    el.append(child instanceof Node ? child : String(child));
  }
  return el;
}

const store = {
  get(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      return raw == null ? fallback : JSON.parse(raw);
    } catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* almacenamiento bloqueado: se sigue sin persistir */ }
  },
};

const guideUrl = (id, ext = "md") => {
  const g = GUIDES[id];
  return ext === "md" ? `${GUIDE_BASE}/${g.path}.md` : `${RAW_BASE}/${g.path}.docx`;
};

const guideLink = (id) => h("a", { href: guideUrl(id), text: `Guía ${id}` });

let uid = 0;
const nextId = (prefix) => `${prefix}-${++uid}`;

function normalize(text) {
  return text.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
}

function downloadText(filename, text) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/markdown;charset=utf-8" }));
  const a = h("a", { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* =================================================================== Copiar al portapapeles */

const copyTimers = new WeakMap();
let lastCopyMessage = "";

function reportCopy(button, ok) {
  const tip = button.nextElementSibling;
  clearTimeout(copyTimers.get(button));
  button.removeAttribute("data-copied");
  button.removeAttribute("data-failed");
  let message = ok ? "Copiado" : "No se pudo copiar";
  if (message === lastCopyMessage) message += " "; // VoiceOver no repite mensajes idénticos
  lastCopyMessage = message;
  tip.textContent = "";
  button.setAttribute(ok ? "data-copied" : "data-failed", "");
  requestAnimationFrame(() => { tip.textContent = message; });
  copyTimers.set(button, setTimeout(() => {
    button.removeAttribute("data-copied");
    button.removeAttribute("data-failed");
    tip.textContent = "";
  }, 2000));
}

async function copyFrom(button, target) {
  const text = target.matches("input, textarea") ? target.value : target.innerText.trim();
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    reportCopy(button, true);
  } catch {
    reportCopy(button, false);
  }
}

// Invoker Commands (command/commandfor) con respaldo por click para navegadores sin soporte.
if ("CommandEvent" in window) {
  document.addEventListener("command", (event) => {
    if (event.command === "--copy") copyFrom(event.source, event.target);
  }, true);
} else {
  document.addEventListener("click", (event) => {
    if (event.defaultPrevented) return;
    const button = event.target.closest('button[command="--copy"]');
    if (!button) return;
    const target = document.getElementById(button.getAttribute("commandfor"));
    if (target) copyFrom(button, target);
  });
}

function copyControl(targetId, label) {
  return h("span", { class: "copy" },
    h("button", { type: "button", class: "copy-button", command: "--copy", commandfor: targetId, "aria-label": label }, "Copiar"),
    h("span", { class: "tip", role: "status" }),
  );
}

/** Bloque de código con botón de copiar. Devuelve {node, set(text)} para actualizarlo. */
function codeBlock(lang, text = "", label = "Copiar código") {
  const id = nextId("code");
  const code = h("code", { id }, text);
  const node = h("div", { class: "code-block" },
    h("span", { class: "lang", text: lang }),
    h("pre", { tabindex: "0" }, code),
    copyControl(id, label),
  );
  return { node, code, set(value) { code.textContent = value; } };
}

/** Añade botón de copiar a los bloques de código estáticos del HTML. */
function enhanceStaticCode() {
  for (const block of document.querySelectorAll(".code-block")) {
    if (block.querySelector(".copy")) continue;
    const code = block.querySelector("pre > code");
    const pre = block.querySelector("pre");
    if (!code) continue;
    code.id ||= nextId("code");
    pre.tabIndex = 0;
    const lang = block.querySelector(".lang")?.textContent ?? "código";
    block.append(copyControl(code.id, `Copiar ejemplo ${lang}`));
  }
}

/* =================================================================== Navegación (scrollspy) */

function initScrollSpy() {
  const links = [...document.querySelectorAll(".toc a")];
  const list = document.querySelector(".toc ol");
  const byId = new Map(links.map((a) => [a.getAttribute("href").slice(1), a]));
  const setCurrent = (id) => {
    for (const a of links) a.setAttribute("aria-current", String(a === byId.get(id)));
    const active = byId.get(id);
    // En la barra horizontal (móvil) se desplaza la pestaña activa a la vista sin mover la página.
    if (active && list.scrollWidth > list.clientWidth) {
      list.scrollTo({ left: active.offsetLeft - 16, behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
    }
  };
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) if (entry.isIntersecting) setCurrent(entry.target.id);
  }, { rootMargin: "-40% 0px -55% 0px", threshold: 0 });
  for (const id of byId.keys()) {
    const section = document.getElementById(id);
    if (section) observer.observe(section);
  }
  setCurrent(location.hash.slice(1) || "inicio");
}

/* =================================================================== ¿Sí o no? */

function initQA() {
  const input = document.getElementById("qa-search");
  const rows = [...document.querySelectorAll("#qa-table tbody tr")];
  const count = document.getElementById("qa-count");
  const update = () => {
    const q = normalize(input.value.trim());
    let visible = 0;
    for (const row of rows) {
      const show = !q || normalize(row.textContent).includes(q);
      row.hidden = !show;
      if (show) visible++;
    }
    count.textContent = q ? `${visible} de ${rows.length} preguntas` : `${rows.length} preguntas`;
  };
  input.addEventListener("input", update);
  update();
}

/* =================================================================== Checklist */

function initChecklist() {
  const root = document.getElementById("checklist-app");
  const KEY = "dsg.checklist.v1";
  const state = Object.assign({ profiles: [], checked: [], onlyBlocking: false }, store.get(KEY, {}));
  const save = () => store.set(KEY, state);

  const chips = h("ul", { class: "chips", "aria-label": "Qué vas a construir" });
  for (const p of PROFILES) {
    const btn = h("button", { type: "button", "aria-pressed": String(state.profiles.includes(p.id)) }, p.label);
    btn.addEventListener("click", () => {
      const on = !state.profiles.includes(p.id);
      state.profiles = on ? [...state.profiles, p.id] : state.profiles.filter((x) => x !== p.id);
      btn.setAttribute("aria-pressed", String(on));
      save(); renderList();
    });
    chips.append(h("li", {}, btn));
  }

  const setAll = (on) => {
    state.profiles = on ? PROFILES.map((p) => p.id) : [];
    for (const btn of chips.querySelectorAll("button")) btn.setAttribute("aria-pressed", String(on));
    save(); renderList();
  };

  const blockingToggle = h("input", { type: "checkbox", id: "only-blocking" });
  blockingToggle.checked = state.onlyBlocking;
  blockingToggle.addEventListener("change", () => { state.onlyBlocking = blockingToggle.checked; save(); renderList(); });

  const progress = h("progress", { max: "1", value: "0", "aria-labelledby": "progress-text" });
  const progressText = h("span", { class: "progress-text", id: "progress-text", "aria-live": "polite" });
  const listHost = h("div", { class: "check-group" });
  const status = h("p", { class: "hint", role: "status" });

  const currentItems = () => CHECK_ITEMS.filter((it) =>
    (it.tags.includes("base") || it.tags.some((t) => state.profiles.includes(t)))
    && (!state.onlyBlocking || it.level === "B"));

  function updateProgress(items) {
    const done = items.filter((it) => state.checked.includes(it.id)).length;
    progress.max = Math.max(items.length, 1);
    progress.value = done;
    const blockingLeft = items.filter((it) => it.level === "B" && !state.checked.includes(it.id)).length;
    progressText.textContent = `${done} de ${items.length} controles cumplidos · ${blockingLeft} bloqueantes pendientes`;
  }

  function renderList() {
    const items = currentItems();
    const groups = new Map();
    for (const it of items) {
      if (!groups.has(it.cat)) groups.set(it.cat, []);
      groups.get(it.cat).push(it);
    }
    const frag = document.createDocumentFragment();
    if (!state.profiles.length) {
      frag.append(h("p", { class: "hint" }, "Mostrando solo los controles base. Selecciona arriba lo que vas a construir para ver los específicos."));
    }
    for (const [cat, list] of groups) {
      frag.append(h("h3", {}, cat, h("span", { class: "badge info" }, String(list.length))));
      const ul = h("ul", { class: "check-list" });
      for (const it of list) {
        const id = `chk-${it.id}`;
        const box = h("input", { type: "checkbox", id });
        box.checked = state.checked.includes(it.id);
        box.addEventListener("change", () => {
          state.checked = box.checked ? [...new Set([...state.checked, it.id])] : state.checked.filter((x) => x !== it.id);
          save(); updateProgress(currentItems());
        });
        ul.append(h("li", { class: "check-item" },
          h("div", { class: "check-main" }, box, h("label", { for: id, class: "check-text" }, it.text)),
          h("div", { class: "check-meta" },
            h("span", { class: `badge level-${it.level.toLowerCase()}` }, it.level === "B" ? "Bloqueante" : "Requerido"),
            guideLink(it.guide)),
          h("details", {}, h("summary", {}, "¿Por qué?"), h("p", {}, it.why)),
        ));
      }
      frag.append(ul);
    }
    listHost.replaceChildren(frag);
    updateProgress(items);
  }

  function toMarkdown() {
    const items = currentItems();
    const labels = PROFILES.filter((p) => state.profiles.includes(p.id)).map((p) => p.label);
    const done = items.filter((it) => state.checked.includes(it.id)).length;
    const lines = [
      "## Checklist de seguridad",
      "",
      `- Alcance: ${labels.length ? labels.join(", ") : "controles base"}`,
      `- Progreso: ${done}/${items.length}`,
      `- Generado con la Guía Práctica de Desarrollo Seguro (${new Date().toISOString().slice(0, 10)})`,
    ];
    let cat = "";
    for (const it of items) {
      if (it.cat !== cat) { cat = it.cat; lines.push("", `### ${cat}`); }
      lines.push(`- [${state.checked.includes(it.id) ? "x" : " "}] **${it.level === "B" ? "Bloqueante" : "Requerido"}** — ${it.text}`);
    }
    return lines.join("\n") + "\n";
  }

  const copyMd = h("button", { type: "button" }, "Copiar Markdown para el PR");
  copyMd.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(toMarkdown()); status.textContent = "Checklist copiado en formato Markdown."; }
    catch { status.textContent = "No se pudo copiar; usa Descargar .md."; }
  });
  const download = h("button", { type: "button", onclick: () => { downloadText("checklist-seguridad.md", toMarkdown()); status.textContent = "Descarga iniciada."; } }, "Descargar .md");
  const reset = h("button", { type: "button", class: "ghost", onclick: () => {
    state.checked = []; save(); renderList(); status.textContent = "Marcas reiniciadas.";
  } }, "Reiniciar marcas");

  root.replaceChildren(
    h("p", { id: "chips-label", class: "hint" }, "Selecciona uno o varios:"),
    chips,
    h("div", { class: "toolbar" },
      h("button", { type: "button", onclick: () => setAll(true) }, "Todo (revisión Go-Live)"),
      h("button", { type: "button", class: "ghost", onclick: () => setAll(false) }, "Quitar selección"),
      h("label", { class: "check-row", for: "only-blocking" }, blockingToggle, "Solo bloqueantes"),
    ),
    h("div", { class: "progress-wrap" }, progress, progressText),
    listHost,
    h("div", { class: "toolbar" }, copyMd, download, reset),
    status,
  );
  chips.setAttribute("aria-labelledby", "chips-label");
  renderList();
}

/* =================================================================== CSP: análisis */

function parseCSP(value) {
  const map = new Map();
  for (const part of value.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    if (!map.has(name)) map.set(name, tokens.slice(1)); // el navegador ignora directivas duplicadas
  }
  return map;
}

/** Devuelve hallazgos {status, title, detail} para una CSP. */
function analyzeCSP(value) {
  const out = [];
  const add = (status, title, detail) => out.push({ status, title, detail });
  const d = parseCSP(value);
  if (!d.size) { add("fail", "CSP vacía", "No se encontraron directivas."); return out; }

  const script = d.get("script-src") ?? d.get("default-src");
  if (!script) {
    add("fail", "Sin script-src ni default-src", "Cualquier script está permitido: la CSP no protege contra XSS.");
  } else {
    const lower = script.map((t) => t.toLowerCase());
    const hasNonceHash = lower.some((t) => /^'(nonce|sha256|sha384|sha512)-/.test(t));
    const strictDynamic = lower.includes("'strict-dynamic'");
    const src = d.has("script-src") ? "script-src" : "default-src";
    if (lower.includes("'unsafe-inline'")) {
      if (hasNonceHash) add("info", "'unsafe-inline' presente pero ignorado", "Con nonce/hash los navegadores modernos lo ignoran; solo sirve de compatibilidad con navegadores antiguos.");
      else add("fail", `'unsafe-inline' en ${src}`, "Permite ejecutar scripts inline inyectados: anula la protección contra XSS. Usa nonces o hashes.");
    }
    if (lower.includes("'unsafe-eval'")) add("fail", `'unsafe-eval' en ${src}`, "Permite eval() y new Function(): convierte cadenas en código. Elimina su uso.");
    const wide = lower.filter((t) => ["*", "http:", "https:", "data:", "blob:"].includes(t));
    for (const t of wide) {
      if (strictDynamic && hasNonceHash && (t === "https:" || t === "http:")) {
        add("info", `${t} ignorado por 'strict-dynamic'`, "Es un respaldo para navegadores antiguos; los modernos lo ignoran.");
      } else {
        add(t === "https:" ? "warn" : "fail", `Fuente demasiado amplia en ${src}: ${t}`, "Permite cargar scripts desde casi cualquier origen. Usa nonce/hash + 'strict-dynamic'.");
      }
    }
    const hosts = lower.filter((t) => !t.startsWith("'") && !["*", "http:", "https:", "data:", "blob:"].includes(t));
    if (hosts.length && !strictDynamic) add("warn", "Allow-list de dominios para scripts", `Dominios (${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? "…" : ""}) se evaden con JSONP, redirecciones o librerías alojadas en ellos. Prefiere nonce/hash + 'strict-dynamic'.`);
    if (hasNonceHash && !lower.includes("'unsafe-eval'") && !out.some((f) => f.status === "fail")) add("ok", "script-src con nonce/hash", "Base sólida contra XSS.");
    else if (!hasNonceHash && lower.length && lower.every((t) => t === "'self'" || t === "'none'" || t === "'report-sample'")) add("ok", `${src} restringido a 'self'`, "Correcto para sitios estáticos sin scripts inline (revisa que no haya uploads servidos desde el mismo origen).");
  }

  const object = d.get("object-src") ?? d.get("default-src");
  if (!object || !object.includes("'none'")) add("warn", "object-src no es 'none'", "Agrega object-src 'none' para bloquear plugins (<object>, <embed>).");
  else add("ok", "object-src 'none'", "Plugins bloqueados.");

  if (!d.has("base-uri")) add("warn", "Falta base-uri", "base-uri no hereda de default-src. Agrega base-uri 'none' (o 'self') para evitar el secuestro de URLs relativas con <base>.");
  else add("ok", "base-uri definido", d.get("base-uri").join(" "));

  if (!d.has("frame-ancestors")) add("warn", "Falta frame-ancestors", "No hereda de default-src. Agrega frame-ancestors 'none' (o 'self') contra clickjacking. No funciona en <meta>: debe ir como cabecera.");
  else if (d.get("frame-ancestors").includes("*")) add("fail", "frame-ancestors *", "Cualquier sitio puede enmarcar la página (clickjacking).");
  else add("ok", "frame-ancestors definido", d.get("frame-ancestors").join(" "));

  if (!d.has("form-action")) add("info", "Falta form-action", "Opcional: form-action 'self' impide enviar formularios a orígenes del atacante.");
  if (!d.has("require-trusted-types-for")) add("info", "Sin Trusted Types", "Opcional: require-trusted-types-for 'script' bloquea DOM XSS en innerHTML y similares (despliega primero en Report-Only).");
  if (!d.has("report-to") && !d.has("report-uri")) add("info", "Sin reportes de violaciones", "Agrega report-to para saber qué bloquea la política y detectar ataques.");
  return out;
}

/* =================================================================== CSP: generador */

const cspState = { value: "", mode: "nonce", headerName: "Content-Security-Policy", reporting: "" };
const cspListeners = new Set();

function initCSPBuilder() {
  const root = document.getElementById("csp-builder");
  const f = {
    mode: "nonce", tt: true, reportOnly: true, framing: "'none'", imgHttps: false, connect: "", reportUrl: "",
  };

  const modeField = h("fieldset", {},
    h("legend", {}, "Tipo de aplicación"),
    ...[["nonce", "Renderizada en servidor (nonce por respuesta)"], ["static", "SPA / sitio estático (solo scripts externos)"], ["api", "API que solo devuelve JSON"]]
      .map(([v, label]) => {
        const r = h("input", { type: "radio", name: "csp-mode", value: v, id: `csp-mode-${v}` });
        r.checked = v === f.mode;
        r.addEventListener("change", () => { f.mode = v; update(); });
        return h("div", { class: "check-row" }, r, h("label", { for: `csp-mode-${v}` }, label));
      }));

  const checkbox = (key, label) => {
    const id = nextId("csp");
    const c = h("input", { type: "checkbox", id });
    c.checked = f[key];
    c.addEventListener("change", () => { f[key] = c.checked; update(); });
    return h("div", { class: "check-row" }, c, h("label", { for: id }, label));
  };

  const framingSel = h("select", { id: "csp-framing" },
    h("option", { value: "'none'" }, "Nunca (frame-ancestors 'none')"),
    h("option", { value: "'self'" }, "Solo mi propio origen ('self')"));
  framingSel.addEventListener("change", () => { f.framing = framingSel.value; update(); });

  const connectIn = h("input", { type: "text", id: "csp-connect", placeholder: "https://api.empresa.com, https://otra.com", autocomplete: "off", spellcheck: "false" });
  connectIn.addEventListener("input", () => { f.connect = connectIn.value; update(); });
  const reportIn = h("input", { type: "url", id: "csp-report", placeholder: "https://reportes.empresa.com/csp", autocomplete: "off", spellcheck: "false" });
  reportIn.addEventListener("input", () => { f.reportUrl = reportIn.value; update(); });

  const warnings = h("ul", { class: "findings" });
  const out = codeBlock("Cabecera HTTP", "", "Copiar cabecera CSP");
  const snippet = codeBlock("Uso en la plantilla", "", "Copiar ejemplo de uso");

  const parseOrigins = (raw) => {
    const ok = [], bad = [];
    for (const item of raw.split(/[\s,]+/).filter(Boolean)) {
      try {
        const u = new URL(item);
        if (u.protocol === "https:" || u.protocol === "wss:") ok.push(`${u.protocol}//${u.host}`); else bad.push(item);
      } catch { bad.push(item); }
    }
    return { ok: [...new Set(ok)], bad };
  };

  function update() {
    const notes = [];
    const dirs = [];
    let reporting = "";
    const connect = parseOrigins(f.connect);
    if (connect.bad.length) notes.push(["warn", `Orígenes ignorados (deben ser https:// o wss:// válidos): ${connect.bad.join(", ")}`]);

    if (f.mode === "api") {
      dirs.push("default-src 'none'", `frame-ancestors ${f.framing}`);
    } else {
      dirs.push("default-src 'self'");
      dirs.push(f.mode === "nonce"
        ? "script-src 'nonce-{NONCE}' 'strict-dynamic' 'report-sample' https: 'unsafe-inline'"
        : "script-src 'self' 'report-sample'");
      dirs.push("style-src 'self'", `img-src 'self' data:${f.imgHttps ? " https:" : ""}`);
      dirs.push(`connect-src 'self'${connect.ok.length ? " " + connect.ok.join(" ") : ""}`);
      dirs.push("object-src 'none'", "base-uri 'none'", `frame-ancestors ${f.framing}`, "form-action 'self'");
      if (f.tt) dirs.push("require-trusted-types-for 'script'");
      dirs.push("upgrade-insecure-requests");
    }
    if (f.reportUrl.trim()) {
      try {
        const u = new URL(f.reportUrl.trim());
        if (u.protocol !== "https:") throw new Error("no https");
        dirs.push(`report-uri ${u.href}`, "report-to csp");
        reporting = `Reporting-Endpoints: csp="${u.href}"`;
      } catch { notes.push(["warn", "La URL de reportes debe ser https:// válida."]); }
    } else if (f.reportOnly) {
      notes.push(["info", "En modo Report-Only agrega una URL de reportes para recibir las violaciones."]);
    }
    if (f.mode === "nonce") notes.push(["info", "Reemplaza {NONCE} por un valor aleatorio (≥128 bits) NUEVO en cada respuesta y no lo cachees. 'https:' y 'unsafe-inline' solo son respaldo para navegadores antiguos: los modernos los ignoran por usar nonce + 'strict-dynamic'."]);
    if (f.mode === "static") notes.push(["info", "Si necesitas un script inline, agrega su hash 'sha256-…' a script-src en lugar de 'unsafe-inline'."]);
    if (f.mode !== "api") notes.push(["info", "style-src 'self' bloquea estilos inline (atributos style=\"…\"); muévelos a archivos .css o usa nonce también en style-src."]);

    const name = f.reportOnly ? "Content-Security-Policy-Report-Only" : "Content-Security-Policy";
    const value = dirs.join("; ");
    out.set([reporting, `${name}: ${value}`].filter(Boolean).join("\n"));
    snippet.set(f.mode === "nonce"
      ? `<!-- Solo los scripts con el nonce de ESTA respuesta se ejecutan -->\n<script nonce="{NONCE}" src="/app.js"></script>\n\n// Node (por petición)\nconst nonce = crypto.randomBytes(16).toString("base64");\n\n# Python (por petición)\nnonce = secrets.token_urlsafe(16)`
      : f.mode === "static"
        ? `<!-- Sin scripts inline ni handlers onclick="…" -->\n<script type="module" src="/assets/app.js"></script>\n\n# Hash de un script inline (si fuera imprescindible):\n# echo -n 'contenido-del-script' | openssl dgst -sha256 -binary | openssl base64`
        : `// La API responde JSON: no necesita cargar nada.\n// Envía también: X-Content-Type-Options: nosniff y Content-Type: application/json`);
    warnings.replaceChildren(...notes.map(([s, t]) => h("li", { class: `finding ${s}` }, h("div", { class: "finding-head" }, h("span", { class: `badge ${s}` }, s === "warn" ? "Atención" : "Nota")), h("p", {}, t))));

    Object.assign(cspState, { value, mode: f.mode, headerName: name, reporting });
    for (const fn of cspListeners) fn();
  }

  root.replaceChildren(
    modeField,
    h("fieldset", {}, h("legend", {}, "Opciones"),
      checkbox("reportOnly", "Modo prueba (Report-Only): no bloquea, solo reporta"),
      checkbox("tt", "Trusted Types (bloquea DOM XSS en innerHTML y similares)"),
      checkbox("imgHttps", "Permitir imágenes de cualquier origen https:"),
      h("div", { class: "field" }, h("label", { for: "csp-framing" }, "¿Quién puede mostrar tu página en un iframe?"), framingSel),
      h("div", { class: "field" }, h("label", { for: "csp-connect" }, "APIs externas que llama el navegador (connect-src)", h("span", { class: "hint" }, " Separadas por coma")), connectIn),
      h("div", { class: "field" }, h("label", { for: "csp-report" }, "URL para reportes de violaciones (opcional)"), reportIn),
    ),
    out.node, snippet.node, warnings,
  );
  update();
}

function initCSPAnalyzer() {
  const root = document.getElementById("csp-analyzer");
  const ta = h("textarea", { id: "csp-input", rows: "6", spellcheck: "false", placeholder: "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.ejemplo.com" });
  const results = h("ul", { class: "findings", "aria-live": "polite" });
  const run = () => {
    const raw = ta.value.trim().replace(/^content-security-policy(?:-report-only)?\s*:\s*/i, "");
    if (!raw) { results.replaceChildren(h("li", { class: "empty" }, "Pega una política para analizarla.")); return; }
    results.replaceChildren(...renderFindings(analyzeCSP(raw)));
  };
  root.replaceChildren(
    h("div", { class: "field" }, h("label", { for: "csp-input" }, "Pega el valor de tu Content-Security-Policy"), ta),
    h("div", { class: "toolbar" },
      h("button", { type: "button", class: "primary", onclick: run }, "Analizar CSP"),
      h("button", { type: "button", onclick: () => { ta.value = cspState.value; run(); } }, "Usar la del generador")),
    results,
  );
}

const STATUS_LABEL = { ok: "Correcto", warn: "Atención", fail: "Falla", info: "Info" };

function renderFindings(list) {
  const order = { fail: 0, warn: 1, info: 2, ok: 3 };
  return [...list].sort((a, b) => order[a.status] - order[b.status]).map((f) =>
    h("li", { class: `finding ${f.status}` },
      h("div", { class: "finding-head" },
        h("span", { class: `badge ${f.status}` }, STATUS_LABEL[f.status]),
        h("strong", {}, f.title),
        f.guide ? guideLink(f.guide) : null),
      f.detail ? h("p", {}, f.detail) : null,
      f.fix ? h("pre", {}, f.fix) : null,
    ));
}

/* =================================================================== Generador de headers */

function initHeadersGenerator() {
  const root = document.getElementById("headers-app");
  const f = { stack: "nginx", preload: false, framing: "DENY", coop: "same-origin", csp: true, noStore: false, corp: false };

  const STACKS = [["nginx", "Nginx"], ["apache", "Apache"], ["express", "Node / Express"], ["fastapi", "Python / FastAPI"], ["django", "Python / Django"], ["raw", "Cabeceras HTTP"]];
  const stackGroup = h("div", { class: "toolbar", role: "group", "aria-label": "Tecnología" });
  for (const [v, label] of STACKS) {
    const b = h("button", { type: "button", "aria-pressed": String(v === f.stack) }, label);
    b.addEventListener("click", () => {
      f.stack = v;
      for (const x of stackGroup.children) x.setAttribute("aria-pressed", String(x === b));
      update();
    });
    stackGroup.append(b);
  }

  const cb = (key, label) => {
    const id = nextId("hdr");
    const c = h("input", { type: "checkbox", id });
    c.checked = f[key];
    c.addEventListener("change", () => { f[key] = c.checked; update(); });
    return h("div", { class: "check-row" }, c, h("label", { for: id }, label));
  };
  const select = (key, label, options) => {
    const id = nextId("hdr");
    const s = h("select", { id }, ...options.map(([v, t]) => h("option", { value: v }, t)));
    s.value = f[key];
    s.addEventListener("change", () => { f[key] = s.value; update(); });
    return h("div", { class: "field" }, h("label", { for: id }, label), s);
  };

  const out = codeBlock("Configuración", "", "Copiar configuración de cabeceras");
  const note = h("p", { class: "hint" });

  function headers() {
    const list = [
      ["Strict-Transport-Security", `max-age=63072000; includeSubDomains${f.preload ? "; preload" : ""}`],
      ["X-Content-Type-Options", "nosniff"],
      ["X-Frame-Options", f.framing],
      ["Referrer-Policy", "strict-origin-when-cross-origin"],
      ["Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()"],
      ["Cross-Origin-Opener-Policy", f.coop],
    ];
    if (f.corp) list.push(["Cross-Origin-Resource-Policy", "same-origin"]);
    if (f.noStore) list.push(["Cache-Control", "no-store"]);
    return list;
  }

  function update() {
    const list = headers();
    const csp = f.csp ? cspState : null;
    const nonce = csp && csp.mode === "nonce";
    let text = "";
    const notes = [];
    switch (f.stack) {
      case "nginx": {
        text = "# Dentro de server { }. 'always' también aplica a respuestas de error.\n"
          + "# OJO: un add_header dentro de un location reemplaza TODOS los heredados; usa un include.\n"
          + "server_tokens off;\nproxy_hide_header X-Powered-By;\nproxy_hide_header X-AspNet-Version;\n"
          + list.map(([k, v]) => `add_header ${k} "${v}" always;`).join("\n");
        if (csp && !nonce) text += `\n${csp.reporting ? `add_header Reporting-Endpoints '${csp.reporting.split(": ")[1]}' always;\n` : ""}add_header ${csp.headerName} "${csp.value}" always;`;
        if (nonce) notes.push("La CSP con nonce debe generarla la aplicación (nonce distinto por respuesta), no Nginx.");
        break;
      }
      case "apache": {
        text = "# httpd.conf o VirtualHost (requiere mod_headers)\nServerTokens Prod\nServerSignature Off\nHeader always unset X-Powered-By\n"
          + list.map(([k, v]) => `Header always set ${k} "${v}"`).join("\n");
        if (csp && !nonce) text += `\nHeader always set ${csp.headerName} "${csp.value}"`;
        if (nonce) notes.push("La CSP con nonce debe generarla la aplicación (nonce distinto por respuesta), no Apache.");
        break;
      }
      case "express": {
        const lines = [
          'import crypto from "node:crypto";', "",
          'app.disable("x-powered-by");', "",
          "app.use((req, res, next) => {",
        ];
        if (nonce) lines.push('  const nonce = crypto.randomBytes(16).toString("base64");', "  res.locals.cspNonce = nonce; // úsalo en <script nonce=\"…\">");
        for (const [k, v] of list) lines.push(`  res.setHeader("${k}", "${v}");`);
        if (csp) {
          if (csp.reporting) lines.push(`  res.setHeader("Reporting-Endpoints", ${JSON.stringify(csp.reporting.split(": ")[1])});`);
          lines.push(nonce
            ? `  res.setHeader("${csp.headerName}", \`${csp.value.replaceAll("{NONCE}", "${nonce}")}\`);`
            : `  res.setHeader("${csp.headerName}", ${JSON.stringify(csp.value)});`);
        }
        lines.push("  next();", "});", "", "// Alternativa: el paquete helmet configura la mayoría de estas cabeceras.");
        text = lines.join("\n");
        break;
      }
      case "fastapi": {
        const lines = [
          "import secrets",
          "from starlette.middleware.base import BaseHTTPMiddleware", "",
          "class SecurityHeaders(BaseHTTPMiddleware):",
          "    async def dispatch(self, request, call_next):",
        ];
        if (nonce) lines.push("        nonce = secrets.token_urlsafe(16)", "        request.state.csp_nonce = nonce  # úsalo en la plantilla");
        lines.push("        response = await call_next(request)", "        response.headers.update({");
        for (const [k, v] of list) lines.push(`            "${k}": "${v}",`);
        if (csp) {
          if (csp.reporting) lines.push(`            "Reporting-Endpoints": ${JSON.stringify(csp.reporting.split(": ")[1])},`);
          lines.push(nonce
            ? `            "${csp.headerName}": f"${csp.value.replaceAll("{NONCE}", "{nonce}")}",`
            : `            "${csp.headerName}": ${JSON.stringify(csp.value)},`);
        }
        lines.push("        })", "        return response", "", "app.add_middleware(SecurityHeaders)",
          "# Uvicorn: --no-server-header para ocultar el header Server.");
        text = lines.join("\n");
        break;
      }
      case "django": {
        const lines = [
          "# settings.py",
          "SECURE_HSTS_SECONDS = 63072000",
          "SECURE_HSTS_INCLUDE_SUBDOMAINS = True",
          `SECURE_HSTS_PRELOAD = ${f.preload ? "True" : "False"}`,
          "SECURE_SSL_REDIRECT = True",
          "SECURE_CONTENT_TYPE_NOSNIFF = True",
          `X_FRAME_OPTIONS = "${f.framing}"`,
          'SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"',
          `SECURE_CROSS_ORIGIN_OPENER_POLICY = "${f.coop}"`,
          "DEBUG = False", "",
          "# middleware.py — cabeceras que Django no cubre por configuración",
          "import secrets", "",
          "class SecurityHeadersMiddleware:",
          "    def __init__(self, get_response):",
          "        self.get_response = get_response", "",
          "    def __call__(self, request):",
        ];
        if (nonce) lines.push("        request.csp_nonce = secrets.token_urlsafe(16)  # úsalo en la plantilla");
        lines.push("        response = self.get_response(request)",
          '        response["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"');
        if (f.corp) lines.push('        response["Cross-Origin-Resource-Policy"] = "same-origin"');
        if (f.noStore) lines.push('        response["Cache-Control"] = "no-store"');
        if (csp) {
          if (csp.reporting) lines.push(`        response["Reporting-Endpoints"] = ${JSON.stringify(csp.reporting.split(": ")[1])}`);
          lines.push(nonce
            ? `        response["${csp.headerName}"] = f"${csp.value.replaceAll("{NONCE}", "{request.csp_nonce}")}"`
            : `        response["${csp.headerName}"] = ${JSON.stringify(csp.value)}`);
        }
        lines.push("        return response", "", '# Registra "app.middleware.SecurityHeadersMiddleware" en MIDDLEWARE.');
        text = lines.join("\n");
        break;
      }
      default: {
        const lines = list.map(([k, v]) => `${k}: ${v}`);
        if (csp) { if (csp.reporting) lines.push(csp.reporting); lines.push(`${csp.headerName}: ${csp.value}`); }
        text = lines.join("\n");
      }
    }
    if (f.preload) notes.push("preload es difícil de revertir: actívalo solo si TODOS los subdominios sirven HTTPS. Empieza con un max-age corto y súbelo de forma progresiva.");
    if (f.coop === "same-origin") notes.push("Si usas login con OAuth o pagos en ventana emergente, elige same-origin-allow-popups.");
    if (f.csp) notes.push("La CSP proviene del generador de la sección 06.");
    out.set(text);
    note.textContent = notes.join(" ");
  }

  cspListeners.add(update);
  root.replaceChildren(
    stackGroup,
    h("div", { class: "grid-2" },
      h("fieldset", {}, h("legend", {}, "Opciones"),
        cb("csp", "Incluir la CSP del generador (sección 06)"),
        cb("noStore", "Respuestas privadas: Cache-Control no-store"),
        cb("corp", "Cross-Origin-Resource-Policy: same-origin (API / recursos privados)"),
        cb("preload", "HSTS preload"),
      ),
      h("div", {},
        select("framing", "¿Iframes de tu propio sitio?", [["DENY", "No (DENY)"], ["SAMEORIGIN", "Sí, solo mismo origen (SAMEORIGIN)"]]),
        select("coop", "Ventanas emergentes (COOP)", [["same-origin", "same-origin"], ["same-origin-allow-popups", "same-origin-allow-popups (OAuth / pagos)"]]),
      ),
    ),
    out.node, note,
  );
  update();
}

/* =================================================================== Generador de cookies */

function initCookieBuilder() {
  const root = document.getElementById("cookie-app");
  const f = { name: "session", kind: "session", sameSite: "Strict", hours: 8, embedded: false };
  const out = codeBlock("Set-Cookie", "", "Copiar cabecera Set-Cookie");
  const fw = codeBlock("Frameworks", "", "Copiar configuración de frameworks");
  const notes = h("ul", { class: "findings" });

  const nameIn = h("input", { type: "text", id: "ck-name", value: f.name, autocomplete: "off", spellcheck: "false" });
  nameIn.addEventListener("input", () => { f.name = nameIn.value; update(); });
  const kindSel = h("select", { id: "ck-kind" },
    h("option", { value: "session" }, "Sesión / autenticación"),
    h("option", { value: "csrf" }, "Token CSRF (double-submit, lo lee JS)"),
    h("option", { value: "pref" }, "Preferencia no sensible (tema, idioma)"));
  kindSel.addEventListener("change", () => { f.kind = kindSel.value; update(); });
  const ssSel = h("select", { id: "ck-samesite" },
    h("option", { value: "Strict" }, "Strict (máxima protección)"),
    h("option", { value: "Lax" }, "Lax (permite llegar desde enlaces externos)"));
  ssSel.addEventListener("change", () => { f.sameSite = ssSel.value; update(); });
  const hoursIn = h("input", { type: "number", id: "ck-hours", min: "0", max: "8760", value: String(f.hours) });
  hoursIn.addEventListener("input", () => { f.hours = Number(hoursIn.value) || 0; update(); });
  const embId = nextId("ck");
  const emb = h("input", { type: "checkbox", id: embId });
  emb.addEventListener("change", () => { f.embedded = emb.checked; update(); });

  function update() {
    const list = [];
    const base = (f.name.trim() || "session").replace(/^__(Host|Secure)-/i, "").replace(/[^A-Za-z0-9_.-]/g, "");
    const name = f.embedded ? `__Secure-${base}` : `__Host-${base}`;
    const httpOnly = f.kind !== "csrf";
    const sameSite = f.embedded ? "None" : f.sameSite;
    const maxAge = Math.round(f.hours * 3600);
    const attrs = ["Path=/", "Secure"];
    if (httpOnly) attrs.push("HttpOnly");
    attrs.push(`SameSite=${sameSite}`);
    if (f.embedded) attrs.push("Partitioned");
    if (maxAge > 0) attrs.push(`Max-Age=${maxAge}`);
    out.set(`Set-Cookie: ${name}=<valor-aleatorio>; ${attrs.join("; ")}`);

    const ss = sameSite.toLowerCase();
    fw.set([
      "// Express",
      `res.cookie("${name}", valor, { httpOnly: ${httpOnly}, secure: true, sameSite: "${ss}", path: "/"${maxAge ? `, maxAge: ${maxAge * 1000}` : ""}${f.embedded ? ", partitioned: true" : ""} });`,
      "",
      "# Flask",
      `resp.set_cookie("${name}", valor, httponly=${httpOnly ? "True" : "False"}, secure=True, samesite="${sameSite}", path="/"${maxAge ? `, max_age=${maxAge}` : ""})`,
      "",
      "# Django (settings.py, cookie de sesión)",
      `SESSION_COOKIE_NAME = "${name}"`,
      "SESSION_COOKIE_SECURE = True",
      `SESSION_COOKIE_HTTPONLY = ${httpOnly ? "True" : "False"}`,
      `SESSION_COOKIE_SAMESITE = "${sameSite}"`,
      "",
      "# FastAPI / Starlette",
      `response.set_cookie("${name}", valor, httponly=${httpOnly ? "True" : "False"}, secure=True, samesite="${ss}", path="/"${maxAge ? `, max_age=${maxAge}` : ""})`,
    ].join("\n"));

    if (f.kind === "csrf") list.push(["info", "El token CSRF de double-submit debe leerlo JavaScript, por eso no lleva HttpOnly. La cookie de sesión sí debe llevarlo."]);
    if (f.kind === "session" && f.hours > 24) list.push(["warn", "Una sesión de más de 24 horas amplía la ventana de uso de una cookie robada. Considera expiración por inactividad en el servidor."]);
    if (maxAge === 0) list.push(["info", "Sin Max-Age es una cookie de sesión del navegador (se borra al cerrarlo, aunque algunos navegadores restauran sesiones)."]);
    if (f.embedded) list.push(["warn", "Embebida en iframes de terceros: requiere SameSite=None; Secure; Partitioned y prefijo __Secure-. Pierdes la protección de SameSite contra CSRF: usa token anti-CSRF."]);
    else list.push(["ok", "__Host- obliga a Secure y Path=/ y prohíbe Domain: ningún subdominio puede sobrescribirla."]);
    list.push(["info", "El valor debe ser aleatorio (≥128 bits, CSPRNG), regenerarse al iniciar sesión e invalidarse en el servidor al cerrarla."]);
    notes.replaceChildren(...list.map(([s, t]) => h("li", { class: `finding ${s}` }, h("div", { class: "finding-head" }, h("span", { class: `badge ${s}` }, STATUS_LABEL[s])), h("p", {}, t))));
  }

  root.replaceChildren(
    h("div", { class: "grid-2" },
      h("div", {},
        h("div", { class: "field" }, h("label", { for: "ck-name" }, "Nombre"), nameIn),
        h("div", { class: "field" }, h("label", { for: "ck-kind" }, "Uso de la cookie"), kindSel)),
      h("div", {},
        h("div", { class: "field" }, h("label", { for: "ck-samesite" }, "SameSite"), ssSel),
        h("div", { class: "field" }, h("label", { for: "ck-hours" }, "Duración (horas, 0 = cookie de sesión)"), hoursIn),
        h("div", { class: "check-row" }, emb, h("label", { for: embId }, "Se usa dentro de un iframe en sitios de terceros")))),
    out.node, fw.node, notes,
  );
  update();
}

/* =================================================================== Analizador de respuesta HTTP */

function parseHttp(text) {
  const headers = [];
  let status = "";
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (/^HTTP\/\d/i.test(line)) { status = line; headers.length = 0; continue; } // con redirecciones, se analiza la última respuesta
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    headers.push({ name: line.slice(0, idx).trim().toLowerCase(), value: line.slice(idx + 1).trim() });
  }
  return { status, headers };
}

const SENSITIVE_COOKIE = /sess|sid|token|auth|jwt|login|remember|identity|access|refresh/i;

function analyzeCookie(raw) {
  const [pair, ...attrParts] = raw.split(";");
  const name = pair.split("=")[0].trim();
  const attrs = new Map(attrParts.map((a) => {
    const [k, ...v] = a.trim().split("=");
    return [k.trim().toLowerCase(), v.join("=").trim()];
  }));
  const out = [];
  const isCsrf = /csrf|xsrf/i.test(name);
  const sensitive = SENSITIVE_COOKIE.test(name) || isCsrf;
  const title = (t) => `Cookie ${name}: ${t}`;
  if (!attrs.has("secure")) out.push({ status: sensitive ? "fail" : "warn", title: title("sin Secure"), detail: "Puede viajar por HTTP en claro.", fix: "Agrega Secure." , guide: "01.02" });
  if (!attrs.has("httponly")) {
    if (isCsrf) out.push({ status: "info", title: title("sin HttpOnly"), detail: "Aceptable si es un token CSRF double-submit que debe leer JavaScript." });
    else out.push({ status: sensitive ? "fail" : "info", title: title("sin HttpOnly"), detail: sensitive ? "Cualquier XSS puede robarla con document.cookie." : "Solo es aceptable en cookies no sensibles que lee el frontend.", fix: sensitive ? "Agrega HttpOnly." : null, guide: "01.02" });
  }
  const ss = attrs.get("samesite")?.toLowerCase();
  if (!attrs.has("samesite")) out.push({ status: "warn", title: title("sin SameSite"), detail: "Declárala explícitamente; no dependas del valor por defecto de cada navegador.", fix: "SameSite=Strict (o Lax)." , guide: "01.02" });
  else if (ss === "none" && !attrs.has("secure")) out.push({ status: "fail", title: title("SameSite=None sin Secure"), detail: "Los navegadores la rechazan y, de aceptarla, se enviaría en peticiones cross-site." });
  else if (ss === "none") out.push({ status: attrs.has("partitioned") ? "info" : "warn", title: title("SameSite=None"), detail: "Se envía en peticiones desde otros sitios: requiere token anti-CSRF. Si es para iframes de terceros, agrega Partitioned." });
  if (attrs.has("domain") && sensitive) out.push({ status: "warn", title: title(`Domain=${attrs.get("domain")}`), detail: "Se envía a todos los subdominios; uno comprometido puede leerla o sobrescribirla.", fix: "Quita Domain y usa el prefijo __Host-." });
  if (name.startsWith("__Host-") && (!attrs.has("secure") || attrs.get("path") !== "/" || attrs.has("domain"))) out.push({ status: "fail", title: title("prefijo __Host- inválido"), detail: "__Host- exige Secure, Path=/ y sin Domain; el navegador la rechazará." });
  else if (sensitive && !isCsrf && !name.startsWith("__Host-") && !name.startsWith("__Secure-")) out.push({ status: "info", title: title("sin prefijo __Host-"), detail: "Recomendado para cookies de sesión: impide que un subdominio la sobrescriba." });
  const maxAge = Number(attrs.get("max-age"));
  if (sensitive && !isCsrf && maxAge > 30 * 24 * 3600) out.push({ status: "info", title: title("duración larga"), detail: `Max-Age de ${Math.round(maxAge / 86400)} días; limita la vida de las sesiones.` });
  if (!out.some((f) => f.status === "fail" || f.status === "warn")) out.push({ status: "ok", title: title("sin problemas relevantes"), detail: sensitive ? "Flags adecuadas para una cookie sensible." : "Flags adecuadas para una cookie no sensible." });
  return out;
}

function analyzeHttp(text) {
  const { status, headers } = parseHttp(text);
  const get = (n) => headers.filter((x) => x.name === n).map((x) => x.value);
  const one = (n) => get(n)[0];
  const out = [];
  const add = (s, title, detail, fix, guide) => out.push({ status: s, title, detail, fix, guide });

  // HSTS
  const hsts = one("strict-transport-security");
  if (!hsts) add("fail", "Falta Strict-Transport-Security", "El navegador podría conectarse por HTTP y ser interceptado.", "Strict-Transport-Security: max-age=63072000; includeSubDomains", "03.01");
  else {
    const age = Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts)?.[1] ?? 0);
    if (age < 31536000) add("warn", `HSTS con max-age bajo (${age} s)`, "Recomendado ≥ 1 año (31536000) una vez validado.", "Strict-Transport-Security: max-age=63072000; includeSubDomains", "03.01");
    else add("ok", "HSTS correcto", hsts);
    if (!/includesubdomains/i.test(hsts)) add("info", "HSTS sin includeSubDomains", "Considera incluir los subdominios si todos sirven HTTPS.");
  }

  // CSP
  const csp = one("content-security-policy");
  const cspRO = one("content-security-policy-report-only");
  if (!csp && !cspRO) add("fail", "Falta Content-Security-Policy", "Sin CSP, un XSS ejecuta cualquier script.", "Usa el generador de la sección 06.", "01.02");
  else {
    if (!csp) add("warn", "CSP solo en modo Report-Only", "No bloquea: solo reporta. Planifica la fecha para hacerla obligatoria.", null, "01.02");
    for (const f of analyzeCSP(csp ?? cspRO)) out.push({ ...f, title: `CSP: ${f.title}`, guide: f.status === "ok" || f.status === "info" ? null : "01.02" });
  }

  // Clickjacking
  const xfo = one("x-frame-options");
  const fa = parseCSP(csp ?? "").get("frame-ancestors");
  if (!xfo && !fa) add("fail", "Sin protección contra clickjacking", "Ni X-Frame-Options ni frame-ancestors.", "X-Frame-Options: DENY\nContent-Security-Policy: frame-ancestors 'none'", "03.03");
  else if (xfo && !/^(deny|sameorigin)$/i.test(xfo)) add("warn", `X-Frame-Options inválido: ${xfo}`, "Solo DENY o SAMEORIGIN son válidos (ALLOW-FROM está obsoleto).");
  else add("ok", "Protección contra clickjacking", xfo ? `X-Frame-Options: ${xfo}` : `frame-ancestors ${fa.join(" ")}`);

  // nosniff
  const xcto = one("x-content-type-options");
  if (!xcto || xcto.toLowerCase() !== "nosniff") add("fail", "Falta X-Content-Type-Options: nosniff", "El navegador puede interpretar un archivo como script (MIME sniffing).", "X-Content-Type-Options: nosniff", "03.03");
  else add("ok", "X-Content-Type-Options: nosniff", "");

  // Referrer
  const rp = one("referrer-policy");
  if (!rp) add("warn", "Falta Referrer-Policy", "Las URLs completas (con tokens o IDs) pueden filtrarse a otros sitios.", "Referrer-Policy: strict-origin-when-cross-origin", "03.03");
  else if (/unsafe-url|no-referrer-when-downgrade/i.test(rp)) add("warn", `Referrer-Policy débil: ${rp}`, "Envía la URL completa a otros orígenes.", "Referrer-Policy: strict-origin-when-cross-origin");
  else add("ok", "Referrer-Policy", rp);

  // Permissions / COOP
  if (!one("permissions-policy")) add("warn", "Falta Permissions-Policy", "Desactiva las APIs del navegador que no usas.", "Permissions-Policy: camera=(), microphone=(), geolocation=()", "03.03");
  else add("ok", "Permissions-Policy", one("permissions-policy"));
  if (!one("cross-origin-opener-policy")) add("info", "Falta Cross-Origin-Opener-Policy", "Aísla tu ventana frente a ventanas de otros sitios.", "Cross-Origin-Opener-Policy: same-origin");

  // Fugas de información
  const server = one("server");
  if (server && /\d/.test(server)) add("fail", `Header Server revela versión: ${server}`, "Facilita buscar exploits para esa versión exacta.", "Nginx: server_tokens off;  ·  Apache: ServerTokens Prod", "03.03");
  else if (server) add("info", `Header Server: ${server}`, "No revela versión; puedes eliminarlo por completo si tu servidor lo permite.");
  for (const n of ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-runtime", "x-generator", "x-drupal-cache", "x-backend-server"]) {
    const v = one(n);
    if (v) add("fail", `Header ${n} expuesto: ${v}`, "Revela tecnología/versión interna.", n === "x-powered-by" ? "Express: app.disable(\"x-powered-by\")  ·  Nginx: proxy_hide_header X-Powered-By;" : `Elimina el header ${n}.`, "03.03");
  }
  const xxss = one("x-xss-protection");
  if (xxss && !/^0/.test(xxss)) add("warn", `X-XSS-Protection: ${xxss}`, "El filtro XSS legado está retirado y llegó a introducir vulnerabilidades.", "X-XSS-Protection: 0 (o elimínalo) y usa CSP.");

  // CORS
  const acao = one("access-control-allow-origin");
  const acac = (one("access-control-allow-credentials") ?? "").toLowerCase() === "true";
  if (acao === "*" && acac) add("fail", "CORS: '*' con credenciales", "Configuración inválida y señal de CORS reflejado/permisivo en otras rutas.", "Allow-list exacta: Access-Control-Allow-Origin: https://app.empresa.com", "03.03");
  else if (acao === "null") add("fail", "CORS: Access-Control-Allow-Origin: null", "Documentos sandbox o file:// de un atacante obtienen acceso.", "Allow-list exacta de orígenes.", "03.03");
  else if (acao === "*") add("warn", "CORS abierto (*)", "Aceptable solo para recursos públicos sin datos de usuario.", null, "03.03");
  else if (acao && acac) add("info", `CORS con credenciales para ${acao}`, "Verifica que el servidor valida el Origin contra una allow-list y no refleja cualquier origen.");

  // Cookies
  for (const c of get("set-cookie")) out.push(...analyzeCookie(c));

  // Redirecciones y caché
  const loc = one("location");
  if (loc && /^http:\/\//i.test(loc)) add("warn", "Redirección a http://", `Location: ${loc}`, "Redirige siempre a https://.", "03.01");
  if (get("set-cookie").length && !/no-store|private/i.test(one("cache-control") ?? "")) add("info", "Respuesta con cookies sin Cache-Control privado", "Si contiene datos del usuario, usa Cache-Control: no-store.");
  if (!headers.length) return { status, out: [], empty: true };
  return { status, out, empty: false };
}

function gradeFrom(findings) {
  let score = 100;
  for (const f of findings) score -= f.status === "fail" ? 12 : f.status === "warn" ? 4 : 0;
  score = Math.max(0, score);
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 45 ? "D" : "F";
  return { score, grade };
}

function initHttpAnalyzer() {
  const root = document.getElementById("http-app");
  const ta = h("textarea", { id: "http-input", rows: "10", spellcheck: "false", placeholder: "HTTP/2 200\ncontent-type: text/html\nstrict-transport-security: max-age=63072000\n…" });
  const summary = h("div", { class: "result-summary", "aria-live": "polite" });
  const results = h("ul", { class: "findings" });
  const status = h("p", { class: "hint", role: "status" });
  let last = [];

  const run = () => {
    const text = ta.value.slice(0, 100_000);
    if (!text.trim()) { summary.replaceChildren(); results.replaceChildren(h("li", { class: "empty" }, "Pega las cabeceras de respuesta para analizarlas.")); return; }
    const r = analyzeHttp(text);
    if (r.empty) { summary.replaceChildren(); results.replaceChildren(h("li", { class: "empty" }, "No se encontraron cabeceras con el formato «Nombre: valor».")); return; }
    last = r.out;
    const { score, grade } = gradeFrom(r.out);
    const count = (s) => r.out.filter((f) => f.status === s).length;
    summary.replaceChildren(
      h("span", { class: `grade g-${grade.toLowerCase()}`, "aria-label": `Calificación ${grade}` }, grade),
      h("div", {},
        h("strong", {}, `Puntaje ${score}/100`), r.status ? h("span", { class: "hint" }, ` · ${r.status}`) : null,
        h("div", { class: "toolbar" },
          h("span", { class: "badge fail" }, `${count("fail")} fallas`),
          h("span", { class: "badge warn" }, `${count("warn")} advertencias`),
          h("span", { class: "badge info" }, `${count("info")} notas`),
          h("span", { class: "badge ok" }, `${count("ok")} correctos`))),
    );
    results.replaceChildren(...renderFindings(r.out));
  };

  const toMd = () => ["## Análisis de cabeceras HTTP", "",
    ...last.filter((f) => f.status !== "ok").map((f) => `- **${STATUS_LABEL[f.status]}** — ${f.title}${f.detail ? `: ${f.detail}` : ""}${f.fix ? ` → \`${f.fix.replace(/\n/g, " · ")}\`` : ""}`)].join("\n");

  root.replaceChildren(
    h("p", { class: "privacy-note" }, "Los valores de las cookies no se muestran en el reporte. Aun así, evita pegar cabeceras de sesiones reales de producción."),
    h("div", { class: "field" }, h("label", { for: "http-input" }, "Cabeceras de respuesta"), ta),
    h("div", { class: "toolbar" },
      h("button", { type: "button", class: "primary", onclick: run }, "Analizar"),
      h("button", { type: "button", onclick: () => { ta.value = SAMPLE_HTTP; run(); } }, "Cargar ejemplo vulnerable"),
      h("button", { type: "button", class: "ghost", onclick: async () => {
        if (!last.length) { status.textContent = "Primero analiza una respuesta."; return; }
        try { await navigator.clipboard.writeText(toMd()); status.textContent = "Reporte copiado en Markdown."; } catch { status.textContent = "No se pudo copiar."; }
      } }, "Copiar reporte"),
      h("button", { type: "button", class: "ghost", onclick: () => { ta.value = ""; last = []; summary.replaceChildren(); results.replaceChildren(); } }, "Limpiar")),
    h("div", { class: "code-block" }, h("span", { class: "lang", text: "Obtén las cabeceras" }),
      h("pre", { tabindex: "0" }, h("code", { id: "curl-cmd" }, "curl -sSI https://tu-app.com\n# Con redirecciones:  curl -sSIL https://tu-app.com")),
      copyControl("curl-cmd", "Copiar comando curl")),
    status, summary, results,
  );
}

/* =================================================================== Escáner local de código */

function maskSecret(line, re) {
  return line.replace(new RegExp(re.source, re.flags.replace("g", "") + "g"), (m) => `${m.slice(0, 4)}…[oculto]`);
}

function scanCode(text) {
  const isDocker = /^\s*FROM\s+\S+/m.test(text) && /^\s*(RUN|COPY|ADD|CMD|ENTRYPOINT|WORKDIR|EXPOSE|USER)\b/m.test(text);
  const findings = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((full, i) => {
    const line = full.length > 2000 ? full.slice(0, 2000) : full; // límite defensivo contra líneas enormes
    for (const rule of SCAN_RULES) {
      if (rule.scope === "docker" && !isDocker) continue;
      if (!rule.re.test(line)) continue;
      const shown = (rule.secret ? maskSecret(line, rule.re) : line).trim();
      findings.push({ rule, line: i + 1, snippet: shown.length > 180 ? `${shown.slice(0, 180)}…` : shown });
    }
  });
  const order = { crit: 0, alta: 1, media: 2, info: 3 };
  return findings.sort((a, b) => order[a.rule.sev] - order[b.rule.sev] || a.line - b.line);
}

function initCodeScanner() {
  const root = document.getElementById("code-app");
  const ta = h("textarea", { id: "code-input", rows: "14", spellcheck: "false", placeholder: "Pega aquí tu código, configuración o Dockerfile…" });
  const summary = h("div", { class: "result-summary", "aria-live": "polite" });
  const results = h("ul", { class: "findings" });
  const status = h("p", { class: "hint", role: "status" });
  let last = [];

  const run = () => {
    const text = ta.value.slice(0, 300_000);
    if (!text.trim()) { summary.replaceChildren(); results.replaceChildren(h("li", { class: "empty" }, "Pega código para revisarlo.")); return; }
    last = scanCode(text);
    const count = (s) => last.filter((f) => f.rule.sev === s).length;
    summary.replaceChildren(last.length
      ? h("div", { class: "toolbar" },
        h("strong", {}, `${last.length} hallazgos`),
        h("span", { class: "badge crit" }, `${count("crit")} críticos`),
        h("span", { class: "badge alta" }, `${count("alta")} altos`),
        h("span", { class: "badge media" }, `${count("media")} medios`),
        h("span", { class: "badge info" }, `${count("info")} info`))
      : h("span", { class: "badge ok" }, "Sin hallazgos por patrones. Ejecuta igualmente Semgrep, gitleaks y la revisión humana."));
    results.replaceChildren(...last.map((f) => h("li", { class: `finding ${f.rule.sev}` },
      h("div", { class: "finding-head" },
        h("span", { class: `badge ${f.rule.sev}` }, SEV_LABEL[f.rule.sev]),
        h("strong", {}, f.rule.title),
        h("span", { class: "hint" }, `Línea ${f.line} · ${f.rule.cat}`),
        guideLink(f.rule.guide)),
      h("pre", {}, f.snippet),
      h("p", { class: "fix" }, `Cómo corregirlo: ${f.rule.fix}`))));
  };

  const toMd = () => ["## Revisión rápida de código (patrones)", "",
    ...last.map((f) => `- **${SEV_LABEL[f.rule.sev]}** L${f.line} — ${f.rule.title}: ${f.rule.fix}`)].join("\n");

  root.replaceChildren(
    h("p", { class: "privacy-note" }, "El análisis se hace en tu navegador; el código no se envía a ningún sitio. Los secretos detectados se muestran enmascarados. Si encuentras uno real: revócalo y rótalo."),
    h("div", { class: "field" }, h("label", { for: "code-input" }, "Código o configuración"), ta),
    h("div", { class: "toolbar" },
      h("button", { type: "button", class: "primary", onclick: run }, "Revisar código"),
      h("button", { type: "button", onclick: () => { ta.value = SAMPLE_CODE; run(); } }, "Cargar ejemplo vulnerable"),
      h("button", { type: "button", class: "ghost", onclick: async () => {
        if (!last.length) { status.textContent = "No hay hallazgos que copiar."; return; }
        try { await navigator.clipboard.writeText(toMd()); status.textContent = "Reporte copiado en Markdown."; } catch { status.textContent = "No se pudo copiar."; }
      } }, "Copiar reporte"),
      h("button", { type: "button", class: "ghost", onclick: () => { ta.value = ""; last = []; summary.replaceChildren(); results.replaceChildren(); } }, "Limpiar")),
    status, summary, results,
  );
}

/* =================================================================== Dependencias: SLA y comandos */

function initSLA() {
  const root = document.getElementById("sla-app");
  const today = new Date();
  const iso = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  const dateIn = h("input", { type: "date", id: "sla-date", value: iso(today) });
  const sevSel = h("select", { id: "sla-sev" },
    h("option", { value: "crit" }, "Crítica (CVSS ≥ 9.0)"),
    h("option", { value: "alta" }, "Alta (7.0 – 8.9)"),
    h("option", { value: "media" }, "Media (4.0 – 6.9)"),
    h("option", { value: "baja" }, "Baja"));
  const exId = nextId("sla");
  const exploit = h("input", { type: "checkbox", id: exId });
  const result = h("div", { class: "callout", "aria-live": "polite" });
  const fmt = new Intl.DateTimeFormat("es", { dateStyle: "full" });

  const update = () => {
    const [y, m, d] = (dateIn.value || iso(today)).split("-").map(Number);
    const start = new Date(y, m - 1, d);
    const sev = sevSel.value;
    let days = { crit: 7, alta: 30, media: 90 }[sev];
    let label = "";
    if (sev === "crit" && exploit.checked) { days = 3; label = "72 horas (explotación activa conocida)"; }
    if (sev === "baja") {
      result.replaceChildren(h("p", {}, h("strong", {}, "Próximo ciclo de mantenimiento."), " Regístrala y corrígela con la siguiente actualización planificada."));
      return;
    }
    const due = new Date(start); due.setDate(due.getDate() + days);
    const nodes = [
      h("p", {}, "Fecha límite para producción: ", h("strong", {}, fmt.format(due)), ` (${label || `${days} días`}).`),
      h("p", {}, "Si no se puede actualizar a tiempo: mitigación compensatoria (WAF, deshabilitar la función) y excepción documentada con fecha de expiración."),
    ];
    if (exploit.checked && sev !== "crit") nodes.push(h("p", {}, "Con explotación activa conocida (p. ej. en CISA KEV), valora tratarla como crítica."));
    result.replaceChildren(...nodes);
  };
  for (const el of [dateIn, sevSel, exploit]) el.addEventListener("input", update);
  root.replaceChildren(
    h("div", { class: "field" }, h("label", { for: "sla-date" }, "Fecha de detección"), dateIn),
    h("div", { class: "field" }, h("label", { for: "sla-sev" }, "Severidad"), sevSel),
    h("div", { class: "check-row" }, exploit, h("label", { for: exId }, "Hay explotación activa conocida (CISA KEV / exploit público)")),
    result);
  update();
}

function initDepsCommands() {
  const root = document.getElementById("deps-cmds");
  const CMDS = {
    "npm": "npm ci --ignore-scripts\nnpm audit --omit=dev --audit-level=high\nnpm audit signatures\nnpm outdated",
    "pnpm": "pnpm install --frozen-lockfile\npnpm audit --prod --audit-level high\npnpm outdated",
    "Python": "uv sync --frozen            # o: pip install --require-hashes -r requirements.lock\npip-audit -r requirements.lock --strict --desc\nuv pip list --outdated",
    "Docker": "trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 mi-imagen:tag\ntrivy fs --scanners vuln,secret,misconfig .",
    "Multi": "osv-scanner scan source -r .\ngitleaks git -v .",
    "Dependabot": "# .github/dependabot.yml\nversion: 2\nupdates:\n  - package-ecosystem: npm        # pip, docker, github-actions…\n    directory: \"/\"\n    schedule: { interval: weekly }\n    cooldown: { default-days: 3 }",
  };
  const block = codeBlock("Comandos", "", "Copiar comandos de auditoría");
  const group = h("div", { class: "toolbar", role: "group", "aria-label": "Ecosistema" });
  for (const key of Object.keys(CMDS)) {
    const b = h("button", { type: "button", "aria-pressed": String(key === "npm") }, key);
    b.addEventListener("click", () => {
      for (const x of group.children) x.setAttribute("aria-pressed", String(x === b));
      block.set(CMDS[key]);
    });
    group.append(b);
  }
  block.set(CMDS.npm);
  root.replaceChildren(group, block.node);
}

/* =================================================================== Guías */

function initGuides() {
  const ul = document.getElementById("guides-list");
  ul.replaceChildren(...Object.entries(GUIDES).map(([id, g]) => h("li", {},
    h("span", { class: "gid" }, id),
    h("strong", {}, g.title),
    h("span", { class: "links" },
      h("a", { href: guideUrl(id, "md") }, "Leer (Markdown)"),
      h("a", { href: guideUrl(id, "docx") }, "Descargar Word")))));
}

/* =================================================================== Arranque */

function safeInit(fn) {
  try { fn(); } catch (err) { console.error(`[guia] ${fn.name}:`, err); }
}

[enhanceStaticCode, initScrollSpy, initQA, initChecklist, initCSPBuilder, initCSPAnalyzer,
  initHeadersGenerator, initCookieBuilder, initHttpAnalyzer, initCodeScanner, initSLA,
  initDepsCommands, initGuides].forEach(safeInit);
