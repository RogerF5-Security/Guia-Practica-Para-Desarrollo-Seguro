# Guía Rápida de Desarrollo Seguro

| Campo | Valor |
|---|---|
| Para quién | Cualquier desarrollador (backend, frontend, móvil, DevOps) |
| Tiempo de lectura | 10 minutos |
| Objetivo | Conocer las reglas mínimas antes de escribir, revisar o desplegar código |
| Detalle completo | Guías 01 a 04 de esta misma carpeta (se indica cuál al final de cada sección) |

---

## 1. Las 12 reglas de oro

1. **Nunca confíes en nada que venga del cliente:** formularios, query strings, headers, cookies, JSON, archivos, webhooks ni respuestas de una IA. Todo se valida **en el servidor**.
2. **Nunca concatenes entrada en SQL, comandos, plantillas o `eval`.** Usa consultas parametrizadas y APIs seguras.
3. **Escapa todo lo que pintas en pantalla** (autoescape de la plantilla y `textContent`, nunca `innerHTML` con datos).
4. **Verifica permisos en cada endpoint y para cada objeto.** Ocultar un botón no es seguridad.
5. **Cero secretos en el código.** No se hardcodean contraseñas, API keys, tokens ni llaves.
6. **Las contraseñas se hashean con Argon2id o bcrypt.** Nunca MD5, SHA-1 ni SHA-256.
7. **Solo HTTPS (TLS 1.2/1.3)** y nunca `verify=False`.
8. **Pon las cabeceras de seguridad y la CSP** en todas las respuestas.
9. **Las cookies de sesión llevan `HttpOnly`, `Secure` y `SameSite`.**
10. **Mantén las librerías actualizadas** y con versiones fijadas (lockfile).
11. **Muestra errores genéricos al usuario.** El detalle técnico va solo al log del servidor.
12. **No pegues código crítico, secretos ni datos de clientes en una IA externa**, y revisa todo lo que la IA te sugiera.

---

## 2. Preguntas rápidas: ¿sí o no?

| Pregunta | Respuesta |
|---|---|
| ¿Hay que actualizar las librerías? | **SÍ.** Revisa sus CVEs en cada PR y cada semana; las críticas se corrigen en días, no en meses (sección 10). |
| ¿Puedo usar `"express": "*"` o `FROM node:latest`? | **NO.** Fija las versiones y versiona el lockfile. |
| ¿Tengo que poner headers de seguridad? | **SÍ**, en todas las respuestas (sección 5). |
| ¿Hay que poner CSP? | **SÍ.** Empieza en modo `Report-Only` y luego hazla obligatoria (sección 6). |
| ¿Las cookies llevan flags? | **SÍ:** `HttpOnly; Secure; SameSite=Strict` (o `Lax`) y prefijo `__Host-` (sección 7). |
| ¿Basta con validar los inputs en el frontend? | **NO.** El frontend es solo experiencia de usuario; la validación real va en el backend (sección 3). |
| ¿Hardcodeo la API key o la contraseña "solo para probar"? | **NUNCA.** Usa variables de entorno o una bóveda. Lo que entra en Git se queda en el historial (sección 8). |
| ¿Ofusco el código para proteger mi API key? | **NO.** Ofuscar no protege secretos: todo lo que se envía al cliente se puede leer. Lo sensible va en el servidor (sección 9). |
| ¿Minifico el JS de producción? | **SÍ**, y **sin source maps públicos**. |
| ¿Guardo el token JWT en `localStorage`? | **NO.** Usa una cookie `HttpOnly`. |
| ¿Uso `eval()`, `exec()`, `os.system()` o `shell=True`? | **NO.** |
| ¿Puedo devolver el stack trace en la respuesta de la API? | **NO.** Devuelve un mensaje genérico con un `error_id`. |
| ¿Puedo desactivar la verificación SSL porque "no conecta"? | **NO.** Corrige el certificado o configura la CA interna. |
| ¿Uso datos reales de clientes en desarrollo o QA? | **NO.** Usa datos sintéticos o enmascarados. |

---

## 3. Inputs: cómo debe ir cada entrada

**Regla:** valida en el servidor con un **esquema estricto**: el tipo, la longitud, el rango y el formato, aceptando solo lo permitido (allow-list) y rechazando los campos extra.

| Tipo de dato | Cómo validarlo |
|---|---|
| Texto libre | Longitud mínima y máxima, sin caracteres de control; se escapa al mostrarlo |
| Email, teléfono, documento | Formato con regex o un tipo específico (`EmailStr`, `z.string().email()`) |
| IDs | Tipo estricto (`int > 0`, UUID) **y** verificación de que el recurso pertenece al usuario |
| Números o montos | Rango (`min`/`max`); montos en `Decimal` o en centavos enteros, **nunca `float`** |
| Valores de una lista (estado, orden) | Enumeración cerrada (`Literal[...]`, `z.enum([...])`) |
| URLs | Solo `https://`, con dominios permitidos si el servidor va a llamarlas (evita SSRF) |
| Archivos | Tamaño máximo, tipo real por *magic bytes*, nombre generado por el servidor, guardados fuera del webroot |
| JSON completo | Rechaza los campos no declarados (`extra="forbid"` / `.strict()`) |

```python
# Python (FastAPI + Pydantic)
from typing import Literal
from pydantic import BaseModel, Field, EmailStr

class CrearUsuario(BaseModel):
    model_config = {"extra": "forbid"}          # rechaza "role":"admin" y otros campos no declarados
    nombre: str = Field(min_length=2, max_length=80)
    email: EmailStr
    edad: int = Field(ge=18, le=120)
    plan: Literal["basico", "pro"]
```

```typescript
// TypeScript (Zod)
const CrearUsuario = z.object({
  nombre: z.string().min(2).max(80),
  email: z.string().email(),
  edad: z.number().int().min(18).max(120),
  plan: z.enum(["basico", "pro"]),
}).strict();
const data = CrearUsuario.parse(req.body);
```

**Usa siempre la entrada de forma segura:**

```python
# NO: concatenar
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")
subprocess.run(f"ping {host}", shell=True)

# SÍ: parametrizar y pasar los argumentos como lista
cur.execute("SELECT * FROM users WHERE email = %s", (email,))
subprocess.run(["ping", "-c", "1", str(ipaddress.ip_address(host))], timeout=5)
```

> Detalle: guía 01.01 (Inyecciones) y guía 03.03 (Validación de esquemas).

---

## 4. Salidas: evitar XSS

| NO | SÍ |
|---|---|
| `el.innerHTML = dato` | `el.textContent = dato` |
| `{{ dato \| safe }}` / `dangerouslySetInnerHTML` sin sanitizar | Autoescape por defecto; si necesitas HTML, sanitiza con **DOMPurify** (JS) o **nh3** (Python) |
| `<a href="{{ url_usuario }}">` | Valida que la URL empiece por `https:` (bloquea `javascript:`) |
| `<script>var x = {{ dato }}</script>` | Pasa los datos con `tojson` o un atributo `data-*` |

> Detalle: guía 01.02 (XSS, CSRF y Seguridad Frontend).

---

## 5. Headers de seguridad: cuáles y para qué sirve cada uno

| Header | Valor recomendado | Para qué sirve |
|---|---|---|
| `Strict-Transport-Security` (HSTS) | `max-age=63072000; includeSubDomains` | Obliga al navegador a usar siempre HTTPS y evita que alguien en la red fuerce HTTP |
| `Content-Security-Policy` (CSP) | Ver la sección 6 | Define qué scripts, estilos e iframes puede cargar la página; es la barrera principal contra XSS |
| `X-Content-Type-Options` | `nosniff` | Impide que el navegador "adivine" el tipo de archivo (que un `.txt` o una imagen subida se ejecute como script) |
| `X-Frame-Options` | `DENY` | Impide que tu página se cargue dentro de un iframe ajeno (*clickjacking*: engañar al usuario para que haga clic) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Evita filtrar la URL completa (con tokens o IDs) a otros sitios cuando el usuario hace clic en un enlace |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Desactiva las APIs del navegador que tu app no usa, para que un script inyectado no pueda usarlas |
| `Cross-Origin-Opener-Policy` | `same-origin` | Aísla tu ventana de las ventanas abiertas por otros sitios (evita fugas entre pestañas) |
| `Cache-Control` | `no-store` (en respuestas con datos privados) | Evita que los datos sensibles queden en la caché del navegador o de proxies |
| `X-Powered-By`, versión en `Server` | **Eliminarlos** | Dejan de revelar la tecnología y la versión exactas, que el atacante usaría para buscar exploits |

```nginx
# Nginx: copia y pega en el bloque server {}
server_tokens off;
proxy_hide_header X-Powered-By;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
```

```typescript
// Express: helmet configura la mayoría de estas cabeceras
import helmet from "helmet";
app.disable("x-powered-by");
app.use(helmet());
```

Verifícalo con `curl -sI https://tu-app` o con Mozilla HTTP Observatory.

> Detalle: guía 03.03 (Hardening de APIs y Servidores).

---

## 6. CSP (Content Security Policy)

**Qué es:** una lista de las fuentes desde las que la página puede cargar y ejecutar contenido. Si un atacante logra inyectar un `<script>`, el navegador **no lo ejecuta** porque no está autorizado.

**Política base recomendada (con *nonce*: un valor aleatorio nuevo en cada respuesta):**

```http
Content-Security-Policy: default-src 'self'; script-src 'nonce-{ALEATORIO}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'
```

```html
<script nonce="{ALEATORIO}" src="/app.js"></script>   <!-- solo se ejecutan los scripts con el nonce correcto -->
```

| Regla | Por qué |
|---|---|
| Sin `'unsafe-inline'` ni `'unsafe-eval'` en `script-src` | Anulan la protección |
| Sin comodines (`*`) | Permiten cargar scripts de cualquier sitio |
| `frame-ancestors 'none'` | Protección moderna contra clickjacking |
| Sin `onclick="..."` ni scripts inline sin nonce | La CSP los bloquea; mueve esa lógica a archivos `.js` |
| Despliega primero con `Content-Security-Policy-Report-Only` | Así ves qué se rompería antes de bloquear |

> Para APIs que solo devuelven JSON: `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`.
>
> Detalle: guía 01.02, sección 3.

---

## 7. Cookies: flags obligatorias

| Flag | Para qué sirve |
|---|---|
| `HttpOnly` | JavaScript no puede leer la cookie: un XSS no puede robar la sesión |
| `Secure` | La cookie solo viaja por HTTPS |
| `SameSite=Strict` (o `Lax`) | El navegador no envía la cookie en peticiones desde otros sitios (protege contra CSRF) |
| Prefijo `__Host-` | Obliga a `Secure` y `Path=/` y prohíbe `Domain`, así que un subdominio no puede sobrescribirla |
| `Max-Age` corto | Limita el tiempo en que una sesión robada es útil |

```http
Set-Cookie: __Host-session=<id-aleatorio>; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800
```

**Además:**

- Regenera el ID de sesión al hacer login e invalídalo en el servidor al hacer logout.
- En formularios con cookie de sesión, usa también un **token anti-CSRF** en POST, PUT y DELETE.
- **Nunca** cambies el estado con GET (`/borrar?id=5`).

> Detalle: guía 01.02, secciones 4 y 5.

---

## 8. ¿Hardcodear? Secretos y configuración

**Regla absoluta: NO se hardcodean** contraseñas, API keys, tokens, llaves privadas ni cadenas de conexión. Tampoco en tests, Dockerfiles, `docker-compose.yml`, `.env` versionado ni notebooks.

```python
# NO
API_KEY = "sk_live_51H..."
JWT_SECRET = os.getenv("JWT_SECRET", "changeme")      # valor por defecto inseguro

# SÍ: se lee del entorno o de una bóveda, y la app no arranca si falta
from pydantic_settings import BaseSettings
from pydantic import SecretStr
class Settings(BaseSettings):
    api_key: SecretStr
    jwt_secret: SecretStr
settings = Settings()
```

| Hacer | Herramienta |
|---|---|
| Guardar los secretos en una bóveda | HashiCorp Vault, AWS Secrets Manager, Azure Key Vault |
| Detectar secretos antes del commit | `gitleaks` como pre-commit hook |
| Ignorar los archivos sensibles | `.gitignore` con `.env*`, `*.pem`, `*.key` (solo se versiona `.env.example` con valores falsos) |
| En CI/CD, credenciales temporales | OIDC (GitHub Actions → nube) en lugar de llaves fijas |

**Si se filtró un secreto:** primero **revócalo y rótalo**, y después límpialo del historial. Borrarlo en un nuevo commit no basta.

> **Prefijos públicos:** en el frontend, cualquier variable con prefijo `NEXT_PUBLIC_`, `VITE_` o `REACT_APP_` es **pública**, así que nunca debe contener secretos.
>
> Detalle: guía 02.01 (Gestión de Secretos).

---

## 9. ¿Ofuscar? Qué hacer con el código del cliente

**Verdad básica:** todo lo que se envía al navegador o al teléfono (JS, APK, IPA, EXE) **se puede leer y modificar**. Ofuscar solo hace más lento el análisis; **no protege nada que sea secreto**.

| ¿Qué hago? | Respuesta |
|---|---|
| Minificar el JS en producción | **SÍ** (Terser, esbuild): reduce el tamaño y elimina comentarios y logs |
| Publicar source maps (`.map`) | **NO.** Genéralos en modo `hidden` y súbelos solo a la herramienta de errores (Sentry) |
| Ofuscar todo el frontend | **NO** es necesario. Solo módulos de alto valor (anti-bot, lógica propietaria), y midiendo el impacto en el rendimiento |
| Poner API keys privadas en el frontend o la app | **NUNCA.** Haz que el frontend llame a tu backend y que el backend llame al tercero |
| Calcular precios, descuentos o permisos en el cliente | **NO.** El cliente envía la intención (producto, cantidad) y el **servidor** calcula y valida |
| App Android en release | R8/minify activo, `debuggable=false`, `allowBackup=false`, tokens en Android Keystore |
| App iOS en release | Tokens en Keychain y símbolos eliminados |

> Detalle: guía 02.03 (Ofuscación y Endurecimiento del Cliente).

---

## 10. Librerías y dependencias: sí, hay que actualizarlas

| Regla | Cómo |
|---|---|
| Fija las versiones | Versiona el lockfile (`package-lock.json`, `pnpm-lock.yaml`, `uv.lock`, `requirements.txt` con hashes) |
| Instala de forma reproducible en CI | `npm ci`, `uv sync --frozen`, `pip install --require-hashes` |
| Busca vulnerabilidades en cada PR y cada semana | `npm audit`, `pip-audit`, `osv-scanner`, `trivy image` |
| Automatiza las actualizaciones | Dependabot o Renovate (incluidas las imágenes Docker y las GitHub Actions) |
| Usa imágenes base mínimas y fijadas | `python:3.13-slim@sha256:...` o distroless; nunca `:latest` |
| No uses runtimes sin soporte (EOL) | Revisa endoflife.date (p. ej., Node solo en versiones LTS) |
| Revisa cada librería nueva | ¿Existe de verdad? ¿Está mantenida? ¿Es popular? ¿Tiene una licencia permitida? (cuidado con los nombres que inventa la IA) |

**Plazos máximos para corregir una vulnerabilidad en producción:**

| Severidad | Plazo |
|---|---|
| Crítica con exploit público | 72 horas |
| Crítica | 7 días |
| Alta | 30 días |
| Media | 90 días |

> Detalle: guía 03.02 (Gestión de Dependencias).

---

## 11. Contraseñas, sesiones y permisos

- **Contraseñas:** Argon2id (o bcrypt con cost ≥ 12), con una longitud mínima de 12 caracteres y límite de intentos en el login.
- **Mensajes genéricos:** "Credenciales inválidas" (no digas si el usuario existe).
- **Autorización por objeto:** filtra siempre por el dueño o el tenant en la consulta.

```python
# NO: cualquiera ve la factura 1003 cambiando el número en la URL (IDOR)
db.get(Invoice, invoice_id)
# SÍ: el filtro de dueño va en la consulta; si no es suyo, devuelve 404
db.scalars(select(Invoice).where(Invoice.id == invoice_id, Invoice.owner_id == user.id)).first()
```

- **Identidad del usuario:** el `user_id`, el rol y el tenant se obtienen de la **sesión o el token verificados**, nunca del body ni de la URL.
- **Datos sensibles (PII, tarjetas):** cifrados con AES-256-GCM y con las llaves en un KMS. No se guardan si no se necesitan.

> Detalle: guías 01.03 (Control de Acceso) y 02.02 (Cifrado y Hashing).

---

## 12. HTTPS, errores y logs

- **HTTPS:** solo TLS 1.2 y 1.3, con HTTP redirigido a HTTPS y certificados renovados automáticamente (Let's Encrypt / cert-manager).
- **TLS en todas las conexiones:** también hacia la base de datos, la caché y otros servicios (`sslmode=verify-full`).
- **Nunca desactives la verificación TLS:** nada de `verify=False`, `rejectUnauthorized: false` ni `NODE_TLS_REJECT_UNAUTHORIZED=0`.
- **Errores:** el usuario recibe `{"error":"internal_error","error_id":"..."}` y el stack trace va solo al log.
- **Debug apagado en producción:** `DEBUG=False`, `NODE_ENV=production` y Swagger no expuesto.
- **Rate limiting** en el login, en la recuperación de contraseña, en los OTP y en las operaciones costosas.
- **Logs:** registra los logins, los accesos denegados y los errores, pero **nunca** contraseñas, tokens, tarjetas ni datos personales completos.

> Detalle: guías 03.01 (TLS) y 03.03 (Hardening).

---

## 13. Si usas IA (Copilot, ChatGPT, Claude, Cursor…)

- Usa **solo las herramientas aprobadas** por la empresa.
- **No pegues** secretos, `.env`, llaves, datos de clientes ni código crítico.
- **Revisa todo** lo que sugiera la IA como si fuera código de un desconocido: inyecciones, permisos, secretos y librerías inexistentes.
- Si tu app **integra** un LLM, la respuesta del modelo es entrada no confiable: valídala, no la ejecutes y no la renderices como HTML. Las acciones importantes requieren la confirmación de una persona.

> Detalle: guías 04.01 y 04.02.

---

## 14. Checklist de 1 minuto antes de abrir un PR

- [ ] Toda la entrada se valida en el backend con un esquema estricto.
- [ ] No hay SQL, comandos ni HTML construidos concatenando datos del usuario.
- [ ] Cada endpoint nuevo verifica la autenticación y los permisos sobre el objeto.
- [ ] No hay secretos en el código, los tests, la configuración ni el Dockerfile (`gitleaks` pasa).
- [ ] Las contraseñas usan Argon2id/bcrypt y los datos sensibles van cifrados.
- [ ] Los headers de seguridad y la CSP están presentes; las cookies llevan `HttpOnly; Secure; SameSite`.
- [ ] Las dependencias están fijadas y sin vulnerabilidades altas o críticas (`npm audit` / `pip-audit` / `trivy`).
- [ ] No hay source maps ni secretos en el build del frontend o la app.
- [ ] Los errores son genéricos, el debug está apagado y no hay datos sensibles en los logs.
- [ ] Hay pruebas de los casos negativos (otro usuario, datos inválidos, sin sesión).

**¿Vas a producción?** Revisa además el **Go-Live Security Gate** del [README](README.md).
