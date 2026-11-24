# Hardening de APIs y Servidores

| Campo | Valor |
|---|---|
| Dominio | Infraestructura, transporte y dependencias |
| Aplica a | APIs REST/GraphQL, gateways, reverse proxies (Nginx), servidores de aplicación (Gunicorn/Uvicorn/Node), contenedores |
| Referencias | OWASP API Security Top 10:2023 (API4 Unrestricted Resource Consumption, API8 Security Misconfiguration, API9 Improper Inventory Management); OWASP Top 10:2025 A02 (Security Misconfiguration), A10 (Mishandling of Exceptional Conditions); OWASP ASVS 5.0 V4 (API and Web Service), V13 (Configuration), V16 (Security Logging and Error Handling); OWASP Secure Headers Project; CIS Benchmarks (NGINX, Docker, Kubernetes); CWE-770, CWE-209, CWE-497, CWE-200, CWE-1021, CWE-693 |
| Severidad típica | Media–Alta (DoS, enumeración, divulgación de información que habilita ataques dirigidos) |

---

## 1. Principio de Seguridad

**Qué se mitiga:**

- **Consumo de recursos sin límite (CWE-770):** fuerza bruta de credenciales, *credential stuffing*, *scraping*, DoS de aplicación y costos desbocados (APIs de pago, LLMs, SMS).
- **Entrada malformada o inesperada:** campos extra, tipos incorrectos, payloads gigantes y anidamientos profundos que provocan errores, *mass assignment* o agotamiento de memoria.
- **Divulgación de información (CWE-200/209/497):** banners de versión, *stack traces*, mensajes de error de la BD y endpoints de debug que reducen el tiempo de reconocimiento del atacante.
- **Ausencia de cabeceras defensivas (CWE-693):** *MIME sniffing*, *clickjacking* y fuga de URLs por `Referer`.
- **Manejo incorrecto de condiciones excepcionales (A10:2025):** fallar "abierto" ante errores, timeouts o excepciones no controladas.

**Reglas rectoras:** *fallar cerrado*, *validar todo en la frontera*, *limitar todo lo que consume recursos*, *revelar lo mínimo* y *registrar lo suficiente para detectar*.

---

## 2. Rate limiting y control de consumo

### 2.1 Estrategia en capas

| Capa | Control | Ejemplo |
|---|---|---|
| Edge / WAF / CDN | Límite por IP, reputación, bot management | Cloudflare / AWS WAF rate-based rules |
| Reverse proxy | `limit_req`, `limit_conn`, tamaño del body, timeouts | Nginx |
| Aplicación | Límite por **identidad** (usuario, API key, tenant) y por **costo** de la operación | SlowAPI / express-rate-limit con Redis |
| Negocio | Cuotas, bloqueo progresivo de login, CAPTCHA adaptativo, límite de SMS/OTP | Lógica de dominio |

### 2.2 Nginx

**Patrón Vulnerable (Qué NO hacer)**

```nginx
# Sin límites: el login acepta peticiones ilimitadas y bodies de cualquier tamaño.
client_max_body_size 0;
location /api/ { proxy_pass http://app; }
```

**Patrón Seguro (Qué SÍ hacer)**

```nginx
# http {} — zonas de rate limit (clave: IP real; detrás de una CDN use real_ip_header con set_real_ip_from)
limit_req_zone  $binary_remote_addr zone=api_general:20m rate=20r/s;
limit_req_zone  $binary_remote_addr zone=api_auth:10m    rate=5r/m;
limit_conn_zone $binary_remote_addr zone=conn_per_ip:10m;
limit_req_status 429;
limit_conn_status 429;

server {
    client_max_body_size      1m;          # ajustar por endpoint (uploads aparte)
    client_body_timeout       10s;
    client_header_timeout     10s;
    keepalive_timeout         15s;
    send_timeout              10s;
    large_client_header_buffers 4 8k;

    location /api/auth/ {
        limit_req  zone=api_auth burst=5 nodelay;
        limit_conn conn_per_ip 5;
        proxy_pass http://app;
    }
    location /api/ {
        limit_req  zone=api_general burst=40 nodelay;
        limit_conn conn_per_ip 50;
        proxy_read_timeout 30s;
        proxy_pass http://app;
    }
    location /api/uploads/ {
        client_max_body_size 20m;
        limit_req zone=api_general burst=5;
        proxy_request_buffering on;
        proxy_pass http://app;
    }
}
```

### 2.3 Python (FastAPI + SlowAPI con Redis, por identidad)

```python
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from fastapi import Request
from fastapi.responses import JSONResponse

def rate_key(request: Request) -> str:
    # Autenticado: límite por usuario/tenant (evita evasión rotando IPs). Anónimo: por IP.
    user = getattr(request.state, "user", None)
    return f"user:{user.id}" if user else f"ip:{get_remote_address(request)}"

limiter = Limiter(key_func=rate_key, storage_uri="redis://redis:6379/1", strategy="moving-window")
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def ratelimit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse({"error": "too_many_requests"}, status_code=429, headers={"Retry-After": "60"})

@app.post("/api/auth/login")
@limiter.limit("5/minute;20/hour")
async def login(request: Request, body: LoginIn): ...

@app.post("/api/reports/generate")
@limiter.limit("10/hour")            # operación costosa: límite por costo, no solo por frecuencia
async def generate(request: Request, body: ReportIn): ...
```

### 2.4 TypeScript (Express + express-rate-limit + Redis)

```typescript
import rateLimit from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import { createClient } from "redis";

const redis = createClient({ url: process.env.REDIS_URL });
await redis.connect();

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",        // cabeceras RateLimit-* estándar
  legacyHeaders: false,
  keyGenerator: (req) => `${req.ip}:${String(req.body?.username ?? "").toLowerCase()}`, // por IP+cuenta
  store: new RedisStore({ sendCommand: (...args: string[]) => redis.sendCommand(args) }),
  handler: (_req, res) => res.status(429).json({ error: "too_many_requests" }),
});

app.set("trust proxy", 1);           // necesario para que req.ip sea la IP real detrás de 1 proxy
app.post("/api/auth/login", authLimiter, login);
```

### 2.5 Límites de consumo adicionales

- **Paginación obligatoria** con un tope (`limit ≤ 100`); prohibido devolver colecciones completas.
- **GraphQL:** límite de profundidad (≤ 7), de complejidad o costo por consulta, de alias y de *batching*; introspección deshabilitada en producción.
- **Timeouts** en todas las llamadas salientes (HTTP, BD, colas) y *circuit breakers*.
- **Uploads:** límite de tamaño, validación del tipo real (*magic bytes*), nombre generado por el servidor, almacenamiento fuera del webroot y escaneo antimalware.
- **Operaciones con costo directo** (SMS, correo, LLM): cuota diaria por usuario/tenant y alertas de gasto.

---

## 3. Validación de esquemas (JSON Schema / Pydantic / Zod)

**Principio:** cada endpoint declara un contrato estricto de entrada y de salida. Todo lo que no está en el contrato se rechaza (`additionalProperties: false`). La validación ocurre **antes** de cualquier lógica de negocio.

### 3.1 Python (Pydantic v2)

**Patrón Vulnerable (Qué NO hacer)**

```python
@app.post("/api/transfers")
async def create_transfer(request: Request):
    data = await request.json()                       # dict arbitrario, sin límites
    amount = float(data["amount"])                    # float para dinero; acepta negativos, NaN, inf
    db.add(Transfer(**data))                          # mass assignment
```

**Patrón Seguro (Qué SÍ hacer)**

```python
from decimal import Decimal
from typing import Annotated, Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

IBAN = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$", strip_whitespace=True)]

class TransferIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=256, frozen=True)

    destination_account: IBAN
    amount: Decimal = Field(gt=Decimal("0"), le=Decimal("50000"), max_digits=12, decimal_places=2)
    currency: Literal["GTQ", "USD", "EUR"]
    reference: Annotated[str, StringConstraints(max_length=140, pattern=r"^[\w\s.,\-#/]*$")] = ""
    idempotency_key: UUID                            # evita la doble ejecución en reintentos

class TransferOut(BaseModel):
    id: UUID
    status: Literal["pending", "completed", "rejected"]
    amount: Decimal
    currency: str

@app.post("/api/transfers", response_model=TransferOut, status_code=201)
async def create_transfer(body: TransferIn, user=Depends(require(Perm.TRANSFER_CREATE))):
    return await transfers.create(user, body)
```

### 3.2 TypeScript (Zod)

```typescript
import { z } from "zod";

export const TransferIn = z.object({
  destinationAccount: z.string().regex(/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/),
  amountCents: z.number().int().positive().max(5_000_000),   // dinero en enteros (centavos)
  currency: z.enum(["GTQ", "USD", "EUR"]),
  reference: z.string().max(140).regex(/^[\w\s.,\-#/]*$/).default(""),
  idempotencyKey: z.string().uuid(),
}).strict();

export const validate = <T extends z.ZodTypeAny>(schema: T) => (req, res, next) => {
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    // Errores de validación: sí se informa QUÉ campo falla (sin repetir el valor recibido).
    return res.status(422).json({ error: "validation_error", fields: parsed.error.issues.map(i => i.path.join(".")) });
  }
  req.body = parsed.data;
  next();
};

app.use(express.json({ limit: "100kb", strict: true }));
app.post("/api/transfers", requireAuth, validate(TransferIn), createTransfer);
```

### 3.3 Contrato OpenAPI / JSON Schema en el gateway

```yaml
# openapi.yaml (extracto): el gateway valida antes de llegar al backend
components:
  schemas:
    TransferIn:
      type: object
      additionalProperties: false
      required: [destinationAccount, amountCents, currency, idempotencyKey]
      properties:
        destinationAccount: { type: string, pattern: "^[A-Z]{2}\\d{2}[A-Z0-9]{11,30}$", maxLength: 34 }
        amountCents:        { type: integer, minimum: 1, maximum: 5000000 }
        currency:           { type: string, enum: [GTQ, USD, EUR] }
        idempotencyKey:     { type: string, format: uuid }
```

> **Inventario de APIs (API9):** toda API expuesta debe estar en el catálogo OpenAPI. Las versiones antiguas (`/v1`) se retiran con una fecha anunciada; no deje endpoints "shadow" o "zombie" sin autenticación ni monitoreo.

---

## 4. Cabeceras de seguridad HTTP

| Cabecera | Valor recomendado | Mitiga |
|---|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | Downgrade a HTTP (ver la guía TLS) |
| `Content-Security-Policy` | Estricta con nonces (ver la guía XSS). Para APIs JSON: `default-src 'none'; frame-ancestors 'none'` | XSS, clickjacking |
| `X-Content-Type-Options` | `nosniff` | *MIME sniffing* (ejecutar un JSON o una imagen como script) |
| `X-Frame-Options` | `DENY` (fallback de `frame-ancestors`) | Clickjacking (CWE-1021) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` (o `no-referrer` en apps sensibles) | Fuga de rutas o tokens en la URL hacia terceros |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=()` | Abuso de APIs del navegador por contenido embebido |
| `Cross-Origin-Opener-Policy` | `same-origin` | XS-Leaks, *tabnabbing* |
| `Cross-Origin-Resource-Policy` | `same-origin` | Inclusión cross-origin de recursos |
| `Cache-Control` | `no-store` en respuestas con datos sensibles o autenticadas | Datos en cachés compartidas o del navegador |
| `X-XSS-Protection` | `0` (deshabilitar el filtro legado) | El auditor XSS legado introducía vulnerabilidades |
| **Eliminar** | `Server` (versión), `X-Powered-By`, `X-AspNet-Version`, `X-Runtime` | Fingerprinting (CWE-497) |

### 4.1 Nginx

**Patrón Vulnerable (Qué NO hacer)**

```nginx
server_tokens on;                     # Server: nginx/1.18.0 (Ubuntu)
autoindex on;                         # listado de directorios
# Sin cabeceras de seguridad; X-Powered-By: Express / PHP/7.4 propagados desde el backend
```

**Patrón Seguro (Qué SÍ hacer)**

```nginx
# /etc/nginx/snippets/security-headers.conf  (include en cada server/location que defina add_header)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header X-XSS-Protection "0" always;

# nginx.conf (http {})
server_tokens off;                    # oculta la versión en el header Server y en las páginas de error
autoindex off;
proxy_hide_header X-Powered-By;
proxy_hide_header X-AspNet-Version;
proxy_hide_header X-Runtime;
proxy_hide_header Server;
# Eliminar por completo el header "Server" requiere el módulo headers-more:
# more_clear_headers Server;

# Métodos permitidos
if ($request_method !~ ^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)$) { return 405; }

# Bloquear archivos sensibles y ocultos
location ~ /\.(?!well-known) { deny all; return 404; }
location ~* \.(env|ini|log|bak|old|sql|swp|map|yml|yaml)$ { deny all; return 404; }

# Páginas de error genéricas propias
error_page 404 /errors/404.html;
error_page 500 502 503 504 /errors/50x.html;
```

> **Atención:** en Nginx, un `add_header` dentro de un `location` **reemplaza** todos los heredados del `server`. Use `include snippets/security-headers.conf;` en cada bloque que añada cabeceras propias.

### 4.2 Aplicación

```typescript
// Express + Helmet
import helmet from "helmet";
app.disable("x-powered-by");
app.use(helmet({
  strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true },
  frameguard: { action: "deny" },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  crossOriginOpenerPolicy: { policy: "same-origin" },
}));
```

```python
# FastAPI: middleware de cabeceras + eliminación del header del servidor
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers.update({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cache-Control": "no-store",
    })
    return response
# Uvicorn: --no-server-header ; Gunicorn: no anunciar versión (detrás de Nginx con proxy_hide_header Server)
```

---

## 5. Manejo de errores sin filtrar stack traces

**Mecánica:** un *stack trace* revela el framework y su versión, las rutas del sistema de archivos, los nombres de tablas y columnas, las consultas SQL, las IPs internas y a veces secretos en variables. El modo debug de algunos frameworks (Werkzeug debugger, Django `DEBUG=True`, Laravel Ignition) llega a permitir **ejecución remota de código**.

**Patrón Vulnerable (Qué NO hacer)**

```python
app.run(debug=True)                                   # Werkzeug debugger: consola interactiva = RCE
DEBUG = True                                          # Django en producción: páginas con settings y SQL

@app.exception_handler(Exception)
async def handler(request, exc):
    return JSONResponse({"error": str(exc), "trace": traceback.format_exc()}, 500)  # filtra internals
```

```typescript
app.use((err, req, res, next) => res.status(500).send(err.stack));  // VULNERABLE
// NODE_ENV distinto de "production": Express muestra stack traces por defecto
```

**Patrón Seguro (Qué SÍ hacer) — Python (FastAPI)**

```python
import logging
import uuid
from fastapi import Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

log = logging.getLogger("app")

app = FastAPI(
    debug=False,
    docs_url=None if settings.env == "prod" else "/docs",       # sin Swagger público en producción
    redoc_url=None,
    openapi_url=None if settings.env == "prod" else "/openapi.json",
)

@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    fields = [".".join(map(str, e["loc"][1:])) for e in exc.errors()]
    return JSONResponse({"error": "validation_error", "fields": fields}, status_code=422)

@app.exception_handler(HTTPException)
async def http_handler(request: Request, exc: HTTPException):
    return JSONResponse({"error": exc.detail if exc.status_code < 500 else "internal_error"},
                        status_code=exc.status_code)

@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    error_id = uuid.uuid4().hex
    # Detalle completo SOLO en el log del servidor, correlacionado por error_id.
    log.exception("unhandled_error", extra={"error_id": error_id, "path": request.url.path})
    return JSONResponse({"error": "internal_error", "error_id": error_id}, status_code=500)
```

**Patrón Seguro (Qué SÍ hacer) — TypeScript (Express)**

```typescript
import { randomUUID } from "node:crypto";

// Debe ser el último middleware.
app.use((err: unknown, req, res, _next) => {
  const errorId = randomUUID();
  req.log.error({ err, errorId, path: req.path }, "unhandled_error");   // pino: stack solo en logs
  if (res.headersSent) return;
  const status = typeof (err as any)?.status === "number" && (err as any).status < 500 ? (err as any).status : 500;
  res.status(status).json({ error: status === 500 ? "internal_error" : "request_error", errorId });
});

process.on("unhandledRejection", (reason) => { logger.fatal({ reason }, "unhandledRejection"); process.exit(1); });
```

**Fallar cerrado (A10:2025)**

```python
# VULNERABLE: si el servicio de autorización falla, se permite el acceso.
try:
    allowed = authz_client.check(user, action, resource)
except Exception:
    allowed = True        # "para no afectar al usuario"

# SEGURO: cualquier error en un control de seguridad deniega y se registra.
try:
    allowed = authz_client.check(user, action, resource, timeout=2)
except Exception:
    log.exception("authz_unavailable")
    allowed = False
if not allowed:
    raise HTTPException(403)
```

### 5.1 Respuestas que no habilitan enumeración

| Caso | Respuesta incorrecta | Respuesta correcta |
|---|---|---|
| Login fallido | "Usuario no existe" / "Contraseña incorrecta" | "Credenciales inválidas" (y tiempo de respuesta similar) |
| Recuperación de contraseña | "Este correo no está registrado" | "Si la cuenta existe, recibirá un correo" |
| Recurso ajeno | 403 "No tiene acceso a la factura 1003" | 404 genérico |

---

## 6. Hardening del servidor y del runtime

```dockerfile
# Imagen mínima, no root, sin herramientas de depuración
FROM gcr.io/distroless/python3-debian12:nonroot
COPY --chown=nonroot:nonroot app/ /app/
USER nonroot
EXPOSE 8000
ENTRYPOINT ["python3", "-m", "gunicorn", "-k", "uvicorn.workers.UvicornWorker", \
            "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "30", \
            "--limit-request-line", "4094", "--limit-request-fields", "50", "app.main:app"]
```

```yaml
# Kubernetes securityContext (alineado con CIS Kubernetes Benchmark / Pod Security "restricted")
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: ["ALL"] }
  seccompProfile: { type: RuntimeDefault }
resources:
  requests: { cpu: "250m", memory: "256Mi" }
  limits:   { cpu: "1",    memory: "512Mi" }
```

- **Endpoints administrativos y de monitoreo** (`/metrics`, `/actuator`, `/admin`, `/debug/pprof`, `/_profiler`) solo en una interfaz o puerto interno, nunca públicos.
- **Health checks** que no expongan las versiones ni el estado de las dependencias a usuarios anónimos.
- **CORS** con una allow-list exacta de orígenes; nunca `*` con credenciales.
- **Métodos HTTP:** deshabilitar `TRACE` y responder 405 a los métodos no usados.
- **Logs de seguridad** (logins, fallos de authz, 429, errores 5xx, cambios de privilegios) en formato JSON hacia un SIEM, con retención definida y sin PII ni secretos.
- **SSH y SO:** solo autenticación por llave, sin root login, parches automáticos de seguridad, firewall de host con *default deny*; aplique el CIS Benchmark del SO.

---

## 7. Verificación

```bash
# Cabeceras y banners
curl -sI https://api.empresa.com | grep -iE "server|x-powered-by|strict-transport|x-content-type|x-frame|referrer-policy"

# Rate limiting (debe aparecer 429)
for i in $(seq 1 15); do curl -s -o /dev/null -w "%{http_code}\n" -X POST https://api.empresa.com/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"test","password":"x"}'; done | sort | uniq -c

# Error sin stack trace (body malformado)
curl -s -X POST https://api.empresa.com/api/transfers -H 'Content-Type: application/json' -d '{"amount":'

# Campos extra rechazados (422 esperado)
curl -s -X POST https://api.empresa.com/api/transfers -H 'Content-Type: application/json' -H "Authorization: Bearer $T" \
  -d '{"destinationAccount":"GT82TRAJ01020000001210029690","amountCents":100,"currency":"GTQ","idempotencyKey":"9b2f...","isApproved":true}'

# Escaneo de configuración y exposición
nuclei -u https://api.empresa.com -tags misconfig,exposure,headers,tech -severity low,medium,high,critical
nmap -sV --script http-headers,http-methods,http-server-header -p 443 api.empresa.com
```

Herramientas complementarias: **Mozilla HTTP Observatory**, **securityheaders.com**, **OWASP ZAP** (API scan con OpenAPI) y **Schemathesis** (*fuzzing* basado en el contrato OpenAPI):

```bash
schemathesis run https://staging-api.empresa.com/openapi.json --checks all --header "Authorization: Bearer $T"
```

---

## 8. Checklist de Verificación (antes de merge / deploy)

- [ ] Hay rate limiting en el proxy y en la aplicación, por IP y por identidad; los endpoints de autenticación, OTP y recuperación tienen límites estrictos y bloqueo progresivo.
- [ ] Están limitados el tamaño del body, el número y tamaño de cabeceras, los timeouts de cliente y backend, la paginación máxima y la profundidad y complejidad de GraphQL.
- [ ] Cada endpoint valida la entrada con un esquema estricto (`extra=forbid` / `.strict()` / `additionalProperties:false`) y declara un esquema de salida.
- [ ] Los montos usan `Decimal` o enteros (nunca `float`); las operaciones no idempotentes exigen `Idempotency-Key`.
- [ ] Las cabeceras `HSTS`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`/`frame-ancestors`, `Referrer-Policy`, `Permissions-Policy` y CSP están presentes (verificado con curl/Observatory).
- [ ] `server_tokens off`; no hay `X-Powered-By` ni versiones en `Server`; `autoindex off`.
- [ ] Debug deshabilitado (`DEBUG=False`, `NODE_ENV=production`, sin Werkzeug debugger); Swagger y OpenAPI no son públicos en producción salvo aprobación.
- [ ] Los errores devuelven mensajes genéricos con `error_id`; los stack traces y los detalles SQL solo se registran en el servidor.
- [ ] Los controles de seguridad fallan cerrado ante excepciones o timeouts.
- [ ] Los mensajes de login, registro y recuperación no permiten enumerar usuarios.
- [ ] Los endpoints de administración, métricas y debug no están expuestos públicamente.
- [ ] El contenedor se ejecuta como no root, con FS de solo lectura, `drop ALL` capabilities y límites de CPU y memoria.
- [ ] CORS usa una allow-list exacta y `TRACE` está deshabilitado.
- [ ] La API está registrada en el inventario OpenAPI, con versión y fecha de retiro de las versiones antiguas.
- [ ] Nuclei, ZAP y Schemathesis no reportan hallazgos medios o superiores en staging.

---

## 9. Referencias

- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- OWASP ASVS 5.0 — V4 API and Web Service, V13 Configuration, V16 Security Logging and Error Handling: https://github.com/OWASP/ASVS
- OWASP Cheat Sheets: REST Security, Error Handling, HTTP Headers, GraphQL, Denial of Service: https://cheatsheetseries.owasp.org/
- CIS Benchmarks (NGINX, Docker, Kubernetes): https://www.cisecurity.org/cis-benchmarks
- Mozilla HTTP Observatory: https://developer.mozilla.org/en-US/observatory
