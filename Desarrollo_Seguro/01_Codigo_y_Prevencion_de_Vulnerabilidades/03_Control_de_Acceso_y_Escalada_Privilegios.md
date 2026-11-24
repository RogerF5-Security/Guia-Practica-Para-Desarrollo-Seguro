# Control de Acceso y Escalada de Privilegios

| Campo | Valor |
|---|---|
| Dominio | Código y prevención de vulnerabilidades |
| Aplica a | Endpoints REST/GraphQL/gRPC, jobs, colas, paneles administrativos, multi-tenant SaaS |
| Referencias | OWASP Top 10:2025 A01 (Broken Access Control, n.º 1 desde 2021, incluye SSRF); OWASP API Security Top 10:2023 API1 (BOLA), API3 (BOPLA), API5 (BFLA); OWASP ASVS 5.0 V8 (Authorization); CWE-639, CWE-862, CWE-863, CWE-284, CWE-269, CWE-915 |
| Severidad típica | Alta–Crítica (exposición masiva de datos de otros clientes, toma de cuentas, acciones administrativas) |

---

## 1. Principio de Seguridad

**Qué se mitiga:** que un sujeto autenticado (o anónimo) ejecute acciones o acceda a objetos fuera de su autorización.

- **Escalada horizontal (IDOR/BOLA, CWE-639):** el usuario A accede a recursos del usuario B con el mismo rol cambiando un identificador (`/api/invoices/1002` → `/1003`).
- **Escalada vertical (BFLA, CWE-862/863):** un usuario estándar invoca funciones de administrador (`DELETE /api/admin/users/7`) porque el backend solo ocultó el botón en la UI.
- **Mass Assignment / BOPLA (CWE-915):** el cliente envía campos que no debería controlar (`"role":"admin"`, `"tenant_id":2`, `"is_verified":true`) y el ORM los persiste.

**Mecánica del fallo:** la autorización se implementa de forma *dispersa* (en cada handler, a criterio del desarrollador) o se delega al frontend. Basta un endpoint que olvide el chequeo. En el CWE Top 25 de 2025, *Missing Authorization* (CWE-862) subió al 4.º lugar.

**Reglas rectoras:**

1. **Denegar por defecto (deny-by-default):** todo endpoint requiere autenticación y una política explícita. La ausencia de una política equivale a 403.
2. **El backend es la única autoridad.** El frontend solo decide qué *mostrar*; nunca qué está *permitido*. Cualquier valor del cliente (ID, rol, tenant, precio, flags) es entrada no confiable.
3. **Autorizar a nivel de función *y* a nivel de objeto** en cada petición, incluidos los endpoints internos, los webhooks, los jobs y las mutaciones de GraphQL.
4. **Mínimo privilegio (PoLP):** cada usuario, servicio, token y credencial de base de datos tiene solo los permisos necesarios, con duración acotada.
5. **Centralizar la decisión** (política como código) y **auditar** cada denegación y cada acción privilegiada.

---

## 2. Modelos de autorización

| Modelo | Decisión basada en | Uso recomendado |
|---|---|---|
| **RBAC** (Role-Based) | Rol del sujeto → conjunto de permisos | Funciones de la aplicación (BFLA): "¿puede este rol ejecutar `invoice:approve`?" |
| **ABAC** (Attribute-Based) | Atributos del sujeto, del recurso, de la acción y del contexto (tenant, propietario, monto, hora, IP) | Autorización a nivel de objeto (BOLA) y reglas de negocio |
| **ReBAC** (Relationship-Based) | Grafo de relaciones (usuario → miembro de → equipo → dueño de → documento) | Compartición fina tipo Google Drive (OpenFGA, SpiceDB) |

**Recomendación:** RBAC para los *permisos* (no para los nombres de rol en el código), ABAC/ReBAC para la *propiedad* del objeto, y el *tenant* como filtro obligatorio en la capa de datos.

```text
Petición -> [AuthN: identidad verificada] -> [AuthZ función: permiso requerido por el endpoint]
         -> [AuthZ objeto: ¿sujeto puede <acción> sobre <recurso_id>?] -> [Filtro tenant en query]
         -> [Allow-list de campos en input/output] -> Lógica de negocio -> Auditoría
```

---

## 3. IDOR / BOLA (escalada horizontal)

### 3.1 Python (FastAPI + SQLAlchemy)

**Patrón Vulnerable (Qué NO hacer)**

```python
# VULNERABLE: autenticado != autorizado. Cualquier usuario lee cualquier factura.
@app.get("/api/invoices/{invoice_id}")
def get_invoice(invoice_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    return db.get(Invoice, invoice_id)

# VULNERABLE: el owner_id viene del cliente.
@app.get("/api/invoices")
def list_invoices(owner_id: int, db=Depends(get_db)):
    return db.query(Invoice).filter(Invoice.owner_id == owner_id).all()
```

**Patrón Seguro (Qué SÍ hacer)**

```python
from fastapi import Depends, HTTPException, status
from sqlalchemy import select

def get_owned_invoice(invoice_id: int, user=Depends(get_current_user), db=Depends(get_db)) -> Invoice:
    # Filtro de propiedad y tenant EN LA CONSULTA: no se carga el objeto ajeno.
    stmt = select(Invoice).where(
        Invoice.id == invoice_id,
        Invoice.tenant_id == user.tenant_id,
        Invoice.owner_id == user.id,
    )
    invoice = db.scalars(stmt).first()
    if invoice is None:
        # 404 (no 403) para no confirmar la existencia de IDs ajenos (enumeración).
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    return invoice

@app.get("/api/invoices/{invoice_id}", response_model=InvoiceOut)
def get_invoice(invoice: Invoice = Depends(get_owned_invoice)):
    return invoice

@app.get("/api/invoices", response_model=list[InvoiceOut])
def list_invoices(user=Depends(get_current_user), db=Depends(get_db)):
    # El sujeto proviene del token verificado, nunca de un parámetro.
    return db.scalars(select(Invoice).where(Invoice.owner_id == user.id,
                                            Invoice.tenant_id == user.tenant_id)).all()
```

> **IDs no secuenciales (UUIDv4/UUIDv7) no son un control de acceso.** Reducen la enumeración, pero los IDs se filtran en logs, URLs compartidas y respuestas. Siempre verifique la propiedad.

### 3.2 TypeScript (Express + Prisma)

**Patrón Vulnerable (Qué NO hacer)**

```typescript
app.get("/api/documents/:id", requireAuth, async (req, res) => {
  const doc = await prisma.document.findUnique({ where: { id: req.params.id } });
  res.json(doc); // VULNERABLE: no verifica owner ni tenant
});
```

**Patrón Seguro (Qué SÍ hacer)**

```typescript
app.get("/api/documents/:id", requireAuth, async (req, res) => {
  const { id: userId, tenantId } = req.auth; // del JWT/sesión verificada en el servidor
  const doc = await prisma.document.findFirst({
    where: {
      id: req.params.id,
      tenantId,
      OR: [{ ownerId: userId }, { shares: { some: { userId, permission: { in: ["READ", "WRITE"] } } } }],
    },
    select: { id: true, title: true, content: true, updatedAt: true }, // allow-list de salida
  });
  if (!doc) return res.status(404).end();
  res.json(doc);
});
```

### 3.3 Aislamiento multi-tenant en la base de datos (PostgreSQL RLS)

Defensa en profundidad: aunque un desarrollador olvide el filtro, la base de datos lo impone.

```sql
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;  -- aplica también al dueño de la tabla

CREATE POLICY tenant_isolation ON invoices
  USING (tenant_id = current_setting('app.tenant_id')::uuid)
  WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- La aplicación fija el tenant por transacción, tomado del token verificado:
-- SET LOCAL app.tenant_id = '<uuid-del-token>';
-- El rol de la app NO debe tener BYPASSRLS ni ser superusuario.
```

```python
# SQLAlchemy: fijar el tenant al inicio de cada transacción.
from sqlalchemy import event, text

@event.listens_for(Session, "after_begin")
def set_tenant(session, transaction, connection):
    tenant_id = tenant_ctx.get()  # contextvar poblada por el middleware de auth
    connection.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)})
```

---

## 4. Escalada vertical (BFLA) y RBAC centralizado

**Patrón Vulnerable (Qué NO hacer)**

```tsx
// VULNERABLE: "seguridad" solo en el frontend.
{user.role === "admin" && <button onClick={() => api.delete(`/api/admin/users/${id}`)}>Eliminar</button>}
```

```python
# VULNERABLE: el backend confía en un rol enviado por el cliente o en un header.
@app.delete("/api/admin/users/{uid}")
def delete_user(uid: int, x_role: str = Header(None)):
    if x_role == "admin":
        ...

# VULNERABLE: chequeos de rol hardcodeados y dispersos; un endpoint nuevo los olvida.
if user.role in ("admin", "superadmin", "manager"):
    ...
```

**Patrón Seguro (Qué SÍ hacer) — permisos declarativos (Python)**

```python
from enum import StrEnum
from fastapi import Depends, HTTPException, status

class Perm(StrEnum):
    USER_READ = "user:read"
    USER_DELETE = "user:delete"
    INVOICE_APPROVE = "invoice:approve"

# Mapa rol -> permisos: versionado, revisado y cargado desde la configuración o el IdP.
ROLE_PERMISSIONS: dict[str, frozenset[Perm]] = {
    "viewer": frozenset({Perm.USER_READ}),
    "finance": frozenset({Perm.USER_READ, Perm.INVOICE_APPROVE}),
    "admin": frozenset(Perm),
}

def require(*perms: Perm):
    def checker(user=Depends(get_current_user)):
        granted = ROLE_PERMISSIONS.get(user.role, frozenset())
        if not set(perms) <= granted:
            audit.warning("authz_denied", user=user.id, needed=[p.value for p in perms])
            raise HTTPException(status.HTTP_403_FORBIDDEN)
        return user
    return checker

@app.delete("/api/admin/users/{uid}", dependencies=[Depends(require(Perm.USER_DELETE))])
def delete_user(uid: int, db=Depends(get_db)):
    ...
```

**Deny-by-default a nivel de router (FastAPI):** registre los routers con dependencias globales y haga que una prueba automatizada falle si existe una ruta sin una política declarada.

```python
# tests/test_authz_coverage.py — falla el build si una ruta no declara permiso.
PUBLIC = {"/health", "/api/auth/login", "/docs", "/openapi.json"}

def test_every_route_has_authorization():
    for route in app.routes:
        if getattr(route, "path", None) in PUBLIC:
            continue
        deps = {d.call.__qualname__ for d in getattr(route, "dependant", None).dependencies} if hasattr(route, "dependant") else set()
        assert any("require" in d or "checker" in d for d in deps), f"Ruta sin política: {route.path}"
```

**Patrón Seguro (Qué SÍ hacer) — middleware TypeScript con política como código**

```typescript
type Permission = "user:read" | "user:delete" | "invoice:approve";
const ROLE_PERMS: Record<string, ReadonlySet<Permission>> = {
  viewer: new Set(["user:read"]),
  finance: new Set(["user:read", "invoice:approve"]),
  admin: new Set(["user:read", "user:delete", "invoice:approve"]),
};

export const authorize = (...needed: Permission[]) => (req, res, next) => {
  const granted = ROLE_PERMS[req.auth?.role] ?? new Set();
  if (!needed.every((p) => granted.has(p))) {
    req.log.warn({ user: req.auth?.id, needed }, "authz_denied");
    return res.status(403).json({ error: "forbidden" });
  }
  next();
};

router.delete("/admin/users/:id", requireAuth, authorize("user:delete"), deleteUser);
```

> Para organizaciones con muchos servicios, externalice la política a un motor de decisión (**OPA/Rego**, **Cedar**, **Casbin**, **OpenFGA**) con pruebas unitarias de las políticas en el pipeline.

```rego
# policy/invoice.rego (OPA)
package invoice
default allow := false
allow if {
  input.action == "approve"
  "invoice:approve" in input.subject.permissions
  input.resource.tenant_id == input.subject.tenant_id
  input.resource.amount <= input.subject.approval_limit
  input.resource.created_by != input.subject.id   # segregación de funciones (SoD)
}
```

---

## 5. Mass Assignment / BOPLA

**Patrón Vulnerable (Qué NO hacer)**

```python
# VULNERABLE: se vuelca el JSON completo al modelo.
@app.patch("/api/users/me")
def update_me(payload: dict, user=Depends(get_current_user), db=Depends(get_db)):
    for k, v in payload.items():
        setattr(user, k, v)       # {"role": "admin", "is_active": true, "tenant_id": 1}
    db.commit()
```

```typescript
// VULNERABLE
await prisma.user.update({ where: { id: req.auth.id }, data: req.body });
```

**Patrón Seguro (Qué SÍ hacer)**

```python
from pydantic import BaseModel, EmailStr, Field

class UserSelfUpdate(BaseModel):
    model_config = {"extra": "forbid"}          # campos no declarados -> 422
    display_name: str | None = Field(default=None, max_length=80)
    email: EmailStr | None = None

class UserOut(BaseModel):                       # allow-list de salida: evita fugas (password_hash, mfa_secret)
    id: int
    display_name: str
    email: EmailStr

@app.patch("/api/users/me", response_model=UserOut)
def update_me(payload: UserSelfUpdate, user=Depends(get_current_user), db=Depends(get_db)):
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(user, k, v)
    db.commit()
    return user
```

```typescript
const SelfUpdate = z.object({ displayName: z.string().max(80).optional(), email: z.string().email().optional() }).strict();
const data = SelfUpdate.parse(req.body);
await prisma.user.update({ where: { id: req.auth.id }, data, select: { id: true, displayName: true, email: true } });
```

---

## 6. Otros vectores de escalada

| Vector | Fallo | Control |
|---|---|---|
| **JWT manipulado** | Aceptar `alg: none`, confundir HS256/RS256, no validar `exp`/`aud`/`iss`, roles editables en el token sin verificar la firma | Fijar los algoritmos permitidos, validar todos los *claims* y obtener los permisos en el servidor |
| **Parámetros ocultos** | `?admin=true`, `debug=1`, `X-Original-URL`, `X-Forwarded-For` usados para decisiones de acceso | Ignorar las cabeceras de enrutamiento no confiables y configurar `trusted proxies` |
| **Path / method confusion** | `/admin` bloqueado en el proxy pero `/ADMIN`, `/admin/.`, `/admin;x` o `HEAD` llegan al backend | Autorizar en la aplicación, no solo en el WAF o el proxy, y normalizar las rutas |
| **GraphQL** | Autorización en el resolver raíz pero no en los campos anidados; introspección expuesta | Autorización por campo/tipo (directivas), limitar la profundidad y la complejidad, deshabilitar la introspección en producción |
| **Flujos multipaso** | Saltar el paso 2 (pago/aprobación) y llamar al paso 3 directamente | Máquina de estados en el servidor; validar el estado previo |
| **SSRF (parte de A01:2025)** | El servidor hace peticiones a URLs controladas por el usuario y alcanza metadatos de la nube (`169.254.169.254`) o servicios internos | Allow-list de destinos, resolución DNS y validación de IP (bloquear rangos privados y de enlace local), IMDSv2, egress filtering |
| **Privilegios del runtime** | Contenedor como root, `--privileged`, service account con `*:*` | Usuario no root, `cap_drop: ALL`, IAM con mínimo privilegio y credenciales de corta vida |

**Validación de JWT (Python, PyJWT)**

```python
import jwt

# VULNERABLE
claims = jwt.decode(token, options={"verify_signature": False})

# SEGURO
claims = jwt.decode(
    token,
    key=public_key,
    algorithms=["RS256"],                 # nunca derivar el algoritmo del header del token
    audience="api.empresa.com",
    issuer="https://idp.empresa.com/",
    options={"require": ["exp", "iat", "sub", "aud", "iss"]},
    leeway=30,
)
permissions = load_permissions_from_db(claims["sub"])  # no confiar ciegamente en claims de rol de larga vida
```

**Mitigación de SSRF (Python)**

```python
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.partner.com", "hooks.slack.com"}

def assert_safe_url(url: str) -> None:
    p = urlparse(url)
    if p.scheme != "https" or p.hostname not in ALLOWED_HOSTS:
        raise ValueError("Destino no permitido")
    for info in socket.getaddrinfo(p.hostname, 443, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("IP de destino interna bloqueada")
# Además: deshabilitar redirects (allow_redirects=False) o revalidar cada salto, y fijar
# la IP resuelta en la conexión para evitar DNS rebinding.
```

---

## 7. Mínimo privilegio en infraestructura

```dockerfile
# Contenedor sin root
FROM python:3.13-slim
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
USER 10001:10001
```

```yaml
# docker-compose / Kubernetes securityContext equivalente
services:
  api:
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    user: "10001:10001"
```

```json
// IAM (AWS) — política acotada a un prefijo de bucket, no s3:*
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::empresa-facturas/tenant-${aws:PrincipalTag/tenant}/*"
  }]
}
```

- Las cuentas administrativas requieren MFA resistente a phishing (FIDO2/passkeys) y, cuando aplique, acceso *just-in-time* (JIT) con expiración.
- Revisión trimestral de permisos (recertificación) y desactivación automática de las cuentas inactivas.

---

## 8. Pruebas de autorización

```python
# Pruebas negativas obligatorias por endpoint: matriz sujeto x recurso x acción.
import pytest

@pytest.mark.parametrize("actor,expected", [("owner", 200), ("other_user_same_tenant", 404),
                                            ("user_other_tenant", 404), ("anonymous", 401)])
def test_invoice_read_authz(client, tokens, invoice_of_owner, actor, expected):
    headers = {"Authorization": f"Bearer {tokens[actor]}"} if actor != "anonymous" else {}
    r = client.get(f"/api/invoices/{invoice_of_owner.id}", headers=headers)
    assert r.status_code == expected

def test_viewer_cannot_delete_users(client, tokens):
    r = client.delete("/api/admin/users/1", headers={"Authorization": f"Bearer {tokens['viewer']}"})
    assert r.status_code == 403

def test_mass_assignment_rejected(client, tokens):
    r = client.patch("/api/users/me", json={"role": "admin"},
                     headers={"Authorization": f"Bearer {tokens['viewer']}"})
    assert r.status_code == 422
```

En pruebas manuales: Burp Suite con las extensiones **Autorize** o **AuthMatrix**, repitiendo cada petición con la sesión de un usuario de menor privilegio y de otro tenant.

---

## 9. Checklist de Verificación (antes de merge / deploy)

- [ ] Cada endpoint nuevo o modificado declara explícitamente su política (permiso requerido). Las rutas públicas están en una allow-list revisada.
- [ ] Existe una prueba automatizada que falla si una ruta carece de política (deny-by-default verificable).
- [ ] Todo acceso a un objeto por ID verifica la propiedad, la compartición o el tenant **en la consulta**, y devuelve 404 ante recursos ajenos.
- [ ] El identificador del sujeto (`user_id`, `tenant_id`, rol) se obtiene del token o la sesión verificada, nunca del body, del query string ni de cabeceras del cliente.
- [ ] Los esquemas de entrada usan `extra=forbid`/`.strict()`, y no hay asignación masiva de `req.body` al ORM.
- [ ] Los esquemas de salida (`response_model`/`select`) exponen solo los campos permitidos, sin hashes, secretos ni flags internos.
- [ ] Las funciones administrativas verifican el permiso en el backend; la UI no es un control.
- [ ] Los JWT validan la firma, el algoritmo fijo, `exp`, `aud` e `iss`; no se acepta `alg: none`.
- [ ] Los flujos multipaso validan el estado previo en el servidor.
- [ ] Las peticiones salientes con URLs de usuario pasan por una allow-list y bloquean IPs internas y de metadatos (SSRF).
- [ ] RLS u otro filtro obligatorio de tenant está activo en las tablas multi-tenant, y el rol de la app no tiene `BYPASSRLS`.
- [ ] Hay pruebas negativas (otro usuario, otro tenant, rol inferior, anónimo) para los endpoints afectados.
- [ ] Las denegaciones (403/404 por authz) y las acciones privilegiadas se registran en auditoría con usuario, recurso, acción y resultado.
- [ ] Contenedores, cuentas de servicio y credenciales de BD aplican mínimo privilegio (no root, sin `*:*`, sin DDL).

---

## 10. Referencias

- OWASP Top 10:2025 — A01 Broken Access Control: https://owasp.org/Top10/2025/
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/
- OWASP ASVS 5.0 — V8 Authorization: https://github.com/OWASP/ASVS
- OWASP Cheat Sheets: Authorization, Insecure Direct Object Reference Prevention, Mass Assignment, SSRF Prevention, JSON Web Token: https://cheatsheetseries.owasp.org/
- PostgreSQL Row Security Policies: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
