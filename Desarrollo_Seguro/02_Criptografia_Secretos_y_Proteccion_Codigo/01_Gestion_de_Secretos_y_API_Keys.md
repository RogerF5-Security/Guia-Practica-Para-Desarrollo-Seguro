# Gestión de Secretos y API Keys

| Campo | Valor |
|---|---|
| Dominio | Criptografía, secretos y protección de código |
| Aplica a | Código fuente, historial Git, CI/CD, imágenes de contenedor, IaC, configuración y logs |
| Referencias | OWASP Top 10:2025 A04 (Cryptographic Failures), A02 (Security Misconfiguration); OWASP ASVS 5.0 V13 (Configuration, sección de secretos) y V11 (Cryptography); OWASP Secrets Management Cheat Sheet; CWE-798, CWE-259, CWE-321, CWE-532, CWE-312 |
| Severidad típica | Crítica (acceso directo a nube, bases de datos, pasarelas de pago o terceros) |

---

## 1. Principio de Seguridad

**Qué se mitiga:** la exposición de credenciales (contraseñas, API keys, tokens OAuth, llaves privadas, cadenas de conexión, *webhook secrets*, llaves de firma JWT) por estar embebidas en artefactos que se copian, versionan y distribuyen.

**Mecánica del fallo:** un secreto escrito en el código (CWE-798) queda replicado en cada clon del repositorio, *fork*, caché de CI, imagen Docker, *bundle* de frontend y backup. Git conserva el historial: **borrar el secreto en un commit posterior no lo elimina**. Existen bots que escanean GitHub, npm, PyPI y Docker Hub públicos en minutos tras un *push*, y los repositorios privados se filtran por accesos de terceros, integraciones comprometidas o empleados salientes.

**Política obligatoria:**

1. **Prohibición absoluta** de secretos en el código fuente, el historial de Git, los Dockerfiles, las capas de imagen, la IaC, los notebooks, los archivos `.env` versionados, los tickets, las wikis y los logs.
2. Los secretos se **inyectan en tiempo de ejecución** desde una bóveda (Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager) o mediante identidades de carga de trabajo (*workload identity*) sin secretos estáticos.
3. Todo secreto tiene un **propietario, un alcance mínimo, una fecha de expiración y un procedimiento de rotación**.
4. **Detección preventiva** (pre-commit) y **detectiva** (CI y escaneo histórico). Un secreto expuesto se considera **comprometido**: se revoca y se rota primero, y después se limpia el historial.

### Jerarquía preferente

| Nivel | Mecanismo | Ejemplo |
|---|---|---|
| 1 (ideal) | **Sin secreto**: identidad federada de corta vida | IAM Roles / IRSA / Azure Managed Identity / GCP Workload Identity; OIDC de GitHub Actions hacia la nube |
| 2 | **Secretos dinámicos** generados bajo demanda con TTL | Vault Database Secrets Engine (usuario de BD por sesión, TTL de 1 h) |
| 3 | **Secreto estático en bóveda** con rotación automática | AWS Secrets Manager con rotación por Lambda cada 30–90 días |
| 4 (mínimo aceptable) | Variable de entorno inyectada por el orquestador desde una bóveda | Kubernetes External Secrets Operator → `Secret` → variable de entorno |
| Prohibido | Hardcode, `.env` en Git, `ARG`/`ENV` en Dockerfile, valor por defecto en el código | — |

---

## 2. Ejemplos de código

### 2.1 Python

**Patrón Vulnerable (Qué NO hacer)**

```python
# VULNERABLE: credenciales hardcodeadas (CWE-798).
DB_URL = "postgresql://admin:S3cr3t!2024@prod-db.empresa.local:5432/core"
STRIPE_KEY = "sk_live_51H..."  # cualquier clon del repo tiene acceso a pagos
AWS_ACCESS_KEY_ID = "AKIA..."

# VULNERABLE: "valor por defecto" que termina en producción.
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")

# VULNERABLE: secreto en logs (CWE-532).
logger.info(f"Conectando con {DB_URL}")
logger.debug("Headers: %s", request.headers)   # incluye Authorization
```

**Patrón Seguro (Qué SÍ hacer) — configuración tipada con fallo cerrado**

```python
from pydantic import SecretStr, PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """Falla al arrancar si falta un secreto: no hay valores por defecto inseguros."""
    model_config = SettingsConfigDict(env_prefix="APP_", case_sensitive=False)

    database_url: PostgresDsn
    jwt_signing_key: SecretStr          # SecretStr enmascara el valor en repr()/logs
    stripe_api_key: SecretStr

settings = Settings()  # ValidationError si falta alguno -> el contenedor no arranca

# Uso explícito y puntual del valor:
stripe.api_key = settings.stripe_api_key.get_secret_value()
logger.info("Conectando a la base de datos host=%s", settings.database_url.hosts()[0]["host"])
```

**Patrón Seguro (Qué SÍ hacer) — lectura directa desde AWS Secrets Manager con caché**

```python
import json
from functools import lru_cache
import boto3

@lru_cache(maxsize=32)
def get_secret(secret_id: str) -> dict:
    # Autenticación por rol IAM del workload (sin access keys estáticas).
    client = boto3.client("secretsmanager")
    resp = client.get_secret_value(SecretId=secret_id)
    return json.loads(resp["SecretString"])

db = get_secret("prod/core-api/db")
# Para soportar rotación sin reinicio, use aws-secretsmanager-caching con TTL en lugar de lru_cache.
```

**Patrón Seguro (Qué SÍ hacer) — HashiCorp Vault con credenciales dinámicas**

```python
import hvac

client = hvac.Client(url="https://vault.empresa.local:8200")
# Autenticación de Kubernetes: el pod prueba su identidad con su ServiceAccount token.
with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
    client.auth.kubernetes.login(role="core-api", jwt=f.read())

creds = client.secrets.database.generate_credentials(name="core-api-rw")
# creds["data"]["username"] / ["password"] expiran según el TTL (p. ej., 1 h); se renueva el lease.
```

**Patrón Seguro (Qué SÍ hacer) — Azure Key Vault con Managed Identity**

```python
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

client = SecretClient(vault_url="https://kv-core-prod.vault.azure.net", credential=DefaultAzureCredential())
api_key = client.get_secret("partner-api-key").value
```

### 2.2 TypeScript / Node.js

**Patrón Vulnerable (Qué NO hacer)**

```typescript
// VULNERABLE: secreto en el código y, peor, en el bundle del navegador.
const OPENAI_KEY = "sk-proj-...";
// VULNERABLE: las variables con prefijo público se incrustan en el JS del cliente.
// .env -> NEXT_PUBLIC_PAYMENT_SECRET=..., VITE_API_SECRET=..., REACT_APP_DB_PASSWORD=...
fetch("https://api.tercero.com", { headers: { Authorization: `Bearer ${import.meta.env.VITE_API_SECRET}` } });
```

**Patrón Seguro (Qué SÍ hacer)**

```typescript
import { z } from "zod";

// Validación de entorno al arrancar (solo servidor).
const Env = z.object({
  DATABASE_URL: z.string().url(),
  JWT_PRIVATE_KEY: z.string().min(100),
  PARTNER_API_KEY: z.string().min(20),
});
export const env = Env.parse(process.env); // lanza excepción y aborta si falta algo

// El frontend llama a un backend propio (BFF); la llave del tercero nunca sale del servidor.
app.post("/api/partner/quote", requireAuth, async (req, res) => {
  const r = await fetch("https://api.tercero.com/quote", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.PARTNER_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify(QuoteSchema.parse(req.body)),
  });
  res.status(r.status).json(await r.json());
});
```

> **Regla:** cualquier variable con prefijo `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `PUBLIC_` o `EXPO_PUBLIC_` es **pública**. Nunca contiene secretos.

### 2.3 Docker

**Patrón Vulnerable (Qué NO hacer)**

```dockerfile
# VULNERABLE: ARG/ENV quedan en las capas y en `docker history`.
FROM node:22
ARG NPM_TOKEN
ENV DATABASE_PASSWORD=Pr0dPass!
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > ~/.npmrc && npm ci
COPY . .            # copia .env, .git y llaves si no hay .dockerignore
```

**Patrón Seguro (Qué SÍ hacer) — BuildKit secrets + .dockerignore**

```dockerfile
# syntax=docker/dockerfile:1.7
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
# El secreto se monta solo durante este RUN; no persiste en ninguna capa.
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci --omit=dev
COPY src ./src

FROM gcr.io/distroless/nodejs22-debian12
WORKDIR /app
COPY --from=build /app /app
USER nonroot
CMD ["src/server.js"]
# Los secretos de runtime los inyecta el orquestador (K8s Secret/CSI, ECS secrets), no la imagen.
```

```bash
docker build --secret id=npmrc,src=$HOME/.npmrc -t core-api:1.4.2 .
```

```gitignore
# .dockerignore y .gitignore (mínimo)
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*.pfx
id_rsa*
.aws/
.git
terraform.tfstate*
*.tfvars
```

### 2.4 CI/CD sin secretos estáticos (GitHub Actions → AWS por OIDC)

**Patrón Vulnerable (Qué NO hacer)**

```yaml
env:
  AWS_ACCESS_KEY_ID: AKIA...           # llave de larga vida en el workflow
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET }}
steps:
  - run: echo "Deploy con ${{ secrets.AWS_SECRET }}"   # riesgo de fuga en logs y en PRs de forks
```

**Patrón Seguro (Qué SÍ hacer)**

```yaml
permissions:
  id-token: write   # necesario para OIDC
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production        # requiere aprobación y restringe los secretos al entorno
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/gha-deploy-core-api
          aws-region: us-east-1
      # Credenciales temporales (~1 h), condicionadas por la trust policy a repo + rama + environment.
```

```json
// Trust policy del rol: solo este repo, en la rama main y el entorno production
"Condition": {
  "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
  "StringLike": { "token.actions.githubusercontent.com:sub": "repo:empresa/core-api:environment:production" }
}
```

### 2.5 Kubernetes (External Secrets Operator)

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: core-api-db
spec:
  refreshInterval: 1h                 # recoge las rotaciones
  secretStoreRef: { name: aws-secrets-manager, kind: ClusterSecretStore }
  target: { name: core-api-db, creationPolicy: Owner }
  data:
    - secretKey: DATABASE_URL
      remoteRef: { key: prod/core-api/db, property: url }
```

> Los `Secret` de Kubernetes están solo en Base64. Habilite el **cifrado en reposo de etcd** (KMS provider), restrinja `get/list secrets` por RBAC y prefiera montarlos como archivos en lugar de variables de entorno (las variables se filtran en volcados de procesos, *crash reports* y en `/proc/<pid>/environ`).

---

## 3. Detección: pre-commit hooks y CI

### 3.1 Gitleaks como pre-commit (obligatorio en estaciones de desarrollo)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.24.2            # fijar versión; actualizar vía Dependabot/Renovate
    hooks:
      - id: gitleaks
  - repo: https://github.com/trufflesecurity/trufflehog
    rev: v3.88.0
    hooks:
      - id: trufflehog
        entry: trufflehog git file://. --since-commit HEAD --results=verified,unknown --fail
        stages: ["pre-push"]
```

```bash
pip install pre-commit
pre-commit install --hook-type pre-commit --hook-type pre-push
pre-commit run --all-files
```

```toml
# .gitleaks.toml — extender las reglas por defecto con patrones propios
[extend]
useDefault = true

[[rules]]
id = "empresa-internal-token"
description = "Token interno de la plataforma"
regex = '''emp_(live|test)_[A-Za-z0-9]{32}'''
keywords = ["emp_live_", "emp_test_"]

[allowlist]
description = "Fixtures de prueba sin valor real"
paths = ['''tests/fixtures/fake_keys\.json''']
```

### 3.2 Escaneo en CI (bloqueante) e histórico

```yaml
# .github/workflows/secrets.yml
name: secret-scan
on: [pull_request, push]
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }      # historial completo
      - uses: gitleaks/gitleaks-action@v2
        env: { GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}" }
  trufflehog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: trufflesecurity/trufflehog@main   # en producción fije un tag o SHA
        with: { extra_args: --results=verified,unknown }
```

```bash
# Auditoría histórica completa de un repositorio y de imágenes
gitleaks git --report-format json --report-path gitleaks.json -v .
trufflehog git file://. --results=verified --json > trufflehog.json
trufflehog docker --image empresa/core-api:1.4.2
```

Habilite además **GitHub Secret Scanning + Push Protection** (o su equivalente en GitLab/Azure DevOps) a nivel de organización.

---

## 4. Respuesta ante un secreto expuesto

El orden importa: **primero contener, después limpiar.**

1. **Revocar o rotar inmediatamente** el secreto en el proveedor (no esperar a limpiar Git).
2. **Evaluar el uso indebido:** revisar CloudTrail / Azure Activity Log / logs del proveedor desde la fecha del commit. TruffleHog `--results=verified` confirma si la llave estaba activa.
3. **Emitir un secreto nuevo** desde la bóveda y desplegarlo.
4. **Limpiar el historial** con `git filter-repo` (no `filter-branch`), forzar el push coordinado, invalidar los forks y cachés, y solicitar la purga al proveedor de hosting si es público.
5. **Registrar el incidente** con la línea de tiempo y la causa raíz, y añadir una regla de detección si el patrón no estaba cubierto.

```bash
# Reemplazar el literal en todo el historial (requiere git-filter-repo)
printf 'sk_live_51H...==>REMOVED\n' > replacements.txt
git filter-repo --replace-text replacements.txt
git push --force --all && git push --force --tags
```

---

## 5. Rotación de llaves

| Tipo de secreto | Rotación máxima recomendada | Mecanismo |
|---|---|---|
| Credenciales de BD de aplicación | Dinámicas (TTL ≤ 24 h) o 90 días | Vault DB engine / Secrets Manager rotation |
| API keys de terceros | 90 días o según el proveedor | Doble llave activa (A/B) para rotar sin corte |
| Llaves de firma JWT | 90–180 días | JWKS con `kid`; publicar la nueva, firmar con la nueva y retirar la vieja tras el TTL máximo del token |
| Llaves de cifrado de datos (KEK) | Anual o por volumen | KMS con rotación automática; *envelope encryption* |
| Tokens personales (PAT) de devs | ≤ 90 días, con alcance mínimo | *Fine-grained tokens* con expiración obligatoria |
| Inmediata | Ante sospecha de exposición, salida de personal con acceso o incidente | Runbook de revocación |

**Rotación sin corte (patrón de doble llave)**

```python
# Verificación de webhook aceptando la llave actual y la anterior durante la ventana de rotación.
import hmac, hashlib

def verify_signature(body: bytes, signature: str, keys: list[bytes]) -> bool:
    return any(
        hmac.compare_digest(hmac.new(k, body, hashlib.sha256).hexdigest(), signature)
        for k in keys  # [current, previous]; previous se elimina al terminar la ventana
    )
```

---

## 6. Checklist de Verificación (antes de merge / deploy)

- [ ] `gitleaks` y `trufflehog` pasan sin hallazgos en el diff y en el historial de la rama.
- [ ] El hook `pre-commit` está instalado y versionado en `.pre-commit-config.yaml`.
- [ ] No hay secretos en el código, los tests, los notebooks, la IaC (`*.tfvars`, `values.yaml`), los Dockerfiles ni la documentación.
- [ ] `.gitignore` y `.dockerignore` excluyen `.env*`, llaves, `tfstate` y credenciales. Solo se versiona `.env.example` con valores ficticios.
- [ ] La aplicación falla al arrancar si falta un secreto (sin defaults inseguros como `"changeme"`).
- [ ] Los secretos se obtienen de una bóveda o una identidad federada; no se usan access keys de larga vida en CI/CD (OIDC).
- [ ] Ninguna variable de entorno pública del frontend (`NEXT_PUBLIC_`, `VITE_`…) contiene secretos.
- [ ] Las imágenes usan `--mount=type=secret` y `docker history` no muestra credenciales. `trufflehog docker` está limpio.
- [ ] Los logs y las trazas no imprimen secretos, cabeceras `Authorization`, cookies ni cadenas de conexión (uso de `SecretStr`/redacción).
- [ ] Cada secreto nuevo tiene un propietario, un alcance mínimo, una expiración y un procedimiento de rotación documentados.
- [ ] Los secretos de Kubernetes están cifrados en etcd (KMS) y restringidos por RBAC.
- [ ] Secret Scanning + Push Protection está habilitado en el repositorio.

---

## 7. Referencias

- OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- OWASP ASVS 5.0 — V13 Configuration (gestión de secretos): https://github.com/OWASP/ASVS
- Gitleaks: https://github.com/gitleaks/gitleaks · TruffleHog: https://github.com/trufflesecurity/trufflehog
- GitHub Actions OIDC: https://docs.github.com/actions/security-for-github-actions/security-hardening-your-deployments
- HashiCorp Vault, AWS Secrets Manager, Azure Key Vault (documentación oficial de cada proveedor)
- CWE-798 Use of Hard-coded Credentials: https://cwe.mitre.org/data/definitions/798.html
