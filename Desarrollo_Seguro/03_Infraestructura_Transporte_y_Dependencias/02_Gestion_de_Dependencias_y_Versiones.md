# Gestión de Dependencias, Versiones y Software Supply Chain

| Campo | Valor |
|---|---|
| Dominio | Infraestructura, transporte y dependencias |
| Aplica a | Paquetes npm/PyPI/Maven/NuGet, imágenes de contenedor, runtimes, GitHub Actions, modelos de IA, herramientas de build |
| Referencias | OWASP Top 10:2025 A03 (Software Supply Chain Failures, nueva categoría) y A08 (Software or Data Integrity Failures); OWASP ASVS 5.0 V15 (Secure Coding and Architecture, dependencias); SLSA v1.x; NIST SSDF (SP 800-218); OpenSSF Scorecard; CIS Docker Benchmark; CWE-1104, CWE-1395, CWE-829, CWE-494 |
| Severidad típica | Variable, hasta Crítica (p. ej., Log4Shell, xz-utils, paquetes maliciosos con robo de tokens) |

---

## 1. Principio de Seguridad

**Qué se mitiga:**

1. **Componentes vulnerables conocidos (CWE-1104/1395):** librerías, runtimes o imágenes base con CVEs públicos y exploits disponibles.
2. **Compromiso de la cadena de suministro:** paquetes maliciosos (*typosquatting*, *dependency confusion*, *slopsquatting* con nombres alucinados por IA), cuentas de mantenedores comprometidas, scripts `postinstall` que roban credenciales, *gusanos* que se auto-propagan por el registro, y acciones de CI manipuladas.
3. **Builds no reproducibles:** resolver versiones "flotantes" (`^`, `~`, `latest`, `>=`) introduce código no revisado en cada build.

**Reglas rectoras:**

- **Fijar** todas las versiones (lockfile con hashes de integridad) y **reproducir** el build desde el lockfile.
- **Auditar de forma continua** (en cada PR, cada noche y en el registro de imágenes), no solo al crear el proyecto.
- **Actualizar de forma disciplinada** con SLAs por severidad y automatización (Dependabot/Renovate).
- **Minimizar** dependencias: cada paquete es código de terceros que se ejecuta con los privilegios de la aplicación.
- **Verificar la procedencia**: firmas (Sigstore/cosign), atestaciones SLSA y SBOM por artefacto.

---

## 2. Fijación de versiones y lockfiles

### 2.1 JavaScript / TypeScript (npm / pnpm)

**Patrón Vulnerable (Qué NO hacer)**

```json
{
  "dependencies": {
    "express": "*",
    "lodash": "latest",
    "axios": ">=0.21.0",
    "internal-utils": "^1.0.0"
  }
}
```

```bash
npm install            # en CI: puede reescribir el lockfile y resolver versiones nuevas
# package-lock.json en .gitignore  -> builds no deterministas
```

**Patrón Seguro (Qué SÍ hacer)**

```json
{
  "dependencies": {
    "express": "5.1.0",
    "zod": "3.25.76"
  },
  "engines": { "node": ">=22.12 <23" },
  "packageManager": "pnpm@10.12.1",
  "overrides": { "cross-spawn": "7.0.6" }
}
```

```ini
# .npmrc
save-exact=true
ignore-scripts=true            # bloquea postinstall maliciosos; habilitar por paquete solo si es imprescindible
audit-level=high
engine-strict=true
@empresa:registry=https://npm.empresa.local/    # scope interno -> evita dependency confusion
```

```bash
npm ci                          # instala EXACTAMENTE el lockfile y falla si package.json no coincide
npm audit signatures            # verifica las firmas del registro y las atestaciones de procedencia
```

> **pnpm 10+** no ejecuta los scripts de ciclo de vida de las dependencias por defecto (`onlyBuiltDependencies` como allow-list) y soporta `minimumReleaseAge` para no instalar versiones publicadas hace menos de N minutos. Esto mitiga los paquetes comprometidos que se detectan y retiran en las primeras horas.

### 2.2 Python (pip / uv / Poetry)

**Patrón Vulnerable (Qué NO hacer)**

```text
# requirements.txt
flask
requests>=2.0
django
```

```bash
pip install -r requirements.txt --extra-index-url https://pypi.empresa.local/simple
# --extra-index-url mezcla índices: un paquete público con el mismo nombre y versión mayor gana (dependency confusion)
```

**Patrón Seguro (Qué SÍ hacer)**

```toml
# pyproject.toml (rangos compatibles en la declaración; versiones exactas en el lock)
[project]
name = "core-api"
requires-python = ">=3.12,<3.14"
dependencies = ["fastapi>=0.115,<1.0", "pydantic>=2.11,<3", "httpx>=0.28,<1"]
```

```bash
# uv: lockfile multiplataforma con hashes
uv lock
uv sync --frozen                     # falla si el lock no corresponde con pyproject

# pip-tools: requirements con hashes y modo estricto
pip-compile --generate-hashes --strip-extras -o requirements.lock pyproject.toml
pip install --require-hashes --no-deps -r requirements.lock
```

```ini
# pip.conf: un ÚNICO índice (proxy interno que replica PyPI y aloja los paquetes internos)
[global]
index-url = https://pypi.empresa.local/simple
require-virtualenv = true
```

### 2.3 Imágenes de contenedor

**Patrón Vulnerable (Qué NO hacer)**

```dockerfile
FROM python:latest              # tag mutable: cambia sin aviso; imagen completa con cientos de paquetes
FROM node                       # implícitamente :latest
RUN apt-get update && apt-get install -y curl vim gcc   # herramientas innecesarias en runtime
```

**Patrón Seguro (Qué SÍ hacer)**

```dockerfile
# syntax=docker/dockerfile:1.7
# Tag legible + digest inmutable (Renovate actualiza ambos).
FROM python:3.13.9-slim-bookworm@sha256:<digest> AS build
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.lock --target /deps
COPY src/ ./src/

# Runtime mínimo (distroless/chainguard/wolfi): sin shell ni gestor de paquetes.
FROM gcr.io/distroless/python3-debian12:nonroot@sha256:<digest>
COPY --from=build /deps /deps
COPY --from=build /app/src /app/src
ENV PYTHONPATH=/deps PYTHONDONTWRITEBYTECODE=1
USER nonroot
ENTRYPOINT ["python3", "/app/src/main.py"]
```

### 2.4 GitHub Actions (las acciones también son dependencias)

```yaml
# VULNERABLE: tag mutable (un tag comprometido inyecta código en todos los pipelines; caso tj-actions/changed-files, 2025)
- uses: some-org/some-action@v1

# SEGURO: SHA completo del commit + comentario de versión (Dependabot/Renovate lo mantienen)
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
permissions: { contents: read }      # mínimo privilegio del GITHUB_TOKEN a nivel de workflow
```

---

## 3. Auditoría continua

### 3.1 Herramientas por ecosistema

| Ámbito | Herramienta | Comando |
|---|---|---|
| npm | `npm audit` / OSV-Scanner | `npm audit --omit=dev --audit-level=high` |
| Python | `pip-audit` (base PyPA/OSV) | `pip-audit -r requirements.lock --strict --desc` |
| Multi-lenguaje (repositorio) | **OSV-Scanner** (Google) | `osv-scanner scan source -r .` |
| Contenedores, IaC, FS, SBOM | **Trivy** | `trivy image --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed img:tag` |
| SBOM y vulnerabilidades | **Syft + Grype** | `syft img:tag -o cyclonedx-json > sbom.json && grype sbom:sbom.json --fail-on high` |
| Repositorio (PRs automáticos) | **Dependabot** / **Renovate** | Configuración abajo |
| Reputación del paquete | OpenSSF Scorecard, Socket.dev, deps.dev | `scorecard --repo=github.com/org/lib` |
| Licencias | Trivy `--scanners license`, ScanCode | Bloquear licencias no aprobadas (AGPL, etc., según política) |

### 3.2 Pipeline CI (bloqueante)

```yaml
# .github/workflows/supply-chain.yml
name: supply-chain
on:
  pull_request:
  schedule: [{ cron: "0 6 * * *" }]     # escaneo diario: aparecen CVEs nuevos sin cambiar el código
permissions: { contents: read, security-events: write }
jobs:
  deps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - name: npm audit
        run: npm ci --ignore-scripts && npm audit --omit=dev --audit-level=high
      - name: pip-audit
        run: pipx run pip-audit -r requirements.lock --strict
      - name: OSV-Scanner
        run: |
          go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
          osv-scanner scan source -r --format sarif --output osv.sarif . || exit 1
  image:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - run: docker build -t core-api:${{ github.sha }} .
      - name: Trivy (vulnerabilidades + secretos + misconfig)
        uses: aquasecurity/trivy-action@<sha-fijado>
        with:
          image-ref: core-api:${{ github.sha }}
          scanners: vuln,secret,misconfig
          severity: HIGH,CRITICAL
          ignore-unfixed: true
          exit-code: "1"
          format: sarif
          output: trivy.sarif
```

### 3.3 Dependabot y Renovate

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: npm
    directory: "/"
    schedule: { interval: weekly }
    open-pull-requests-limit: 10
    groups:
      minor-and-patch: { update-types: ["minor", "patch"] }
    cooldown: { default-days: 3 }       # no proponer versiones con menos de 3 días de publicación
  - package-ecosystem: pip
    directory: "/"
    schedule: { interval: weekly }
  - package-ecosystem: docker
    directory: "/"
    schedule: { interval: weekly }
  - package-ecosystem: github-actions
    directory: "/"
    schedule: { interval: weekly }
```

```json
// renovate.json — alternativa con pin de digests y automerge controlado
{
  "extends": ["config:recommended", "helpers:pinGitHubActionDigests", "docker:pinDigests"],
  "minimumReleaseAge": "3 days",
  "vulnerabilityAlerts": { "labels": ["security"], "minimumReleaseAge": null },
  "packageRules": [
    { "matchUpdateTypes": ["patch"], "matchCurrentVersion": "!/^0/", "automerge": true, "automergeType": "pr" },
    { "matchUpdateTypes": ["major"], "dependencyDashboardApproval": true }
  ]
}
```

---

## 4. Política de actualización y SLAs

### 4.1 Remediación de vulnerabilidades en dependencias

| Severidad (CVSS / contexto) | Explotación conocida (CISA KEV / EPSS alto) | SLA de remediación en producción |
|---|---|---|
| Crítica (≥ 9.0) | Sí | **72 horas** (o mitigación compensatoria inmediata) |
| Crítica (≥ 9.0) | No | 7 días |
| Alta (7.0–8.9) | — | 30 días |
| Media (4.0–6.9) | — | 90 días |
| Baja | — | Próximo ciclo de mantenimiento |

**Excepciones:** si la función vulnerable no es alcanzable (análisis de alcanzabilidad, VEX), documente la excepción con su justificación, el responsable y la fecha de expiración (máximo 90 días). Las excepciones viven en el repositorio (`.trivyignore`, `osv-scanner.toml`) con comentario y fecha:

```toml
# osv-scanner.toml
[[IgnoredVulns]]
id = "GHSA-xxxx-xxxx-xxxx"
ignoreUntil = 2027-01-31
reason = "Función vulnerable (parseXML) no se invoca; verificado por análisis de alcanzabilidad. Ticket SEC-1234."
```

### 4.2 Runtimes y sistemas operativos

| Componente | Política |
|---|---|
| Lenguajes (Python, Node.js, Java, .NET, Go) | Solo versiones con **soporte de seguridad activo**. Node.js: solo líneas LTS pares. Python: versiones no EOL (3.11+ a noviembre de 2026; 3.10 alcanzó EOL en octubre de 2026). Planifique la migración 6 meses antes del EOL |
| Frameworks (Django, Spring, Angular, React) | Versión soportada por el proyecto; *majors* con EOL anunciado van al *roadmap* |
| Imagen base | Reconstruir **al menos semanalmente** aunque el código no cambie (recoge parches del SO) |
| Distribución base | Preferir distroless / Chainguard / Alpine / Debian slim; prohibidas las imágenes EOL (p. ej., Debian 10, Ubuntu 18.04, CentOS 7) |
| Inventario | Consulte endoflife.date (API) en CI para alertar sobre runtimes próximos a su EOL |

```bash
# Alerta de EOL en CI (ejemplo con la API pública de endoflife.date)
curl -s https://endoflife.date/api/python/3.11.json | jq -r '.eol'
```

---

## 5. Integridad y procedencia (SLSA, SBOM, firmas)

```bash
# 1) SBOM por artefacto (CycloneDX)
syft core-api:1.4.2 -o cyclonedx-json > sbom.cdx.json

# 2) Firma de la imagen sin llaves de larga vida (Sigstore keyless con OIDC del CI)
cosign sign --yes registry.empresa.com/core-api@sha256:<digest>

# 3) Adjuntar el SBOM como atestación firmada
cosign attest --yes --predicate sbom.cdx.json --type cyclonedx registry.empresa.com/core-api@sha256:<digest>

# 4) Verificación en el despliegue (o con una política de admisión en K8s: Kyverno / Sigstore policy-controller)
cosign verify registry.empresa.com/core-api@sha256:<digest> \
  --certificate-identity-regexp "^https://github.com/empresa/core-api/.github/workflows/release.yml@refs/tags/v" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

```yaml
# Atestación de procedencia SLSA nativa de GitHub
- uses: actions/attest-build-provenance@<sha-fijado>
  with:
    subject-name: registry.empresa.com/core-api
    subject-digest: ${{ steps.push.outputs.digest }}
    push-to-registry: true
```

```yaml
# Kyverno: solo se admiten imágenes firmadas por el pipeline oficial
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: { name: verify-signed-images }
spec:
  validationFailureAction: Enforce
  rules:
    - name: cosign-keyless
      match: { any: [{ resources: { kinds: [Pod] } }] }
      verifyImages:
        - imageReferences: ["registry.empresa.com/*"]
          attestors:
            - entries:
                - keyless:
                    issuer: https://token.actions.githubusercontent.com
                    subject: "https://github.com/empresa/*"
```

---

## 6. Evaluación de una dependencia nueva

Antes de añadir un paquete, el autor del PR documenta en la descripción:

| Criterio | Señal de alerta |
|---|---|
| ¿Es necesaria? | La funcionalidad es trivial (p. ej., `left-pad`, `is-odd`) y puede escribirse en pocas líneas |
| Mantenimiento | Sin commits ni releases en más de 12 meses; issues de seguridad sin respuesta; un único mantenedor |
| Popularidad y antigüedad | Paquete recién publicado, pocas descargas, nombre parecido a uno popular (*typosquatting*) |
| Existencia real | El nombre fue sugerido por un asistente de IA y no aparece en el registro oficial o en la documentación del proyecto (*slopsquatting*) |
| Scripts de instalación | `preinstall`/`postinstall` que descargan binarios o ejecutan código ofuscado |
| OpenSSF Scorecard | Puntuación < 5; sin *branch protection*, sin firmas, sin política de seguridad |
| Dependencias transitivas | Árbol grande para una función pequeña |
| Licencia | Incompatible con la política corporativa |

```bash
# Inspección rápida antes de instalar
npm view <paquete> time.created maintainers repository scripts
npx @socketsecurity/cli npm info <paquete>
pip download <paquete>==<versión> --no-deps -d /tmp/inspect && unzip -l /tmp/inspect/*.whl
scorecard --repo=github.com/<org>/<repo> --format json | jq '.score'
```

---

## 7. Checklist de Verificación (antes de merge / deploy)

- [ ] El lockfile (`package-lock.json`, `pnpm-lock.yaml`, `uv.lock`, `requirements.lock` con hashes, `poetry.lock`) está versionado y actualizado.
- [ ] El CI instala de forma determinista: `npm ci`, `uv sync --frozen`, `pip install --require-hashes`.
- [ ] No hay versiones flotantes (`*`, `latest`, `>=` sin techo) ni imágenes `:latest`; las imágenes base están fijadas por digest.
- [ ] Las GitHub Actions de terceros están fijadas por SHA completo; `permissions` es mínimo.
- [ ] `npm audit` / `pip-audit` / OSV-Scanner / Trivy no reportan vulnerabilidades altas o críticas con fix disponible, y las excepciones están documentadas con su fecha de expiración.
- [ ] Un índice o registro único (proxy interno) con scopes o namespaces reservados para los paquetes internos (anti *dependency confusion*).
- [ ] Los scripts de instalación de dependencias están deshabilitados por defecto (`ignore-scripts`, allow-list de pnpm).
- [ ] Toda dependencia nueva fue evaluada (necesidad, mantenimiento, Scorecard, existencia real, licencia) y aprobada en el PR.
- [ ] El runtime y la imagen base están en una versión con soporte de seguridad activo (no EOL).
- [ ] La imagen final es mínima (distroless/slim), sin compiladores ni shells innecesarios, y se ejecuta como no root.
- [ ] Se genera un SBOM (CycloneDX/SPDX) por release y se publica como atestación.
- [ ] La imagen está firmada (cosign) y el clúster verifica la firma en la admisión.
- [ ] Dependabot/Renovate está activo para todos los ecosistemas del repositorio (incluidos `docker` y `github-actions`).

---

## 8. Referencias

- OWASP Top 10:2025 — A03 Software Supply Chain Failures: https://owasp.org/Top10/2025/
- OWASP Dependency-Check / CycloneDX / Software Component Verification Standard (SCVS): https://owasp.org/
- SLSA: https://slsa.dev/ · Sigstore: https://www.sigstore.dev/ · OpenSSF Scorecard: https://scorecard.dev/
- NIST SP 800-218 (SSDF): https://csrc.nist.gov/pubs/sp/800/218/final
- OSV-Scanner: https://google.github.io/osv-scanner/ · Trivy: https://trivy.dev/ · pip-audit: https://pypi.org/project/pip-audit/
- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- endoflife.date: https://endoflife.date/
