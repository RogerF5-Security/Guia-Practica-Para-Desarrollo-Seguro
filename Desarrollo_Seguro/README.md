# Desarrollo Seguro — Base de Conocimiento AppSec / DevSecOps

| Campo | Valor |
|---|---|
| Propósito | Guías técnicas y accionables para construir productos nuevos y mantener sistemas existentes con seguridad desde el diseño |
| Audiencia | Desarrolladores backend/frontend/móvil, DevOps/SRE, arquitectos, QA y revisores de código |
| Marco de referencia | OWASP Top 10:2025 · OWASP ASVS 5.0 · OWASP API Security Top 10:2023 · OWASP Top 10 for LLM Applications 2025 · OWASP MASVS v2 · CWE Top 25 (2025) · Mozilla Server Side TLS (v6.0) · CIS Benchmarks · NIST SSDF (SP 800-218/218A) · SLSA |
| Formatos | Cada guía está en Markdown (`.md`, para leer en el repositorio y revisar cambios) y en Word (`.docx`, para distribución y auditoría), con el mismo nombre |
| Última revisión | 2026-11-23 |

---

## 1. Índice general

### Empieza aquí

| Guía | Contenido principal | Lectura |
|---|---|---|
| [00_Guia_Rapida_Desarrollo_Seguro](00_Guia_Rapida_Desarrollo_Seguro.md) | Resumen obligatorio para todo desarrollador: 12 reglas de oro, preguntas de sí o no, inputs, headers (para qué sirve cada uno), CSP, flags de cookies, hardcodeo de secretos, ofuscación, actualización de librerías y checklist de 1 minuto antes del PR | 10 min |

### 01 — Código y Prevención de Vulnerabilidades

| Guía | Contenido principal | OWASP / CWE |
|---|---|---|
| [01_Inyecciones_SQLi_Command_RCE](01_Codigo_y_Prevencion_de_Vulnerabilidades/01_Inyecciones_SQLi_Command_RCE.md) | Prepared statements, ORM seguro, NoSQLi, Command y Argument Injection, prohibición de `eval`/`exec`/`os.system`/`shell=True`, SSTI, deserialización segura, XXE y path traversal | A05:2025 · CWE-89, 78, 94, 502 |
| [02_XSS_CSRF_y_Seguridad_Frontend](01_Codigo_y_Prevencion_de_Vulnerabilidades/02_XSS_CSRF_y_Seguridad_Frontend.md) | XSS reflejado, almacenado y DOM, codificación contextual, DOMPurify/nh3, Trusted Types, CSP estricta con nonces, anti-CSRF, Fetch Metadata y cookies `__Host-`/`HttpOnly`/`Secure`/`SameSite` | A05/A01:2025 · CWE-79, 352, 1004 |
| [03_Control_de_Acceso_y_Escalada_Privilegios](01_Codigo_y_Prevencion_de_Vulnerabilidades/03_Control_de_Acceso_y_Escalada_Privilegios.md) | IDOR/BOLA, BFLA, mass assignment, deny-by-default, RBAC/ABAC/ReBAC, OPA, PostgreSQL RLS, JWT, SSRF y PoLP en infraestructura | A01:2025 · API1/3/5 · CWE-639, 862, 863 |

### 02 — Criptografía, Secretos y Protección de Código

| Guía | Contenido principal | OWASP / CWE |
|---|---|---|
| [01_Gestion_de_Secretos_y_API_Keys](02_Criptografia_Secretos_y_Proteccion_Codigo/01_Gestion_de_Secretos_y_API_Keys.md) | Prohibición de hardcode, Vault / AWS Secrets Manager / Azure Key Vault, OIDC en CI/CD, BuildKit secrets, External Secrets, Gitleaks/TruffleHog en pre-commit y CI, respuesta ante una fuga y rotación | A04/A02:2025 · CWE-798, 532 |
| [02_Cifrado_Almacenamiento_y_Hashing](02_Criptografia_Secretos_y_Proteccion_Codigo/02_Cifrado_Almacenamiento_y_Hashing.md) | Argon2id/bcrypt (MD5/SHA para passwords prohibidos), migración de hashes heredados, AES-256-GCM con AAD, envelope encryption con KMS, blind index, PII, CSPRNG y agilidad post-cuántica | A04:2025 · CWE-311, 312, 327, 916 |
| [03_Ofuscacion_y_Endurecimiento_Cliente](02_Criptografia_Secretos_y_Proteccion_Codigo/03_Ofuscacion_y_Endurecimiento_Cliente.md) | Lógica prohibida en el cliente, source maps fuera de producción, Terser y ofuscación selectiva, R8/Keystore/Play Integrity, Keychain/App Attest, pinning, Electron y binarios | MASVS-RESILIENCE · CWE-602, 540, 656 |

### 03 — Infraestructura, Transporte y Dependencias

| Guía | Contenido principal | OWASP / CWE |
|---|---|---|
| [01_TLS_SSL_y_Cifrado_en_Transito](03_Infraestructura_Transporte_y_Dependencias/01_TLS_SSL_y_Cifrado_en_Transito.md) | TLS 1.2/1.3 únicamente, ciphers ECDHE+AEAD (Mozilla Intermediate), HSTS progresivo, validación en clientes, certbot/cert-manager, CAA, PKI interna, mTLS (Istio/Nginx) y testssl.sh/Nuclei | A04:2025 · ASVS V12 · CWE-319, 295 |
| [02_Gestion_de_Dependencias_y_Versiones](03_Infraestructura_Transporte_y_Dependencias/02_Gestion_de_Dependencias_y_Versiones.md) | Lockfiles con hashes, `npm ci`/`uv sync --frozen`, digests de imagen, Actions fijadas por SHA, npm audit/pip-audit/OSV-Scanner/Trivy, Dependabot/Renovate, SLAs, EOL de runtimes, SBOM, cosign y SLSA | A03:2025 · CWE-1104, 1395, 829 |
| [03_Hardening_APIs_y_Servidores](03_Infraestructura_Transporte_y_Dependencias/03_Hardening_APIs_y_Servidores.md) | Rate limiting en capas, Pydantic/Zod/JSON Schema, cabeceras de seguridad, ocultamiento de banners, manejo de errores sin stack traces, fallo cerrado y contenedores endurecidos | A02/A10:2025 · API4/8/9 · CWE-770, 209, 497 |

### 04 — Desarrollo Seguro con IA y LLMs

| Guía | Contenido principal | OWASP / CWE |
|---|---|---|
| [01_Prompt_Engineering_Seguro_y_Prevencion_Injection](04_Desarrollo_Seguro_con_IA_y_LLMs/01_Prompt_Engineering_Seguro_y_Prevencion_Injection.md) | System prompts robustos, prompt injection directo e indirecto, *lethal trifecta*, delimitación y spotlighting, broker de tools con mínimo privilegio, human-in-the-loop, validación de salidas, RAG con ACL y red teaming | LLM01/02/05/06/07/08/10 |
| [02_Uso_Seguro_de_IA_por_Desarrolladores](04_Desarrollo_Seguro_con_IA_y_LLMs/02_Uso_Seguro_de_IA_por_Desarrolladores.md) | Herramientas aprobadas, matriz de clasificación de datos, prohibiciones (secretos, PII, código crítico), auditoría obligatoria del código generado, slopsquatting, agentes de código, MCP y respuesta ante una exposición | LLM02/03/06/09 · A03:2025 |

---

## 2. Matriz rápida: "¿Qué vas a construir hoy?" → Lee esta guía

| Si hoy vas a… | Lectura obligatoria | Lectura complementaria |
|---|---|---|
| Incorporarte al equipo o revisar código por primera vez | 00 Guía Rápida | Go-Live Security Gate (sección 3) |
| Crear un endpoint REST/GraphQL nuevo | 01.03 Control de Acceso · 03.03 Hardening APIs | 01.01 Inyecciones |
| Escribir o modificar consultas SQL / ORM / NoSQL | 01.01 Inyecciones | 01.03 Control de Acceso (filtros por tenant) |
| Ejecutar comandos del sistema, procesar archivos o convertir formatos | 01.01 Inyecciones (Command/RCE, path traversal) | 03.03 Hardening (uploads) |
| Deserializar datos, procesar YAML/XML o cargar modelos de ML | 01.01 Inyecciones (deserialización, XXE) | 03.02 Dependencias |
| Construir vistas, plantillas o componentes React/Vue/Angular | 01.02 XSS/CSRF | 02.03 Endurecimiento del Cliente |
| Implementar login, sesiones, cookies o JWT | 01.02 XSS/CSRF (cookies) · 02.02 Hashing | 01.03 Control de Acceso (JWT) · 03.03 (rate limiting) |
| Implementar roles, permisos, multi-tenant o un panel administrativo | 01.03 Control de Acceso | 03.03 Hardening (fallo cerrado) |
| Integrar una API de terceros, pagos o webhooks | 02.01 Secretos · 01.03 (SSRF) | 03.01 TLS · 02.02 (HMAC/firmas) |
| Almacenar PII, datos financieros, de salud o contraseñas | 02.02 Cifrado y Hashing | 02.01 Secretos (llaves en KMS) |
| Configurar variables de entorno, CI/CD o despliegues | 02.01 Secretos | 03.02 Dependencias (Actions por SHA, OIDC) |
| Publicar una SPA o app web en producción | 02.03 Endurecimiento del Cliente (source maps) · 01.02 (CSP) | 03.03 (cabeceras) |
| Publicar una app móvil, Electron o un binario | 02.03 Endurecimiento del Cliente | 02.01 Secretos · 03.01 TLS (pinning) |
| Configurar Nginx, un balanceador, un Ingress o certificados | 03.01 TLS · 03.03 Hardening | — |
| Comunicar microservicios entre sí | 03.01 TLS (mTLS) · 01.03 (authz entre servicios) | 02.01 Secretos (workload identity) |
| Añadir o actualizar dependencias o la imagen base | 03.02 Dependencias | 04.02 (paquetes sugeridos por IA) |
| Escribir un Dockerfile, un Helm chart o un manifiesto K8s | 03.02 Dependencias · 03.03 Hardening | 02.01 Secretos (BuildKit, External Secrets) · 01.03 (PoLP) |
| Integrar un LLM, chatbot, RAG o agente con tools/MCP | 04.01 Prompt Engineering Seguro | 01.02 (XSS por la salida) · 03.03 (consumo) · 02.01 (llaves de API) |
| Usar Copilot, Codex, ChatGPT, Claude o Cursor para programar | 04.02 Uso Seguro de IA | 03.02 Dependencias |
| Mantener o refactorizar un sistema heredado | Checklist Go-Live (sección 3) · 03.02 Dependencias (EOL) | 02.02 (migración de hashes) · 01.01 |
| Responder a un secreto filtrado | 02.01 Secretos (sección 4: respuesta) | 04.02 (sección 7) |

---

## 3. Go-Live Security Gate (Definition of Done de Seguridad)

**Regla:** ningún sistema, servicio o release mayor pasa a producción sin cumplir **todos** los controles marcados como **Bloqueante**. Los controles **Requerido** sin cumplir necesitan una excepción formal (riesgo aceptado por el propietario del producto y por Seguridad, con fecha de expiración y plan de remediación). Las guías de detalle se indican entre paréntesis.

### 3.1 Diseño y gobierno

- [ ] **Bloqueante** — Existe un modelo de amenazas (STRIDE o equivalente) actualizado para la arquitectura y los flujos de datos sensibles.
- [ ] **Bloqueante** — Los datos manejados están clasificados (Público / Interno / Confidencial / Restringido) y hay un inventario de PII. (02.02)
- [ ] **Requerido** — El nivel ASVS objetivo está definido (L1 mínimo; L2 para sistemas con datos sensibles o transacciones) y sus requisitos fueron verificados.
- [ ] **Requerido** — La API está registrada en el inventario con su contrato OpenAPI, propietario y versión. (03.03)

### 3.2 Código y vulnerabilidades

- [ ] **Bloqueante** — SAST (Semgrep/CodeQL/Bandit/ESLint security) sin hallazgos críticos ni altos abiertos. (01.01, 01.02)
- [ ] **Bloqueante** — Sin concatenación de entrada en SQL, shell, plantillas ni `eval`; sin deserialización insegura. (01.01)
- [ ] **Bloqueante** — Todos los endpoints exigen autenticación (excepto la allow-list pública revisada) y verifican la autorización por función y por objeto en el backend. (01.03)
- [ ] **Bloqueante** — Hay pruebas automatizadas negativas de autorización (otro usuario, otro tenant, rol inferior, anónimo). (01.03)
- [ ] **Bloqueante** — Validación de entrada con un esquema estricto (`extra=forbid`/`.strict()`) y esquemas de salida con allow-list de campos. (03.03, 01.03)
- [ ] **Requerido** — CSP estricta (nonce/hash + `strict-dynamic`) activa, o en Report-Only con un plan de enforcement fechado. (01.02)
- [ ] **Bloqueante** — Protección anti-CSRF en todas las operaciones con cookie de sesión que cambian estado. (01.02)

### 3.3 Secretos y criptografía

- [ ] **Bloqueante** — Gitleaks/TruffleHog sin hallazgos en el repositorio (historial completo) y en la imagen. (02.01)
- [ ] **Bloqueante** — Los secretos provienen de una bóveda o identidad federada; no hay credenciales estáticas de larga vida en CI/CD. (02.01)
- [ ] **Bloqueante** — Contraseñas con Argon2id/bcrypt con parámetros vigentes; sin MD5/SHA directos. (02.02)
- [ ] **Bloqueante** — Los datos Restringidos se cifran en reposo (AES-256-GCM a nivel de aplicación + cifrado de volumen/BD) con llaves en KMS/HSM. (02.02)
- [ ] **Requerido** — Logs y trazas sin secretos ni PII (redacción verificada). (02.02, 02.01)
- [ ] **Requerido** — Existe un procedimiento de rotación documentado para cada secreto y llave. (02.01)

### 3.4 Transporte

- [ ] **Bloqueante** — Solo TLS 1.2/1.3 con ciphers ECDHE+AEAD; SSLv3, TLS 1.0 y TLS 1.1 verificados como rechazados. (03.01)
- [ ] **Bloqueante** — HSTS ≥ 1 año en dominios públicos; HTTP redirige a HTTPS. (03.01)
- [ ] **Bloqueante** — Ningún cliente desactiva la verificación de certificados; BD, cache y colas con TLS verificado. (03.01)
- [ ] **Requerido** — Renovación automática de certificados probada (`--dry-run`) con alerta a ≤ 21 días de la expiración; registros CAA publicados. (03.01)
- [ ] **Requerido** — mTLS (STRICT) entre microservicios con autorización por identidad de workload. (03.01)

### 3.5 Dependencias y cadena de suministro

- [ ] **Bloqueante** — Lockfiles versionados e instalación determinista en CI. (03.02)
- [ ] **Bloqueante** — Sin vulnerabilidades críticas o altas con fix disponible (npm audit / pip-audit / OSV-Scanner / Trivy), o con una excepción documentada y vigente. (03.02)
- [ ] **Bloqueante** — Runtime, frameworks e imagen base en versiones con soporte de seguridad activo (sin EOL). (03.02)
- [ ] **Requerido** — Imágenes fijadas por digest, mínimas (distroless/slim), firmadas (cosign) y con SBOM publicado. (03.02)
- [ ] **Requerido** — Dependabot/Renovate activo para todos los ecosistemas, incluidos `docker` y `github-actions`. (03.02)

### 3.6 Configuración y runtime

- [ ] **Bloqueante** — Modo debug deshabilitado; errores genéricos con `error_id`; sin stack traces al cliente. (03.03)
- [ ] **Bloqueante** — Rate limiting activo en autenticación, OTP, recuperación de cuenta y operaciones costosas. (03.03)
- [ ] **Bloqueante** — Endpoints de administración, métricas, debug y documentación no expuestos públicamente sin aprobación. (03.03)
- [ ] **Requerido** — Cabeceras de seguridad presentes (`HSTS`, `nosniff`, `frame-ancestors`/`X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`), sin banners de versión. (03.03)
- [ ] **Requerido** — Contenedores no root, FS de solo lectura, `cap_drop: ALL`, `no-new-privileges` y límites de recursos. (03.03, 01.03)
- [ ] **Requerido** — Logging de seguridad (logins, fallos de authz, 429, 5xx, cambios de privilegios) enviado al SIEM, con alertas definidas.

### 3.7 Cliente (web / móvil / escritorio)

- [ ] **Bloqueante** — Sin secretos, llaves privadas ni lógica de autorización o de precios en el cliente. (02.03)
- [ ] **Bloqueante** — Source maps no desplegados públicamente (`*.map` devuelve 404). (02.03)
- [ ] **Requerido** — Builds de release minificados y sin logs de debug; móvil: R8/stripping, `debuggable=false`, almacenamiento en Keystore/Keychain. (02.03)

### 3.8 IA y LLMs (si aplica)

- [ ] **Bloqueante** — System prompt sin secretos; autorización de las tools en el backend con la identidad del usuario. (04.01)
- [ ] **Bloqueante** — Las acciones con efectos ejecutadas por agentes requieren confirmación humana; no existe la combinación datos privados + contenido no confiable + egress sin un control determinista. (04.01)
- [ ] **Bloqueante** — La salida del modelo se valida con un esquema y nunca se ejecuta ni se renderiza como HTML sin sanitizar. (04.01)
- [ ] **Requerido** — Suite de red teaming (promptfoo/garak/PyRIT) ejecutada sin regresiones; límites de consumo por usuario/tenant. (04.01)
- [ ] **Requerido** — El código asistido por IA fue revisado según la checklist 4.3 de la guía 04.02 y declarado en los PRs. (04.02)

### 3.9 Verificación final

- [ ] **Bloqueante** — DAST (OWASP ZAP baseline / API scan) en staging sin hallazgos altos.
- [ ] **Requerido** — Escaneo de configuración y exposición (Nuclei, testssl.sh, Mozilla Observatory) sin hallazgos medios o superiores.
- [ ] **Requerido** — Pentest manual previo al go-live para sistemas expuestos a Internet o que manejen datos Restringidos, con los hallazgos críticos y altos remediados y retesteados.
- [ ] **Bloqueante** — Runbook de respuesta a incidentes y contactos de escalamiento actualizados para el servicio.

---

## 4. Integración en el ciclo de desarrollo

| Fase | Control | Herramientas de referencia |
|---|---|---|
| Diseño | Modelo de amenazas, clasificación de datos, nivel ASVS | OWASP Threat Dragon, STRIDE |
| Estación del desarrollador | pre-commit: secretos, linters de seguridad, exclusión de archivos sensibles del contexto de la IA | Gitleaks, Semgrep, ESLint security, Bandit |
| Pull Request | SAST, SCA, secretos, IaC, revisión humana con checklist | Semgrep/CodeQL, OSV-Scanner, Trivy, Gitleaks, Checkov |
| Build | Instalación determinista, SBOM, firma, atestación de procedencia | `npm ci`, `uv sync --frozen`, Syft, cosign, SLSA |
| Staging | DAST, fuzzing de contrato, escaneo de configuración y TLS | OWASP ZAP, Schemathesis, Nuclei, testssl.sh |
| Producción | Verificación de firmas en la admisión, WAF/rate limiting, monitoreo, SIEM | Kyverno, WAF, SIEM |
| Operación continua | Escaneo nocturno de CVEs, actualización de dependencias, rotación de secretos, alertas de EOL y de certificados | Dependabot/Renovate, Trivy, endoflife.date |

**Pipeline mínimo recomendado (orden):**

```text
pre-commit (gitleaks + semgrep) → PR: [lint+tests] → [SAST] → [SCA] → [secrets] → [IaC]
  → build: [lockfile frozen] → [SBOM] → [image scan] → [cosign sign + attest]
  → staging: [ZAP] → [Schemathesis] → [Nuclei/testssl] → Go-Live Gate → producción (verify signatures)
```

---

## 5. Convenciones de las guías

Cada guía contiene, en este orden:

1. **Principio de Seguridad:** qué se mitiga, cómo se produce el fallo y por qué importa.
2. **Ejemplos de código:** **Patrón Vulnerable (Qué NO hacer)** frente a **Patrón Seguro (Qué SÍ hacer)** en Python, JavaScript/TypeScript, SQL y Docker/Nginx según el tema.
3. **Detección automatizada:** reglas y comandos para el pipeline.
4. **Checklist de Verificación:** controles a validar antes de merge o deploy.
5. **Referencias:** estándares oficiales.

**Mantenimiento de la base:** revisión semestral o ante una versión nueva de los estándares de referencia (OWASP Top 10, ASVS, LLM Top 10, guías de Mozilla, CIS). Los cambios se proponen por PR con revisión del equipo de AppSec. Las versiones de herramientas que aparecen en los ejemplos son ilustrativas: fije las suyas y manténgalas con Dependabot/Renovate.

---

## 6. Referencias oficiales

- OWASP Top 10:2025 — https://owasp.org/Top10/2025/
- OWASP ASVS 5.0 — https://github.com/OWASP/ASVS
- OWASP API Security Top 10 — https://owasp.org/API-Security/
- OWASP Top 10 for LLM Applications 2025 — https://genai.owasp.org/llm-top-10/
- OWASP MASVS / MASTG — https://mas.owasp.org/
- OWASP Cheat Sheet Series — https://cheatsheetseries.owasp.org/
- MITRE CWE Top 25 (2025) — https://cwe.mitre.org/top25/
- Mozilla Server Side TLS / SSL Configuration Generator — https://wiki.mozilla.org/Security/Server_Side_TLS · https://ssl-config.mozilla.org/
- CIS Benchmarks — https://www.cisecurity.org/cis-benchmarks
- NIST SSDF SP 800-218 / 800-218A — https://csrc.nist.gov/pubs/sp/800/218/final
- SLSA — https://slsa.dev/
