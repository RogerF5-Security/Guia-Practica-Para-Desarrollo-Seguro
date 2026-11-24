# Uso Seguro de Asistentes de IA por Desarrolladores

| Campo | Valor |
|---|---|
| Dominio | Desarrollo seguro con IA y LLMs |
| Aplica a | GitHub Copilot, OpenAI Codex/ChatGPT, Claude / Claude Code, Gemini, Cursor, Windsurf, agentes de código en IDE/CLI/CI y servidores MCP |
| Referencias | OWASP Top 10 for LLM Applications 2025 (LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM06 Excessive Agency, LLM09 Misinformation); OWASP Top 10:2025 A03 (Software Supply Chain Failures); NIST SSDF SP 800-218 y SP 800-218A (perfil para IA generativa); NIST AI 600-1; CWE-200, CWE-359, CWE-798, CWE-1104 |
| Tipo | Política de uso obligatoria + guía práctica |

---

## 1. Principio de Seguridad

**Qué se mitiga:**

1. **Fuga de información (LLM02):** código propietario crítico, secretos, llaves privadas, datos de clientes o detalles de infraestructura enviados a un servicio externo cuyo almacenamiento, retención, uso para entrenamiento y accesos no controla la organización.
2. **Integración de código inseguro o incorrecto (LLM09):** los asistentes generan con fluidez código que *parece* correcto pero contiene vulnerabilidades (inyección, criptografía débil, autorización ausente, validación omitida), APIs inexistentes o patrones obsoletos. Estudios académicos reiterados muestran una proporción significativa de sugerencias con debilidades CWE cuando no se revisan.
3. **Riesgos de cadena de suministro (LLM03):** dependencias inventadas por el modelo (*package hallucination*) que un atacante registra con código malicioso (*slopsquatting*), extensiones o servidores MCP no verificados, y licencias incompatibles.
4. **Agencia excesiva (LLM06):** agentes de código con permisos amplios (shell, Git, nube, producción) que ejecutan comandos destructivos o siguen instrucciones inyectadas en issues, READMEs, dependencias o páginas web.

**Regla rectora:** *el asistente es un colaborador no confiable y externo.* Todo lo que se le envía puede salir de la organización; todo lo que devuelve es **entrada no confiable** que debe pasar por los mismos controles que el código de un tercero: revisión humana, pruebas, SAST/SCA y aprobación de PR.

**Responsabilidad:** el desarrollador que integra el código es **el autor responsable**. "Lo generó la IA" no es una justificación en revisión de código, auditoría ni análisis post-incidente.

---

## 2. Herramientas autorizadas y clasificación de datos

### 2.1 Solo herramientas aprobadas por la organización

| Requisito de la herramienta | Motivo |
|---|---|
| Contrato empresarial (Business/Enterprise/API con DPA) | Garantías contractuales de confidencialidad |
| **Sin uso de datos para entrenamiento** (por contrato y verificado en la configuración) | Evitar que el código o los datos se incorporen a modelos públicos |
| Retención de datos definida (idealmente ZDR o una retención mínima) | Reducir la ventana de exposición |
| SSO, gestión centralizada de usuarios y logs de auditoría | Control de acceso y trazabilidad |
| Filtro de coincidencia con código público y referencias de licencia | Riesgo de propiedad intelectual |
| Ubicación del procesamiento conforme a la regulación aplicable | Cumplimiento legal y contractual |

**Prohibido:** cuentas personales o gratuitas de asistentes para trabajar con código o datos de la organización; extensiones de IDE no aprobadas; *proxies* o "wrappers" de terceros desconocidos; pegar contenido corporativo en chatbots públicos.

### 2.2 Matriz de datos: qué se puede compartir

| Clasificación del dato | Herramienta empresarial aprobada | Herramienta pública / personal | Modelo local / autoalojado aprobado |
|---|---|---|---|
| **Público** (docs oficiales, código open source, errores genéricos) | Permitido | Permitido | Permitido |
| **Interno** (código de negocio no crítico, configuración sin secretos) | Permitido | **Prohibido** | Permitido |
| **Confidencial** (código propietario crítico: algoritmos core, antifraude, motores de precios, criptografía propia, lógica de seguridad) | Solo con aprobación explícita del propietario del sistema y de Seguridad | **Prohibido** | Permitido según la política |
| **Restringido** (secretos, llaves privadas, tokens, contraseñas, certificados, **datos reales de clientes/PII**, datos de salud o financieros, volcados de BD, logs de producción con datos personales, hallazgos de vulnerabilidades no corregidas) | **Prohibido** | **Prohibido** | **Prohibido** salvo un entorno aislado aprobado formalmente |

---

## 3. Prohibiciones explícitas

Queda **prohibido** incluir en prompts, archivos de contexto, capturas de pantalla o adjuntos enviados a asistentes de IA externos:

1. **Llaves privadas y secretos:** `-----BEGIN PRIVATE KEY-----`, archivos `.pem`/`.key`/`.p12`, API keys, tokens (JWT, OAuth, PAT), contraseñas, cadenas de conexión, archivos `.env`, `kubeconfig`, `~/.aws/credentials`, `terraform.tfstate`.
2. **Datos reales de clientes o empleados:** nombres, documentos de identidad, correos, teléfonos, direcciones, números de cuenta o tarjeta, historiales, registros de BD, CSV de producción, tickets de soporte con datos personales.
3. **Código propietario crítico** sin aprobación (ver la matriz).
4. **Detalles sensibles de infraestructura:** IPs y hostnames internos, topología de red, reglas de firewall, configuraciones de producción completas.
5. **Información de vulnerabilidades no remediadas** de sistemas propios (reportes de pentest, PoCs contra activos internos) fuera de herramientas aprobadas para ese fin.
6. **Información de terceros bajo NDA** (código, documentación o datos de clientes y socios).

### 3.1 Patrón Vulnerable (Qué NO hacer)

```text
PROMPT (a un chatbot público):
"Mi app falla al conectar. Este es mi .env:
DATABASE_URL=postgresql://admin:Pr0d!2026@10.20.0.15:5432/clientes
STRIPE_SECRET=sk_live_51H...
Y este es un ejemplo de los datos que fallan:
{"nombre":"María López","dpi":"2456 78901 0101","tarjeta":"4111 1111 1111 1111"}"
```

### 3.2 Patrón Seguro (Qué SÍ hacer)

```text
PROMPT (en una herramienta empresarial aprobada):
"Uso psycopg 3 con PostgreSQL 16. La conexión falla con:
  psycopg.OperationalError: connection failed: SSL error: certificate verify failed
La cadena de conexión tiene la forma postgresql://<usuario>:<password>@<host>:5432/<db>?sslmode=verify-full
y uso sslrootcert apuntando a la CA interna. Un registro de ejemplo (datos sintéticos):
{"nombre":"Usuario Prueba","dpi":"0000 00000 0000","tarjeta":"4242 4242 4242 4242"}
¿Qué causas probables hay y cómo las verifico?"
```

**Técnicas de saneamiento antes de preguntar:**

- Reemplace los secretos por marcadores (`<API_KEY>`, `<PASSWORD>`) y los hosts por nombres genéricos (`db.example.internal`).
- Use **datos sintéticos** (Faker) o números de prueba documentados (tarjetas de prueba del proveedor de pagos).
- Reduzca el código a un **ejemplo mínimo reproducible**, sin lógica de negocio sensible.
- Elimine comentarios con nombres de clientes, tickets internos o URLs privadas.

### 3.3 Controles técnicos de apoyo

```gitignore
# Excluir archivos sensibles del contexto de asistentes en el IDE/CLI.
# Cada herramienta usa su propio archivo o configuración (p. ej., .cursorignore, .aiexclude,
# reglas de exclusión de contenido en Copilot Business/Enterprise, deny rules de permisos en Claude Code).
.env
.env.*
*.pem
*.key
*.p12
secrets/
**/fixtures/production/**
terraform.tfstate*
```

```json
// .claude/settings.json (ejemplo para Claude Code): denegar la lectura de archivos sensibles
// y exigir aprobación para comandos de red o destructivos.
{
  "permissions": {
    "deny": [
      "Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)", "Read(./**/*.pem)", "Read(./**/*.key)",
      "Bash(curl:*)", "Bash(wget:*)", "Bash(rm -rf:*)", "Bash(git push --force:*)"
    ]
  }
}
```

- **Pre-commit con Gitleaks** (ver la guía de Gestión de Secretos): detecta los secretos que un asistente haya copiado al código.
- **DLP en el endpoint o en el proxy corporativo**, configurado para detectar llaves, tokens y PII hacia dominios de IA.
- **Exclusión de contenido a nivel de organización** en las herramientas que lo soporten, para los repositorios críticos.

---

## 4. Obligación de auditar todo código sugerido por IA

### 4.1 Proceso obligatorio

1. **Comprender antes de aceptar:** no integre código que no pueda explicar línea por línea. Si no lo entiende, pida una explicación, consulte la documentación oficial o descártelo.
2. **Verificar las APIs y las dependencias:** confirme en la documentación oficial que las funciones, los parámetros y los paquetes **existen** y no están deprecados. Valide cada paquete nuevo en el registro oficial (nombre exacto, mantenedor, antigüedad, descargas, repositorio).
3. **Revisión de seguridad dirigida** con la checklist de la sección 4.3.
4. **Pruebas:** escriba o ajuste pruebas unitarias, incluidos los **casos negativos** (entrada maliciosa, usuario no autorizado, límites).
5. **Controles automáticos:** el PR pasa SAST (Semgrep/CodeQL/Bandit), SCA (OSV-Scanner/Trivy), Gitleaks y el linter con reglas de seguridad.
6. **Transparencia en el PR:** indique en la descripción del PR qué partes relevantes fueron generadas o asistidas por IA, para que el revisor ajuste su nivel de escrutinio.
7. **Revisión humana independiente:** al menos un revisor distinto del autor aprueba el PR. La revisión automatizada por IA **complementa, no sustituye**, la aprobación humana en código sensible.

### 4.2 Errores típicos del código generado por IA

**Patrón Vulnerable (Qué NO hacer) — sugerencias frecuentes que deben rechazarse**

```python
# 1) SQL por concatenación "para simplificar"
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

# 2) Desactivar la verificación TLS "para que funcione"
requests.get(url, verify=False)

# 3) Hash débil de contraseñas
hashlib.sha256(password.encode()).hexdigest()

# 4) Secreto de ejemplo que llega a producción
app.config["SECRET_KEY"] = "super-secret-key"

# 5) Deserialización insegura
data = pickle.loads(request.data)

# 6) Endpoint sin autorización por objeto
@app.get("/api/orders/{order_id}")
def get_order(order_id: int): return db.get(Order, order_id)

# 7) Shell con entrada externa
subprocess.run(f"convert {filename} out.png", shell=True)

# 8) CORS permisivo con credenciales
CORS(app, origins="*", supports_credentials=True)
```

```typescript
// 9) Dependencia inexistente o con un nombre parecido (alucinación / typosquatting)
import { sanitize } from "express-xss-sanitizer-pro";   // ¿existe? ¿quién la publica? ¿desde cuándo?

// 10) innerHTML con datos del usuario
element.innerHTML = userComment;
```

**Patrón Seguro (Qué SÍ hacer):** aplique los patrones de las guías 01–03 de este repositorio (consultas parametrizadas, verificación TLS activa, Argon2id, secretos desde una bóveda, formatos de solo datos, autorización por objeto, `subprocess` con lista de argumentos, CORS con allow-list y `textContent` o DOMPurify).

### 4.3 Checklist de revisión de código asistido por IA

| Área | Pregunta de revisión |
|---|---|
| Entrada | ¿Se valida toda la entrada externa con un esquema estricto? |
| Inyección | ¿Hay concatenación en SQL, shell, plantillas, `eval` o deserialización? |
| AuthN/AuthZ | ¿El endpoint exige autenticación y verifica la autorización por función y por objeto? |
| Secretos | ¿Hay credenciales, tokens o llaves de ejemplo en el código? |
| Criptografía | ¿Usa algoritmos y modos actuales (Argon2id, AES-GCM, CSPRNG)? ¿Verifica TLS? |
| Errores | ¿Falla cerrado? ¿Expone stack traces o detalles internos? |
| Dependencias | ¿Los paquetes nuevos existen, están mantenidos, tienen una licencia aceptable y están fijados en el lockfile? |
| Lógica de negocio | ¿Respeta las reglas del dominio (límites, estados, idempotencia) o solo "compila"? |
| Pruebas | ¿Las pruebas cubren casos negativos o solo confirman el camino feliz? Las pruebas generadas por IA tienden a validar el comportamiento actual, incluidos sus errores |
| Licencias | ¿El fragmento coincide con código público bajo una licencia incompatible? |

---

## 5. Agentes de código (IDE/CLI/CI) y servidores MCP

Los agentes que leen el repositorio, ejecutan comandos, modifican archivos y abren PRs amplían el riesgo: **cualquier texto que lean puede contener instrucciones inyectadas** (un README de una dependencia, un issue, un comentario de código, una página web o la salida de una herramienta).

**Reglas:**

1. **Mínimo privilegio:** el agente trabaja en un repositorio o *worktree* aislado, preferentemente en un contenedor o *devcontainer* sin credenciales de producción. Nunca con perfiles de nube administrativos activos ni con `kubectl` apuntando a producción.
2. **Aprobación humana** para los comandos con efectos: `git push`, despliegues, migraciones de BD, borrados, instalación de paquetes, peticiones de red salientes. No use modos de "aprobación automática total" en repositorios con acceso a secretos o a producción.
3. **Sin secretos en el entorno del agente:** variables de entorno limpias; credenciales de corta vida y alcance mínimo cuando sean imprescindibles.
4. **Servidores MCP y extensiones:** solo los aprobados e inventariados, con la versión fijada, el origen verificado y los scopes OAuth mínimos. Trate las descripciones de las herramientas MCP como contenido no confiable (*tool poisoning*).
5. **Agentes en CI (revisión automática de PRs, auto-fix):** se ejecutan con un `GITHUB_TOKEN` de permisos mínimos, **sin acceso a secretos en PRs de forks** y sin capacidad de hacer merge. El contenido del PR (título, descripción, diff y comentarios) es entrada no confiable.
6. **Revisión del diff completo** generado por el agente antes de commit/merge, incluidos los archivos que no se esperaba modificar (CI, Dockerfiles, lockfiles, configuración de seguridad, hooks).

```yaml
# Ejemplo: workflow de revisión con IA con permisos mínimos y sin secretos para forks
on:
  pull_request:            # NO pull_request_target con checkout del código del PR
permissions:
  contents: read
  pull-requests: write     # solo comentar
jobs:
  ai-review:
    if: github.event.pull_request.head.repo.full_name == github.repository   # excluye forks
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      # ... paso de revisión con IA: solo comentarios; nunca push, merge ni despliegue
```

---

## 6. Propiedad intelectual, licencias y trazabilidad

- Active los **filtros de coincidencia con código público** cuando la herramienta los ofrezca. Ante un fragmento extenso y muy específico, verifique su origen y su licencia.
- No use asistentes para reproducir código de proyectos con licencias incompatibles ni de competidores.
- Registre en el PR el uso relevante de IA (sección 4.1, paso 6) para facilitar las auditorías de licencias y de calidad.
- La documentación, los diagramas y los textos generados se revisan con el mismo rigor: las referencias, versiones y comandos inventados son errores comunes.

---

## 7. Respuesta ante una exposición accidental

Si se envió información restringida a un asistente externo:

1. **Notifique de inmediato** al equipo de Seguridad (canal de incidentes), indicando la herramienta, la fecha y la hora y el tipo de dato.
2. **Secretos:** **revoque y rote** el secreto expuesto de inmediato (ver la guía de Gestión de Secretos). Considérelo comprometido.
3. **Datos personales:** Seguridad y el área de Privacidad/Legal evalúan las obligaciones de notificación según la regulación y los contratos aplicables.
4. **Elimine la conversación** en la herramienta y solicite el borrado al proveedor según el contrato, documentando la evidencia.
5. **Causa raíz:** ajuste los controles (exclusiones de contexto, DLP, formación).

---

## 8. Checklist de Verificación (antes de merge / deploy)

- [ ] Solo se usaron asistentes de IA aprobados por la organización, con contrato empresarial y sin entrenamiento con nuestros datos.
- [ ] No se enviaron secretos, llaves privadas, tokens, `.env`, volcados de BD ni datos reales de clientes o empleados a ningún asistente externo.
- [ ] El código propietario crítico solo se compartió con una aprobación documentada o con herramientas locales aprobadas.
- [ ] El autor puede explicar todo el código sugerido por IA que integró en este cambio.
- [ ] Se verificó en la documentación oficial que las APIs y funciones usadas existen y no están deprecadas.
- [ ] Toda dependencia nueva propuesta por IA fue verificada en el registro oficial (existencia, mantenedor, antigüedad, Scorecard, licencia) y fijada en el lockfile.
- [ ] Se aplicó la checklist de revisión de seguridad (sección 4.3): entrada, inyección, authz, secretos, criptografía, errores y lógica de negocio.
- [ ] Existen pruebas con casos negativos para el código generado.
- [ ] SAST, SCA, Gitleaks y el linter de seguridad pasan sin hallazgos altos ni críticos.
- [ ] La descripción del PR indica las partes relevantes asistidas por IA, y al menos un revisor humano independiente aprobó.
- [ ] Si se usó un agente de código: se revisó el diff completo (incluidos CI, Dockerfiles, lockfiles y hooks), y el agente no tuvo acceso a credenciales de producción.
- [ ] Los servidores MCP y las extensiones usados están en el inventario aprobado.

---

## 9. Referencias

- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- NIST SP 800-218A — Secure Software Development Practices for Generative AI and Dual-Use Foundation Models: https://csrc.nist.gov/pubs/sp/800/218/a/final
- NIST AI 600-1 — Generative AI Profile: https://www.nist.gov/itl/ai-risk-management-framework
- OpenSSF — Security-Focused Guide for AI Code Assistant Instructions: https://best.openssf.org/
- Documentación de privacidad y administración de cada herramienta (GitHub Copilot Business/Enterprise, OpenAI Enterprise/API, Anthropic Claude for Work/API, Google Gemini Code Assist)
