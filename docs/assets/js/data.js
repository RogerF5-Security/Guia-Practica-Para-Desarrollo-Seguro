/**
 * data.js — Contenido estructurado de la Guía Práctica de Desarrollo Seguro.
 * Todo se ejecuta en el navegador: ningún dato introducido por el usuario sale del equipo.
 */

export const REPO = "https://github.com/RogerF5-Security/Gu-a-Practica-Para-Desarrollo-Seguro";
export const GUIDE_BASE = `${REPO}/blob/main/Desarrollo_Seguro`;
export const RAW_BASE = `${REPO}/raw/main/Desarrollo_Seguro`;

/** Guías completas del repositorio (ruta relativa sin extensión). */
export const GUIDES = {
  "00": { title: "Guía Rápida de Desarrollo Seguro", path: "00_Guia_Rapida_Desarrollo_Seguro" },
  "01.01": { title: "Inyecciones: SQLi, Command Injection y RCE", path: "01_Codigo_y_Prevencion_de_Vulnerabilidades/01_Inyecciones_SQLi_Command_RCE" },
  "01.02": { title: "XSS, CSRF y Seguridad Frontend", path: "01_Codigo_y_Prevencion_de_Vulnerabilidades/02_XSS_CSRF_y_Seguridad_Frontend" },
  "01.03": { title: "Control de Acceso y Escalada de Privilegios", path: "01_Codigo_y_Prevencion_de_Vulnerabilidades/03_Control_de_Acceso_y_Escalada_Privilegios" },
  "02.01": { title: "Gestión de Secretos y API Keys", path: "02_Criptografia_Secretos_y_Proteccion_Codigo/01_Gestion_de_Secretos_y_API_Keys" },
  "02.02": { title: "Cifrado en Almacenamiento, Hashing y PII", path: "02_Criptografia_Secretos_y_Proteccion_Codigo/02_Cifrado_Almacenamiento_y_Hashing" },
  "02.03": { title: "Ofuscación y Endurecimiento del Cliente", path: "02_Criptografia_Secretos_y_Proteccion_Codigo/03_Ofuscacion_y_Endurecimiento_Cliente" },
  "03.01": { title: "TLS/SSL y Cifrado en Tránsito", path: "03_Infraestructura_Transporte_y_Dependencias/01_TLS_SSL_y_Cifrado_en_Transito" },
  "03.02": { title: "Gestión de Dependencias y Versiones", path: "03_Infraestructura_Transporte_y_Dependencias/02_Gestion_de_Dependencias_y_Versiones" },
  "03.03": { title: "Hardening de APIs y Servidores", path: "03_Infraestructura_Transporte_y_Dependencias/03_Hardening_APIs_y_Servidores" },
  "04.01": { title: "Prompt Engineering Seguro y Prompt Injection", path: "04_Desarrollo_Seguro_con_IA_y_LLMs/01_Prompt_Engineering_Seguro_y_Prevencion_Injection" },
  "04.02": { title: "Uso Seguro de IA por Desarrolladores", path: "04_Desarrollo_Seguro_con_IA_y_LLMs/02_Uso_Seguro_de_IA_por_Desarrolladores" },
};

/* ------------------------------------------------------------------ Checklist */

/** ¿Qué vas a construir hoy? Cada perfil agrega ítems al checklist. */
export const PROFILES = [
  { id: "api", label: "Endpoint / API" },
  { id: "db", label: "Consultas a base de datos" },
  { id: "front", label: "Frontend / vistas" },
  { id: "auth", label: "Login, sesiones o JWT" },
  { id: "roles", label: "Roles, permisos o multi-tenant" },
  { id: "files", label: "Archivos, uploads o comandos" },
  { id: "terceros", label: "APIs de terceros, pagos o webhooks" },
  { id: "pii", label: "Datos personales o sensibles" },
  { id: "infra", label: "Docker, CI/CD o servidor" },
  { id: "deps", label: "Agregar o actualizar librerías" },
  { id: "movil", label: "App móvil o de escritorio" },
  { id: "llm", label: "Integrar un LLM / chatbot / agente" },
  { id: "iadev", label: "Programar con asistentes de IA" },
];

/**
 * Ítems del checklist.
 * level: "B" = Bloqueante (no pasa a producción), "R" = Requerido (excepción formal si no se cumple).
 * tags: perfiles que lo activan; "base" = siempre presente.
 */
export const CHECK_ITEMS = [
  // Base: aplica a todo cambio
  { id: "b1", cat: "Código", level: "B", tags: ["base"], guide: "01.01", text: "Toda entrada externa se valida en el backend con un esquema estricto (tipo, longitud, rango, formato; campos extra rechazados).", why: "La validación del frontend se omite enviando la petición con curl o Burp. Sin validación en el servidor aparecen inyecciones, mass assignment y errores 500 explotables." },
  { id: "b2", cat: "Código", level: "B", tags: ["base"], guide: "01.01", text: "No hay SQL, comandos, plantillas ni HTML construidos concatenando datos del usuario; no hay eval/exec.", why: "Concatenar permite que los metacaracteres del atacante cambien la instrucción: SQLi, RCE, SSTI y XSS." },
  { id: "b3", cat: "Secretos", level: "B", tags: ["base"], guide: "02.01", text: "No hay secretos (contraseñas, API keys, tokens, llaves) en el código, los tests, la configuración ni el Dockerfile; gitleaks pasa.", why: "Lo que entra en Git queda en el historial, en cada clon y en cada imagen. Los bots encuentran claves publicadas en minutos." },
  { id: "b4", cat: "Configuración", level: "B", tags: ["base"], guide: "03.03", text: "Los errores devuelven mensajes genéricos con error_id; debug apagado; sin stack traces al cliente.", why: "Los stack traces revelan rutas, versiones, SQL y a veces secretos. El modo debug de algunos frameworks permite ejecutar código." },
  { id: "b5", cat: "Pruebas", level: "R", tags: ["base"], guide: "01.03", text: "Hay pruebas de casos negativos: otro usuario, datos inválidos, sin sesión, rol inferior.", why: "Las pruebas del camino feliz no detectan IDOR, escaladas ni validaciones ausentes." },
  { id: "b6", cat: "Pipeline", level: "R", tags: ["base"], guide: "03.02", text: "SAST (Semgrep/CodeQL/Bandit), SCA y escaneo de secretos pasan sin hallazgos altos o críticos.", why: "Detectan automáticamente gran parte de lo que un auditor encontrará después." },

  // API
  { id: "a1", cat: "Acceso", level: "B", tags: ["api", "roles"], guide: "01.03", text: "Cada endpoint exige autenticación (salvo allow-list pública revisada) y declara el permiso requerido.", why: "Un solo endpoint olvidado expone funciones o datos. 'Missing Authorization' (CWE-862) está en el Top 4 del CWE Top 25 de 2025." },
  { id: "a2", cat: "Acceso", level: "B", tags: ["api", "roles", "db"], guide: "01.03", text: "Todo acceso por ID verifica en la consulta que el objeto pertenece al usuario o tenant; responde 404 si no.", why: "Cambiar /facturas/1002 por /1003 es el IDOR/BOLA más común en auditorías de APIs." },
  { id: "a3", cat: "Acceso", level: "B", tags: ["api", "roles"], guide: "01.03", text: "El user_id, rol y tenant salen de la sesión o token verificados, nunca del body, query ni headers del cliente.", why: "Si el cliente envía su rol o su ID, el atacante simplemente envía otro." },
  { id: "a4", cat: "API", level: "B", tags: ["api"], guide: "03.03", text: "Esquemas de salida con allow-list de campos (sin password_hash, tokens ni flags internos).", why: "Devolver el objeto completo del ORM filtra datos sensibles (OWASP API3: BOPLA)." },
  { id: "a5", cat: "API", level: "B", tags: ["api", "auth"], guide: "03.03", text: "Rate limiting en login, recuperación de cuenta, OTP y operaciones costosas.", why: "Sin límites: fuerza bruta, credential stuffing, scraping y costos desbocados." },
  { id: "a6", cat: "API", level: "R", tags: ["api"], guide: "03.03", text: "Paginación con tope, tamaño máximo de body y timeouts en llamadas salientes.", why: "Evita denegación de servicio por consumo de recursos (OWASP API4)." },
  { id: "a7", cat: "API", level: "R", tags: ["api"], guide: "03.03", text: "CORS con allow-list exacta de orígenes; nunca '*' con credenciales.", why: "Un CORS permisivo permite a sitios ajenos leer respuestas autenticadas." },
  { id: "a8", cat: "API", level: "R", tags: ["api"], guide: "03.03", text: "La API está en el inventario OpenAPI; Swagger/docs no expuestos públicamente en producción.", why: "Las APIs 'shadow' o 'zombie' sin dueño son blanco frecuente (OWASP API9)." },

  // DB
  { id: "d1", cat: "Base de datos", level: "B", tags: ["db"], guide: "01.01", text: "Consultas parametrizadas u ORM; las funciones raw/Unsafe están justificadas y revisadas.", why: "La parametrización envía los datos por un canal separado: el motor no puede confundirlos con código." },
  { id: "d2", cat: "Base de datos", level: "B", tags: ["db"], guide: "01.01", text: "Columnas y orden dinámicos (ORDER BY, nombre de tabla) solo desde una allow-list.", why: "Los identificadores no se pueden parametrizar; sin allow-list vuelven a ser inyectables." },
  { id: "d3", cat: "Base de datos", level: "R", tags: ["db", "roles"], guide: "01.03", text: "El usuario de BD de la aplicación no tiene DDL ni superusuario; RLS o filtro de tenant obligatorio en tablas multi-tenant.", why: "Limita el radio de impacto si un control falla." },

  // Frontend
  { id: "f1", cat: "Frontend", level: "B", tags: ["front"], guide: "01.02", text: "Autoescape activo; sin innerHTML, |safe, dangerouslySetInnerHTML o v-html con datos sin sanitizar (DOMPurify/nh3).", why: "XSS (CWE-79) es la debilidad n.º 1 del CWE Top 25 2025: permite robar sesiones y actuar como la víctima." },
  { id: "f2", cat: "Frontend", level: "R", tags: ["front"], guide: "01.02", text: "CSP estricta (nonce/hash + strict-dynamic, object-src 'none', base-uri 'none', frame-ancestors) activa o en Report-Only con fecha de enforcement.", why: "Si se escapa un XSS, la CSP impide que el script inyectado se ejecute." },
  { id: "f3", cat: "Frontend", level: "R", tags: ["front", "infra"], guide: "03.03", text: "Cabeceras de seguridad presentes: HSTS, nosniff, frame-ancestors/X-Frame-Options, Referrer-Policy, Permissions-Policy; sin banners de versión.", why: "Son hallazgos casi seguros en cualquier auditoría y se corrigen con pocas líneas." },
  { id: "f4", cat: "Frontend", level: "B", tags: ["front"], guide: "02.03", text: "No hay source maps públicos, secretos ni URLs internas en el bundle; JS minificado sin console de datos.", why: "Los .map reconstruyen el código fuente; el bundle se lee completo desde DevTools." },
  { id: "f5", cat: "Frontend", level: "B", tags: ["front"], guide: "02.03", text: "Precios, descuentos, permisos y reglas de negocio se calculan y validan en el servidor.", why: "Todo lo que corre en el cliente se puede modificar." },
  { id: "f6", cat: "Frontend", level: "R", tags: ["front"], guide: "01.02", text: "href/src con datos externos validan esquema https: (bloquean javascript:); postMessage valida event.origin.", why: "Vectores de XSS frecuentes incluso en frameworks que escapan por defecto." },

  // Auth
  { id: "s1", cat: "Sesiones", level: "B", tags: ["auth"], guide: "01.02", text: "Cookies de sesión: __Host- + HttpOnly + Secure + SameSite (Strict o Lax), sin Domain.", why: "HttpOnly impide robarla con XSS, Secure evita HTTP en claro y SameSite mitiga CSRF." },
  { id: "s2", cat: "Sesiones", level: "B", tags: ["auth"], guide: "01.02", text: "Token anti-CSRF en POST/PUT/PATCH/DELETE con cookie de sesión; nunca cambiar estado con GET.", why: "Sin token, otro sitio puede hacer que el navegador de la víctima ejecute acciones." },
  { id: "s3", cat: "Sesiones", level: "B", tags: ["auth"], guide: "02.02", text: "Contraseñas con Argon2id (o bcrypt cost ≥ 12); nunca MD5/SHA directos ni cifrado reversible.", why: "Los hashes rápidos se rompen a miles de millones de intentos por segundo en GPU." },
  { id: "s4", cat: "Sesiones", level: "B", tags: ["auth"], guide: "01.03", text: "JWT: algoritmo fijo, firma, exp, aud e iss validados; nunca alg:none ni tokens en localStorage.", why: "Los JWT mal validados permiten falsificar identidades; localStorage es legible por cualquier XSS." },
  { id: "s5", cat: "Sesiones", level: "R", tags: ["auth"], guide: "01.02", text: "ID de sesión regenerado al hacer login/elevar privilegios e invalidado en el servidor al hacer logout.", why: "Previene session fixation y sesiones vivas tras cerrar sesión." },
  { id: "s6", cat: "Sesiones", level: "R", tags: ["auth"], guide: "03.03", text: "Mensajes genéricos ('Credenciales inválidas'); recuperación de cuenta sin revelar si el usuario existe.", why: "Evita la enumeración de usuarios." },

  // Roles
  { id: "r1", cat: "Acceso", level: "B", tags: ["roles"], guide: "01.03", text: "Las funciones de administración verifican el permiso en el backend; la UI no es un control.", why: "Ocultar un botón no impide llamar al endpoint directamente (escalada vertical)." },
  { id: "r2", cat: "Acceso", level: "B", tags: ["roles", "api"], guide: "01.03", text: "Sin mass assignment: no se vuelca req.body al ORM; role, tenant_id e is_admin no son editables por el usuario.", why: "Enviar \"role\":\"admin\" en el JSON es una escalada clásica." },
  { id: "r3", cat: "Acceso", level: "R", tags: ["roles"], guide: "03.03", text: "Los controles de seguridad fallan cerrado ante excepciones o timeouts (si authz falla, se deniega).", why: "OWASP A10:2025 Mishandling of Exceptional Conditions." },

  // Files
  { id: "u1", cat: "Archivos", level: "B", tags: ["files"], guide: "01.01", text: "Sin os.system, shell=True ni child_process.exec; comandos con lista de argumentos, ruta absoluta, '--' y timeout.", why: "El shell interpreta ; | $() y convierte un nombre de archivo en ejecución remota." },
  { id: "u2", cat: "Archivos", level: "B", tags: ["files"], guide: "01.01", text: "Rutas canonicalizadas y validadas contra un directorio base; nombres de archivo generados por el servidor.", why: "Previene path traversal (../../etc/passwd)." },
  { id: "u3", cat: "Archivos", level: "B", tags: ["files"], guide: "03.03", text: "Uploads: tamaño máximo, tipo real por magic bytes, fuera del webroot y escaneo antimalware.", why: "Un upload sin control termina en webshell, XSS almacenado o DoS." },
  { id: "u4", cat: "Archivos", level: "B", tags: ["files"], guide: "01.01", text: "No se deserializa con pickle, yaml.load inseguro, ObjectInputStream ni node-serialize; XML con DTD deshabilitado (defusedxml).", why: "Deserializar datos no confiables equivale a ejecutar código no confiable." },

  // Terceros
  { id: "t1", cat: "Integraciones", level: "B", tags: ["terceros"], guide: "02.01", text: "Las API keys de terceros viven en una bóveda/variables de entorno del servidor; el frontend llama al backend (BFF).", why: "Una llave en el cliente es pública por definición." },
  { id: "t2", cat: "Integraciones", level: "B", tags: ["terceros"], guide: "02.02", text: "Webhooks verificados con firma HMAC y comparación en tiempo constante.", why: "Sin firma, cualquiera puede invocar el webhook con datos falsos." },
  { id: "t3", cat: "Integraciones", level: "B", tags: ["terceros", "api"], guide: "01.03", text: "Peticiones a URLs suministradas por el usuario: allow-list de destinos y bloqueo de IPs internas/metadatos (SSRF).", why: "SSRF permite alcanzar 169.254.169.254 y servicios internos; ahora forma parte de A01:2025." },
  { id: "t4", cat: "Integraciones", level: "B", tags: ["terceros", "infra"], guide: "03.01", text: "TLS verificado en todas las conexiones salientes (sin verify=False ni rejectUnauthorized:false).", why: "Desactivar la verificación permite MITM transparente." },

  // PII
  { id: "p1", cat: "Datos", level: "B", tags: ["pii"], guide: "02.02", text: "Datos restringidos cifrados con AES-256-GCM a nivel de aplicación y llaves en KMS/HSM/Vault.", why: "Un volcado de BD o backup filtrado no debe exponer PII en claro." },
  { id: "p2", cat: "Datos", level: "B", tags: ["pii"], guide: "02.02", text: "Logs y trazas sin contraseñas, tokens, tarjetas ni PII completa (redacción automática).", why: "Los logs se replican a muchos sistemas y personas con menos controles." },
  { id: "p3", cat: "Datos", level: "B", tags: ["pii", "iadev"], guide: "02.02", text: "Sin datos reales de clientes en desarrollo, QA ni prompts de IA: datos sintéticos o enmascarados.", why: "Los entornos no productivos y las herramientas externas son la vía de fuga más común." },
  { id: "p4", cat: "Datos", level: "R", tags: ["pii"], guide: "02.02", text: "Clasificación del dato, retención definida y mecanismo de borrado.", why: "Minimizar es el control más barato: lo que no se guarda no se filtra." },

  // Infra
  { id: "i1", cat: "Infraestructura", level: "B", tags: ["infra"], guide: "03.01", text: "Solo TLS 1.2/1.3 con ciphers ECDHE+AEAD; HTTP redirige a HTTPS; HSTS ≥ 1 año.", why: "Protocolos antiguos permiten downgrade e interceptación." },
  { id: "i2", cat: "Infraestructura", level: "B", tags: ["infra"], guide: "02.01", text: "CI/CD sin llaves de larga vida (OIDC); secretos con --mount=type=secret, nunca ARG/ENV en el Dockerfile.", why: "ARG/ENV quedan en las capas de la imagen y en docker history." },
  { id: "i3", cat: "Infraestructura", level: "R", tags: ["infra"], guide: "03.03", text: "Contenedor no root, FS de solo lectura, cap_drop ALL, no-new-privileges y límites de CPU/memoria.", why: "Reduce el impacto de un RCE." },
  { id: "i4", cat: "Infraestructura", level: "B", tags: ["infra"], guide: "03.03", text: "Endpoints de admin, métricas, actuator y debug no expuestos públicamente.", why: "Son puertas traseras frecuentes en auditorías externas." },
  { id: "i5", cat: "Infraestructura", level: "R", tags: ["infra"], guide: "03.01", text: "Renovación automática de certificados probada y alerta a ≤ 21 días de la expiración.", why: "Las vigencias públicas bajan a 200 días (2026), 100 (2027) y 47 (2029)." },

  // Deps
  { id: "e1", cat: "Dependencias", level: "B", tags: ["deps", "infra"], guide: "03.02", text: "Lockfile versionado e instalación determinista (npm ci, uv sync --frozen, pip --require-hashes).", why: "Las versiones flotantes meten código no revisado en cada build." },
  { id: "e2", cat: "Dependencias", level: "B", tags: ["deps"], guide: "03.02", text: "Sin vulnerabilidades críticas/altas con fix disponible (npm audit, pip-audit, osv-scanner, trivy), o excepción documentada.", why: "Los componentes con CVE conocidos son de los hallazgos más comunes y fáciles de explotar." },
  { id: "e3", cat: "Dependencias", level: "B", tags: ["deps", "infra"], guide: "03.02", text: "Runtime, frameworks e imagen base con soporte de seguridad (no EOL); imágenes fijadas por digest, nunca :latest.", why: "Una versión EOL ya no recibe parches." },
  { id: "e4", cat: "Dependencias", level: "R", tags: ["deps", "iadev"], guide: "03.02", text: "Cada librería nueva fue verificada: existe en el registro oficial, está mantenida y tiene licencia permitida.", why: "Typosquatting y 'slopsquatting' (nombres inventados por IA registrados por atacantes)." },
  { id: "e5", cat: "Dependencias", level: "R", tags: ["deps", "infra"], guide: "03.02", text: "Dependabot/Renovate activo (incluye Docker y GitHub Actions fijadas por SHA).", why: "Actualizar a tiempo cuesta menos que remediar después de la auditoría." },

  // Móvil
  { id: "m1", cat: "Cliente", level: "B", tags: ["movil"], guide: "02.03", text: "Sin secretos ni lógica de autorización en el APK/IPA/binario; tokens en Keystore/Keychain.", why: "Los binarios se descompilan con jadx, apktool o Ghidra." },
  { id: "m2", cat: "Cliente", level: "R", tags: ["movil"], guide: "02.03", text: "Release con R8/minify o stripping, debuggable=false, allowBackup=false y sin tráfico en claro.", why: "Configuraciones de debug en release facilitan el análisis y la extracción de datos." },
  { id: "m3", cat: "Cliente", level: "R", tags: ["movil"], guide: "02.03", text: "Atestación de integridad (Play Integrity / App Attest) verificada en el backend para operaciones sensibles.", why: "La detección en el cliente se evade; la verificación en servidor no." },

  // LLM
  { id: "l1", cat: "IA / LLM", level: "B", tags: ["llm"], guide: "04.01", text: "System prompt sin secretos; la autorización de herramientas la decide el backend con la identidad del usuario.", why: "El prompt no es una frontera de seguridad; asume que se filtrará (LLM07)." },
  { id: "l2", cat: "IA / LLM", level: "B", tags: ["llm"], guide: "04.01", text: "La salida del modelo se valida con esquema y nunca se ejecuta (eval/SQL/shell) ni se renderiza como HTML sin sanitizar.", why: "La salida del LLM es entrada no confiable (LLM05)." },
  { id: "l3", cat: "IA / LLM", level: "B", tags: ["llm"], guide: "04.01", text: "Acciones con efectos (enviar, pagar, borrar) requieren confirmación humana; sin combinación datos privados + contenido externo + salida a internet.", why: "Prompt injection indirecto + agencia excesiva = exfiltración (LLM01/LLM06)." },
  { id: "l4", cat: "IA / LLM", level: "R", tags: ["llm"], guide: "04.01", text: "Límites de tokens, pasos del agente y costo por usuario/tenant; suite de red teaming sin regresiones.", why: "Consumo sin límites (LLM10) y regresiones de seguridad al cambiar prompt o modelo." },

  // IA dev
  { id: "g1", cat: "IA en desarrollo", level: "B", tags: ["iadev"], guide: "04.02", text: "Solo asistentes aprobados por la empresa; no se pegaron secretos, .env, llaves ni código crítico.", why: "Lo que se envía a un servicio externo sale del control de la organización." },
  { id: "g2", cat: "IA en desarrollo", level: "B", tags: ["iadev"], guide: "04.02", text: "Todo código sugerido por IA fue entendido, revisado con checklist de seguridad y probado con casos negativos.", why: "Los asistentes generan con fluidez código vulnerable o con APIs inexistentes." },
];

/* ------------------------------------------------------------------ Headers */

/** Definición de cabeceras para el generador y el analizador. */
export const HEADER_INFO = {
  "strict-transport-security": { name: "Strict-Transport-Security", purpose: "Obliga al navegador a usar siempre HTTPS; impide forzar HTTP en la red.", guide: "03.01" },
  "content-security-policy": { name: "Content-Security-Policy", purpose: "Define qué scripts, estilos e iframes puede cargar la página; barrera principal contra XSS.", guide: "01.02" },
  "x-content-type-options": { name: "X-Content-Type-Options", purpose: "Impide que el navegador 'adivine' el tipo de archivo y ejecute un upload como script.", guide: "03.03" },
  "x-frame-options": { name: "X-Frame-Options", purpose: "Impide que tu página se cargue en un iframe ajeno (clickjacking). Fallback de frame-ancestors.", guide: "03.03" },
  "referrer-policy": { name: "Referrer-Policy", purpose: "Evita filtrar la URL completa (tokens, IDs) a otros sitios.", guide: "03.03" },
  "permissions-policy": { name: "Permissions-Policy", purpose: "Desactiva APIs del navegador que no usas (cámara, micrófono, geolocalización).", guide: "03.03" },
  "cross-origin-opener-policy": { name: "Cross-Origin-Opener-Policy", purpose: "Aísla tu ventana de las abiertas por otros sitios (XS-Leaks).", guide: "03.03" },
  "cross-origin-resource-policy": { name: "Cross-Origin-Resource-Policy", purpose: "Impide que otros orígenes incrusten o lean tus recursos.", guide: "03.03" },
  "cache-control": { name: "Cache-Control", purpose: "Evita que datos privados queden en caché del navegador o proxies.", guide: "03.03" },
};

/* ------------------------------------------------------------------ Escáner de código */

/**
 * Reglas del escáner local. Se evalúan línea por línea.
 * sev: "crit" | "alta" | "media" | "info"; secret: true => se enmascara el valor en el reporte.
 */
export const SCAN_RULES = [
  // Secretos
  { id: "sec-aws", sev: "crit", secret: true, cat: "Secreto", title: "AWS Access Key ID", re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/, fix: "Revoca la llave en IAM, rótala y usa roles/OIDC en lugar de llaves estáticas.", guide: "02.01" },
  { id: "sec-pk", sev: "crit", secret: true, cat: "Secreto", title: "Llave privada embebida", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/, fix: "Elimina la llave del código, considérala comprometida, rótala y guárdala en una bóveda.", guide: "02.01" },
  { id: "sec-stripe", sev: "crit", secret: true, cat: "Secreto", title: "Stripe live key", re: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/, fix: "Revoca la llave en el dashboard de Stripe y léela desde variables de entorno o bóveda.", guide: "02.01" },
  { id: "sec-gh", sev: "crit", secret: true, cat: "Secreto", title: "Token de GitHub", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b/, fix: "Revoca el token en GitHub y usa GITHUB_TOKEN/OIDC o un secret del repositorio.", guide: "02.01" },
  { id: "sec-slack", sev: "crit", secret: true, cat: "Secreto", title: "Token de Slack", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/, fix: "Revoca el token y guárdalo en una bóveda.", guide: "02.01" },
  { id: "sec-gapi", sev: "alta", secret: true, cat: "Secreto", title: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/, fix: "Restringe o rota la llave y muévela al servidor.", guide: "02.01" },
  { id: "sec-ai", sev: "crit", secret: true, cat: "Secreto", title: "API key de proveedor de IA", re: /\bsk-(?:proj-|ant-[a-z0-9]{2,6}-)?[A-Za-z0-9_-]{24,}\b/, fix: "Revoca la llave en la consola del proveedor; nunca la incluyas en código ni en el frontend.", guide: "02.01" },
  { id: "sec-jwt", sev: "alta", secret: true, cat: "Secreto", title: "JWT embebido", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, fix: "No incluyas tokens reales en código o tests; usa tokens generados en el test con una llave de prueba.", guide: "02.01" },
  { id: "sec-conn", sev: "crit", secret: true, cat: "Secreto", title: "Cadena de conexión con contraseña", re: /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@'"]+:[^\s@/'"$<{]{3,}@[^\s'"]+/i, fix: "Lee la cadena de conexión desde el entorno o una bóveda; rota la contraseña expuesta.", guide: "02.01" },
  { id: "sec-generic", sev: "alta", secret: true, cat: "Secreto", title: "Credencial hardcodeada", re: /\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b["']?\s*[:=]\s*["'](?![<{$%]|\s*["'])[^"'\s]{6,}["']/i, fix: "Usa variables de entorno o una bóveda (Vault, AWS Secrets Manager, Azure Key Vault). La app debe fallar al arrancar si falta.", guide: "02.01" },
  { id: "sec-default", sev: "alta", cat: "Secreto", title: "Valor por defecto inseguro para un secreto", re: /getenv\(\s*["'][A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD)[A-Z_]*["']\s*,\s*["'][^"']+["']\s*\)|process\.env\.[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD)[A-Z_]*\s*(?:\|\||\?\?)\s*["']/, fix: "Sin valores por defecto: si falta el secreto, la aplicación no debe arrancar (pydantic-settings / zod).", guide: "02.01" },
  { id: "sec-pubenv", sev: "alta", cat: "Secreto", title: "Secreto en variable pública del frontend", re: /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC)_[A-Z0-9_]*(?:SECRET|PASSWORD|PRIVATE|TOKEN)[A-Z0-9_]*/, fix: "Las variables con prefijo público se incrustan en el bundle. Mueve el secreto al backend.", guide: "02.03" },

  // Inyección / RCE
  { id: "inj-sql-f", sev: "crit", cat: "Inyección", title: "SQL construido con f-string / template / concatenación", re: /(?:\b(?:execute|executemany|query|raw|text|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*(?:f["']|`[^`]*\$\{)|["'`]\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'`]*["'`]\s*\+|\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^"'`\n]*["'`]\s*%\s*[(\w]|\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'\n]*["']\s*\.format\()/i, fix: "Usa consultas parametrizadas: cursor.execute(\"... WHERE id = %s\", (id,)) / pool.query(\"... $1\", [id]).", guide: "01.01" },
  { id: "rce-eval", sev: "crit", cat: "Inyección", title: "eval / exec / new Function", re: /(?:^|[^\w.])(?:eval|exec)\s*\(|\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*["'`]/, fix: "Elimina la evaluación dinámica: usa ast.literal_eval, JSON.parse o un diccionario de funciones permitidas.", guide: "01.01" },
  { id: "rce-shell", sev: "crit", cat: "Inyección", title: "Ejecución de comandos con shell", re: /\bos\.(?:system|popen)\s*\(|\bshell\s*=\s*True\b|\bshell\s*:\s*true\b|\bchild_process\b.*\bexec(?:Sync)?\b|(?:^|[^\w.])execSync\s*\(|\bRuntime\.getRuntime\(\)\.exec\s*\(/, fix: "subprocess.run([\"/usr/bin/cmd\", \"--\", arg], timeout=...) / execFile(...) sin shell, con validación estricta del argumento.", guide: "01.01" },
  { id: "rce-deser", sev: "crit", cat: "Inyección", title: "Deserialización insegura", re: /\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\(|\bjoblib\.load\s*\(|\byaml\.load\s*\((?![^)]*SafeLoader)|\bunserialize\s*\(|\bObjectInputStream\b|\bBinaryFormatter\b|\btorch\.load\s*\((?![^)]*weights_only\s*=\s*True)/, fix: "Usa formatos de solo datos (JSON + esquema), yaml.safe_load, safetensors o torch.load(weights_only=True).", guide: "01.01" },
  { id: "inj-ssti", sev: "crit", cat: "Inyección", title: "Plantilla construida con datos (SSTI)", re: /\brender_template_string\s*\(\s*f["']|\bTemplate\s*\(\s*f["']|\bfrom_string\s*\(\s*f["']/, fix: "Pasa los datos como variables de contexto: render_template_string(\"Hola {{ name }}\", name=name).", guide: "01.01" },
  { id: "inj-xxe", sev: "media", cat: "Inyección", title: "Parser XML potencialmente vulnerable a XXE", re: /\bxml\.etree\.ElementTree\b|\bxml\.dom\.minidom\b|\blxml\.etree\.(?:parse|fromstring)\s*\(|\bDocumentBuilderFactory\.newInstance\s*\(/, fix: "Usa defusedxml en Python y deshabilita DTD/entidades externas en Java.", guide: "01.01" },

  // XSS
  { id: "xss-sink", sev: "alta", cat: "XSS", title: "Sink de DOM peligroso", re: /\.(?:innerHTML|outerHTML)\s*\+?=(?!=)|\binsertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(/, fix: "Usa textContent para texto; si necesitas HTML, sanitiza con DOMPurify o element.setHTML().", guide: "01.02" },
  { id: "xss-fw", sev: "alta", cat: "XSS", title: "Desactivación del escape del framework", re: /\bdangerouslySetInnerHTML\b|\bv-html\b|\|\s*safe\b|\bmark_safe\s*\(|\bMarkup\s*\(|\bbypassSecurityTrust\w*\s*\(|\{@html\b|\.html\s*\(\s*[^)]/, fix: "Confirma que el contenido está sanitizado (DOMPurify / nh3) justo antes de renderizarlo.", guide: "01.02" },
  { id: "xss-jsurl", sev: "media", cat: "XSS", title: "URL javascript:", re: /["'`]\s*javascript:/i, fix: "Valida el esquema de URLs dinámicas (solo https: / mailto:).", guide: "01.02" },
  { id: "xss-pm", sev: "media", cat: "XSS", title: "postMessage con destino '*'", re: /\.postMessage\s*\([^)]*,\s*["']\*["']/, fix: "Especifica el origen destino exacto y valida event.origin en el receptor.", guide: "01.02" },

  // TLS / crypto
  { id: "tls-off", sev: "crit", cat: "TLS", title: "Verificación TLS desactivada", re: /\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=?\s*["']?0|\bCERT_NONE\b|_create_unverified_context|InsecureSkipVerify\s*:\s*true|check_hostname\s*=\s*False/, fix: "Mantén la verificación activa; si es una CA interna, configura su certificado (cafile / ca).", guide: "03.01" },
  { id: "tls-old", sev: "alta", cat: "TLS", title: "Protocolo TLS/SSL obsoleto", re: /\b(?:SSLv2|SSLv3|TLSv1(?:\.1)?|PROTOCOL_TLSv1(?:_1)?)\b(?!\.[23])|ssl_protocols[^;]*\bTLSv1(?:\.1)?\b(?!\.[23])/, fix: "Permite solo TLS 1.2 y 1.3.", guide: "03.01" },
  { id: "cry-hash", sev: "alta", cat: "Criptografía", title: "Hash débil (MD5/SHA-1)", re: /\b(?:hashlib\.(?:md5|sha1)|createHash\s*\(\s*["'](?:md5|sha1)["']|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']|\bmd5\s*\(|\bsha1\s*\()/i, fix: "Para contraseñas: Argon2id/bcrypt. Para integridad: SHA-256 o superior.", guide: "02.02" },
  { id: "cry-pw", sev: "crit", cat: "Criptografía", title: "Contraseña con hash rápido", re: /\b(?:sha256|sha512|sha1|md5)\b[^\n]*\bpassw(?:or)?d\b|\bpassw(?:or)?d\b[^\n]*\b(?:sha256|sha512|sha1|md5)\b/i, fix: "Usa argon2-cffi / argon2 (Node) con Argon2id, o bcrypt cost ≥ 12.", guide: "02.02" },
  { id: "cry-ecb", sev: "alta", cat: "Criptografía", title: "Cifrado en modo ECB o API obsoleta", re: /\bMODE_ECB\b|aes-\d{3}-ecb|\bcreateCipher\s*\(|AES\/ECB|\bDES(?:ede)?\b/i, fix: "Usa AES-256-GCM (AEAD) con nonce aleatorio de 96 bits por operación.", guide: "02.02" },
  { id: "cry-iv", sev: "alta", cat: "Criptografía", title: "IV/nonce fijo", re: /\b(?:iv|nonce)\s*=\s*(?:b["']\\x00|Buffer\.alloc\s*\(\s*\d+\s*,\s*0|["'][0-9a-f]{16,}["'])/i, fix: "Genera un nonce aleatorio por cada cifrado (os.urandom(12) / crypto.randomBytes(12)).", guide: "02.02" },
  { id: "cry-rand", sev: "media", cat: "Criptografía", title: "Aleatoriedad no criptográfica", re: /\bMath\.random\s*\(|\brandom\.(?:random|randint|choice|randrange)\s*\(/, fix: "Para tokens, OTP o IDs usa secrets (Python) o crypto.randomBytes / randomInt (Node).", guide: "02.02" },

  // Sesiones / auth
  { id: "auth-ls", sev: "alta", cat: "Sesiones", title: "Token en localStorage/sessionStorage", re: /\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*["'][^"']*(?:token|jwt|auth|session)[^"']*["']/i, fix: "Usa una cookie __Host- con HttpOnly; Secure; SameSite.", guide: "01.02" },
  { id: "auth-cookie", sev: "alta", cat: "Sesiones", title: "Cookie sin flags de seguridad", re: /\b(?:httpOnly|httponly|secure)\s*[:=]\s*(?:false|False)\b|SESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False|sameSite\s*:\s*["']none["']/i, fix: "Cookies de sesión: HttpOnly, Secure, SameSite=Strict o Lax y prefijo __Host-.", guide: "01.02" },
  { id: "auth-jwt", sev: "crit", cat: "Sesiones", title: "JWT sin verificación de firma", re: /verify_signature["']?\s*:\s*False|algorithms\s*=\s*\[\s*["']none["']|\bjwt\.decode\s*\([^)]*\bverify\s*=\s*False|ignoreExpiration\s*:\s*true|algorithms\s*:\s*\[\s*["']none["']/i, fix: "jwt.decode(token, key, algorithms=[\"RS256\"], audience=..., issuer=...) con exp obligatorio.", guide: "01.03" },
  { id: "auth-csrf", sev: "alta", cat: "Sesiones", title: "Protección CSRF deshabilitada", re: /@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|csrf\s*\(\s*\)\s*\.disable|\.csrf\(\s*\w+\s*->\s*\w+\.disable/, fix: "Mantén la protección CSRF activa; documenta y revisa cualquier excepción.", guide: "01.02" },

  // Config
  { id: "cfg-debug", sev: "alta", cat: "Configuración", title: "Modo debug activo", re: /\bDEBUG\s*=\s*True\b|\bdebug\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True|\bdebug\s*:\s*true\b/, fix: "Debug apagado en producción; controla con variable de entorno y valida al arrancar.", guide: "03.03" },
  { id: "cfg-cors", sev: "alta", cat: "Configuración", title: "CORS abierto", re: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|\borigins?\s*[:=]\s*["']\*["']|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|allow_origins\s*=\s*\[\s*["']\*["']/, fix: "Allow-list exacta de orígenes; nunca '*' junto con credenciales.", guide: "03.03" },
  { id: "cfg-stack", sev: "media", cat: "Configuración", title: "Stack trace o error crudo hacia el cliente", re: /traceback\.format_exc\(\)|res\.(?:send|json)\s*\([^)]*\b(?:err|error|e)\.stack|["']trace["']\s*:/, fix: "Devuelve {error, error_id}; el detalle va solo al log del servidor.", guide: "03.03" },
  { id: "cfg-http", sev: "info", cat: "Configuración", title: "URL http:// sin cifrar", re: /["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.)[^"'`\s]+/, fix: "Usa https:// en todas las conexiones, también internas.", guide: "03.01" },
  { id: "cfg-perm", sev: "media", cat: "Configuración", title: "Permisos de archivo excesivos", re: /\bchmod\s+(?:-R\s+)?0?777\b|0o777\b/, fix: "Usa permisos mínimos (p. ej. 0600 para llaves, 0644 para archivos públicos).", guide: "03.03" },

  // Docker / deps
  // scope "docker": solo se evalúan si el texto parece un Dockerfile (evita falsos positivos con SQL "FROM tabla").
  { id: "dk-latest", scope: "docker", sev: "media", cat: "Dependencias", title: "Imagen sin versión fija (:latest)", re: /^\s*FROM\s+[^\s:@]+(?::latest)?(?:\s+AS\s+\w+)?\s*$/i, fix: "Fija la versión y el digest: FROM python:3.13-slim@sha256:...", guide: "03.02" },
  { id: "dk-root", scope: "docker", sev: "media", cat: "Infraestructura", title: "Contenedor ejecutándose como root", re: /^\s*USER\s+(?:root|0)\s*$/i, fix: "Crea un usuario sin privilegios y usa USER 10001.", guide: "03.03" },
  { id: "dk-envsec", sev: "alta", cat: "Secreto", title: "Secreto en ARG/ENV del Dockerfile", re: /^\s*(?:ARG|ENV)\s+\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE)\w*\s*[= ]/i, fix: "Usa RUN --mount=type=secret en build y secretos del orquestador en runtime.", guide: "02.01" },
  { id: "dep-float", sev: "media", cat: "Dependencias", title: "Versión de dependencia flotante", re: /["'][@\w./-]+["']\s*:\s*["'](?:\*|latest|x)["']|^[A-Za-z0-9_.-]+\s*>=\s*[\d.]+\s*$/, fix: "Fija versiones y usa lockfile; actualiza con Dependabot/Renovate.", guide: "03.02" },
  { id: "dep-ignore", sev: "info", cat: "Dependencias", title: "Scripts de instalación habilitados globalmente", re: /ignore-scripts\s*=\s*false/, fix: "Usa ignore-scripts=true y habilita scripts solo para paquetes revisados.", guide: "03.02" },
];

export const SEV_LABEL = { crit: "Crítica", alta: "Alta", media: "Media", info: "Info" };

/* ------------------------------------------------------------------ Ejemplos */

export const SAMPLE_HTTP = `HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval'
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=3600
Set-Cookie: session=abc123; Path=/; Domain=.empresa.com
Set-Cookie: theme=dark; Path=/; Secure; SameSite=Lax`;

export const SAMPLE_CODE = `import os, hashlib, pickle, requests
DB_URL = "postgresql://admin:Sup3rS3cret@10.0.0.5:5432/core"
API_KEY = "${"sk_" + "live_"}EjemploFalsoNoReal0000"
JWT_SECRET = os.getenv("JWT_SECRET", "changeme")

def login(cur, email, password):
    cur.execute(f"SELECT * FROM users WHERE email = '{email}'")
    return hashlib.md5(password.encode()).hexdigest()

def ping(host):
    os.system("ping -c 1 " + host)

def load(data):
    return pickle.loads(data)

requests.get("https://api.partner.com", verify=False)
app.run(debug=True)
// frontend
el.innerHTML = location.hash.slice(1);
localStorage.setItem("token", jwt);`;
