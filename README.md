# Guía Práctica para Desarrollo Seguro

Base de conocimiento y herramienta interactiva de **AppSec / DevSecOps** para desarrolladores que crean productos nuevos o mantienen sistemas existentes. Busca que el código llegue a producción con menos vulnerabilidades y que la auditoría no encuentre lo de siempre.

**Herramienta web:** https://rogerf5-security.github.io/Gu-a-Practica-Para-Desarrollo-Seguro/

## Qué incluye la herramienta web

| Herramienta | Para qué sirve |
|---|---|
| **Mi checklist** | Eliges qué vas a construir (API, login, frontend, BD, uploads, Docker, LLM…) y obtienes solo los controles aplicables, marcados como Bloqueante o Requerido. El progreso se guarda en tu navegador y puedes exportarlo en Markdown para el Pull Request. |
| **¿Sí o no?** | Buscador de respuestas rápidas: ¿actualizo las librerías?, ¿pongo CSP?, ¿ofusco?, ¿hardcodeo?… |
| **Generador de headers** | Configuración lista para Nginx, Apache, Express, FastAPI, Django o cabeceras HTTP sin formato. Explica para qué sirve cada cabecera. |
| **Generador y analizador de CSP** | Políticas con nonce, para sitios estáticos o para APIs, más el análisis de una CSP existente. |
| **Generador de cookies** | `Set-Cookie` con `__Host-`, `HttpOnly`, `Secure` y `SameSite`, y su equivalente en los frameworks más usados. |
| **Analizador de respuesta HTTP** | Pegas la salida de `curl -sI` y obtienes una calificación con hallazgos sobre headers, CSP, cookies, CORS y fugas de versión. |
| **Escáner local de código** | Detecta secretos hardcodeados (los muestra enmascarados) y patrones peligrosos: SQLi, `eval`, `shell=True`, `verify=False`, `pickle`, MD5, `innerHTML`… |
| **Calculadora de plazos** | Fecha límite para remediar una vulnerabilidad según su severidad y si existe explotación activa. |

**Privacidad:** la página es estática. Todo se procesa en tu navegador y no se envía ningún dato. Aplica lo que recomienda: CSP estricta sin scripts inline ni recursos de terceros, y Trusted Types obligatorio.

## Guías completas

En [`Desarrollo_Seguro/`](Desarrollo_Seguro/README.md), en Markdown y en Word (`.docx`):

| # | Guía |
|---|---|
| 00 | [Guía Rápida de Desarrollo Seguro](Desarrollo_Seguro/00_Guia_Rapida_Desarrollo_Seguro.md) (10 minutos) |
| 01.01 | [Inyecciones: SQLi, Command Injection y RCE](Desarrollo_Seguro/01_Codigo_y_Prevencion_de_Vulnerabilidades/01_Inyecciones_SQLi_Command_RCE.md) |
| 01.02 | [XSS, CSRF y Seguridad Frontend](Desarrollo_Seguro/01_Codigo_y_Prevencion_de_Vulnerabilidades/02_XSS_CSRF_y_Seguridad_Frontend.md) |
| 01.03 | [Control de Acceso y Escalada de Privilegios](Desarrollo_Seguro/01_Codigo_y_Prevencion_de_Vulnerabilidades/03_Control_de_Acceso_y_Escalada_Privilegios.md) |
| 02.01 | [Gestión de Secretos y API Keys](Desarrollo_Seguro/02_Criptografia_Secretos_y_Proteccion_Codigo/01_Gestion_de_Secretos_y_API_Keys.md) |
| 02.02 | [Cifrado en Almacenamiento, Hashing y PII](Desarrollo_Seguro/02_Criptografia_Secretos_y_Proteccion_Codigo/02_Cifrado_Almacenamiento_y_Hashing.md) |
| 02.03 | [Ofuscación y Endurecimiento del Cliente](Desarrollo_Seguro/02_Criptografia_Secretos_y_Proteccion_Codigo/03_Ofuscacion_y_Endurecimiento_Cliente.md) |
| 03.01 | [TLS/SSL y Cifrado en Tránsito](Desarrollo_Seguro/03_Infraestructura_Transporte_y_Dependencias/01_TLS_SSL_y_Cifrado_en_Transito.md) |
| 03.02 | [Gestión de Dependencias y Versiones](Desarrollo_Seguro/03_Infraestructura_Transporte_y_Dependencias/02_Gestion_de_Dependencias_y_Versiones.md) |
| 03.03 | [Hardening de APIs y Servidores](Desarrollo_Seguro/03_Infraestructura_Transporte_y_Dependencias/03_Hardening_APIs_y_Servidores.md) |
| 04.01 | [Prompt Engineering Seguro y Prevención de Prompt Injection](Desarrollo_Seguro/04_Desarrollo_Seguro_con_IA_y_LLMs/01_Prompt_Engineering_Seguro_y_Prevencion_Injection.md) |
| 04.02 | [Uso Seguro de IA por Desarrolladores](Desarrollo_Seguro/04_Desarrollo_Seguro_con_IA_y_LLMs/02_Uso_Seguro_de_IA_por_Desarrolladores.md) |

El [README de la base de conocimiento](Desarrollo_Seguro/README.md) contiene la matriz *"¿Qué vas a construir hoy?"* y el **Go-Live Security Gate**, el checklist obligatorio de salida a producción.

## Estructura del repositorio

```text
.
├── docs/                 # Sitio de GitHub Pages (HTML/CSS/JS sin dependencias)
├── Desarrollo_Seguro/    # Guías en Markdown (fuente) y Word (.docx)
└── tools/md2docx.py      # Regenera los .docx a partir de los .md
```

## Mantenimiento

- Los `.md` son la fuente. Tras editarlos, regenera los Word con:

  ```bash
  pip install python-docx
  python tools/md2docx.py Desarrollo_Seguro
  ```

- Para probar el sitio en local, sírvelo desde `docs/`:

  ```bash
  python -m http.server 8765 --directory docs
  ```

  Las páginas abiertas como `file://` no cargan módulos ES.

- Revisa el contenido cada semestre o cuando salgan versiones nuevas de OWASP Top 10, ASVS, LLM Top 10, las guías TLS de Mozilla o los CIS Benchmarks.

## Marco de referencia

OWASP Top 10:2025 · OWASP ASVS 5.0 · OWASP API Security Top 10:2023 · OWASP Top 10 for LLM Applications 2025 · OWASP MASVS v2 · MITRE CWE Top 25 (2025) · Mozilla Server Side TLS · CIS Benchmarks · NIST SSDF (SP 800-218/218A) · SLSA.

> Las herramientas de la página son de apoyo. No sustituyen SAST/DAST, la revisión de código ni un pentest.
