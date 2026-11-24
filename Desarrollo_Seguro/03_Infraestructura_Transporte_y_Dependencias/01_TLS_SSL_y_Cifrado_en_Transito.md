# TLS/SSL y Cifrado en Tránsito

| Campo | Valor |
|---|---|
| Dominio | Infraestructura, transporte y dependencias |
| Aplica a | Endpoints públicos, APIs internas, microservicios, bases de datos, colas, SMTP, clientes HTTP salientes |
| Referencias | Mozilla Server Side TLS Guidelines (v6.0, perfil *Intermediate*) y SSL Configuration Generator; OWASP ASVS 5.0 V12 (Secure Communication); OWASP Top 10:2025 A04 (Cryptographic Failures); RFC 8446 (TLS 1.3), RFC 8996 (deprecación de TLS 1.0/1.1), RFC 6797 (HSTS), RFC 9325 (BCP 195); CIS Benchmarks (NGINX, Apache); CWE-319, CWE-326, CWE-295, CWE-297, CWE-757 |
| Severidad típica | Alta (interceptación de credenciales y sesiones, MITM, manipulación de datos) |

---

## 1. Principio de Seguridad

**Qué se mitiga:** la lectura y modificación de datos en tránsito por un adversario en la red (Wi-Fi pública, ISP, red corporativa comprometida, otro *pod* del clúster, proxy malicioso), la suplantación de servidores (MITM) y los ataques de *downgrade* a protocolos débiles.

**Política obligatoria:**

1. **HTTPS en todo**, incluido el tráfico interno (*zero trust*: la red interna no es confiable).
2. Solo **TLS 1.3** y **TLS 1.2**. **Prohibidos SSLv2, SSLv3, TLS 1.0 y TLS 1.1** (RFC 8996): POODLE, BEAST y CBC débiles, y sin AEAD.
3. Solo cipher suites con **intercambio de llaves efímero (ECDHE, forward secrecy)** y **cifrado autenticado (AEAD: AES-GCM, ChaCha20-Poly1305)**. Prohibidos RC4, 3DES, DES, NULL, EXPORT, aNULL, CBC-SHA1 y el intercambio RSA estático.
4. **HSTS** con `max-age` ≥ 1 año en los dominios públicos.
5. **Validación estricta del certificado** en todos los clientes (nunca `verify=False`).
6. **Certificados automatizados**: emisión y renovación sin intervención humana (ACME), con monitoreo de la expiración.
7. **mTLS** (autenticación mutua) entre microservicios y hacia servicios críticos internos.

**Mecánica del fallo:** sin TLS, cualquier nodo intermedio lee las cookies y los tokens. Con TLS mal configurado, el atacante fuerza un protocolo o cipher débil (*downgrade*) o, si el cliente no valida el certificado (CWE-295), presenta uno propio y descifra todo de forma transparente.

---

## 2. Configuración de servidor (Nginx)

Basado en el perfil **Intermediate** de Mozilla (v6.0). Regenere la configuración para su versión exacta de servidor y OpenSSL en https://ssl-config.mozilla.org/.

**Patrón Vulnerable (Qué NO hacer)**

```nginx
server {
    listen 443 ssl;
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;                 # VULNERABLE: protocolos obsoletos
    ssl_ciphers ALL:!aNULL;                                     # VULNERABLE: incluye RC4/3DES/CBC
    ssl_prefer_server_ciphers on;
    # Sin HSTS, sin redirección 80->443, con server_tokens on
}
server {
    listen 80;
    location / { proxy_pass http://backend; }                   # VULNERABLE: sirve contenido en HTTP
}
```

**Patrón Seguro (Qué SÍ hacer)**

```nginx
# /etc/nginx/conf.d/app.conf — Mozilla Intermediate (TLS 1.2 + 1.3), nginx >= 1.25, OpenSSL 3.x

# 1) Todo HTTP redirige a HTTPS (excepto el desafío ACME HTTP-01)
server {
    listen 80;
    listen [::]:80;
    server_name app.empresa.com;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name app.empresa.com;

    ssl_certificate     /etc/letsencrypt/live/app.empresa.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.empresa.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    # TLS 1.2: solo ECDHE + AEAD (las suites de TLS 1.3 son seguras por defecto en OpenSSL).
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;           # Mozilla: con una lista 100% fuerte, dejar elegir al cliente (ChaCha en móviles)
    ssl_ecdh_curve X25519:prime256v1:secp384r1;   # en OpenSSL >= 3.5 puede anteponer X25519MLKEM768 (híbrido post-cuántico)

    ssl_session_timeout 1d;
    ssl_session_cache shared:TLS:10m;
    ssl_session_tickets off;                 # evita comprometer el forward secrecy con llaves de ticket de larga vida

    # HSTS: 2 años; preload solo tras validar que TODOS los subdominios sirven HTTPS.
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    server_tokens off;

    location / {
        proxy_pass https://backend_pool;      # TLS también hacia el backend
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/nginx/pki/internal-ca.pem;
        proxy_ssl_server_name on;
        proxy_ssl_protocols TLSv1.3;
    }
}
```

> **OCSP stapling:** Let's Encrypt eliminó el soporte de OCSP en 2025 (los certificados ya no incluyen la URL OCSP). Con certificados de LE, no configure `ssl_stapling`. Con CAs comerciales que aún publiquen OCSP, puede habilitar `ssl_stapling on; ssl_stapling_verify on;`.

### 2.1 Equivalente en Apache (mod_ssl)

```apache
SSLProtocol             -all +TLSv1.2 +TLSv1.3
SSLCipherSuite          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
SSLHonorCipherOrder     off
SSLSessionTickets       off
SSLCompression          off
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
ServerTokens Prod
ServerSignature Off
```

### 2.2 HSTS: despliegue progresivo

| Fase | Cabecera | Duración |
|---|---|---|
| 1 | `max-age=300` | 1 día (validar que nada se rompa) |
| 2 | `max-age=604800; includeSubDomains` | 1–2 semanas |
| 3 | `max-age=31536000; includeSubDomains` | Producción estable |
| 4 (opcional) | `max-age=63072000; includeSubDomains; preload` + registro en hstspreload.org | Irreversible a corto plazo: los navegadores incrustan el dominio |

---

## 3. TLS en aplicaciones y clientes

### 3.1 Python (clientes HTTP y servidores)

**Patrón Vulnerable (Qué NO hacer)**

```python
import requests, ssl, urllib3

requests.get("https://api.partner.com", verify=False)          # VULNERABLE: MITM trivial (CWE-295)
urllib3.disable_warnings()                                      # oculta el problema

ctx = ssl._create_unverified_context()                          # VULNERABLE
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

requests.post("http://api.interna.local/login", json=creds)    # VULNERABLE: credenciales en claro
```

**Patrón Seguro (Qué SÍ hacer)**

```python
import ssl
import httpx

# Contexto TLS explícito: verificación activa, TLS >= 1.2, CA interna si aplica.
ctx = ssl.create_default_context(cafile="/etc/pki/internal-ca.pem")   # omitir cafile para CAs públicas
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
# check_hostname=True y verify_mode=CERT_REQUIRED vienen por defecto con create_default_context.

client = httpx.Client(verify=ctx, timeout=httpx.Timeout(10.0, connect=5.0), http2=True)
resp = client.get("https://api.partner.com/v1/status")

# Con requests: verify=True (por defecto) o la ruta al bundle de la CA interna.
import requests
requests.get("https://api.interna.local", verify="/etc/pki/internal-ca.pem", timeout=10)
```

**Conexiones a bases de datos y colas con TLS verificado**

```python
# PostgreSQL (psycopg): verify-full = cifrado + validación de CA + hostname
conn = psycopg.connect(
    host="db.interna.local", dbname="core", user="app",
    sslmode="verify-full", sslrootcert="/etc/pki/internal-ca.pem",
)
# Redis: rediss:// + ssl_cert_reqs="required"
r = redis.Redis.from_url("rediss://cache.interna.local:6380/0", ssl_cert_reqs="required",
                         ssl_ca_certs="/etc/pki/internal-ca.pem")
```

### 3.2 Node.js / TypeScript

**Patrón Vulnerable (Qué NO hacer)**

```typescript
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";                       // VULNERABLE: desactiva TODA validación
const agent = new https.Agent({ rejectUnauthorized: false });         // VULNERABLE
new Pool({ ssl: { rejectUnauthorized: false } });                     // VULNERABLE (patrón común con pg)
```

**Patrón Seguro (Qué SÍ hacer)**

```typescript
import https from "node:https";
import fs from "node:fs";
import { Pool } from "pg";

const ca = fs.readFileSync("/etc/pki/internal-ca.pem");

export const agent = new https.Agent({
  ca,                              // confiar en la CA interna (además de las públicas si se concatena)
  minVersion: "TLSv1.2",
  rejectUnauthorized: true,        // explícito
});

export const pool = new Pool({
  host: "db.interna.local",
  ssl: { ca, rejectUnauthorized: true, servername: "db.interna.local" },
});

// Servidor HTTPS directo (si no hay proxy terminador)
https.createServer({
  key: fs.readFileSync("/run/secrets/tls.key"),
  cert: fs.readFileSync("/run/secrets/tls.crt"),
  minVersion: "TLSv1.2",
  ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
}, app).listen(8443);
```

### 3.3 Detrás de un balanceador o proxy

Si TLS termina en el balanceador (ALB, Cloudflare, Ingress), la aplicación debe:

- Confiar en `X-Forwarded-Proto` **solo** desde las IPs del proxy (`ProxyFix`/`trust proxy` acotado).
- Marcar las cookies como `Secure` y generar redirecciones a `https://`.
- Cifrar el tramo balanceador → backend (re-encrypt) cuando cruce redes no confiables o entornos multi-tenant.

```python
# Flask detrás de exactamente 1 proxy
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
```

```typescript
// Express: confiar solo en la subred del balanceador
app.set("trust proxy", ["10.0.0.0/16"]);
```

---

## 4. Gestión y renovación automática de certificados

### 4.1 Requisitos

| Requisito | Detalle |
|---|---|
| Automatización ACME | Let's Encrypt / ZeroSSL / CA interna con ACME (step-ca, Vault PKI). Sin renovaciones manuales |
| Vigencia corta | Por el calendario CA/B Forum (SC-081), la vigencia máxima de certificados públicos baja a 200 días (desde marzo de 2026), 100 días (2027) y 47 días (2029). Diseñe asumiendo renovaciones frecuentes |
| Llaves | ECDSA P-256 (preferido) o RSA ≥ 2048 (3072 para larga vida). Llave privada con permisos `0600`, nunca en Git |
| Monitoreo | Alerta a ≤ 21 días de la expiración; Certificate Transparency (crt.sh / alertas CT) para detectar emisiones no autorizadas |
| CAA | Registro DNS `CAA` que restrinja qué CAs pueden emitir para el dominio |
| Revocación | Procedimiento documentado ante el compromiso de una llave |

### 4.2 Certbot (Let's Encrypt) con recarga automática

```bash
# Emisión con llave ECDSA y webroot (no detiene nginx)
certbot certonly --webroot -w /var/www/acme -d app.empresa.com \
  --key-type ecdsa --elliptic-curve secp256r1 --deploy-hook "systemctl reload nginx"

# La renovación la ejecuta el timer systemd de certbot; validar:
systemctl list-timers | grep certbot
certbot renew --dry-run
```

```dns
; Restringir la emisión a Let's Encrypt y reportar intentos
empresa.com.  IN CAA 0 issue "letsencrypt.org"
empresa.com.  IN CAA 0 iodef "mailto:security@empresa.com"
```

### 4.3 Kubernetes (cert-manager)

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: { name: letsencrypt-prod }
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: pki@empresa.com
    privateKeySecretRef: { name: letsencrypt-prod-account }
    solvers:
      - http01: { ingress: { ingressClassName: nginx } }
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: app-tls, namespace: prod }
spec:
  secretName: app-tls
  dnsNames: [app.empresa.com]
  privateKey: { algorithm: ECDSA, size: 256, rotationPolicy: Always }
  renewBefore: 360h     # 15 días antes
  issuerRef: { name: letsencrypt-prod, kind: ClusterIssuer }
```

### 4.4 PKI interna

- CA raíz **offline** (HSM o medio aislado); emisión desde una CA intermedia online.
- Emisión ACME interna con **step-ca** o **Vault PKI** (certificados de corta vida, horas o días, para servicios).
- Distribuya la CA raíz interna a los *trust stores* vía la gestión de configuración, nunca deshabilitando la validación.

```bash
# Vault PKI: certificado de servicio de 72 h
vault write pki_int/issue/svc-core-api common_name="core-api.prod.svc" ttl="72h"
```

---

## 5. mTLS entre microservicios

**Principio:** en mTLS, **ambas partes** presentan un certificado. El servidor autentica la *identidad de la carga de trabajo* del cliente (no su IP), lo que habilita políticas *zero trust* del tipo "solo `orders-svc` puede llamar a `payments-svc`".

**Opción A — Service mesh (recomendado a escala):** Istio, Linkerd o Cilium emiten certificados SPIFFE automáticamente y los rotan cada pocas horas.

```yaml
# Istio: mTLS obligatorio en el namespace
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata: { name: default, namespace: prod }
spec:
  mtls: { mode: STRICT }
---
# Autorización por identidad de workload (SPIFFE)
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: { name: payments-allow-orders, namespace: prod }
spec:
  selector: { matchLabels: { app: payments } }
  action: ALLOW
  rules:
    - from: [{ source: { principals: ["cluster.local/ns/prod/sa/orders"] } }]
      to: [{ operation: { methods: ["POST"], paths: ["/v1/charges"] } }]
```

**Opción B — mTLS en Nginx (servicios fuera del mesh)**

```nginx
server {
    listen 8443 ssl;
    ssl_certificate         /etc/nginx/pki/payments.crt;
    ssl_certificate_key     /etc/nginx/pki/payments.key;
    ssl_client_certificate  /etc/nginx/pki/internal-ca.pem;   # CA que firma los clientes
    ssl_verify_client       on;
    ssl_verify_depth        2;
    ssl_protocols           TLSv1.3;

    location /v1/charges {
        # Autorizar por identidad del certificado (SAN/CN), no solo por "tiene un certificado válido".
        if ($ssl_client_s_dn !~ "CN=orders-svc") { return 403; }
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header X-Client-Cert-DN $ssl_client_s_dn;
    }
}
```

**Opción C — mTLS en el cliente (Python)**

```python
import ssl, httpx

ctx = ssl.create_default_context(cafile="/etc/pki/internal-ca.pem")
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(certfile="/run/secrets/orders.crt", keyfile="/run/secrets/orders.key")

with httpx.Client(verify=ctx, base_url="https://payments.interna.local:8443") as c:
    c.post("/v1/charges", json=charge)
```

---

## 6. Verificación

```bash
# Escaneo integral (protocolos, ciphers, vulnerabilidades, HSTS, cadena)
testssl.sh --severity MEDIUM --jsonfile tls.json https://app.empresa.com

# Nmap: enumeración de ciphers por protocolo
nmap -p 443 --script ssl-enum-ciphers app.empresa.com

# Confirmar el rechazo de protocolos obsoletos (deben FALLAR)
openssl s_client -connect app.empresa.com:443 -tls1_1 </dev/null
openssl s_client -connect app.empresa.com:443 -tls1   </dev/null

# Comprobar HSTS y la redirección
curl -sI http://app.empresa.com | grep -i location
curl -sI https://app.empresa.com | grep -i strict-transport-security

# Días restantes del certificado
echo | openssl s_client -connect app.empresa.com:443 -servername app.empresa.com 2>/dev/null \
  | openssl x509 -noout -enddate
```

Herramientas externas: Qualys **SSL Labs** (objetivo: calificación A/A+), **Mozilla HTTP Observatory**, y **Nuclei** con plantillas `ssl/` para el inventario masivo:

```bash
nuclei -l hosts.txt -tags ssl,tls -severity medium,high,critical -jsonl -o nuclei-tls.jsonl
```

---

## 7. Checklist de Verificación (antes de merge / deploy)

- [ ] Todo endpoint público y privado sirve solo HTTPS; HTTP redirige con 301 (excepto el desafío ACME).
- [ ] Solo están habilitados TLS 1.2 y TLS 1.3; SSLv3, TLS 1.0 y TLS 1.1 fueron verificados como rechazados con `openssl s_client`.
- [ ] Las cipher suites de TLS 1.2 son solo ECDHE + AEAD (perfil Mozilla Intermediate vigente); sin RC4, 3DES, CBC, NULL ni EXPORT.
- [ ] HSTS con `max-age` ≥ 31536000 e `includeSubDomains` (y `preload` si se aprobó).
- [ ] `ssl_session_tickets off` (o rotación de llaves de ticket gestionada) y compresión TLS deshabilitada.
- [ ] Ningún cliente usa `verify=False`, `rejectUnauthorized:false`, `NODE_TLS_REJECT_UNAUTHORIZED=0` ni `CERT_NONE` (regla Semgrep/Bandit B501 bloqueante).
- [ ] Las conexiones a BD, cache y colas usan TLS con validación (`sslmode=verify-full`, `rediss://`).
- [ ] Los certificados se renuevan automáticamente (certbot timer / cert-manager), con `--dry-run` validado y alertas a ≤ 21 días.
- [ ] Hay registros CAA publicados y monitoreo de Certificate Transparency activo.
- [ ] Las llaves privadas están fuera del repositorio, con permisos `0600` o en un secret store; ECDSA P-256 o RSA ≥ 2048.
- [ ] mTLS en modo STRICT entre microservicios, con autorización por identidad de workload (SPIFFE/CN/SAN).
- [ ] `testssl.sh` / SSL Labs sin hallazgos de severidad media o superior; calificación A o superior.

---

## 8. Referencias

- Mozilla Server Side TLS y SSL Configuration Generator: https://wiki.mozilla.org/Security/Server_Side_TLS · https://ssl-config.mozilla.org/
- OWASP Transport Layer Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
- OWASP ASVS 5.0 — V12 Secure Communication: https://github.com/OWASP/ASVS
- RFC 8446 (TLS 1.3), RFC 8996 (deprecación de TLS 1.0/1.1), RFC 6797 (HSTS), RFC 9325 (recomendaciones TLS)
- CIS Benchmarks NGINX / Apache HTTP Server: https://www.cisecurity.org/cis-benchmarks
- testssl.sh: https://testssl.sh/ · cert-manager: https://cert-manager.io/
