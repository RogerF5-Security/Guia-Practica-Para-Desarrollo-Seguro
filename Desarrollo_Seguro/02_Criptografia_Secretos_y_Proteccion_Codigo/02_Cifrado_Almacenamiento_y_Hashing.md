# Cifrado en Almacenamiento, Hashing y Protección de PII

| Campo | Valor |
|---|---|
| Dominio | Criptografía, secretos y protección de código |
| Aplica a | Bases de datos, almacenamiento de objetos, backups, colas, caches, logs, exportaciones, credenciales de usuarios |
| Referencias | OWASP Top 10:2025 A04 (Cryptographic Failures); OWASP ASVS 5.0 V11 (Cryptography), V14 (Data Protection), V6 (Authentication); OWASP Password Storage Cheat Sheet; NIST SP 800-63B, SP 800-38D (GCM), SP 800-57; CWE-311, CWE-312, CWE-327, CWE-328, CWE-916, CWE-759, CWE-330, CWE-323 |
| Severidad típica | Alta–Crítica (filtración masiva de credenciales/PII, impacto regulatorio) |

---

## 1. Principio de Seguridad

**Qué se mitiga:** que un atacante con acceso a un volcado de base de datos, a un backup, a un bucket mal configurado, a un disco o a logs pueda leer datos sensibles o recuperar contraseñas.

**Reglas rectoras:**

1. **Prohibido almacenar datos sensibles en texto plano** (CWE-312): credenciales, tokens, PII (documentos de identidad, teléfonos, direcciones, datos de salud), datos financieros y secretos de MFA.
2. **Las contraseñas no se cifran: se *hashean*** con una función lenta y con sal, diseñada para contraseñas (Argon2id, scrypt, bcrypt; PBKDF2 solo si se exige FIPS-140). Un hash rápido (MD5, SHA-1, SHA-256, SHA-512), incluso con sal, se rompe a miles de millones de intentos por segundo en GPU.
3. **Los datos que hay que recuperar se cifran** con cifrado autenticado (AEAD): **AES-256-GCM** o **ChaCha20-Poly1305**. Nunca ECB, ni CBC sin MAC, ni algoritmos caseros.
4. **Las llaves no viven junto a los datos.** *Envelope encryption* con KMS/HSM: la llave de datos (DEK) cifra los datos y la llave maestra (KEK) en KMS cifra la DEK.
5. **Minimizar antes de proteger:** el dato más seguro es el que no se recolecta. Defina la retención y elimine o seudonimice lo innecesario.

### Mecánica del fallo (por qué cada regla)

| Error | Consecuencia técnica |
|---|---|
| SHA-256(password) sin sal | Tablas precomputadas o *rainbow tables*; contraseñas iguales producen hashes iguales |
| SHA-256(salt + password) | La sal evita las tablas, pero la GPU calcula más de 10⁹ hashes/s; un diccionario con reglas rompe la mayoría |
| MD5/SHA-1 | Rotos (colisiones) y extremadamente rápidos |
| AES-ECB | Bloques iguales producen texto cifrado igual, lo que filtra patrones |
| AES-CBC sin MAC | *Padding oracle* que permite descifrar o modificar sin la llave |
| Nonce GCM reutilizado con la misma llave | Se recupera el XOR de los textos planos y **la llave de autenticación**, lo que permite falsificar mensajes |
| Llave en el mismo servidor/BD/repositorio | Quien roba los datos roba la llave: el cifrado es cosmético |
| `random`/`Math.random()` para tokens | PRNG predecible (CWE-330) |

---

## 2. Hashing de contraseñas

### 2.1 Parámetros recomendados (OWASP Password Storage Cheat Sheet)

| Algoritmo | Configuración mínima | Notas |
|---|---|---|
| **Argon2id** (preferido) | m = 19 MiB (19456 KiB), t = 2, p = 1 · o bien m = 46 MiB, t = 1, p = 1 | Ganador de la PHC; resistente a GPU/ASIC por el uso de memoria. Calibrar para ~200–500 ms en el hardware de producción |
| **scrypt** | N = 2¹⁷, r = 8, p = 1 | Alternativa si Argon2 no está disponible |
| **bcrypt** | cost ≥ 12 (mínimo 10) | **Trunca a 72 bytes**. No pre-hashear con SHA sin codificar (el byte nulo trunca); valide la longitud máxima |
| **PBKDF2-HMAC-SHA256** | ≥ 600 000 iteraciones | Solo cuando FIPS-140 lo exija |
| **Prohibidos** | MD5, SHA-1, SHA-2/SHA-3 directos, `crypt()` DES, cifrado reversible, Base64 | — |

**Pepper (opcional, recomendado en alto riesgo):** un secreto global guardado en KMS/HSM (no en la BD), aplicado como HMAC antes del hash o cifrando el hash resultante. Protege si se filtra solo la base de datos.

### 2.2 Python

**Patrón Vulnerable (Qué NO hacer)**

```python
import hashlib

# VULNERABLE: hash rápido sin sal.
password_hash = hashlib.md5(password.encode()).hexdigest()

# VULNERABLE: SHA-256 con sal sigue siendo rápido para ataques offline.
password_hash = hashlib.sha256((salt + password).encode()).hexdigest()

# VULNERABLE: comparación no constante (timing attack) y contraseña reversible.
if stored == hashlib.sha1(pw.encode()).hexdigest(): ...
encrypted_pw = fernet.encrypt(password.encode())   # las contraseñas NO se cifran
```

**Patrón Seguro (Qué SÍ hacer) — Argon2id con rehash transparente**

```python
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# Parámetros explícitos (no depender de los defaults de la librería).
ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16, type=Type.ID)

MAX_PASSWORD_LEN = 128  # evita DoS por contraseñas gigantes

def hash_password(password: str) -> str:
    if not 12 <= len(password) <= MAX_PASSWORD_LEN:   # NIST 800-63B: mínimo 8, recomendado 15 sin MFA
        raise ValueError("Longitud de contraseña inválida")
    return ph.hash(password)  # formato PHC: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>

def verify_password(stored_hash: str, password: str, user) -> bool:
    try:
        ph.verify(stored_hash, password)          # comparación en tiempo constante
    except (VerifyMismatchError, InvalidHashError):
        return False
    if ph.check_needs_rehash(stored_hash):        # migración automática al subir los parámetros
        user.password_hash = ph.hash(password)
        user.save()
    return True
```

**Migración desde hashes heredados (MD5/SHA-1) sin forzar un reset masivo**

```python
# Paso 1 (batch, una vez): envolver el hash legado -> argon2id(md5_hex). Marca legacy=True.
# Paso 2 (en el login): si legacy, verificar argon2(md5(pw)); si es OK, rehash como argon2id(pw), legacy=False.
def verify_legacy_wrapped(user, password: str) -> bool:
    inner = hashlib.md5(password.encode()).hexdigest()
    try:
        ph.verify(user.password_hash, inner)
    except VerifyMismatchError:
        return False
    user.password_hash, user.legacy_hash = ph.hash(password), False
    user.save()
    return True
```

### 2.3 TypeScript / Node.js

**Patrón Vulnerable (Qué NO hacer)**

```typescript
import crypto from "node:crypto";
const hash = crypto.createHash("sha256").update(password).digest("hex"); // VULNERABLE
if (hash === user.passwordHash) { /* VULNERABLE: comparación no constante */ }
```

**Patrón Seguro (Qué SÍ hacer)**

```typescript
import argon2 from "argon2";

const OPTS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 } as const;

export async function hashPassword(pw: string): Promise<string> {
  if (pw.length < 12 || pw.length > 128) throw new Error("Longitud inválida");
  return argon2.hash(pw, OPTS);
}

export async function verifyPassword(stored: string, pw: string): Promise<{ ok: boolean; rehash?: string }> {
  const ok = await argon2.verify(stored, pw);
  if (ok && argon2.needsRehash(stored, OPTS)) return { ok, rehash: await argon2.hash(pw, OPTS) };
  return { ok };
}
```

> **Controles complementarios:** compare las contraseñas nuevas contra listas de contraseñas filtradas (HIBP *k-anonymity*), aplique rate limiting y bloqueo progresivo en el login, use MFA, y devuelva mensajes de error genéricos ("credenciales inválidas") para no enumerar usuarios.

---

## 3. Cifrado en reposo (AES-256-GCM)

### 3.1 Capas de cifrado

| Capa | Protege contra | No protege contra |
|---|---|---|
| Disco/volumen (EBS, LUKS, BitLocker) | Robo físico del disco, snapshots expuestos sin la llave | Acceso vía la aplicación, SQLi, credenciales de BD robadas |
| Base de datos (TDE) / bucket (SSE-KMS) | Backups y archivos de datos robados | Consultas legítimas de un atacante con acceso a la BD |
| **Aplicación (campo a campo)** | Volcados de BD, DBAs, SQLi, backups, réplicas | Compromiso del proceso de la aplicación que tiene la llave |

Para PII y datos regulados: **cifrado a nivel de aplicación** de los campos sensibles, además de cifrado de volumen y de BD.

### 3.2 Python (`cryptography`)

**Patrón Vulnerable (Qué NO hacer)**

```python
from Crypto.Cipher import AES  # pycryptodome
import hashlib

KEY = b"0123456789abcdef0123456789abcdef"            # VULNERABLE: llave hardcodeada
cipher = AES.new(KEY, AES.MODE_ECB)                   # VULNERABLE: ECB
ct = cipher.encrypt(pad(data, 16))

IV = b"\x00" * 16                                     # VULNERABLE: IV fijo
cipher = AES.new(KEY, AES.MODE_CBC, IV)               # VULNERABLE: CBC sin autenticación

key = hashlib.sha256(b"mi-frase").digest()            # VULNERABLE: llave derivada de una frase con hash rápido
```

**Patrón Seguro (Qué SÍ hacer) — AES-256-GCM con nonce aleatorio, AAD y versionado de llave**

```python
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_VERSION = 3                     # permite rotar sin re-cifrar todo de golpe
NONCE_LEN = 12                      # 96 bits, tamaño recomendado para GCM (NIST SP 800-38D)

def encrypt_field(dek: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """
    Formato: [version:1B][nonce:12B][ciphertext+tag:16B].
    aad (Associated Data) ata el texto cifrado a su contexto (p. ej., tabla|columna|id de fila),
    lo que impide copiar un valor cifrado de un registro a otro.
    """
    nonce = os.urandom(NONCE_LEN)   # CSPRNG; NUNCA reutilizar el nonce con la misma llave
    ct = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return struct.pack("B", KEY_VERSION) + nonce + ct

def decrypt_field(keyring: dict[int, bytes], blob: bytes, aad: bytes) -> bytes:
    version = blob[0]
    nonce, ct = blob[1:1 + NONCE_LEN], blob[1 + NONCE_LEN:]
    return AESGCM(keyring[version]).decrypt(nonce, ct, aad)  # lanza InvalidTag si hubo manipulación

# Uso
aad = b"customers|national_id|" + str(customer_id).encode()
customer.national_id_enc = encrypt_field(dek_v3, national_id.encode(), aad)
```

> **Límite de GCM con nonces aleatorios:** no cifre más de ~2³² mensajes con la misma llave (riesgo de colisión de nonce). Para volúmenes altos, rote la DEK por periodo o tenant, o use **AES-GCM-SIV** / **XChaCha20-Poly1305** (nonce de 192 bits).

**Patrón Seguro (Qué SÍ hacer) — Envelope encryption con AWS KMS**

```python
import boto3

kms = boto3.client("kms")
KEK_ID = "alias/core-api-pii"

def new_data_key() -> tuple[bytes, bytes]:
    resp = kms.generate_data_key(KeyId=KEK_ID, KeySpec="AES_256",
                                 EncryptionContext={"app": "core-api", "purpose": "pii"})
    return resp["Plaintext"], resp["CiphertextBlob"]   # usar Plaintext en memoria; guardar CiphertextBlob

def unwrap_data_key(wrapped: bytes) -> bytes:
    return kms.decrypt(CiphertextBlob=wrapped,
                       EncryptionContext={"app": "core-api", "purpose": "pii"})["Plaintext"]
# La DEK cifrada se guarda junto a los datos; la KEK nunca sale del KMS/HSM.
# La rotación de la KEK en KMS es transparente; el acceso a kms:Decrypt queda auditado en CloudTrail.
```

> Alternativas listas para usar: **AWS Encryption SDK**, **Google Tink** (AEAD con gestión de llaves y rotación integrada) y **HashiCorp Vault Transit** (cifrado como servicio: la aplicación nunca ve la llave).

### 3.3 TypeScript / Node.js

**Patrón Vulnerable (Qué NO hacer)**

```typescript
// VULNERABLE: createCipher (sin IV, derivación MD5) está eliminado; aes-256-cbc sin MAC.
const c = crypto.createCipheriv("aes-256-cbc", key, Buffer.alloc(16, 0));
```

**Patrón Seguro (Qué SÍ hacer)**

```typescript
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

export function encrypt(key: Buffer, plaintext: Buffer, aad: Buffer): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]); // iv(12) | tag(16) | ct
}

export function decrypt(key: Buffer, blob: Buffer, aad: Buffer): Buffer {
  const iv = blob.subarray(0, 12), tag = blob.subarray(12, 28), ct = blob.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);                 // obligatorio: sin el tag no hay integridad
  return Buffer.concat([decipher.update(ct), decipher.final()]); // lanza excepción si fue alterado
}
```

### 3.4 SQL (PostgreSQL)

```sql
-- VULNERABLE: PII en claro y llave pasada en la consulta (queda en logs/pg_stat_statements).
INSERT INTO customers (national_id) VALUES ('1234567890101');
SELECT pgp_sym_decrypt(national_id, 'llave-en-la-query') FROM customers;

-- SEGURO: la columna almacena bytea cifrado por la aplicación + índice ciego (blind index) para búsquedas.
CREATE TABLE customers (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  national_id_enc bytea NOT NULL,          -- AES-256-GCM desde la aplicación
  national_id_bix bytea NOT NULL,          -- HMAC-SHA256(llave_índice, valor_normalizado)
  key_version     smallint NOT NULL
);
CREATE UNIQUE INDEX ux_customers_national_id_bix ON customers (national_id_bix);
```

```python
# Blind index: permite búsqueda exacta sin descifrar ni exponer el valor.
import hmac, hashlib
def blind_index(index_key: bytes, value: str) -> bytes:
    normalized = value.strip().replace("-", "").upper()
    return hmac.new(index_key, normalized.encode(), hashlib.sha256).digest()
# Use una llave distinta a la DEK. Un dominio pequeño (p. ej., fecha de nacimiento) sigue siendo enumerable: evalúe el riesgo.
```

---

## 4. Manejo seguro de PII

| Práctica | Implementación |
|---|---|
| **Clasificación** | Etiquete cada campo: Público / Interno / Confidencial / Restringido (PII sensible, credenciales, salud, financiero). Mantenga un inventario de datos (*data map*) |
| **Minimización** | No recolecte lo que no usa. Guarde solo los últimos 4 dígitos cuando baste |
| **Tokenización** | Datos de tarjeta: no los almacene; use la tokenización de la pasarela (alcance PCI DSS) |
| **Seudonimización** | Analítica y entornos no productivos con IDs seudónimos (HMAC con llave) en lugar de PII |
| **Datos reales en QA/dev** | **Prohibido.** Use datos sintéticos (Faker) o enmascaramiento irreversible |
| **Logs** | Redacte PII y secretos antes de escribir; nunca registre el body de las peticiones de autenticación ni de pago |
| **Retención y borrado** | TTL por tipo de dato; borrado criptográfico (destruir la DEK del tenant/usuario) para backups |
| **Exportaciones** | Cifradas, con expiración del enlace y registro de quién exporta |
| **Respuestas de API** | Allow-list de campos; enmascarar (`****1234`) por defecto |

**Redacción de PII en logs (Python, structlog)**

```python
import re
import structlog

SENSITIVE_KEYS = {"password", "token", "authorization", "national_id", "card_number", "cvv", "secret"}
EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+)")

def redact(_, __, event_dict):
    for k in list(event_dict):
        if k.lower() in SENSITIVE_KEYS:
            event_dict[k] = "[REDACTED]"
        elif isinstance(event_dict[k], str):
            event_dict[k] = EMAIL_RE.sub(r"\1***\2", event_dict[k])
    return event_dict

structlog.configure(processors=[redact, structlog.processors.JSONRenderer()])
```

**Generación de tokens y aleatoriedad**

```python
# VULNERABLE
import random; token = str(random.randint(100000, 999999))      # PRNG predecible (Mersenne Twister)
# SEGURO
import secrets
reset_token = secrets.token_urlsafe(32)        # 256 bits
otp = f"{secrets.randbelow(10**6):06d}"
# Guarde en BD solo el HASH del token de reset (SHA-256 basta aquí: alta entropía, no es una contraseña).
```

```typescript
// VULNERABLE: Math.random()   SEGURO:
import { randomBytes, randomInt } from "node:crypto";
const token = randomBytes(32).toString("base64url");
const otp = randomInt(0, 1_000_000).toString().padStart(6, "0");
```

---

## 5. Preparación post-cuántica (agilidad criptográfica)

- **Simétrico/hash:** AES-256 y SHA-256/384 se consideran adecuados frente a ataques cuánticos conocidos (Grover reduce a la mitad la seguridad efectiva; 256 bits deja un margen de 128).
- **Asimétrico:** RSA y ECC son vulnerables a Shor. NIST publicó FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) y FIPS 205 (SLH-DSA) en 2024. Para datos con confidencialidad de largo plazo (*harvest now, decrypt later*), priorice TLS con intercambio híbrido (X25519MLKEM768) en los terminadores que lo soporten.
- **Agilidad:** versione los algoritmos y las llaves en el formato almacenado (byte de versión, `kid`, formato PHC) para migrar sin rediseñar.

---

## 6. Detección automatizada

- **Semgrep:** `p/secrets`, reglas `python.cryptography.security.*` y `javascript.node-crypto.*` (ECB, IV fijo, MD5/SHA1 para passwords, `Math.random` para tokens).
- **Bandit:** `B303`/`B324` (MD5/SHA1), `B311` (random), `B413` (pycrypto), `B505` (llaves débiles).
- **Revisión de esquemas:** las columnas con nombres `password`, `ssn`, `dpi`, `national_id`, `card` o `token` deben ser `bytea` cifrado o hash; un script de CI puede validar el esquema contra el inventario de datos.

---

## 7. Checklist de Verificación (antes de merge / deploy)

- [ ] Las contraseñas usan Argon2id (m ≥ 19 MiB, t ≥ 2) o bcrypt (cost ≥ 12) con parámetros explícitos y `needs_rehash`.
- [ ] No existe MD5, SHA-1 ni SHA-2 directo para contraseñas; no hay contraseñas cifradas de forma reversible.
- [ ] Se limita la longitud máxima de la contraseña (DoS / truncamiento de bcrypt a 72 bytes).
- [ ] Las comparaciones de hashes, tokens y MAC usan funciones de tiempo constante (`hmac.compare_digest`, `crypto.timingSafeEqual`).
- [ ] Los datos sensibles recuperables usan AEAD (AES-256-GCM / ChaCha20-Poly1305), con nonce aleatorio de 96 bits por operación y AAD de contexto.
- [ ] No hay ECB, CBC sin MAC, IV/nonce fijo, `createCipher` ni librerías obsoletas (`pycrypto`).
- [ ] Las llaves provienen de KMS/HSM/Vault (*envelope encryption*); no están en el código, la BD ni el repositorio. Las llaves están versionadas.
- [ ] Los tokens, OTP, IDs de sesión y nonces se generan con CSPRNG (`secrets`, `crypto.randomBytes`).
- [ ] Los tokens de un solo uso (reset, verificación) se guardan hasheados y expiran (≤ 1 h) y se invalidan tras su uso.
- [ ] Los campos PII están clasificados; los restringidos están cifrados a nivel de aplicación; las búsquedas usan un *blind index*.
- [ ] Los logs, las trazas y los mensajes de error no contienen PII ni secretos (redacción automática verificada en pruebas).
- [ ] Los entornos no productivos no contienen datos reales de clientes.
- [ ] El cifrado de volumen/BD y SSE-KMS de backups y buckets está habilitado.
- [ ] Existe una política de retención y un mecanismo de borrado (incluido el borrado criptográfico) para los datos nuevos.

---

## 8. Referencias

- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- OWASP ASVS 5.0 — V11 Cryptography, V14 Data Protection: https://github.com/OWASP/ASVS
- NIST SP 800-63B (Digital Identity — Authentication), SP 800-38D (GCM), SP 800-57 (Key Management)
- NIST FIPS 203/204/205 (Post-Quantum Cryptography): https://csrc.nist.gov/projects/post-quantum-cryptography
- RFC 9106 — Argon2: https://www.rfc-editor.org/rfc/rfc9106
