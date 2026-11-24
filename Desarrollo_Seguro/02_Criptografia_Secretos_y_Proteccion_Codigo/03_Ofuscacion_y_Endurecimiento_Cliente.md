# Ofuscación y Endurecimiento del Cliente (Web, Móvil y Binarios)

| Campo | Valor |
|---|---|
| Dominio | Criptografía, secretos y protección de código |
| Aplica a | SPAs y bundles JavaScript, apps Android/iOS, Electron, binarios de escritorio, firmware y agentes distribuidos |
| Referencias | OWASP MASVS v2 (MASVS-RESILIENCE, MASVS-STORAGE, MASVS-CODE) y MASTG; OWASP ASVS 5.0 V3 (Web Frontend Security), V13 (Configuration), V15 (Secure Coding and Architecture); OWASP Top 10:2025 A02 (Security Misconfiguration), A06 (Insecure Design); CWE-656, CWE-602, CWE-540, CWE-615, CWE-489, CWE-312 |
| Severidad típica | Media–Alta (depende de qué lógica o secreto exponga el cliente) |

---

## 1. Principio de Seguridad

**Qué se mitiga:** la ingeniería inversa, la manipulación (*tampering*) y la extracción de información de artefactos que se ejecutan en dispositivos que **controla el atacante** (navegador, teléfono, PC del usuario).

**Verdad fundamental:** *el cliente es territorio hostil*. Todo lo que se envía al cliente (JS, APK/IPA, binarios, WASM) puede descompilarse, depurarse, instrumentarse (Frida, DevTools, jadx, Ghidra) y modificarse. La ofuscación **aumenta el costo y el tiempo del ataque; no lo impide**. Es *seguridad por oscuridad* (CWE-656) si se usa como control principal.

**Reglas rectoras:**

1. **Primero, diseño:** ningún secreto, regla de autorización, cálculo de precio o decisión de seguridad reside exclusivamente en el cliente (CWE-602). El servidor revalida todo.
2. **Después, reducción de superficie:** no publique source maps, comentarios, endpoints de debug, rutas internas, *feature flags* ocultos ni código muerto.
3. **Por último, resiliencia:** minificación, ofuscación, *anti-tampering*, detección de root/jailbreak/hooking y atestación del dispositivo (Play Integrity / App Attest), siempre con **verificación del lado del servidor**.

---

## 2. Qué lógica JAMÁS debe residir en el cliente

| Prohibido en el cliente | Por qué | Dónde va |
|---|---|---|
| API keys privadas, secretos de firma, credenciales de BD, llaves de cifrado simétrico "maestras" | Se extraen del bundle o binario en minutos (`strings`, jadx, DevTools) | Backend / BFF / bóveda |
| Autorización ("¿es admin?", "¿puede ver este registro?") | El atacante modifica el JS o parchea el binario | Backend, en cada petición |
| Cálculo final de precios, descuentos, totales, comisiones, puntos | Manipulación del request o del código | Backend; el cliente solo muestra una estimación |
| Validación como único control | Se omite enviando la petición directamente (curl/Burp) | Backend (la validación del cliente es solo UX) |
| Lógica de licenciamiento o *paywall* como único control | Se parchea el `if (isPremium)` | Backend entrega el contenido o las capacidades según el derecho verificado |
| Reglas antifraude, umbrales, *scoring* | Se aprenden y evaden | Backend |
| Generación de tokens, OTP o semillas | Predecibles o extraíbles | Backend / IdP |
| Consultas SQL o filtros que definen el alcance de los datos | Inyección o ampliación del alcance | Backend con autorización por objeto |
| Lógica de juegos competitivos o de apuestas (resultado, RNG) | Trampas | Servidor autoritativo |

**Patrón Vulnerable (Qué NO hacer)**

```typescript
// VULNERABLE: el precio y el descuento se calculan y confían desde el cliente.
const total = cart.items.reduce((s, i) => s + i.price * i.qty, 0) * (isVip ? 0.8 : 1);
await fetch("/api/checkout", { method: "POST", body: JSON.stringify({ items: cart.items, total }) });

// VULNERABLE: "autorización" y secreto en el bundle.
const ADMIN_EMAILS = ["ceo@empresa.com"];
const SIGNING_SECRET = "b3f1...";                  // extraíble del bundle
if (ADMIN_EMAILS.includes(user.email)) showAdminPanel();
```

**Patrón Seguro (Qué SÍ hacer)**

```typescript
// Cliente: envía solo intención (IDs y cantidades). El precio lo determina el servidor.
await fetch("/api/checkout", {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
  body: JSON.stringify({ items: cart.items.map(({ sku, qty }) => ({ sku, qty })), couponCode }),
});
```

```python
# Servidor: recalcula con los precios del catálogo y valida el cupón y la elegibilidad.
@app.post("/api/checkout")
def checkout(req: CheckoutIn, user=Depends(get_current_user), db=Depends(get_db)):
    lines = [(db.get(Product, i.sku), i.qty) for i in req.items]
    if any(p is None or not p.active or not (1 <= q <= p.max_per_order) for p, q in lines):
        raise HTTPException(422)
    subtotal = sum(p.price * q for p, q in lines)
    discount = coupons.evaluate(req.coupon_code, user, subtotal)   # reglas en el servidor
    return create_order(user, lines, subtotal - discount)
```

---

## 3. Frontend Web (JavaScript/TypeScript)

### 3.1 Source maps en producción

**Mecánica:** un archivo `*.js.map` público reconstruye el código fuente original (nombres, comentarios, estructura y a veces rutas internas o secretos olvidados). Exponerlo es una divulgación de información (CWE-540).

**Patrón Vulnerable (Qué NO hacer)**

```javascript
// vite.config.ts / webpack.config.js
export default { build: { sourcemap: true } };      // genera y PUBLICA .map
module.exports = { devtool: "source-map" };          // .map junto al bundle
// Además: //# sourceMappingURL=app.js.map al final del bundle
```

**Patrón Seguro (Qué SÍ hacer)**

```typescript
// vite.config.ts
import { defineConfig } from "vite";

export default defineConfig(({ mode }) => ({
  build: {
    // "hidden": genera los .map SIN el comentario sourceMappingURL, para subirlos
    // de forma privada a la herramienta de errores (Sentry) y NO desplegarlos.
    sourcemap: mode === "production" ? "hidden" : true,
    minify: "terser",
    terserOptions: {
      compress: { drop_console: true, drop_debugger: true, passes: 2 },
      mangle: { toplevel: true },
      format: { comments: false },
    },
  },
  define: { __DEV__: mode !== "production" },  // permite eliminar ramas de debug (dead code elimination)
}));
```

```javascript
// webpack (producción)
module.exports = {
  mode: "production",
  devtool: "hidden-source-map",
  optimization: { minimize: true },
};
```

```bash
# Pipeline: subir los .map al servicio privado y eliminarlos del artefacto ANTES del deploy.
npx @sentry/cli sourcemaps upload --release "$GIT_SHA" ./dist
find ./dist -name "*.map" -delete
test -z "$(find ./dist -name '*.map')" || { echo "Source maps en artefacto"; exit 1; }
```

```nginx
# Defensa en profundidad: bloquear .map y archivos sensibles en el servidor web.
location ~* \.(map|env|git|bak|old|swp|sql|log)$ { deny all; return 404; }
location ~ /\.(?!well-known) { deny all; return 404; }
```

### 3.2 Minificación y ofuscación de JavaScript

| Técnica | Herramienta | Costo de rendimiento | Recomendación |
|---|---|---|---|
| Minificación + *mangling* | Terser, esbuild, SWC | Ninguno (mejora el tamaño) | **Obligatoria** en producción |
| Eliminación de código muerto y de debug | `define` + *tree shaking* | Ninguno | **Obligatoria** |
| Ofuscación (*string array*, *control flow flattening*, *dead code injection*) | `javascript-obfuscator` | Alto (hasta 2–5× en tamaño y CPU) | Solo para módulos de alto valor (anti-bot, DRM, lógica propietaria) |
| Lógica sensible en WebAssembly | Rust/C → WASM | Bajo | Eleva el costo del análisis, pero WASM también se descompila |

```javascript
// Ofuscación selectiva SOLO del módulo crítico (p. ej., recolector de señales anti-bot).
// webpack.config.js
const WebpackObfuscator = require("webpack-obfuscator");
module.exports = {
  module: {
    rules: [{
      test: /src\/antibot\/.*\.js$/,
      enforce: "post",
      use: {
        loader: WebpackObfuscator.loader,
        options: {
          compact: true,
          controlFlowFlattening: true,
          controlFlowFlatteningThreshold: 0.5,
          stringArray: true,
          stringArrayEncoding: ["rc4"],
          stringArrayThreshold: 0.75,
          selfDefending: true,
          debugProtection: false,       // true degrada la experiencia de usuarios legítimos con DevTools abiertas
          sourceMap: false,
        },
      },
    }],
  },
};
```

> **Nunca** ofusque un secreto para "esconderlo": un `stringArrayEncoding` se revierte ejecutando el propio código. Si el cliente necesita una llave, la llave **es pública** por definición.

### 3.3 Reducción de superficie en el bundle

- Elimine `console.log` de datos, los comentarios con TODO o credenciales y las URLs de entornos internos (`dev-api.interna.local`).
- No envíe la lista completa de rutas y roles al cliente si revela funciones administrativas: use *code splitting* por rol y cargue los módulos admin solo tras verificar el permiso en el servidor (el backend protege de todos modos).
- Valide el artefacto final:

```bash
# Escaneo del bundle construido en busca de secretos e indicadores internos
gitleaks dir ./dist --no-banner
grep -rEn "(localhost|\.internal|\.local|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|sk_live_|AKIA[0-9A-Z]{16})" ./dist && exit 1 || true
```

---

## 4. Aplicaciones móviles

### 4.1 Android

**Patrón Vulnerable (Qué NO hacer)**

```kotlin
// VULNERABLE: secreto en BuildConfig / strings.xml / código -> visible con jadx/apktool.
const val API_SECRET = "a9f8..."
// VULNERABLE: datos sensibles en SharedPreferences en claro y logs en release.
prefs.edit().putString("token", jwt).apply()
Log.d("AUTH", "token=$jwt")
```

```groovy
// VULNERABLE: release sin minify, debuggable y backups habilitados.
buildTypes { release { minifyEnabled false; debuggable true } }
// AndroidManifest.xml: android:allowBackup="true" android:usesCleartextTraffic="true"
```

**Patrón Seguro (Qué SÍ hacer)**

```kotlin
// build.gradle.kts (módulo app)
android {
    buildTypes {
        release {
            isMinifyEnabled = true            // R8: shrinking + optimización + ofuscación de nombres
            isShrinkResources = true
            isDebuggable = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}
```

```proguard
# proguard-rules.pro — eliminar logs en release y conservar solo lo necesario (reflexión/serialización)
-assumenosideeffects class android.util.Log { public static *** d(...); public static *** v(...); public static *** i(...); }
-keepattributes Signature, *Annotation*
-keep class com.empresa.api.dto.** { *; }
-repackageclasses ''
```

```xml
<!-- AndroidManifest.xml -->
<application
    android:allowBackup="false"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/network_security_config">
```

```kotlin
// Almacenamiento seguro: llave en Android Keystore (respaldada por hardware cuando existe).
// Nota: androidx.security:security-crypto (EncryptedSharedPreferences) fue deprecado en 2025;
// use Keystore + AES-GCM directamente o una librería mantenida (p. ej., Tink).
val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder("session_key", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .setUserAuthenticationRequired(false)
        .build()
)
keyGen.generateKey()
```

**Integridad y atestación (verificada en el servidor):**

```kotlin
// Play Integrity API: el cliente obtiene un token; el BACKEND lo descifra y verifica con Google
// (deviceIntegrity, appIntegrity, accountDetails) y el nonce/requestHash ligado a la operación.
val tokenResponse = integrityManager.requestIntegrityToken(
    IntegrityTokenRequest.builder().setNonce(serverIssuedNonce).build()
).await()
api.sensitiveOperation(payload, integrityToken = tokenResponse.token())
```

### 4.2 iOS

- Secretos y tokens en **Keychain** con `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (no `UserDefaults` ni plist).
- Compilar release con *stripping* de símbolos (`STRIP_INSTALLED_PRODUCT = YES`, `DEPLOYMENT_POSTPROCESSING = YES`) y sin logs de datos sensibles (`os_log` con `privacy: .private`).
- **App Attest / DeviceCheck** para atestar la integridad de la app, con verificación en el servidor.
- App Transport Security sin excepciones `NSAllowsArbitraryLoads`.

```swift
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "com.empresa.app",
    kSecAttrAccount as String: "refresh_token",
    kSecValueData as String: Data(token.utf8),
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
]
SecItemDelete(query as CFDictionary)
let status = SecItemAdd(query as CFDictionary, nil)
guard status == errSecSuccess else { throw KeychainError(status) }
```

### 4.3 Controles de resiliencia (MASVS-RESILIENCE)

| Control | Objetivo | Nota |
|---|---|---|
| Detección de root/jailbreak | Elevar el costo de la instrumentación | Evadible; úselo como **señal** de riesgo para el backend, no como bloqueo absoluto |
| Detección de depurador / Frida / hooking | Dificultar el análisis dinámico | Combine varias técnicas; actualícelas periódicamente |
| Verificación de firma del APK/IPA | Detectar reempaquetado | Más fiable con la atestación del servidor (Play Integrity/App Attest) |
| *Certificate pinning* | Dificultar el MITM en el análisis | Pinee la **llave pública (SPKI)** con un pin de respaldo y un plan de rotación; un error deja sin servicio a toda la base de usuarios |
| Ofuscación (R8/DexGuard, iXGuard, LLVM-obfuscator) | Elevar el costo de la ingeniería inversa | Las soluciones comerciales cifran strings y recursos |

```xml
<!-- res/xml/network_security_config.xml — pinning con respaldo y expiración -->
<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
  <domain-config>
    <domain includeSubdomains="true">api.empresa.com</domain>
    <pin-set expiration="2027-06-30">
      <pin digest="SHA-256">BASE64_SPKI_PRIMARIO=</pin>
      <pin digest="SHA-256">BASE64_SPKI_RESPALDO=</pin>
    </pin-set>
  </domain-config>
</network-security-config>
```

---

## 5. Binarios compilados, Electron y Python distribuido

| Plataforma | Endurecimiento |
|---|---|
| **C/C++/Rust/Go** | Strip de símbolos (`-s`, `strip`, `-ldflags="-s -w"` en Go), compilación sin asserts de debug, flags de *hardening* (`-fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie -Wl,-z,relro,-z,now`), firma de código (Authenticode, codesign) |
| **.NET** | Publicar en Release, *trimming*/NativeAOT, ofuscador (p. ej., ConfuserEx2, Dotfuscator) solo en ensamblados de alto valor, firma de ensamblados |
| **Electron** | `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, CSP, Fuses (`RunAsNode=false`, `EnableNodeCliInspectArguments=false`, `EnableEmbeddedAsarIntegrityValidation=true`, `OnlyLoadAppFromAsar=true`); **ASAR no es cifrado** |
| **Python distribuido (PyInstaller)** | El bytecode se recupera fácilmente (pyinstxtractor, decompyle). Mueva la lógica sensible al servidor; para elevar el costo use Nuitka (compilación a C) o Cython |
| **Firmware / IoT** | Secure boot, cifrado de flash (ESP32 Flash Encryption + Secure Boot v2), deshabilitar JTAG/UART de debug en producción, llaves únicas por dispositivo (nunca una llave global) |

**Electron — Patrón Vulnerable vs Seguro**

```javascript
// VULNERABLE
new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });

// SEGURO
new BrowserWindow({
  webPreferences: {
    contextIsolation: true,
    nodeIntegration: false,
    sandbox: true,
    preload: path.join(__dirname, "preload.js"),   // expone una API mínima vía contextBridge
  },
});
```

```bash
# Go: binario sin símbolos ni rutas de compilación
go build -trimpath -ldflags="-s -w -buildid=" -o app ./cmd/app
```

---

## 6. Verificación de artefactos

```bash
# Web: no hay .map públicos
curl -s -o /dev/null -w "%{http_code}\n" https://app.empresa.com/assets/index-abc123.js.map   # esperado: 404
curl -s https://app.empresa.com/assets/index-abc123.js | tail -c 200 | grep -c sourceMappingURL  # esperado: 0

# Android: inspección del release
apktool d app-release.apk -o out && grep -rEn "(api[_-]?key|secret|password)\s*[:=]" out/ || true
# MobSF (análisis estático automatizado) en CI para APK/IPA
docker run --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

---

## 7. Checklist de Verificación (antes de merge / deploy)

- [ ] No hay secretos, llaves privadas ni credenciales en el bundle web, el APK/IPA, el binario ni el ASAR (escaneo con Gitleaks sobre `dist/` y el artefacto descompilado).
- [ ] Toda regla de autorización, precio, descuento, límite o elegibilidad se valida y calcula en el servidor.
- [ ] Los source maps no se despliegan (`hidden-source-map` + subida privada + eliminación del artefacto), y el servidor responde 404 a `*.map`.
- [ ] El bundle de producción está minificado, sin `console.*` de datos, sin `debugger` ni comentarios, y sin URLs de entornos internos.
- [ ] La ofuscación avanzada se aplica solo a módulos de alto valor justificados, y se midió su impacto en el rendimiento.
- [ ] Android: R8 activo, `debuggable=false`, `allowBackup=false`, sin tráfico en claro, logs eliminados en release y tokens en Keystore.
- [ ] iOS: Keychain con `ThisDeviceOnly`, símbolos eliminados, ATS sin excepciones globales.
- [ ] La atestación de integridad (Play Integrity/App Attest) se verifica **en el backend** para las operaciones sensibles.
- [ ] El *pinning* (si aplica) usa SPKI con un pin de respaldo, una fecha de expiración y un plan de rotación probado.
- [ ] Electron: `contextIsolation`, `sandbox`, `nodeIntegration=false` y Fuses configurados.
- [ ] Los binarios nativos están firmados, sin símbolos y compilados con flags de hardening.
- [ ] MobSF/Semgrep no reportan hallazgos altos en el artefacto de release.

---

## 8. Referencias

- OWASP MASVS v2 y MASTG: https://mas.owasp.org/
- OWASP ASVS 5.0 — V3 Web Frontend Security, V13 Configuration: https://github.com/OWASP/ASVS
- Android: R8 / Network Security Configuration / Play Integrity API (developer.android.com)
- Apple: App Attest / Keychain Services (developer.apple.com)
- Electron Security Checklist: https://www.electronjs.org/docs/latest/tutorial/security
- CWE-602 Client-Side Enforcement of Server-Side Security: https://cwe.mitre.org/data/definitions/602.html
