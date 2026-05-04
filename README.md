# haxe-rsa

Cross-platform RSA encryption library for Haxe — OAEP encryption/decryption and RSASSA-PKCS1-v1_5 sign/verify.

[中文文档](README_CN.md)

## Supported Platforms

| Platform           | Target Flag  | Crypto Backend                         | Key Format            | Sync    | Async              | Minimum Version                       |
|--------------------|--------------|----------------------------------------|-----------------------|---------|--------------------|---------------------------------------|
| **Node.js**        | `-D nodejs`  | `require('crypto')`                    | PEM (SPKI/PKCS8)      | Full    | Full               | Node.js 12+                           |
| **Browser**        | (default JS) | Web Crypto API (`SubtleCrypto`)        | PEM / JWK (auto-detect) | None    | Full               | Chrome 37 / Firefox 34 / Safari 11    |
| **C++ (macOS)**    | `-cpp`       | OpenSSL 3.x (EVP API)                  | PEM (SPKI/PKCS8)      | Full    | Full (Timer.delay) | macOS 10.9+                           |
| **C++ (Linux)**    | `-cpp`       | OpenSSL 3.x / 1.1.x (EVP API)         | PEM (SPKI/PKCS8)      | Full    | Full (Timer.delay) | glibc 2.17+                           |
| **C++ (Windows)**  | `-cpp`       | OpenSSL (EVP API)                      | PEM (SPKI/PKCS8)      | Full    | Full (Timer.delay) | Windows 7+                            |
| **JVM**            | `--jvm`      | JDK `java.security` / `javax.crypto`   | PEM (SPKI/PKCS8)      | Full    | Full               | JDK 8+                                |

### C++ Async

C++ async methods use `haxe.Timer.delay(fn, 0)` for deferred execution. Callbacks fire automatically via the event loop. `Timer` references `MainLoop`, and hxcpp injects `EntryPoint.run()` at the end of `main()` to ensure async callbacks execute before the process exits.

### C++ Platform Notes

- **macOS**:
  - hxcpp default deployment target is macOS 10.9. The effective minimum OS version depends on the OpenSSL dylib (Homebrew's prebuilt OpenSSL 3.x requires macOS 14.0+).
  - For lower deployment targets, build OpenSSL from source and set `MACOSX_DEPLOYMENT_TARGET`.
  - Apple Silicon native OpenSSL requires the arm64 Homebrew build, or use `arch -x86_64` with Rosetta.
- **Linux**: Install `libssl-dev` and adjust the include/lib paths in `@:buildXml` inside `src/haxe/rsa/backend/hxcpp/RSA.hx`.
- **Windows**: Build or install OpenSSL and adjust the `@:buildXml` paths and library names accordingly.

## Prerequisites

| Tool              | Version      |
|-------------------|--------------|
| Haxe              | 4.3.7+       |
| hxcpp             | 4.3.96+      |
| hxnodejs          | 12.2.0       |
| OpenSSL (C++ only) | 1.1.x / 3.x |
| JDK (JVM only)    | 8+           |

## Build

```bash
# Node.js
haxe build.nodejs.hxml

# Browser
haxe build.js.hxml

# C++ (macOS x86_64)
arch -x86_64 haxe build.cpp.hxml

# JVM
haxe build.jvm.hxml
```

## Test

```bash
# Node.js — build + run
haxe test.nodejs.hxml

# C++ (macOS) — build + run
arch -x86_64 haxe test.cpp.hxml

# Browser — build only, then open bin/index.html
haxe test.js.hxml

# JVM — build + run
haxe test.jvm.hxml
```

## Install

```bash
haxelib install haxe-rsa
```

Or in your `.hxml`:

```
-lib haxe-rsa
```

## API

All backends implement the unified `IRSA` interface via instance methods. Unsupported methods throw errors (e.g. browser does not support sync).

### Synchronous

```haxe
var rsa = new RSA();

// ---- Key generation ----
var keyPair = rsa.generateKeyPair();   // → KeyPair {publicKey: String, privateKey: String}

// ---- OAEP encrypt/decrypt ----
rsa.encryptString("hello", pubKey);    // → Base64 ciphertext
rsa.decryptString(cipher, privKey);    // → plaintext

rsa.encrypt(bytes, pubKey);            // → Bytes ciphertext
rsa.decrypt(encryptedBytes, privKey);  // → Bytes plaintext

// ---- Sign/verify (RSASSA-PKCS1-v1_5) ----
rsa.sign(data, privKey);               // → Bytes signature
rsa.verify(data, sig, pubKey);         // → Bool

// ---- Custom hash ----
rsa.sign(data, privKey, "sha512");
rsa.encrypt(data, pubKey, "sha1");
```

### Async

Node.js, Browser, C++, and JVM all support async Promise-based calls:

```haxe
var rsa = new RSA();

// Chained
rsa.generateKeyPairAsync(2048).then(function(keyPair) {
    return rsa.encryptStringAsync("Hello", keyPair.publicKey);
}).then(function(encrypted) {
    trace("Encrypted: " + encrypted);
    return rsa.decryptStringAsync(encrypted, keyPair.privateKey);
}).then(function(decrypted) {
    trace("Decrypted: " + decrypted);
}).catchError(function(err) {
    trace("Error: " + err);
});

// Async sign/verify
rsa.signAsync(data, privKey).then(function(sig) {
    return rsa.verifyAsync(data, sig, pubKey);
}).then(function(ok) {
    trace("Verify: " + ok);
});
```

| Sync Method          | Async Method            | Description                          |
|----------------------|-------------------------|--------------------------------------|
| `generateKeyPair()`  | `generateKeyPairAsync()`  | Generate key pair                  |
| `encrypt()`          | `encryptAsync()`          | OAEP encrypt (Bytes)              |
| `decrypt()`          | `decryptAsync()`          | OAEP decrypt (Bytes)              |
| `sign()`             | `signAsync()`             | RSASSA-PKCS1-v1_5 sign            |
| `verify()`           | `verifyAsync()`           | RSASSA-PKCS1-v1_5 verify          |
| `encryptString()`    | `encryptStringAsync()`    | OAEP encrypt string (Base64 output) |
| `decryptString()`    | `decryptStringAsync()`    | OAEP decrypt string (Base64 input)  |

## Architecture

```
src/haxe/rsa/
├── KeyPair.hx                        # Shared KeyPair typedef
├── IRSA.hx                           # Unified interface
├── NativePromise.hx                  # Cross-platform Promise abstract
├── PromiseImpl.hx                    # Promise impl for non-JS targets
├── RSA.hx                            # Conditional-compilation bridge (typedef RSA = ...)
└── backend/
    ├── jsnode/RSA.hx                 # Node.js (crypto module)
    ├── jsbrowser/RSA.hx              # Browser (Web Crypto API)
    ├── hxcpp/RSA.hx                  # C++ (OpenSSL)
    └── jvm/RSA.hx                    # JVM (JDK)
```

All targets use identical code — `import haxe.rsa.RSA`. The bridge file routes to the correct backend based on compiler flags.

## License

MIT
