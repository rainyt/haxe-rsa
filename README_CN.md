# haxe-rsa

Haxe 跨平台 RSA 加密库 — 提供 OAEP 加密/解密与 RSASSA-PKCS1-v1_5 签名/验签。

[English](README.md)

## 支持平台

| 平台 | 目标标志 | 密码学后端 | 密钥格式 | 同步 | 异步 | 最低版本 |
|------|----------|------------|----------|------|------|----------|
| **Node.js** | `-D nodejs` | `require('crypto')` | PEM (SPKI/PKCS8) | 全部 | 全部 | Node.js 12+ |
| **浏览器** | (默认 JS) | Web Crypto API (`SubtleCrypto`) | PEM / JWK（自动识别） | 不支持 | 全部 | Chrome 37 / Firefox 34 / Safari 11 |
| **C++ (macOS)** | `-cpp` | OpenSSL 3.x (EVP API) | PEM (SPKI/PKCS8) | 全部 | 全部（Timer.delay） | macOS 10.9+ |
| **C++ (Linux)** | `-cpp` | OpenSSL 3.x / 1.1.x (EVP API) | PEM (SPKI/PKCS8) | 全部 | 全部（Timer.delay） | glibc 2.17+ |
| **C++ (Windows)** | `-cpp` | OpenSSL (EVP API) | PEM (SPKI/PKCS8) | 全部 | 全部（Timer.delay） | Windows 7+ |
| **JVM** | `--jvm` | JDK `java.security` / `javax.crypto` | PEM (SPKI/PKCS8) | 全部 | 全部 | JDK 8+ |

### C++ 异步说明

C++ 目标的异步方法基于 `haxe.Timer.delay(fn, 0)` 延迟执行，回调在程序事件循环中自动触发。`Timer` 内部引用 `MainLoop`，hxcpp 会在 `main()` 末尾自动注入 `EntryPoint.run()`，确保异步回调在进程退出前执行。

### C++ 目标详细说明

- **macOS**：
  - hxcpp 默认部署目标为 macOS 10.9，实际最低系统版本取决于 OpenSSL 动态库自身的最低版本（Homebrew 预编译 OpenSSL 3.x 需 macOS 14.0+）。
  - 如需更低版本支持，可从源码编译 OpenSSL 并设置 `MACOSX_DEPLOYMENT_TARGET`。
  - Apple Silicon 原生 OpenSSL 需通过 Homebrew 安装 arm64 版本，或使用 `arch -x86_64` 以 Rosetta 模式编译运行。
- **Linux**: 需系统安装 `libssl-dev` 并修改 `src/haxe/rsa/backend/hxcpp/RSA.hx` 中 `@:buildXml` 的 include/lib 路径。
- **Windows**: 需自行编译或安装 OpenSSL，调整 `@:buildXml` 中的路径和库名。

## 开发环境要求

| 工具 | 版本 |
|------|------|
| Haxe | 4.3.7+ |
| hxcpp | 4.3.96+ |
| hxnodejs | 12.2.0 |
| OpenSSL (仅 C++) | 1.1.x 或 3.x |
| JDK (仅 JVM) | 8+ |

## 构建

```bash
# Node.js
haxe build.nodejs.hxml

# 浏览器
haxe build.js.hxml

# C++ (macOS x86_64)
arch -x86_64 haxe build.cpp.hxml

# JVM
haxe build.jvm.hxml
```

## 测试

```bash
# Node.js — 构建 + 运行
haxe test.nodejs.hxml

# C++ (macOS) — 构建 + 运行
arch -x86_64 haxe test.cpp.hxml

# 浏览器 — 仅构建，然后浏览器打开 bin/index.html
haxe test.js.hxml

# JVM — 构建 + 运行
haxe test.jvm.hxml
```

## 安装

```bash
haxelib install haxe-ras
```

或在 `.hxml` 中：

```
-lib haxe-ras
```

## API

所有后端实现统一 `IRSA` 接口，通过实例方法调用。不支持的方法会直接抛错（如浏览器不支持同步，C++ 异步已实现）。

### 同步接口

```haxe
var rsa = new RSA();

// ---- 密钥生成 ----
var keyPair = rsa.generateKeyPair();   // → KeyPair {publicKey: String, privateKey: String}

// ---- OAEP 加密/解密 ----
rsa.encryptString("hello", pubKey);    // → 加密后的 Base64 密文
rsa.decryptString(cipher, privKey);    // → 原始明文

rsa.encrypt(bytes, pubKey);            // → Bytes 密文
rsa.decrypt(encryptedBytes, privKey);  // → Bytes 明文

// ---- 签名/验签 (RSASSA-PKCS1-v1_5) ----
rsa.sign(data, privKey);               // → Bytes 签名
rsa.verify(data, sig, pubKey);         // → Bool

// ---- 自定义哈希 ----
rsa.sign(data, privKey, "sha512");
rsa.encrypt(data, pubKey, "sha1");
```

### 异步接口

Node.js、浏览器、C++、JVM 四平台均支持异步 Promise 调用：

```haxe
var rsa = new RSA();

// 链式调用
rsa.generateKeyPairAsync(2048).then(function(keyPair) {
    return rsa.encryptStringAsync("Hello", keyPair.publicKey);
}).then(function(encrypted) {
    trace("加密完成: " + encrypted);
    return rsa.decryptStringAsync(encrypted, keyPair.privateKey);
}).then(function(decrypted) {
    trace("解密完成: " + decrypted);
}).catchError(function(err) {
    trace("错误: " + err);
});

// 异步签名/验签
rsa.signAsync(data, privKey).then(function(sig) {
    return rsa.verifyAsync(data, sig, pubKey);
}).then(function(ok) {
    trace("验签: " + ok);
});
```

| 方法（同步） | 方法（异步） | 说明 |
|-------------|-------------|------|
| `generateKeyPair()` | `generateKeyPairAsync()` | 生成密钥对 |
| `encrypt()` | `encryptAsync()` | OAEP 公钥加密 Bytes |
| `decrypt()` | `decryptAsync()` | OAEP 私钥解密 Bytes |
| `sign()` | `signAsync()` | RSASSA-PKCS1-v1_5 签名 |
| `verify()` | `verifyAsync()` | RSASSA-PKCS1-v1_5 验签 |
| `encryptString()` | `encryptStringAsync()` | OAEP 字符串加密（Base64 输出） |
| `decryptString()` | `decryptStringAsync()` | OAEP 字符串解密（Base64 输入） |

## 架构

```
src/haxe/rsa/
├── KeyPair.hx                        # 共享密钥对 typedef
├── IRSA.hx                           # 统一接口定义
├── NativePromise.hx                  # 跨平台 Promise 抽象类型
├── PromiseImpl.hx                    # 非 JS 平台的 Promise 实现
├── RSA.hx                            # 条件编译桥接 (typedef RSA = ...)
└── backend/
    ├── jsnode/RSA.hx                 # Node.js 实现
    ├── jsbrowser/RSA.hx              # 浏览器实现
    ├── hxcpp/RSA.hx                  # C++ 实现 (OpenSSL)
    └── jvm/RSA.hx                    # JVM 实现 (JDK)
```

每个目标的使用者代码完全相同 — `import haxe.rsa.RSA`，桥接文件根据编译标志自动路由到对应后端。

## 许可

MIT
