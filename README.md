# haxe-ras

Haxe 跨平台 RSA 加密库 — 提供 OAEP 加密/解密与 RSASSA-PKCS1-v1_5 签名/验签。

## 支持平台

| 平台 | 目标标志 | 密码学后端 | 密钥格式 | 最低版本 |
|------|----------|------------|----------|----------|
| **Node.js** | `-D nodejs` | `require('crypto')` | PEM (SPKI/PKCS8) | Node.js 12+ |
| **浏览器** | (默认 JS) | Web Crypto API (`SubtleCrypto`) | JWK | Chrome 37 / Firefox 34 / Safari 11 / Edge 79 |
| **C++ (macOS)** | `-cpp` | OpenSSL 3.x (EVP API) | PEM (SPKI/PKCS8) | macOS 10.9+ |
| **C++ (Linux)** | `-cpp` | OpenSSL 3.x / 1.1.x (EVP API) | PEM (SPKI/PKCS8) | glibc 2.17+ |
| **C++ (Windows)** | `-cpp` | OpenSSL (EVP API) | PEM (SPKI/PKCS8) | Windows 7+ |

### C++ 目标详细说明

- **macOS**：
  - hxcpp 默认部署目标为 macOS 10.9，实际最低系统版本取决于 OpenSSL 动态库自身的最低版本（Homebrew 预编译 OpenSSL 3.x 需 macOS 14.0+）。
  - 如需更低版本支持，可从源码编译 OpenSSL 并设置 `MACOSX_DEPLOYMENT_TARGET`。
  - Apple Silicon 原生 OpenSSL 需通过 Homebrew 安装 arm64 版本，或使用 `arch -x86_64` 以 Rosetta 模式编译运行。
- **Linux**: 需系统安装 `libssl-dev` 并修改 `src/haxe/ras/backend/hxcpp/RSA.hx` 中 `@:buildXml` 的 include/lib 路径。
- **Windows**: 需自行编译或安装 OpenSSL，调整 `@:buildXml` 中的路径和库名。

## 开发环境要求

| 工具 | 版本 |
|------|------|
| Haxe | 4.3.7+ |
| hxcpp | 4.3.96+ |
| hxnodejs | 12.2.0 |
| OpenSSL (仅 C++) | 1.1.x 或 3.x |

## 构建

```bash
# Node.js
haxe build.nodejs.hxml

# 浏览器
haxe build.js.hxml

# C++ (macOS x86_64)
arch -x86_64 haxe build.cpp.hxml
```

## 测试

```bash
# Node.js — 构建 + 运行
haxe test.nodejs.hxml

# C++ (macOS) — 构建 + 运行
arch -x86_64 haxe test.cpp.hxml

# 浏览器 — 仅构建，然后浏览器打开 bin/index.html
haxe test.js.hxml
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

所有平台的静态方法签名一致，仅同步/异步语义不同（Node.js 提供同步方法，浏览器返回 Promise，C++ 为同步）。

```haxe
// ---- 密钥生成 ----
RSA.generateKeyPair();              // → KeyPair {publicKey: String, privateKey: String}

// ---- OAEP 加密/解密 ----
RSA.encryptString("hello", pubKey); // → 加密后的 Base64 密文
RSA.decryptString(cipher, privKey); // → 原始明文

// ---- 签名/验签 (RSASSA-PKCS1-v1_5) ----
RSA.sign(data, privKey);            // → Bytes 签名
RSA.verify(data, sig, pubKey);      // → Bool

// ---- 自定义哈希 ----
RSA.sign(data, privKey, "sha512");
RSA.encrypt(data, pubKey, "sha1");
```

## 架构

```
src/haxe/ras/
├── KeyPair.hx                        # 共享密钥对 typedef
├── RSA.hx                            # 条件编译桥接 (typedef RSA = ...)
└── backend/
    ├── jsnode/RSA.hx                 # Node.js 实现
    ├── jsbrowser/RSA.hx              # 浏览器实现
    └── hxcpp/RSA.hx                  # C++ 实现 (OpenSSL)
```

每个目标的使用者代码完全相同 — `import haxe.ras.RSA`，桥接文件根据编译标志自动路由到对应后端。

## 许可

MIT
