# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

haxe-ras 是一个在 Haxe 中实现 RSA 加密的跨平台库（OAEP 加密 + RSASSA-PKCS1-v1_5 签名）。目前已支持 JS（Node.js / 浏览器）、C++（hxcpp）和 Java（JVM）目标。

## 构建与测试

- `haxe build.nodejs.hxml` — 编译 Node.js 库
- `haxe build.js.hxml` — 编译浏览器库
- `haxe build.cpp.hxml` — 编译 C++ 库
- `haxe test.nodejs.hxml` — 运行 Node.js 测试
- `haxe test.js.hxml` — 编译浏览器测试（在浏览器中打开 bin/index.html）
- `arch -x86_64 haxe test.cpp.hxml` — 编译并运行 C++ 测试（macOS 需 Rosetta，因 Homebrew OpenSSL 为 x86_64）
- `haxe build.jvm.hxml` — 编译 JVM 库
- `haxe test.jvm.hxml` — 编译并运行 JVM 测试

## 架构

**桥接模式**：`RSA.hx` 通过条件编译 `typedef` 将 `RSA` 类型别名指向对应后端：

```
#if (js && nodejs)        typedef RSA = haxe.ras.backend.jsnode.RSA
#elseif (js && !nodejs)   typedef RSA = haxe.ras.backend.jsbrowser.RSA
#elseif cpp               typedef RSA = haxe.ras.backend.hxcpp.RSA
#elseif jvm               typedef RSA = haxe.ras.backend.jvm.RSA
```

**文件结构**：
- `src/haxe/ras/KeyPair.hx` — 共享密钥对 typedef
- `src/haxe/ras/RSA.hx` — 条件编译桥接
- `src/haxe/ras/backend/jsnode/RSA.hx` — Node.js（crypto 模块，PEM 密钥，同步+异步）
- `src/haxe/ras/backend/jsbrowser/RSA.hx` — 浏览器（Web Crypto API，JWK 密钥，全异步）
- `src/haxe/ras/backend/hxcpp/RSA.hx` — C++（OpenSSL EVP API，PEM 密钥，同步）
- `src/haxe/ras/backend/jvm/RSA.hx` — JVM（JDK java.security / javax.crypto，PEM 密钥，同步+异步）

每个后端文件由目标平台的条件编译守卫包裹（`#if (js && nodejs)` 等），互不干扰。

**关键设计**：
- 密钥格式因平台而异：Node.js/C++/JVM 使用 PEM，浏览器使用 JWK
- C++ 后端通过 `@:headerCode` 内联 OpenSSL C 代码，通过 `untyped __cpp__` 桥接
- JVM 后端通过 `@:native` 外部类桥接 JDK 内置加解密 API，`BytesData` 直接对应 Java `byte[]`
- C++ 后端在 macOS 上需 `arch -x86_64`（OpenSSL 仅提供 x86_64 dylib）
