# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

haxe-ras 是一个在 Haxe 中实现 RSA 加密的跨平台库。Haxe 可编译至 JS、Python、C++、Java、C#、PHP 等多种目标，核心挑战在于各平台密码学支持不一致。第一个版本可仅支持JS目标。

## 构建与测试

- `haxe build.hxml` — 编译项目（默认目标）
- `haxe build.<target>.hxml` — 编译特定目标平台（如 js.hxml、python.hxml、java.hxml）
- `haxe test.hxml` — 运行测试

## 架构核心

**跨平台策略**：通过 Haxe 条件编译（`#if js / #elseif python / ...`）为不同目标选择实现路径：
- 有原生密码学支持的平台（Node.js crypto、Python pycrypto、Java security）优先绑定底层库
- 无原生支持的平台使用 `haxe.crypto.BigInteger` 纯 Haxe 实现

**关键模块划分**：
1. **大数运算层** — 统一接口封装 `BigInteger` 或平台原生大数（`java.math.BigInteger` 等）
2. **密钥解析层** — PEM/DER 解码、Base64、ASN.1 解析，输出 `{n, e, d}` 结构
3. **填充层** — PKCS#1 v1.5 或 RSA-OAEP，依赖安全随机数
4. **随机数层** — 封装各平台安全随机源（`getSecureRandomBytes`）
5. **RSA 核心** — 模幂运算 `m^e mod n`，公钥加密/私钥解密

**数据类型注意**：
- Haxe 标准 `Int` 为 32/64 位，无法直接处理 2048 位 RSA 密钥
- 密钥和运算结果使用 `String` 或 `Bytes` 传递，内部使用大整数类型

**安全要求**：
- 填充必须使用真随机数（不可固定种子），生产环境禁用固定种子
- 私钥不可硬编码或输出到日志
- 大批量数据应使用混合加密（RSA 封装对称密钥）
