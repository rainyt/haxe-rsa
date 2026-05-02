# haxe-ras 使用文档

## 目录

1. [快速开始](#快速开始)
2. [密钥对](#密钥对)
3. [加密与解密 (OAEP)](#加密与解密-oaep)
4. [签名与验签 (RSASSA-PKCS1-v1_5)](#签名与验签-rsassa-pkcs1v1_5)
5. [字节级操作](#字节级操作)
6. [哈希算法选择](#哈希算法选择)
7. [各平台差异](#各平台差异)
8. [错误处理](#错误处理)
9. [安全建议](#安全建议)

---

## 快速开始

```haxe
import haxe.ras.RSA;

// 1. 生成密钥对
var key = RSA.generateKeyPair(2048);

// 2. 加密
var cipher = RSA.encryptString("Hello, RSA!", key.publicKey);

// 3. 解密
var plain = RSA.decryptString(cipher, key.privateKey);
// plain == "Hello, RSA!"
```

> **注意**：浏览器目标的所有方法返回 `Promise<T>`，需用 `.then()` 或 `await` 处理。详见[各平台差异](#各平台差异)。

---

## 密钥对

### 生成

```haxe
// 2048 位（默认）
var key = RSA.generateKeyPair();

// 4096 位（更高安全性，但操作更慢）
var key = RSA.generateKeyPair(4096);

// Node.js 额外提供同步方法
var key = RSA.generateKeyPairSync(2048);
```

### KeyPair 结构

```haxe
typedef KeyPair = {
    var publicKey: String;   // 公钥
    var privateKey: String;  // 私钥
}
```

密钥格式随平台而异：
- **Node.js / C++ / JVM**：PEM 字符串，形如 `-----BEGIN PUBLIC KEY-----...`
- **浏览器**：支持 PEM 和 JWK JSON 字符串，自动识别格式

---

## 加密与解密 (OAEP)

OAEP 是推荐的 RSA 填充方案，安全性优于 PKCS#1 v1.5。

### 字符串级

```haxe
// 公钥加密
var cipher = RSA.encryptString("敏感数据", key.publicKey);
// 返回 Base64 编码的密文字符串

// 私钥解密
var plain = RSA.decryptString(cipher, key.privateKey);
// 返回原始明文字符串
```

### 自定义哈希

```haxe
var cipher = RSA.encryptString("数据", key.publicKey, "sha512");
var plain = RSA.decryptString(cipher, key.privateKey, "sha512");
```

### RSA 长度限制

2048 位 RSA-OAEP 最多加密 `模长 - 2*hashLen - 2` 字节：

| 密钥长度 | OAEP-SHA256 | OAEP-SHA512 |
|----------|-------------|-------------|
| 2048 位 | 190 字节 | 94 字节 |
| 4096 位 | 446 字节 | 350 字节 |

长文本应使用混合加密（RSA 加密对称密钥 + AES 加密数据）。

---

## 签名与验签 (RSASSA-PKCS1-v1_5)

### 字符串签名

```haxe
import haxe.io.Bytes;

var data = Bytes.ofString("需要签名的数据");

// 私钥签名
var signature = RSA.sign(data, key.privateKey);

// 公钥验签
var valid = RSA.verify(data, signature, key.publicKey);
if (valid) {
    trace("签名有效，数据未被篡改");
}
```

### 自定义签名算法

```haxe
var sig = RSA.sign(data, key.privateKey, "sha512");
var ok = RSA.verify(data, sig, key.publicKey, "sha512");
```

---

## 字节级操作

来自/到文件、网络的数据通常是 `Bytes`，可直接操作：

```haxe
// 加密 Bytes
var plainData = Bytes.ofString("二进制数据");
var encryptedData = RSA.encrypt(plainData, key.publicKey);

// 解密 Bytes
var decryptedData = RSA.decrypt(encryptedData, key.privateKey);

// 签名 Bytes
var sig = RSA.sign(plainData, key.privateKey);

// 验签 Bytes
var valid = RSA.verify(plainData, sig, key.publicKey);
```

**Node.js 独有**：Node.js 后端额外支持 `Buffer` 类型的加密/解密。

```haxe
#if (js && nodejs)
import js.node.Buffer;

var buf = Buffer.from("数据", "utf8");
var encrypted = RSA.publicEncrypt(buf, key.publicKey);
var decrypted = RSA.privateDecrypt(encrypted, key.privateKey);
#end
```

---

## 哈希算法选择

支持的哈希算法：

| 参数值 | 说明 |
|--------|------|
| `"sha256"` | 默认，推荐 |
| `"sha384"` | 更高安全性 |
| `"sha512"` | 最高安全性，但 OAEP 有效载荷更小 |
| `"sha1"` | 不推荐（仅用于兼容旧系统） |

```haxe
// 加密时指定
RSA.encryptString("data", key.publicKey, "sha512");

// 签名时指定（第四个参数）
RSA.sign(data, key.privateKey, "sha384");
RSA.verify(data, sig, key.publicKey, "sha384");
```

---

## 各平台差异

### 同步 / 异步

| 平台 | 同步方法 | 异步方法 |
|------|----------|----------|
| Node.js | `generateKeyPairSync()`、`encryptString()`、`decryptString()`、`sign()`、`verify()` | `generateKeyPair()` |
| 浏览器 | — | 所有方法返回 `Promise<T>` |
| C++ | 全部同步 | — |

### 浏览器异步链式调用

```haxe
RSA.generateKeyPair().then(function(key) {
    return RSA.encryptString("数据", key.publicKey);
}).then(function(cipher) {
    trace("加密完成: " + cipher);
}).catchError(function(err) {
    trace("出错了: " + err);
});
```

### 密钥跨平台

PEM 格式密钥可在所有平台（Node.js / C++ / JVM / 浏览器）直接使用，无需转换。浏览器后端会自动识别 PEM 并转为 Web Crypto API 所需的 DER 格式导入。

JWK 格式密钥仅限浏览器端使用。如需在其他平台使用浏览器导出的 JWK，需先转换为 PEM。

---

## 错误处理

```haxe
try {
    var key = RSA.generateKeyPair(2048);
    var cipher = RSA.encryptString("数据", key.publicKey);
    var plain = RSA.decryptString(cipher, key.privateKey);
} catch (e:Dynamic) {
    trace("RSA 操作失败: " + e);
}
```

常见错误原因：
- 解密时公/私钥不匹配
- 明文超过密钥长度限制
- 传入的 PEM/JWK 格式错误
- 浏览器中使用了错误的哈希算法导入密钥

---

## 安全建议

1. **密钥长度**：生产环境使用 2048 位以上，敏感场景用 4096 位。
2. **长数据加密**：不要直接用 RSA 加密大量数据，应使用混合加密 — 生成随机 AES 密钥，RSA 加密 AES 密钥，AES 加密数据。
3. **私钥安全**：私钥不可硬编码、不可提交到版本控制、不可输出到日志。
4. **OAEP 优于 PKCS#1 v1.5**：加密场景始终使用 OAEP，v1.5 填充仅用于签名。
5. **SHA-1 已过时**：新系统不应使用 `"sha1"`，最低使用 `"sha256"`。
6. **密钥管理**：私钥应存储在安全环境（密钥管理服务、HSM、环境变量），避免明文落盘。
