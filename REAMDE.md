# haxe-ras
RSA 在 Haxe 中的实现注意事项
1. 环境与平台差异
Haxe 可编译至 JS、Python、C++、Java、C#、PHP 等多种目标。

不同目标的标准库加密支持不一致：

sys.crypto 仅部分平台（如 Java、C#）有完整 RSA 支持。

JS 目标无法直接使用系统 RSA，需依赖外部库如 js.node.crypto（Node.js）或 js.html.crypto（Web Crypto API）。

推荐使用纯 Haxe 实现或交叉编译友好的库，如 haxe-crypto（纯 Haxe 大数运算）。

2. 密钥格式与编码
RSA 密钥通常以 PEM 或 DER 存储。

Haxe 中需自行处理 Base64、ASN.1 解析。

注意：

使用 haxe.crypto.Base64 编解码。

需要 ASN.1 解析器从 PEM 中提取模数（n）和指数（e/d）。

推荐封装为 {n: String, e: String, d: String} 结构。

3. 大数运算
RSA 核心为大整数模幂运算（m^e mod n）。

Haxe 标准库 Int 最大 32/64 位，无法直接处理 2048 位大整数。

必须使用：

haxe.crypto.BigInteger（纯 Haxe，性能较低但跨平台）

或平台原生 BigInteger（Java: java.math.BigInteger，C#: System.Numerics.BigInteger）

建议定义统一的大整数接口，通过条件编译选择实现。

4. 填充方案（Padding）—— 极易出错
绝不能直接对明文做 m^e mod n，会导致确定性加密和选择明文攻击。

必须实现的填充标准：

RSA PKCS#1 v1.5 padding（最常见，需自己实现）

RSA-OAEP（更安全，实现更复杂）

填充代码需注意：

随机字节生成（需安全随机数，见下条）。

长度检查：最大明文长度 = 密钥位数/8 - 填充长度（PKCS#1 为 11 字节）。

5. 随机数质量
填充需要不可预测的随机数。

各平台随机数获取方式：

JS：js.html.Crypto.getRandomValues

Python：python.lib.Random 不适用，需 os.urandom

Java：java.security.SecureRandom

C++：需借助 sys.io.File 读取 /dev/urandom 或平台特定 API。

建议封装 getSecureRandomBytes(length:Int):Bytes 并针对目标平台条件编译。

6. 性能考量
公钥加密（指数 e=65537）较快，私钥解密（大指数 d）很慢。

避免在 Haxe/JS 或纯 Haxe 大数下处理大于 2048 位密钥。

批量加密时应使用对称加密 + RSA 封装密钥（混合加密），而非直接 RSA 大量数据。

7. 跨平台一致性测试
同一明文字符串，在不同目标下 RSA 加密结果应该不同（因随机填充），但解密后应相同。

测试时需固定随机种子仅用于调试，生产环境必须用真随机。

建议提供跨平台测试向量（已知密钥 + 已知填充结果）。

8. 常见错误避免
不检查输入长度 → 运行时崩溃或数据截断。

不做端序转换 → 大整数字节序与整数表示不匹配。

重用相同的随机数或固定填充 → 失去语义安全。

将私钥硬编码或打印到日志 → 安全泄露。

9. 推荐库与最小实现路径
若目标为 AI 辅助实现：

直接用 haxe.crypto.Signer + RSA（仅签名，非加密）。

如需纯加密，推荐绑定现有底层库而非从零实现大数：

Node.js：js.node.crypto.publicEncrypt

Python：python.lib.Crypto.PublicKey.RSA

Java：java.security.Cipher

若必须纯 Haxe 跨平台：基于 haxe.crypto.BigInteger 并手动实现 PKCS#1 v1.5。