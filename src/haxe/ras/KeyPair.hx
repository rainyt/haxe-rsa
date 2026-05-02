package haxe.ras;

/**
 * RSA密钥对
 *
 * 密钥格式因目标平台而异：
 * - Node.js / C++ / JVM：PEM格式字符串（公钥X.509 SPKI，私钥PKCS#8）
 * - 浏览器：JWK格式JSON字符串
 */
typedef KeyPair = {
	var publicKey: String;
	var privateKey: String;
}
