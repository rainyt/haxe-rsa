package haxe.ras;

/**
 * RSA密钥对
 *
 * 密钥格式因目标平台而异：
 * - Node.js：PEM格式字符串（公钥SPKI，私钥PKCS8）
 * - 浏览器：JWK格式JSON字符串
 */
typedef KeyPair = {
	var publicKey: String;
	var privateKey: String;
}
