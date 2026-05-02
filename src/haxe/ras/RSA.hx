package haxe.ras;

#if (js && nodejs)
import js.node.Crypto;
import js.node.Constants;
import js.node.Buffer;
import js.lib.Promise;
#end

/**
 * RSA密钥对
 */
typedef KeyPair = {
	/** PEM格式公钥（SPKI） */
	publicKey: String,
	/** PEM格式私钥（PKCS8） */
	privateKey: String,
}

/**
 * RSA加密/解密/签名/验证
 *
 * 基于Node.js crypto模块实现，支持PKCS#1 v1.5和OAEP填充。
 */
class RSA {
	#if (js && nodejs)

	/** PKCS#1 v1.5 填充常量 */
	static var PKCS1_PADDING(get, never): Int;
	static function get_PKCS1_PADDING() return Constants.RSA_PKCS1_PADDING;

	/** PKCS#1 OAEP 填充常量 */
	static var OAEP_PADDING(get, never): Int;
	static function get_OAEP_PADDING() return Constants.RSA_PKCS1_OAEP_PADDING;

	// ---- 密钥生成 ----

	/**
	 * 同步生成RSA密钥对
	 * @param modulusLength 密钥长度（位），默认2048
	 * @param publicExponent 公钥指数，默认65537
	 */
	public static function generateKeyPairSync(modulusLength: Int = 2048,
		publicExponent: Int = 65537): KeyPair {
		var result = js.Syntax.code("require('crypto').generateKeyPairSync('rsa', {0})", {
			modulusLength: modulusLength,
			publicExponent: publicExponent,
			publicKeyEncoding: {type: "spki", format: "pem"},
			privateKeyEncoding: {type: "pkcs8", format: "pem"}
		});
		return {
			publicKey: result.publicKey,
			privateKey: result.privateKey
		};
	}

	/**
	 * 异步生成RSA密钥对
	 * @param modulusLength 密钥长度（位），默认2048
	 */
	public static function generateKeyPair(modulusLength: Int = 2048,
		publicExponent: Int = 65537): Promise<KeyPair> {
		return new Promise((resolve, reject) -> {
			js.Syntax.code("require('crypto').generateKeyPair('rsa', {0}, {1})", {
				modulusLength: modulusLength,
				publicExponent: publicExponent,
				publicKeyEncoding: {type: "spki", format: "pem"},
				privateKeyEncoding: {type: "pkcs8", format: "pem"}
			}, (err, publicKey, privateKey) -> {
				if (err != null) reject(err)
				else resolve({publicKey: publicKey, privateKey: privateKey});
			});
		});
	}

	// ---- 加密/解密 (OAEP) ----
	// Node.js v22+ 不支持 RSA_PKCS1_PADDING 用于 privateDecrypt
	// 因此统一使用 OAEP 作为加密/解密方案

	/**
	 * 公钥加密 (OAEP填充)
	 * @param data 明文Buffer
	 * @param publicKeyPem PEM格式公钥
	 * @param oaepHash OAEP哈希算法，默认"sha256"
	 */
	public static function publicEncrypt(data: Buffer, publicKeyPem: String,
		oaepHash: String = "sha256"): Buffer {
		return untyped Crypto.publicEncrypt(
			{key: publicKeyPem, padding: OAEP_PADDING, oaepHash: oaepHash}, data);
	}

	/**
	 * 私钥解密 (OAEP填充)
	 * @param data 密文Buffer
	 * @param privateKeyPem PEM格式私钥
	 * @param oaepHash OAEP哈希算法，默认"sha256"
	 */
	public static function privateDecrypt(data: Buffer, privateKeyPem: String,
		oaepHash: String = "sha256"): Buffer {
		return untyped Crypto.privateDecrypt(
			{key: privateKeyPem, padding: OAEP_PADDING, oaepHash: oaepHash}, data);
	}

	/**
	 * 私钥加密 (PKCS#1 v1.5填充) — 底层签名操作
	 */
	public static function privateEncrypt(data: Buffer, privateKeyPem: String): Buffer {
		return Crypto.privateEncrypt(cast {key: privateKeyPem, padding: PKCS1_PADDING}, data);
	}

	/**
	 * 公钥解密 (PKCS#1 v1.5填充) — 底层验签操作
	 */
	public static function publicDecrypt(data: Buffer, publicKeyPem: String): Buffer {
		return Crypto.publicDecrypt(cast {key: publicKeyPem, padding: PKCS1_PADDING}, data);
	}

	// ---- 签名/验签 ----

	/**
	 * RSA签名 (PKCS#1 v1.5 + 哈希)
	 * @param algorithm 哈希算法，默认"sha256"
	 */
	public static function sign(data: Buffer, privateKeyPem: String,
		algorithm: String = "sha256"): Buffer {
		var signer = Crypto.createSign("RSA-" + algorithm.toUpperCase());
		signer.update(data);
		return signer.sign(privateKeyPem);
	}

	/**
	 * RSA验签
	 * @param algorithm 哈希算法，默认"sha256"
	 */
	public static function verify(data: Buffer, signature: Buffer, publicKeyPem: String,
		algorithm: String = "sha256"): Bool {
		var verifier = Crypto.createVerify("RSA-" + algorithm.toUpperCase());
		verifier.update(data);
		return verifier.verify(publicKeyPem, signature);
	}

	// ---- 便捷方法 ----

	/**
	 * 公钥加密字符串 (OAEP)
	 * @return Base64编码的密文
	 */
	public static function encryptString(plaintext: String, publicKeyPem: String,
		oaepHash: String = "sha256", inputEncoding: String = "utf8",
		outputEncoding: String = "base64"): String {
		var encrypted = publicEncrypt(Buffer.from(plaintext, inputEncoding), publicKeyPem, oaepHash);
		return encrypted.toString(outputEncoding);
	}

	/**
	 * 私钥解密字符串 (OAEP)
	 * @param ciphertext Base64编码的密文
	 */
	public static function decryptString(ciphertext: String, privateKeyPem: String,
		oaepHash: String = "sha256", inputEncoding: String = "base64",
		outputEncoding: String = "utf8"): String {
		var decrypted = privateDecrypt(Buffer.from(ciphertext, inputEncoding), privateKeyPem, oaepHash);
		return decrypted.toString(outputEncoding);
	}

	#else
	#error "haxe-ras 当前版本仅支持 Node.js 目标。请使用 -D nodejs 编译，并确认目标平台为 js。"
	#end
}
