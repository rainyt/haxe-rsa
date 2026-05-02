package haxe.ras.backend.jsnode;

#if (js && nodejs)

import js.node.Crypto;
import js.node.Constants;
import js.node.Buffer;
import js.lib.Promise;
import haxe.io.Bytes;
import haxe.ras.KeyPair;

class RSA {
	/** PKCS#1 v1.5 填充常量 */
	static var PKCS1_PADDING(get, never): Int;
	static function get_PKCS1_PADDING() return Constants.RSA_PKCS1_PADDING;

	/** PKCS#1 OAEP 填充常量 */
	static var OAEP_PADDING(get, never): Int;
	static function get_OAEP_PADDING() return Constants.RSA_PKCS1_OAEP_PADDING;

	// ---- 密钥生成 ----

	/** 同步生成RSA密钥对 */
	public static function generateKeyPairSync(modulusLength: Int = 2048,
		publicExponent: Int = 65537): KeyPair {
		var result = js.Syntax.code("require('crypto').generateKeyPairSync('rsa', {0})", {
			modulusLength: modulusLength,
			publicExponent: publicExponent,
			publicKeyEncoding: {type: "spki", format: "pem"},
			privateKeyEncoding: {type: "pkcs8", format: "pem"}
		});
		return {publicKey: result.publicKey, privateKey: result.privateKey};
	}

	/** 异步生成RSA密钥对 */
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

	// ---- OAEP 加密/解密 ----

	/** 公钥加密 (OAEP填充) */
	public static function publicEncrypt(data: Buffer, publicKeyPem: String,
		oaepHash: String = "sha256"): Buffer {
		return untyped Crypto.publicEncrypt(
			{key: publicKeyPem, padding: OAEP_PADDING, oaepHash: oaepHash}, data);
	}

	/** 私钥解密 (OAEP填充) */
	public static function privateDecrypt(data: Buffer, privateKeyPem: String,
		oaepHash: String = "sha256"): Buffer {
		return untyped Crypto.privateDecrypt(
			{key: privateKeyPem, padding: OAEP_PADDING, oaepHash: oaepHash}, data);
	}

	/** 私钥加密 (PKCS#1 v1.5) — 底层签名操作 */
	public static function privateEncrypt(data: Buffer, privateKeyPem: String): Buffer {
		return Crypto.privateEncrypt(cast {key: privateKeyPem, padding: PKCS1_PADDING}, data);
	}

	/** 公钥解密 (PKCS#1 v1.5) — 底层验签操作 */
	public static function publicDecrypt(data: Buffer, publicKeyPem: String): Buffer {
		return Crypto.publicDecrypt(cast {key: publicKeyPem, padding: PKCS1_PADDING}, data);
	}

	// ---- 签名/验签 ----

	/** RSA签名 */
	public static function sign(data: Buffer, privateKeyPem: String,
		algorithm: String = "sha256"): Buffer {
		var signer = Crypto.createSign("RSA-" + algorithm.toUpperCase());
		signer.update(data);
		return signer.sign(privateKeyPem);
	}

	/** RSA验签 */
	public static function verify(data: Buffer, signature: Buffer, publicKeyPem: String,
		algorithm: String = "sha256"): Bool {
		var verifier = Crypto.createVerify("RSA-" + algorithm.toUpperCase());
		verifier.update(data);
		return verifier.verify(publicKeyPem, signature);
	}

	// ---- 字符串便捷方法 ----

	/** 公钥加密字符串 (OAEP) — 返回base64密文 */
	public static function encryptString(plaintext: String, publicKeyPem: String,
		oaepHash: String = "sha256", inputEncoding: String = "utf8",
		outputEncoding: String = "base64"): String {
		var encrypted = publicEncrypt(Buffer.from(plaintext, inputEncoding), publicKeyPem, oaepHash);
		return encrypted.toString(outputEncoding);
	}

	/** 私钥解密字符串 (OAEP) — 输入base64密文 */
	public static function decryptString(ciphertext: String, privateKeyPem: String,
		oaepHash: String = "sha256", inputEncoding: String = "base64",
		outputEncoding: String = "utf8"): String {
		var decrypted = privateDecrypt(Buffer.from(ciphertext, inputEncoding), privateKeyPem, oaepHash);
		return decrypted.toString(outputEncoding);
	}

	// ---- 跨平台异步接口 (*Async) ----

	/** 异步生成RSA密钥对（generateKeyPair 别名） */
	public static function generateKeyPairAsync(modulusLength: Int = 2048,
		publicExponent: Int = 65537): Promise<KeyPair> {
		return generateKeyPair(modulusLength, publicExponent);
	}

	/** 异步公钥加密 Bytes (OAEP) */
	public static function encryptAsync(data: Bytes, publicKeyPem: String,
		oaepHash: String = "sha256"): Promise<Bytes> {
		var buf = Buffer.from(data.getData());
		var result = publicEncrypt(buf, publicKeyPem, oaepHash);
		return Promise.resolve(Bytes.ofData(cast result.buffer));
	}

	/** 异步私钥解密 Bytes (OAEP) */
	public static function decryptAsync(data: Bytes, privateKeyPem: String,
		oaepHash: String = "sha256"): Promise<Bytes> {
		var buf = Buffer.from(data.getData());
		var result = privateDecrypt(buf, privateKeyPem, oaepHash);
		return Promise.resolve(Bytes.ofData(cast result.buffer));
	}

	/** 异步RSA签名 (RSASSA-PKCS1-v1_5) */
	public static function signAsync(data: Bytes, privateKeyPem: String,
		algorithm: String = "sha256"): Promise<Bytes> {
		var buf = Buffer.from(data.getData());
		var result = sign(buf, privateKeyPem, algorithm);
		return Promise.resolve(Bytes.ofData(cast result.buffer));
	}

	/** 异步RSA验签 (RSASSA-PKCS1-v1_5) */
	public static function verifyAsync(data: Bytes, signature: Bytes, publicKeyPem: String,
		algorithm: String = "sha256"): Promise<Bool> {
		var dataBuf = Buffer.from(data.getData());
		var sigBuf = Buffer.from(signature.getData());
		return Promise.resolve(verify(dataBuf, sigBuf, publicKeyPem, algorithm));
	}

	/** 异步公钥加密字符串 (OAEP) — 返回base64密文 */
	public static function encryptStringAsync(plaintext: String, publicKeyPem: String,
		oaepHash: String = "sha256"): Promise<String> {
		return Promise.resolve(encryptString(plaintext, publicKeyPem, oaepHash));
	}

	/** 异步私钥解密字符串 (OAEP) — 输入base64密文 */
	public static function decryptStringAsync(ciphertext: String, privateKeyPem: String,
		oaepHash: String = "sha256"): Promise<String> {
		return Promise.resolve(decryptString(ciphertext, privateKeyPem, oaepHash));
	}
}

#end
