package haxe.rsa.backend.jsnode;

#if (js && nodejs)

import js.node.Crypto;
import js.node.Constants;
import js.node.Buffer;
import js.lib.Promise;
import haxe.io.Bytes;
import haxe.rsa.KeyPair;
import haxe.rsa.IRSA;
import haxe.rsa.NativePromise;

/**
 * RSA Node.js 后端 — 基于 Node.js crypto 模块
 *
 * 支持同步和异步全部操作，PEM 密钥格式。
 */
class RSA implements IRSA {

	public function new() {}

	/** PKCS#1 v1.5 填充常量 */
	static var PKCS1_PADDING(get, never): Int;
	static function get_PKCS1_PADDING() return Constants.RSA_PKCS1_PADDING;

	/** PKCS#1 OAEP 填充常量 */
	static var OAEP_PADDING(get, never): Int;
	static function get_OAEP_PADDING() return Constants.RSA_PKCS1_OAEP_PADDING;

	// ---- 静态工具方法（供外部直接调用，保持向后兼容）----

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

	/** 公钥加密 (OAEP填充) — Buffer 版本 */
	public static function publicEncrypt(data: Buffer, publicKeyPem: String,
		oaepHash: String = "sha256"): Buffer {
		return untyped Crypto.publicEncrypt(
			{key: publicKeyPem, padding: OAEP_PADDING, oaepHash: oaepHash}, data);
	}

	/** 私钥解密 (OAEP填充) — Buffer 版本 */
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

	/** RSA签名 — Buffer 版本 */
	public static function signBuffer(data: Buffer, privateKeyPem: String,
		algorithm: String = "sha256"): Buffer {
		var signer = Crypto.createSign("RSA-" + algorithm.toUpperCase());
		signer.update(data);
		return signer.sign(privateKeyPem);
	}

	/** RSA验签 — Buffer 版本 */
	public static function verifyBuffer(data: Buffer, signature: Buffer, publicKeyPem: String,
		algorithm: String = "sha256"): Bool {
		var verifier = Crypto.createVerify("RSA-" + algorithm.toUpperCase());
		verifier.update(data);
		return verifier.verify(publicKeyPem, signature);
	}

	// ---- IRSA 同步实例方法 ----

	public function generateKeyPair(modulusLength: Int = 2048): KeyPair {
		return generateKeyPairSync(modulusLength);
	}

	public function encrypt(data: Bytes, publicKey: String, oaepHash: String = "sha256"): Bytes {
		var buf = Buffer.from(data.getData());
		var result = publicEncrypt(buf, publicKey, oaepHash);
		return Bytes.ofData(cast result.buffer);
	}

	public function decrypt(data: Bytes, privateKey: String, oaepHash: String = "sha256"): Bytes {
		var buf = Buffer.from(data.getData());
		var result = privateDecrypt(buf, privateKey, oaepHash);
		return Bytes.ofData(cast result.buffer);
	}

	public function sign(data: Bytes, privateKey: String, algorithm: String = "sha256"): Bytes {
		var buf = Buffer.from(data.getData());
		var result = signBuffer(buf, privateKey, algorithm);
		return Bytes.ofData(cast result.buffer);
	}

	public function verify(data: Bytes, signature: Bytes, publicKey: String, algorithm: String = "sha256"): Bool {
		var dataBuf = Buffer.from(data.getData());
		var sigBuf = Buffer.from(signature.getData());
		return verifyBuffer(dataBuf, sigBuf, publicKey, algorithm);
	}

	public function encryptString(plaintext: String, publicKey: String, oaepHash: String = "sha256"): String {
		var encrypted = publicEncrypt(Buffer.from(plaintext, "utf8"), publicKey, oaepHash);
		return encrypted.toString("base64");
	}

	public function decryptString(ciphertext: String, privateKey: String, oaepHash: String = "sha256"): String {
		var decrypted = privateDecrypt(Buffer.from(ciphertext, "base64"), privateKey, oaepHash);
		return decrypted.toString("utf8");
	}

	// ---- IRSA 异步实例方法 ----

	public function generateKeyPairAsync(modulusLength: Int = 2048): NativePromise<KeyPair> {
		return cast new Promise((resolve, reject) -> {
			js.Syntax.code("require('crypto').generateKeyPair('rsa', {0}, {1})", {
				modulusLength: modulusLength,
				publicExponent: 65537,
				publicKeyEncoding: {type: "spki", format: "pem"},
				privateKeyEncoding: {type: "pkcs8", format: "pem"}
			}, (err, publicKey, privateKey) -> {
				if (err != null) reject(err)
				else resolve({publicKey: publicKey, privateKey: privateKey});
			});
		});
	}

	public function encryptAsync(data: Bytes, publicKey: String, oaepHash: String = "sha256"): NativePromise<Bytes> {
		var buf = Buffer.from(data.getData());
		var result = publicEncrypt(buf, publicKey, oaepHash);
		return cast Promise.resolve(Bytes.ofData(cast result.buffer));
	}

	public function decryptAsync(data: Bytes, privateKey: String, oaepHash: String = "sha256"): NativePromise<Bytes> {
		var buf = Buffer.from(data.getData());
		var result = privateDecrypt(buf, privateKey, oaepHash);
		return cast Promise.resolve(Bytes.ofData(cast result.buffer));
	}

	public function signAsync(data: Bytes, privateKey: String, algorithm: String = "sha256"): NativePromise<Bytes> {
		var buf = Buffer.from(data.getData());
		var result = signBuffer(buf, privateKey, algorithm);
		return cast Promise.resolve(Bytes.ofData(cast result.buffer));
	}

	public function verifyAsync(data: Bytes, signature: Bytes, publicKey: String, algorithm: String = "sha256"): NativePromise<Bool> {
		var dataBuf = Buffer.from(data.getData());
		var sigBuf = Buffer.from(signature.getData());
		return cast Promise.resolve(verifyBuffer(dataBuf, sigBuf, publicKey, algorithm));
	}

	public function encryptStringAsync(plaintext: String, publicKey: String, oaepHash: String = "sha256"): NativePromise<String> {
		return cast Promise.resolve(encryptString(plaintext, publicKey, oaepHash));
	}

	public function decryptStringAsync(ciphertext: String, privateKey: String, oaepHash: String = "sha256"): NativePromise<String> {
		return cast Promise.resolve(decryptString(ciphertext, privateKey, oaepHash));
	}
}

#end
