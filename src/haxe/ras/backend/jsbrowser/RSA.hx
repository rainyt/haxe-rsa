package haxe.ras.backend.jsbrowser;

#if (js && !nodejs)

import haxe.io.Bytes;
import haxe.crypto.Base64;
import js.lib.Promise;
import haxe.ras.KeyPair;

/**
 * RSA 浏览器后端 — 基于 Web Crypto API (SubtleCrypto)
 *
 * 浏览器环境所有密码学操作均为异步，方法统一使用 `*Async` 后缀。
 */
class RSA {

	// ---- 内部工具 ----

	static var _subtle(get, never): Dynamic;
	static function get__subtle(): Dynamic {
		return js.Syntax.code("(window.crypto || window.msCrypto).subtle");
	}

	/** 将 sha256 → SHA-256 */
	static function _toWebHash(hash: String): String {
		return switch hash.toLowerCase() {
			case "sha1": "SHA-1";
			case "sha256": "SHA-256";
			case "sha384": "SHA-384";
			case "sha512": "SHA-512";
			default: "SHA-256";
		}
	}

	// ---- 密钥生成 ----

	/**
	 * 异步生成RSA密钥对
	 * @param modulusLength 密钥长度（位），默认2048
	 */
	public static function generateKeyPairAsync(modulusLength: Int = 2048): Promise<KeyPair> {
		var subtle = _subtle;
		return cast subtle.generateKey(
			{
				name: "RSA-OAEP",
				modulusLength: modulusLength,
				publicExponent: js.Syntax.code("new Uint8Array([1, 0, 1])"),
				hash: {name: "SHA-256"}
			},
			true, // extractable
			["encrypt", "decrypt"]
		).then(function(keyPair: Dynamic): Dynamic {
			return js.Syntax.code("Promise.all([{0}.exportKey('jwk', {1}.publicKey), {0}.exportKey('jwk', {1}.privateKey)])", subtle, keyPair);
		}).then(function(jwks: Dynamic): KeyPair {
			// 清除 JWK 中的 alg/key_ops，使密钥可用于签名和加密
			inline function clean(jwk: Dynamic): Dynamic {
				js.Syntax.code("delete {0}.alg", jwk);
				js.Syntax.code("delete {0}.key_ops", jwk);
				return jwk;
			}
			return {
				publicKey: untyped JSON.stringify(clean(jwks[0])),
				privateKey: untyped JSON.stringify(clean(jwks[1]))
			};
		});
	}

	// ---- OAEP 加密/解密 ----

	/**
	 * 异步公钥加密 (OAEP填充)
	 * @param data 明文数据
	 * @param publicKeyJwk JWK格式公钥JSON
	 * @param oaepHash OAEP哈希算法，默认"sha256"
	 */
	public static function encryptAsync(data: Bytes, publicKeyJwk: String,
		oaepHash: String = "sha256"): Promise<Bytes> {
		var subtle = _subtle;
		var jwk: Dynamic = untyped JSON.parse(publicKeyJwk);
		var hash = _toWebHash(oaepHash);
		return cast subtle.importKey("jwk", jwk, {name: "RSA-OAEP", hash: hash}, false, ["encrypt"])
			.then(function(publicKey: Dynamic): Dynamic {
				return subtle.encrypt({name: "RSA-OAEP"}, publicKey, data.getData());
			})
			.then(function(result: Dynamic): Bytes {
				return Bytes.ofData(result);
			});
	}

	/**
	 * 异步私钥解密 (OAEP填充)
	 * @param data 密文数据
	 * @param privateKeyJwk JWK格式私钥JSON
	 * @param oaepHash OAEP哈希算法，默认"sha256"
	 */
	public static function decryptAsync(data: Bytes, privateKeyJwk: String,
		oaepHash: String = "sha256"): Promise<Bytes> {
		var subtle = _subtle;
		var jwk: Dynamic = untyped JSON.parse(privateKeyJwk);
		var hash = _toWebHash(oaepHash);
		return cast subtle.importKey("jwk", jwk, {name: "RSA-OAEP", hash: hash}, false, ["decrypt"])
			.then(function(privateKey: Dynamic): Dynamic {
				return subtle.decrypt({name: "RSA-OAEP"}, privateKey, data.getData());
			})
			.then(function(result: Dynamic): Bytes {
				return Bytes.ofData(result);
			});
	}

	// ---- 签名/验签 ----

	/**
	 * 异步RSA签名 (RSASSA-PKCS1-v1_5)
	 * @param data 待签名数据
	 * @param privateKeyJwk JWK格式私钥JSON
	 * @param algorithm 哈希算法，默认"sha256"
	 */
	public static function signAsync(data: Bytes, privateKeyJwk: String,
		algorithm: String = "sha256"): Promise<Bytes> {
		var subtle = _subtle;
		var jwk: Dynamic = untyped JSON.parse(privateKeyJwk);
		var hash = _toWebHash(algorithm);
		var algo = {name: "RSASSA-PKCS1-v1_5", hash: {name: hash}};
		return cast subtle.importKey("jwk", jwk, algo, false, ["sign"])
			.then(function(privateKey: Dynamic): Dynamic {
				return subtle.sign(algo, privateKey, data.getData());
			})
			.then(function(result: Dynamic): Bytes {
				return Bytes.ofData(result);
			});
	}

	/**
	 * 异步RSA验签 (RSASSA-PKCS1-v1_5)
	 * @param data 原始数据
	 * @param signature 签名数据
	 * @param publicKeyJwk JWK格式公钥JSON
	 * @param algorithm 哈希算法，默认"sha256"
	 */
	public static function verifyAsync(data: Bytes, signature: Bytes, publicKeyJwk: String,
		algorithm: String = "sha256"): Promise<Bool> {
		var subtle = _subtle;
		var jwk: Dynamic = untyped JSON.parse(publicKeyJwk);
		var hash = _toWebHash(algorithm);
		var algo = {name: "RSASSA-PKCS1-v1_5", hash: {name: hash}};
		return cast subtle.importKey("jwk", jwk, algo, false, ["verify"])
			.then(function(publicKey: Dynamic): Dynamic {
				return subtle.verify(algo, publicKey, signature.getData(), data.getData());
			});
	}

	// ---- 字符串便捷方法 ----

	/**
	 * 异步公钥加密字符串 (OAEP)
	 * @param plaintext 明文字符串
	 * @param publicKeyJwk JWK格式公钥JSON
	 * @param oaepHash OAEP哈希算法，默认"sha256"
	 */
	public static function encryptStringAsync(plaintext: String, publicKeyJwk: String,
		oaepHash: String = "sha256"): Promise<String> {
		return encryptAsync(Bytes.ofString(plaintext), publicKeyJwk, oaepHash)
			.then(function(encrypted: Bytes): String {
				return Base64.encode(encrypted);
			});
	}

	/**
	 * 异步私钥解密字符串 (OAEP)
	 * @param ciphertext Base64编码的密文
	 * @param privateKeyJwk JWK格式私钥JSON
	 * @param oaepHash OAEP哈希算法，默认"sha256"
	 */
	public static function decryptStringAsync(ciphertext: String, privateKeyJwk: String,
		oaepHash: String = "sha256"): Promise<String> {
		var data = Base64.decode(ciphertext);
		return decryptAsync(data, privateKeyJwk, oaepHash)
			.then(function(decrypted: Bytes): String {
				return decrypted.toString();
			});
	}
}

#end
