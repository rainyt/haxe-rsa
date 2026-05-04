package haxe.rsa.backend.jsbrowser;

#if (js && !nodejs)

import haxe.io.Bytes;
import haxe.crypto.Base64;
import haxe.rsa.KeyPair;
import haxe.rsa.IRSA;
import haxe.rsa.NativePromise;

/**
 * RSA 浏览器后端 — 基于 Web Crypto API (SubtleCrypto)
 *
 * 浏览器环境所有密码学操作均为异步，同步方法调用会抛错。
 * 支持 JWK（JSON）和 PEM 两种密钥格式，自动识别转换。
 */
class RSA implements IRSA {

	public function new() {}

	// ---- 内部工具 ----

	var _subtle(get, never): Dynamic;
	function get__subtle(): Dynamic {
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

	/** 判断密钥字符串是否为 PEM 格式 */
	inline static function _isPem(key: String): Bool {
		return key.indexOf("-----BEGIN") >= 0;
	}

	/** 将 PEM 字符串解码为 DER 二进制 (ArrayBuffer) */
	static function _pemToDer(key: String): Dynamic {
		var lines = key.split("\n");
		var b64 = "";
		for (i in 0...lines.length) {
			var line = lines[i];
			if (line.indexOf("-----") < 0) {
				b64 += line;
			}
		}
		return js.Syntax.code("Uint8Array.from(atob({0}), c => c.charCodeAt(0)).buffer", b64);
	}

	/** 导入公钥（自动识别 PEM / JWK） */
	inline static function _importPublicKey(keyString: String, subtle: Dynamic,
			algo: Dynamic, usages: Array<String>): Dynamic {
		if (_isPem(keyString)) {
			return untyped subtle.importKey("spki", _pemToDer(keyString), algo, false, usages);
		}
		var jwk: Dynamic = untyped JSON.parse(keyString);
		return untyped subtle.importKey("jwk", jwk, algo, false, usages);
	}

	/** 导入私钥（自动识别 PEM / JWK） */
	inline static function _importPrivateKey(keyString: String, subtle: Dynamic,
			algo: Dynamic, usages: Array<String>): Dynamic {
		if (_isPem(keyString)) {
			return untyped subtle.importKey("pkcs8", _pemToDer(keyString), algo, false, usages);
		}
		var jwk: Dynamic = untyped JSON.parse(keyString);
		return untyped subtle.importKey("jwk", jwk, algo, false, usages);
	}

	// ---- IRSA 同步方法（浏览器不支持）----

	public function generateKeyPair(modulusLength: Int = 2048): KeyPair {
		throw "浏览器环境不支持同步操作，请使用 generateKeyPairAsync()。";
	}

	public function encrypt(data: Bytes, publicKey: String, oaepHash: String = "sha256"): Bytes {
		throw "浏览器环境不支持同步操作，请使用 encryptAsync()。";
	}

	public function decrypt(data: Bytes, privateKey: String, oaepHash: String = "sha256"): Bytes {
		throw "浏览器环境不支持同步操作，请使用 decryptAsync()。";
	}

	public function sign(data: Bytes, privateKey: String, algorithm: String = "sha256"): Bytes {
		throw "浏览器环境不支持同步操作，请使用 signAsync()。";
	}

	public function verify(data: Bytes, signature: Bytes, publicKey: String, algorithm: String = "sha256"): Bool {
		throw "浏览器环境不支持同步操作，请使用 verifyAsync()。";
	}

	public function encryptString(plaintext: String, publicKey: String, oaepHash: String = "sha256"): String {
		throw "浏览器环境不支持同步操作，请使用 encryptStringAsync()。";
	}

	public function decryptString(ciphertext: String, privateKey: String, oaepHash: String = "sha256"): String {
		throw "浏览器环境不支持同步操作，请使用 decryptStringAsync()。";
	}

	// ---- IRSA 异步方法 ----

	public function generateKeyPairAsync(modulusLength: Int = 2048): NativePromise<KeyPair> {
		var subtle = _subtle;
		return cast subtle.generateKey(
			{
				name: "RSA-OAEP",
				modulusLength: modulusLength,
				publicExponent: js.Syntax.code("new Uint8Array([1, 0, 1])"),
				hash: {name: "SHA-256"}
			},
			true,
			["encrypt", "decrypt"]
		).then(function(keyPair: Dynamic): Dynamic {
			return js.Syntax.code("Promise.all([{0}.exportKey('jwk', {1}.publicKey), {0}.exportKey('jwk', {1}.privateKey)])", subtle, keyPair);
		}).then(function(jwks: Dynamic): KeyPair {
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

	public function encryptAsync(data: Bytes, publicKey: String,
			oaepHash: String = "sha256"): NativePromise<Bytes> {
		var subtle = _subtle;
		var hash = _toWebHash(oaepHash);
		var algo = {name: "RSA-OAEP", hash: hash};
		return cast _importPublicKey(publicKey, subtle, algo, ["encrypt"])
			.then(function(pubKey: Dynamic): Dynamic {
				return subtle.encrypt({name: "RSA-OAEP"}, pubKey, data.getData());
			})
			.then(function(result: Dynamic): Bytes {
				return Bytes.ofData(result);
			});
	}

	public function decryptAsync(data: Bytes, privateKey: String,
			oaepHash: String = "sha256"): NativePromise<Bytes> {
		var subtle = _subtle;
		var hash = _toWebHash(oaepHash);
		var algo = {name: "RSA-OAEP", hash: hash};
		return cast _importPrivateKey(privateKey, subtle, algo, ["decrypt"])
			.then(function(privKey: Dynamic): Dynamic {
				return subtle.decrypt({name: "RSA-OAEP"}, privKey, data.getData());
			})
			.then(function(result: Dynamic): Bytes {
				return Bytes.ofData(result);
			});
	}

	public function signAsync(data: Bytes, privateKey: String,
			algorithm: String = "sha256"): NativePromise<Bytes> {
		var subtle = _subtle;
		var hash = _toWebHash(algorithm);
		var algo = {name: "RSASSA-PKCS1-v1_5", hash: {name: hash}};
		return cast _importPrivateKey(privateKey, subtle, algo, ["sign"])
			.then(function(privKey: Dynamic): Dynamic {
				return subtle.sign(algo, privKey, data.getData());
			})
			.then(function(result: Dynamic): Bytes {
				return Bytes.ofData(result);
			});
	}

	public function verifyAsync(data: Bytes, signature: Bytes, publicKey: String,
			algorithm: String = "sha256"): NativePromise<Bool> {
		var subtle = _subtle;
		var hash = _toWebHash(algorithm);
		var algo = {name: "RSASSA-PKCS1-v1_5", hash: {name: hash}};
		return cast _importPublicKey(publicKey, subtle, algo, ["verify"])
			.then(function(pubKey: Dynamic): Dynamic {
				return subtle.verify(algo, pubKey, signature.getData(), data.getData());
			});
	}

	public function encryptStringAsync(plaintext: String, publicKey: String,
			oaepHash: String = "sha256"): NativePromise<String> {
		return cast encryptAsync(Bytes.ofString(plaintext), publicKey, oaepHash)
			.then(function(encrypted: Bytes): String {
				return Base64.encode(encrypted);
			});
	}

	public function decryptStringAsync(ciphertext: String, privateKey: String,
			oaepHash: String = "sha256"): NativePromise<String> {
		var data = Base64.decode(ciphertext);
		return cast decryptAsync(data, privateKey, oaepHash)
			.then(function(decrypted: Bytes): String {
				return decrypted.toString();
			});
	}
}

#end
