package haxe.ras.backend.jvm;

#if jvm

import haxe.io.Bytes;
import haxe.crypto.Base64;
import haxe.ras.KeyPair;
import haxe.ras.IRSA;
import haxe.ras.NativePromise;

// ---- Java 加密相关外部类 ----

@:native("java.security.KeyPairGenerator")
private extern class JavaKeyPairGenerator {
	@:native("getInstance") static function getInstance(algorithm:String):JavaKeyPairGenerator;
	function initialize(bits:Int):Void;
	function generateKeyPair():JavaKeyPair;
}

@:native("java.security.KeyPair")
private extern class JavaKeyPair {
	function getPublic():JavaPublicKey;
	function getPrivate():JavaPrivateKey;
}

@:native("java.security.spec.KeySpec")
private extern interface JavaKeySpec {}

@:native("java.security.KeyFactory")
private extern class JavaKeyFactory {
	@:native("getInstance") static function getInstance(algorithm:String):JavaKeyFactory;
	function generatePublic(keySpec:JavaKeySpec):JavaPublicKey;
	function generatePrivate(keySpec:JavaKeySpec):JavaPrivateKey;
}

@:native("java.security.Key")
private extern interface JavaKey {}

@:native("java.security.PublicKey")
private extern interface JavaPublicKey extends JavaKey {
	function getEncoded():haxe.io.BytesData;
}

@:native("java.security.PrivateKey")
private extern interface JavaPrivateKey extends JavaKey {
	function getEncoded():haxe.io.BytesData;
}

@:native("java.security.Signature")
private extern class JavaSignature {
	@:native("getInstance") static function getInstance(algorithm:String):JavaSignature;
	function initSign(privateKey:JavaPrivateKey):Void;
	function initVerify(publicKey:JavaPublicKey):Void;
	function update(data:haxe.io.BytesData):Void;
	function sign():haxe.io.BytesData;
	function verify(signature:haxe.io.BytesData):Bool;
}

@:native("java.security.spec.X509EncodedKeySpec")
private extern class JavaX509EncodedKeySpec {
	function new(encoded:haxe.io.BytesData):Void;
}

@:native("java.security.spec.PKCS8EncodedKeySpec")
private extern class JavaPKCS8EncodedKeySpec {
	function new(encoded:haxe.io.BytesData):Void;
}

@:native("javax.crypto.Cipher")
private extern class JavaCipher {
	@:native("getInstance") static function getInstance(transformation:String):JavaCipher;
	@:native("ENCRYPT_MODE") static var ENCRYPT_MODE(default, null):Int;
	@:native("DECRYPT_MODE") static var DECRYPT_MODE(default, null):Int;
	function init(opmode:Int, key:JavaKey):Void;
	function doFinal(input:haxe.io.BytesData):haxe.io.BytesData;
}

/**
 * RSA Java/JVM 后端
 *
 * 基于 JDK 内置 java.security / javax.crypto API。
 * PEM 密钥格式，与 Node.js / C++ 后端互通。
 */
class RSA implements IRSA {

	public function new() {}

	// ---- 工具方法 ----

	static function toMd(hash:String):String {
		return switch (hash) {
			case "sha1": "SHA-1";
			case "sha384": "SHA-384";
			case "sha512": "SHA-512";
			default: "SHA-256";
		}
	}

	static function toOaepTransform(hash:String):String {
		var md = toMd(hash);
		return "RSA/ECB/OAEPWith" + md + "AndMGF1Padding";
	}

	static function toSignAlgorithm(hash:String):String {
		var md = toMd(hash);
		return StringTools.replace(md, "-", "") + "withRSA";
	}

	static function derToPem(der:haxe.io.BytesData, type:String):String {
		var b64 = Base64.encode(Bytes.ofData(der));
		var sb = new StringBuf();
		sb.add("-----BEGIN " + type + "-----\n");
		var i = 0;
		while (i < b64.length) {
			var end = i + 64;
			if (end > b64.length) end = b64.length;
			sb.add(b64.substring(i, end));
			sb.add("\n");
			i = end;
		}
		sb.add("-----END " + type + "-----\n");
		return sb.toString();
	}

	static function pemToDer(pem:String):haxe.io.BytesData {
		var b64 = ~/-----[A-Z ]*-----/g.replace(pem, "");
		b64 = ~/\s/g.replace(b64, "");
		return Base64.decode(b64).getData();
	}

	// ---- 同步方法 ----

	public function generateKeyPair(modulusLength:Int = 2048):KeyPair {
		var gen = JavaKeyPairGenerator.getInstance("RSA");
		gen.initialize(modulusLength);
		var pair = gen.generateKeyPair();

		var pubDer = pair.getPublic().getEncoded();
		var privDer = pair.getPrivate().getEncoded();

		return {
			publicKey: derToPem(pubDer, "PUBLIC KEY"),
			privateKey: derToPem(privDer, "PRIVATE KEY")
		};
	}

	public function encrypt(data:Bytes, publicKeyPem:String,
			oaepHash:String = "sha256"):Bytes {
		var pubDer = pemToDer(publicKeyPem);
		var keyFactory = JavaKeyFactory.getInstance("RSA");
		var pubKey = keyFactory.generatePublic(cast new JavaX509EncodedKeySpec(pubDer));

		var cipher = JavaCipher.getInstance(toOaepTransform(oaepHash));
		cipher.init(JavaCipher.ENCRYPT_MODE, pubKey);

		return Bytes.ofData(cipher.doFinal(data.getData()));
	}

	public function decrypt(data:Bytes, privateKeyPem:String,
			oaepHash:String = "sha256"):Bytes {
		var privDer = pemToDer(privateKeyPem);
		var keyFactory = JavaKeyFactory.getInstance("RSA");
		var privKey = keyFactory.generatePrivate(cast new JavaPKCS8EncodedKeySpec(privDer));

		var cipher = JavaCipher.getInstance(toOaepTransform(oaepHash));
		cipher.init(JavaCipher.DECRYPT_MODE, privKey);

		return Bytes.ofData(cipher.doFinal(data.getData()));
	}

	public function sign(data:Bytes, privateKeyPem:String,
			algorithm:String = "sha256"):Bytes {
		var privDer = pemToDer(privateKeyPem);
		var keyFactory = JavaKeyFactory.getInstance("RSA");
		var privKey = keyFactory.generatePrivate(cast new JavaPKCS8EncodedKeySpec(privDer));

		var sig = JavaSignature.getInstance(toSignAlgorithm(algorithm));
		sig.initSign(privKey);
		sig.update(data.getData());

		return Bytes.ofData(sig.sign());
	}

	public function verify(data:Bytes, signature:Bytes, publicKeyPem:String,
			algorithm:String = "sha256"):Bool {
		var pubDer = pemToDer(publicKeyPem);
		var keyFactory = JavaKeyFactory.getInstance("RSA");
		var pubKey = keyFactory.generatePublic(cast new JavaX509EncodedKeySpec(pubDer));

		var sig = JavaSignature.getInstance(toSignAlgorithm(algorithm));
		sig.initVerify(pubKey);
		sig.update(data.getData());

		return sig.verify(signature.getData());
	}

	public function encryptString(plaintext:String, publicKeyPem:String,
			oaepHash:String = "sha256"):String {
		var data = Bytes.ofString(plaintext);
		var encrypted = encrypt(data, publicKeyPem, oaepHash);
		return Base64.encode(encrypted);
	}

	public function decryptString(ciphertext:String, privateKeyPem:String,
			oaepHash:String = "sha256"):String {
		var data = Base64.decode(ciphertext);
		var decrypted = decrypt(data, privateKeyPem, oaepHash);
		return decrypted.toString();
	}

	// ---- 异步方法（同步包装，同 C++ 后端）----

	public function generateKeyPairAsync(modulusLength:Int = 2048):NativePromise<KeyPair> {
		try {
			return cast haxe.ras.PromiseImpl.resolve(generateKeyPair(modulusLength));
		} catch (e:Dynamic) {
			return cast haxe.ras.PromiseImpl.reject(e);
		}
	}

	public function encryptAsync(data:Bytes, publicKey:String,
			oaepHash:String = "sha256"):NativePromise<Bytes> {
		try {
			return cast haxe.ras.PromiseImpl.resolve(encrypt(data, publicKey, oaepHash));
		} catch (e:Dynamic) {
			return cast haxe.ras.PromiseImpl.reject(e);
		}
	}

	public function decryptAsync(data:Bytes, privateKey:String,
			oaepHash:String = "sha256"):NativePromise<Bytes> {
		try {
			return cast haxe.ras.PromiseImpl.resolve(decrypt(data, privateKey, oaepHash));
		} catch (e:Dynamic) {
			return cast haxe.ras.PromiseImpl.reject(e);
		}
	}

	public function signAsync(data:Bytes, privateKey:String,
			algorithm:String = "sha256"):NativePromise<Bytes> {
		try {
			return cast haxe.ras.PromiseImpl.resolve(sign(data, privateKey, algorithm));
		} catch (e:Dynamic) {
			return cast haxe.ras.PromiseImpl.reject(e);
		}
	}

	public function verifyAsync(data:Bytes, signature:Bytes, publicKey:String,
			algorithm:String = "sha256"):NativePromise<Bool> {
		try {
			return cast haxe.ras.PromiseImpl.resolve(verify(data, signature, publicKey, algorithm));
		} catch (e:Dynamic) {
			return cast haxe.ras.PromiseImpl.reject(e);
		}
	}

	public function encryptStringAsync(plaintext:String, publicKey:String,
			oaepHash:String = "sha256"):NativePromise<String> {
		try {
			return cast haxe.ras.PromiseImpl.resolve(encryptString(plaintext, publicKey, oaepHash));
		} catch (e:Dynamic) {
			return cast haxe.ras.PromiseImpl.reject(e);
		}
	}

	public function decryptStringAsync(ciphertext:String, privateKey:String,
			oaepHash:String = "sha256"):NativePromise<String> {
		try {
			return cast haxe.ras.PromiseImpl.resolve(decryptString(ciphertext, privateKey, oaepHash));
		} catch (e:Dynamic) {
			return cast haxe.ras.PromiseImpl.reject(e);
		}
	}
}

#end
