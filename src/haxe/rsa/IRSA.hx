package haxe.rsa;

import haxe.io.Bytes;

/**
 * RSA 统一接口
 *
 * 所有 RSA 后端必须实现此接口。
 * 不支持的操作用于抛错：
 * - 浏览器后端：同步方法抛错（仅支持异步）
 * - C++ 后端：异步方法抛错（仅支持同步）
 * - Node.js 后端：全部支持
 */
interface IRSA {
	// ---- 同步方法 ----

	function generateKeyPair(modulusLength: Int = 2048): KeyPair;
	function encrypt(data: Bytes, publicKey: String, oaepHash: String = "sha256"): Bytes;
	function decrypt(data: Bytes, privateKey: String, oaepHash: String = "sha256"): Bytes;
	function sign(data: Bytes, privateKey: String, algorithm: String = "sha256"): Bytes;
	function verify(data: Bytes, signature: Bytes, publicKey: String, algorithm: String = "sha256"): Bool;
	function encryptString(plaintext: String, publicKey: String, oaepHash: String = "sha256"): String;
	function decryptString(ciphertext: String, privateKey: String, oaepHash: String = "sha256"): String;

	// ---- 异步方法 ----

	function generateKeyPairAsync(modulusLength: Int = 2048): NativePromise<KeyPair>;
	function encryptAsync(data: Bytes, publicKey: String, oaepHash: String = "sha256"): NativePromise<Bytes>;
	function decryptAsync(data: Bytes, privateKey: String, oaepHash: String = "sha256"): NativePromise<Bytes>;
	function signAsync(data: Bytes, privateKey: String, algorithm: String = "sha256"): NativePromise<Bytes>;
	function verifyAsync(data: Bytes, signature: Bytes, publicKey: String, algorithm: String = "sha256"): NativePromise<Bool>;
	function encryptStringAsync(plaintext: String, publicKey: String, oaepHash: String = "sha256"): NativePromise<String>;
	function decryptStringAsync(ciphertext: String, privateKey: String, oaepHash: String = "sha256"): NativePromise<String>;
}
