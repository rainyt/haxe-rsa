package haxe.ras.backend.hxcpp;

import haxe.io.Bytes;
import haxe.crypto.Base64;
import haxe.ras.KeyPair;
import haxe.ras.IRSA;
import haxe.ras.NativePromise;

#if cpp

@:headerCode('
#include <haxe/io/Bytes.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <string.h>
#include <string>

// ---- 哈希算法选择 ----

static const EVP_MD* _hxrsa_get_md(const char* hash) {
	if (strcmp(hash, "sha1") == 0) return EVP_sha1();
	if (strcmp(hash, "sha256") == 0) return EVP_sha256();
	if (strcmp(hash, "sha384") == 0) return EVP_sha384();
	if (strcmp(hash, "sha512") == 0) return EVP_sha512();
	return EVP_sha256();
}

// ---- 密钥生成（结果暂存于静态变量）----

static std::string _hxrsa_pub_pem;
static std::string _hxrsa_priv_pem;

static void _hxrsa_gen_key(int bits) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY_keygen_init(ctx);
	EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_keygen(ctx, &pkey);
	EVP_PKEY_CTX_free(ctx);

	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(bio, pkey);
	BUF_MEM* mem;
	BIO_get_mem_ptr(bio, &mem);
	_hxrsa_pub_pem.assign(mem->data, mem->length);
	BIO_free(bio);

	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
	BIO_get_mem_ptr(bio, &mem);
	_hxrsa_priv_pem.assign(mem->data, mem->length);
	BIO_free(bio);

	EVP_PKEY_free(pkey);
}

// ---- OAEP 加密 ----

static Dynamic _hxrsa_encrypt(::haxe::io::Bytes data, ::String pubKeyPem, ::String oaepHash) {
	unsigned char* raw = data->b->Pointer();
	int rawLen = data->length;

	BIO* bio = BIO_new_mem_buf(pubKeyPem.c_str(), -1);
	EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_free(bio);

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	EVP_PKEY_encrypt_init(ctx);
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
	EVP_PKEY_CTX_set_rsa_oaep_md(ctx, _hxrsa_get_md(oaepHash.c_str()));

	size_t maxLen;
	EVP_PKEY_encrypt(ctx, NULL, &maxLen, raw, rawLen);

	unsigned char* outBuf = (unsigned char*)malloc(maxLen);
	size_t actualLen = maxLen;
	EVP_PKEY_encrypt(ctx, outBuf, &actualLen, raw, rawLen);

	::haxe::io::Bytes result = ::haxe::io::Bytes_obj::alloc(actualLen);
	memcpy(result->b->Pointer(), outBuf, actualLen);
	free(outBuf);

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return result;
}

// ---- OAEP 解密 ----

static Dynamic _hxrsa_decrypt(::haxe::io::Bytes data, ::String privKeyPem, ::String oaepHash) {
	unsigned char* raw = data->b->Pointer();
	int rawLen = data->length;

	BIO* bio = BIO_new_mem_buf(privKeyPem.c_str(), -1);
	EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	BIO_free(bio);

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	EVP_PKEY_decrypt_init(ctx);
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
	EVP_PKEY_CTX_set_rsa_oaep_md(ctx, _hxrsa_get_md(oaepHash.c_str()));

	size_t maxLen;
	EVP_PKEY_decrypt(ctx, NULL, &maxLen, raw, rawLen);

	unsigned char* outBuf = (unsigned char*)malloc(maxLen);
	size_t actualLen = maxLen;
	EVP_PKEY_decrypt(ctx, outBuf, &actualLen, raw, rawLen);

	::haxe::io::Bytes result = ::haxe::io::Bytes_obj::alloc(actualLen);
	memcpy(result->b->Pointer(), outBuf, actualLen);
	free(outBuf);

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return result;
}

// ---- 签名 (RSASSA-PKCS1-v1_5) ----

static Dynamic _hxrsa_sign(::haxe::io::Bytes data, ::String privKeyPem, ::String algorithm) {
	unsigned char* raw = data->b->Pointer();
	int rawLen = data->length;

	BIO* bio = BIO_new_mem_buf(privKeyPem.c_str(), -1);
	EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	BIO_free(bio);

	EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
	EVP_PKEY_CTX* pctx = NULL;
	EVP_DigestSignInit(mdCtx, &pctx, _hxrsa_get_md(algorithm.c_str()), NULL, pkey);
	EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);

	size_t maxSigLen;
	EVP_DigestSign(mdCtx, NULL, &maxSigLen, raw, rawLen);

	unsigned char* sigBuf = (unsigned char*)malloc(maxSigLen);
	size_t actualSigLen = maxSigLen;
	EVP_DigestSign(mdCtx, sigBuf, &actualSigLen, raw, rawLen);

	::haxe::io::Bytes result = ::haxe::io::Bytes_obj::alloc(actualSigLen);
	memcpy(result->b->Pointer(), sigBuf, actualSigLen);
	free(sigBuf);

	EVP_MD_CTX_free(mdCtx);
	EVP_PKEY_free(pkey);
	return result;
}

// ---- 验签 (RSASSA-PKCS1-v1_5) ----

static bool _hxrsa_verify(::haxe::io::Bytes data, ::haxe::io::Bytes signature,
		::String pubKeyPem, ::String algorithm) {
	unsigned char* raw = data->b->Pointer();
	int rawLen = data->length;
	unsigned char* sig = signature->b->Pointer();
	int sigLen = signature->length;

	BIO* bio = BIO_new_mem_buf(pubKeyPem.c_str(), -1);
	EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_free(bio);

	EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
	EVP_PKEY_CTX* pctx = NULL;
	EVP_DigestVerifyInit(mdCtx, &pctx, _hxrsa_get_md(algorithm.c_str()), NULL, pkey);
	EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);

	int rc = EVP_DigestVerify(mdCtx, sig, sigLen, raw, rawLen);

	EVP_MD_CTX_free(mdCtx);
	EVP_PKEY_free(pkey);
	return rc == 1;
}
')

@:buildXml('
<compiler>
	<flag value="-I/usr/local/opt/openssl/include" />
</compiler>
<linker id="exe">
	<flag value="-L/usr/local/opt/openssl/lib" />
	<flag value="-lssl" />
	<flag value="-lcrypto" />
</linker>
')

class RSA implements IRSA {

	public function new() {}

	// ---- 同步方法 ----

	public function generateKeyPair(modulusLength: Int = 2048): KeyPair {
		untyped __cpp__("_hxrsa_gen_key({0})", modulusLength);
		var pubKey:String = untyped __cpp__("::String(_hxrsa_pub_pem.c_str(), _hxrsa_pub_pem.size())");
		var privKey:String = untyped __cpp__("::String(_hxrsa_priv_pem.c_str(), _hxrsa_priv_pem.size())");
		return {publicKey: pubKey, privateKey: privKey};
	}

	public function encrypt(data: Bytes, publicKeyPem: String,
			oaepHash: String = "sha256"): Bytes {
		return cast untyped __cpp__("_hxrsa_encrypt({0}, {1}, {2})", data, publicKeyPem, oaepHash);
	}

	public function decrypt(data: Bytes, privateKeyPem: String,
			oaepHash: String = "sha256"): Bytes {
		return cast untyped __cpp__("_hxrsa_decrypt({0}, {1}, {2})", data, privateKeyPem, oaepHash);
	}

	public function sign(data: Bytes, privateKeyPem: String,
			algorithm: String = "sha256"): Bytes {
		return cast untyped __cpp__("_hxrsa_sign({0}, {1}, {2})", data, privateKeyPem, algorithm);
	}

	public function verify(data: Bytes, signature: Bytes, publicKeyPem: String,
			algorithm: String = "sha256"): Bool {
		return untyped __cpp__("_hxrsa_verify({0}, {1}, {2}, {3})", data, signature, publicKeyPem, algorithm);
	}

	public function encryptString(plaintext: String, publicKeyPem: String,
			oaepHash: String = "sha256"): String {
		var data = Bytes.ofString(plaintext);
		var encrypted = encrypt(data, publicKeyPem, oaepHash);
		return Base64.encode(encrypted);
	}

	public function decryptString(ciphertext: String, privateKeyPem: String,
			oaepHash: String = "sha256"): String {
		var data = Base64.decode(ciphertext);
		var decrypted = decrypt(data, privateKeyPem, oaepHash);
		return decrypted.toString();
	}

	// ---- 异步方法（C++ 不支持）----

	public function generateKeyPairAsync(modulusLength: Int = 2048): NativePromise<KeyPair> {
		throw "C++ 目标不支持异步操作，请使用 generateKeyPair()。";
	}

	public function encryptAsync(data: Bytes, publicKey: String, oaepHash: String = "sha256"): NativePromise<Bytes> {
		throw "C++ 目标不支持异步操作，请使用 encrypt()。";
	}

	public function decryptAsync(data: Bytes, privateKey: String, oaepHash: String = "sha256"): NativePromise<Bytes> {
		throw "C++ 目标不支持异步操作，请使用 decrypt()。";
	}

	public function signAsync(data: Bytes, privateKey: String, algorithm: String = "sha256"): NativePromise<Bytes> {
		throw "C++ 目标不支持异步操作，请使用 sign()。";
	}

	public function verifyAsync(data: Bytes, signature: Bytes, publicKey: String, algorithm: String = "sha256"): NativePromise<Bool> {
		throw "C++ 目标不支持异步操作，请使用 verify()。";
	}

	public function encryptStringAsync(plaintext: String, publicKey: String, oaepHash: String = "sha256"): NativePromise<String> {
		throw "C++ 目标不支持异步操作，请使用 encryptString()。";
	}

	public function decryptStringAsync(ciphertext: String, privateKey: String, oaepHash: String = "sha256"): NativePromise<String> {
		throw "C++ 目标不支持异步操作，请使用 decryptString()。";
	}
}

#end
