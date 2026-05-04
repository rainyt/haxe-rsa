import haxe.rsa.RSA;
import haxe.rsa.KeyPair;
import haxe.io.Bytes;
import haxe.crypto.Base64;

class TestCpp {
	static function main() {
		Sys.println("=== haxe-ras C++ 测试 ===");

		var rsa = new RSA();

		// 测试密钥生成
		var keyPair = rsa.generateKeyPair(2048);
		Sys.println("[OK] 密钥生成成功");
		Sys.println('  公钥长度: ${keyPair.publicKey.length} 字符');
		Sys.println('  私钥长度: ${keyPair.privateKey.length} 字符');

		// 测试加密/解密 (OAEP)
		var plainText = "Hello, haxe-ras! C++ RSA测试。";
		var encrypted = rsa.encryptString(plainText, keyPair.publicKey);
		Sys.println('[OK] 加密成功 (OAEP): ${encrypted.substring(0, 40)}...');

		var decrypted = rsa.decryptString(encrypted, keyPair.privateKey);
		if (decrypted == plainText) {
			Sys.println("[OK] 解密验证通过 (OAEP)");
		} else {
			Sys.println("[FAIL] 解密结果不匹配!");
			Sys.println('  期望: $plainText');
			Sys.println('  实际: $decrypted');
		}

		// 测试不同 OAEP 哈希算法
		var encryptedSha1 = rsa.encryptString(plainText, keyPair.publicKey, "sha1");
		var decryptedSha1 = rsa.decryptString(encryptedSha1, keyPair.privateKey, "sha1");
		if (decryptedSha1 == plainText) {
			Sys.println("[OK] 解密验证通过 (OAEP-sha1)");
		} else {
			Sys.println("[FAIL] 解密结果不匹配 (OAEP-sha1)!");
		}

		// 测试 Bytes 级别加密/解密
		var dataBytes = Bytes.ofString(plainText);
		var encryptedBytes = rsa.encrypt(dataBytes, keyPair.publicKey);
		var decryptedBytes = rsa.decrypt(encryptedBytes, keyPair.privateKey);
		if (decryptedBytes.toString() == plainText) {
			Sys.println("[OK] Bytes加密/解密验证通过");
		} else {
			Sys.println("[FAIL] Bytes加密/解密失败!");
		}

		// 测试签名/验签
		var data = Bytes.ofString("签名测试数据 - Signature Test");
		var signature = rsa.sign(data, keyPair.privateKey);
		Sys.println('[OK] 签名成功: ${Base64.encode(signature).substring(0, 40)}...');

		var verified = rsa.verify(data, signature, keyPair.publicKey);
		if (verified) {
			Sys.println("[OK] 验签验证通过");
		} else {
			Sys.println("[FAIL] 验签失败!");
		}

		// 测试错误签名
		var fakeSig = rsa.sign(Bytes.ofString("错误数据"), keyPair.privateKey);
		var badVerify = rsa.verify(data, fakeSig, keyPair.publicKey);
		if (!badVerify) {
			Sys.println("[OK] 错误签名拒绝测试通过");
		} else {
			Sys.println("[FAIL] 错误签名未被拒绝!");
		}

		// 测试不同签名算法
		var sigSha512 = rsa.sign(data, keyPair.privateKey, "sha512");
		var verifySha512 = rsa.verify(data, sigSha512, keyPair.publicKey, "sha512");
		if (verifySha512) {
			Sys.println("[OK] SHA512签名/验签通过");
		} else {
			Sys.println("[FAIL] SHA512签名/验签失败!");
		}

		// ---- 固定密钥跨平台验证 ----
		Sys.println("--- 固定密钥测试（PEM 格式，验证跨后端一致性） ---");

		var sharedPlain = "跨平台共享密钥测试 - Cross-platform shared key test";
		var sharedEncrypted = rsa.encryptString(sharedPlain, TestKeys.publicKeyPem);
		var sharedDecrypted = rsa.decryptString(sharedEncrypted, TestKeys.privateKeyPem);
		if (sharedDecrypted == sharedPlain) {
			Sys.println("[OK] 固定密钥解密验证通过 (OAEP)");
		} else {
			Sys.println("[FAIL] 固定密钥解密结果不匹配!");
		}

		// 固定密钥 - Bytes 级别
		var sharedData = Bytes.ofString(sharedPlain);
		var sharedEncBytes = rsa.encrypt(sharedData, TestKeys.publicKeyPem);
		var sharedDecBytes = rsa.decrypt(sharedEncBytes, TestKeys.privateKeyPem);
		if (sharedDecBytes.toString() == sharedPlain) {
			Sys.println("[OK] 固定密钥 Bytes 加密/解密验证通过");
		} else {
			Sys.println("[FAIL] 固定密钥 Bytes 加密/解密失败!");
		}

		// 固定密钥 - 签名/验签
		var sharedSig = rsa.sign(sharedData, TestKeys.privateKeyPem);
		if (rsa.verify(sharedData, sharedSig, TestKeys.publicKeyPem)) {
			Sys.println("[OK] 固定密钥签名/验签验证通过");
		} else {
			Sys.println("[FAIL] 固定密钥验签失败!");
		}

		// 固定密钥 - SHA-512 签名
		var sharedSig512 = rsa.sign(sharedData, TestKeys.privateKeyPem, "sha512");
		if (rsa.verify(sharedData, sharedSig512, TestKeys.publicKeyPem, "sha512")) {
			Sys.println("[OK] 固定密钥 SHA512 签名/验签通过");
		} else {
			Sys.println("[FAIL] 固定密钥 SHA512 签名/验签失败!");
		}

		// 测试异步加密/解密链式调用
		var asyncRsa = new RSA();
		var asyncKeyPair = asyncRsa.generateKeyPair(2048);

		asyncRsa.encryptStringAsync(plainText, asyncKeyPair.publicKey).then(function(encrypted: String) {
			Sys.println('[OK] 异步加密成功: ${encrypted.substring(0, 40)}...');
			asyncRsa.decryptStringAsync(encrypted, asyncKeyPair.privateKey).then(function(decrypted: String) {
				if (decrypted == plainText) {
					Sys.println("[OK] 异步解密验证通过 (OAEP)");
				} else {
					Sys.println("[FAIL] 异步解密结果不匹配!");
				}
				asyncRsa.signAsync(dataBytes, asyncKeyPair.privateKey).then(function(asyncSig: Bytes) {
					asyncRsa.verifyAsync(dataBytes, asyncSig, asyncKeyPair.publicKey).then(function(asyncVerified: Bool) {
						if (asyncVerified) {
							Sys.println("[OK] 异步签名/验签通过");
						} else {
							Sys.println("[FAIL] 异步验签失败!");
						}
						Sys.println("=== 测试完成 ===");
					});
				});
			});
			return cast null;
		}).catchError(function(err: Dynamic) {
			Sys.println("[FAIL] 异步错误: " + err);
			Sys.println("=== 测试完成 ===");
			return cast null;
		});

		Sys.println("[INFO] 异步任务已提交，等待回调...");
	}
}
