import haxe.ras.RSA;
import haxe.io.Bytes;

class TestNode {
	static function main() {
		Sys.println("=== haxe-ras Node.js 测试 ===");

		var rsa = new RSA();

		// 测试密钥生成
		var keyPair = rsa.generateKeyPair(2048);
		Sys.println("[OK] 密钥生成成功");
		Sys.println('  公钥长度: ${keyPair.publicKey.length} 字符');
		Sys.println('  私钥长度: ${keyPair.privateKey.length} 字符');

		// 测试加密/解密 (OAEP, 默认)
		var plainText = "Hello, haxe-ras! 你好，RSA加密测试。";
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

		// 测试 Bytes 级别的加密/解密
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
		Sys.println('[OK] 签名成功: ${signature.toHex().substring(0, 40)}...');

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

		// 测试异步接口
		var rsa2 = new RSA();
		rsa2.generateKeyPairAsync(2048).then(function(asyncKeyPair) {
			Sys.println("[OK] 异步密钥生成成功");
			rsa2.encryptStringAsync(plainText, asyncKeyPair.publicKey).then(function(asyncEncrypted) {
				Sys.println('[OK] 异步加密成功: ${asyncEncrypted.substring(0, 40)}...');
				rsa2.decryptStringAsync(asyncEncrypted, asyncKeyPair.privateKey).then(function(asyncDecrypted) {
					if (asyncDecrypted == plainText) {
						Sys.println("[OK] 异步解密验证通过 (OAEP)");
					} else {
						Sys.println("[FAIL] 异步解密结果不匹配!");
					}
					Sys.println("=== 测试完成 ===");
				});
			});
			return cast null;
		}).catchError(function(err) {
			Sys.println('[ERROR] $err');
			return cast null;
		});
	}
}
