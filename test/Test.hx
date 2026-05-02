import haxe.ras.RSA;
import js.node.Buffer;

class Test {
	static function main() {
		Sys.println("=== haxe-ras 测试 ===");

		// 测试密钥生成
		var keyPair = RSA.generateKeyPairSync(2048);
		Sys.println("[OK] 密钥生成成功");
		Sys.println('  公钥长度: ${keyPair.publicKey.length} 字符');
		Sys.println('  私钥长度: ${keyPair.privateKey.length} 字符');

		// 测试加密/解密 (OAEP, 默认)
		var plainText = "Hello, haxe-ras! 你好，RSA加密测试。";
		var encrypted = RSA.encryptString(plainText, keyPair.publicKey);
		Sys.println('[OK] 加密成功 (OAEP): ${encrypted.substring(0, 40)}...');

		var decrypted = RSA.decryptString(encrypted, keyPair.privateKey);
		if (decrypted == plainText) {
			Sys.println("[OK] 解密验证通过 (OAEP)");
		} else {
			Sys.println("[FAIL] 解密结果不匹配!");
			Sys.println('  期望: $plainText');
			Sys.println('  实际: $decrypted');
		}

		// 测试不同 OAEP 哈希算法
		var encryptedSha1 = RSA.encryptString(plainText, keyPair.publicKey, "sha1");
		var decryptedSha1 = RSA.decryptString(encryptedSha1, keyPair.privateKey, "sha1");
		if (decryptedSha1 == plainText) {
			Sys.println("[OK] 解密验证通过 (OAEP-sha1)");
		} else {
			Sys.println("[FAIL] 解密结果不匹配 (OAEP-sha1)!");
		}

		// 测试 Buffer 级别的加密/解密
		var dataBuf = Buffer.from(plainText, "utf8");
		var encryptedBuf = RSA.publicEncrypt(dataBuf, keyPair.publicKey);
		var decryptedBuf = RSA.privateDecrypt(encryptedBuf, keyPair.privateKey);
		if (decryptedBuf.toString("utf8") == plainText) {
			Sys.println("[OK] Buffer加密/解密验证通过");
		} else {
			Sys.println("[FAIL] Buffer加密/解密失败!");
		}

		// 测试签名/验签
		var data = Buffer.from("签名测试数据 - Signature Test", "utf8");
		var signature = RSA.sign(data, keyPair.privateKey);
		Sys.println('[OK] 签名成功: ${signature.toString("base64").substring(0, 40)}...');

		var verified = RSA.verify(data, signature, keyPair.publicKey);
		if (verified) {
			Sys.println("[OK] 验签验证通过");
		} else {
			Sys.println("[FAIL] 验签失败!");
		}

		// 测试错误签名
		var fakeSig = RSA.sign(Buffer.from("错误数据", "utf8"), keyPair.privateKey);
		var badVerify = RSA.verify(data, fakeSig, keyPair.publicKey);
		if (!badVerify) {
			Sys.println("[OK] 错误签名拒绝测试通过");
		} else {
			Sys.println("[FAIL] 错误签名未被拒绝!");
		}

		// 测试不同签名算法
		var sigSha512 = RSA.sign(data, keyPair.privateKey, "sha512");
		var verifySha512 = RSA.verify(data, sigSha512, keyPair.publicKey, "sha512");
		if (verifySha512) {
			Sys.println("[OK] SHA512签名/验签通过");
		} else {
			Sys.println("[FAIL] SHA512签名/验签失败!");
		}

		Sys.println("=== 测试完成 ===");
	}
}
