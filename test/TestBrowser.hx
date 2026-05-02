import haxe.ras.RSA;
import haxe.ras.KeyPair;
import haxe.io.Bytes;

class TestBrowser {
	static function main() {
		trace("=== haxe-ras 浏览器测试 ===");

		// 测试密钥生成
		RSA.generateKeyPairAsync(2048).then(function(keyPair: KeyPair) {
			trace("[OK] 密钥生成成功");
			trace('  JWK公钥: ${keyPair.publicKey.substring(0, 60)}...');
			trace('  JWK私钥: ${keyPair.privateKey.substring(0, 60)}...');

			var plainText = "Hello, haxe-ras! 浏览器RSA测试。";

			// 测试加密/解密 (OAEP)
			return RSA.encryptStringAsync(plainText, keyPair.publicKey).then(function(encrypted: String) {
				trace('[OK] 加密成功: ${encrypted.substring(0, 40)}...');
				return RSA.decryptStringAsync(encrypted, keyPair.privateKey).then(function(decrypted: String) {
					if (decrypted == plainText) {
						trace("[OK] 解密验证通过 (OAEP)");
					} else {
						trace("[FAIL] 解密结果不匹配!");
						trace('  期望: $plainText');
						trace('  实际: $decrypted');
					}

					// 测试 Bytes 级别加密/解密
					var dataBytes = Bytes.ofString(plainText);
					return RSA.encryptAsync(dataBytes, keyPair.publicKey).then(function(encryptedBytes: Bytes) {
						return RSA.decryptAsync(encryptedBytes, keyPair.privateKey).then(function(decryptedBytes: Bytes) {
							if (decryptedBytes.toString() == plainText) {
								trace("[OK] Bytes加密/解密验证通过");
							} else {
								trace("[FAIL] Bytes加密/解密失败!");
							}

							// 测试签名/验签
							return RSA.signAsync(dataBytes, keyPair.privateKey).then(function(signature: Bytes) {
								return RSA.verifyAsync(dataBytes, signature, keyPair.publicKey).then(function(verified: Bool) {
									if (verified) {
										trace("[OK] 签名/验签验证通过");
									} else {
										trace("[FAIL] 验签失败!");
									}

									// 测试不同哈希算法
									return RSA.signAsync(dataBytes, keyPair.privateKey, "sha512").then(function(sigSha512: Bytes) {
										return RSA.verifyAsync(dataBytes, sigSha512, keyPair.publicKey, "sha512").then(function(verifySha512: Bool) {
											if (verifySha512) {
												trace("[OK] SHA512签名/验签通过");
											} else {
												trace("[FAIL] SHA512签名/验签失败!");
											}

											trace("=== 测试完成 ===");
										});
									});
								});
							});
						});
					});
				});
			});
		}).catchError(function(err: Dynamic) {
			trace('[ERROR] ${err}');
		});
	}
}
