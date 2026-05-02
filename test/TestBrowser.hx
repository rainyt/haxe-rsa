import haxe.ras.RSA;
import haxe.ras.KeyPair;
import haxe.io.Bytes;

class TestBrowser {
	static function main() {
		trace("=== haxe-ras 浏览器测试 ===");

		var rsa = new RSA();

		// 测试同步方法抛错
		try {
			rsa.generateKeyPair(2048);
			trace("[FAIL] 同步方法应该抛错但未抛出!");
		} catch (e: Dynamic) {
			trace("[OK] 同步方法正确抛错: " + e);
		}

		// 测试密钥生成
		rsa.generateKeyPairAsync(2048).then(function(keyPair: KeyPair) {
			trace("[OK] 密钥生成成功");
			trace('  JWK公钥: ${keyPair.publicKey.substring(0, 60)}...');
			trace('  JWK私钥: ${keyPair.privateKey.substring(0, 60)}...');

			var plainText = "Hello, haxe-ras! 浏览器RSA测试。";

			// 测试加密/解密 (OAEP)
			return rsa.encryptStringAsync(plainText, keyPair.publicKey).then(function(encrypted: String) {
				trace('[OK] 加密成功: ${encrypted.substring(0, 40)}...');
				return rsa.decryptStringAsync(encrypted, keyPair.privateKey).then(function(decrypted: String) {
					if (decrypted == plainText) {
						trace("[OK] 解密验证通过 (OAEP)");
					} else {
						trace("[FAIL] 解密结果不匹配!");
						trace('  期望: $plainText');
						trace('  实际: $decrypted');
					}

					// 测试 Bytes 级别加密/解密
					var dataBytes = Bytes.ofString(plainText);
					return rsa.encryptAsync(dataBytes, keyPair.publicKey).then(function(encryptedBytes: Bytes) {
						return rsa.decryptAsync(encryptedBytes, keyPair.privateKey).then(function(decryptedBytes: Bytes) {
							if (decryptedBytes.toString() == plainText) {
								trace("[OK] Bytes加密/解密验证通过");
							} else {
								trace("[FAIL] Bytes加密/解密失败!");
							}

							// 测试签名/验签
							return rsa.signAsync(dataBytes, keyPair.privateKey).then(function(signature: Bytes) {
								return rsa.verifyAsync(dataBytes, signature, keyPair.publicKey).then(function(verified: Bool) {
									if (verified) {
										trace("[OK] 签名/验签验证通过");
									} else {
										trace("[FAIL] 验签失败!");
									}

									// 测试不同哈希算法
									return rsa.signAsync(dataBytes, keyPair.privateKey, "sha512").then(function(sigSha512: Bytes) {
										return rsa.verifyAsync(dataBytes, sigSha512, keyPair.publicKey, "sha512").then(function(verifySha512: Bool) {
											if (verifySha512) {
												trace("[OK] SHA512签名/验签通过");
											} else {
												trace("[FAIL] SHA512签名/验签失败!");
											}

											// ---- 固定密钥跨平台验证 (JWK) ----
											trace("--- 固定密钥测试（JWK 格式） ---");
											testSharedKeys(rsa, TestKeys.keyPairJwk, function() {
												// ---- 固定密钥跨平台验证 (PEM) ----
												trace("--- 固定密钥测试（PEM 格式，自动识别） ---");
												testSharedKeys(rsa, TestKeys.keyPairPem, function() {
													trace("=== 测试完成 ===");
												});
											});
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

	/** 固定密钥验证（加密/解密 + 签名/验签 + SHA-512） */
	static function testSharedKeys(rsa: RSA, keyPair: KeyPair, done: () -> Void) {
		var sharedPlain = "跨平台共享密钥测试 - Cross-platform shared key test";
		return rsa.encryptStringAsync(sharedPlain, keyPair.publicKey).then(function(sharedEncrypted: String) {
			return rsa.decryptStringAsync(sharedEncrypted, keyPair.privateKey).then(function(sharedDecrypted: String) {
				if (sharedDecrypted == sharedPlain) {
					trace("[OK] 固定密钥解密验证通过 (OAEP)");
				} else {
					trace("[FAIL] 固定密钥解密结果不匹配!");
				}

				var sharedData = Bytes.ofString(sharedPlain);
				return rsa.encryptAsync(sharedData, keyPair.publicKey).then(function(sharedEncBytes: Bytes) {
					return rsa.decryptAsync(sharedEncBytes, keyPair.privateKey).then(function(sharedDecBytes: Bytes) {
						if (sharedDecBytes.toString() == sharedPlain) {
							trace("[OK] 固定密钥 Bytes 加密/解密验证通过");
						} else {
							trace("[FAIL] 固定密钥 Bytes 加密/解密失败!");
						}

						return rsa.signAsync(sharedData, keyPair.privateKey).then(function(sharedSig: Bytes) {
							return rsa.verifyAsync(sharedData, sharedSig, keyPair.publicKey).then(function(sharedVerified: Bool) {
								if (sharedVerified) {
									trace("[OK] 固定密钥签名/验签验证通过");
								} else {
									trace("[FAIL] 固定密钥验签失败!");
								}

								return rsa.signAsync(sharedData, keyPair.privateKey, "sha512").then(function(sharedSig512: Bytes) {
									return rsa.verifyAsync(sharedData, sharedSig512, keyPair.publicKey, "sha512").then(function(sharedVerify512: Bool) {
										if (sharedVerify512) {
											trace("[OK] 固定密钥 SHA512 签名/验签通过");
										} else {
											trace("[FAIL] 固定密钥 SHA512 签名/验签失败!");
										}
										done();
									});
								});
							});
						});
					});
				});
			});
		});
	}
}
