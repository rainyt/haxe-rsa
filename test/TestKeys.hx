package;

import haxe.ras.KeyPair;

/**
 * 跨后端共享的测试密钥对（2048 位 RSA）。
 *
 * PEM 格式用于 Node.js / C++ / JVM 后端，JWK 格式用于浏览器后端。
 * 两个格式代表同一对 RSA 密钥，确保所有后端使用相同密钥进行加解密验证。
 */
class TestKeys {
	/** PEM 格式公钥（X.509 SPKI） */
	public static var publicKeyPem(default, never): String = "-----BEGIN PUBLIC KEY-----\n"
		+ "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuHo73+jDyxP5LaHWmV1M\n"
		+ "BY6+rBtzt/j2VP6XJ6clR95iFF7g7bkIZqk3qdEqqgT9C1nbEK1Rp9gXxzRWCrrR\n"
		+ "rEM6ZJ++RCzNNh+J0vE09QIdZ01Vr5Uh57Wet95yZU2uzJ3SfQqRgvVR4bXdgRQO\n"
		+ "bZJSSoShF/3/fV8QdFeqLqe/RorK1AHhWuwJFn9vJIRWYjdw3qo858lwC8M6xute\n"
		+ "e4wn5xxRM6ZSJgHRIZgYuyew4IquKFgtVYhXuqVB+C71cUDfT/1oFadKM35ztJni\n"
		+ "TsEwG88XvUVxAFjvt9YIUcIgaVqxLKS5NKrbZ8LEUEw8vZeIrTGU2D9NO38fDeLm\n"
		+ "DQIDAQAB\n"
		+ "-----END PUBLIC KEY-----";

	/** PEM 格式私钥（PKCS#8） */
	public static var privateKeyPem(default, never): String = "-----BEGIN PRIVATE KEY-----\n"
		+ "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC4ejvf6MPLE/kt\n"
		+ "odaZXUwFjr6sG3O3+PZU/pcnpyVH3mIUXuDtuQhmqTep0SqqBP0LWdsQrVGn2BfH\n"
		+ "NFYKutGsQzpkn75ELM02H4nS8TT1Ah1nTVWvlSHntZ633nJlTa7MndJ9CpGC9VHh\n"
		+ "td2BFA5tklJKhKEX/f99XxB0V6oup79GisrUAeFa7AkWf28khFZiN3DeqjznyXAL\n"
		+ "wzrG6157jCfnHFEzplImAdEhmBi7J7Dgiq4oWC1ViFe6pUH4LvVxQN9P/WgVp0oz\n"
		+ "fnO0meJOwTAbzxe9RXEAWO+31ghRwiBpWrEspLk0qttnwsRQTDy9l4itMZTYP007\n"
		+ "fx8N4uYNAgMBAAECggEABxLFJwxzR2vZLv2Vb1UQGpo/mttEzsEu9sRtPy66o4/c\n"
		+ "dfhkvcPnIjXEsqm+7eNAYMlKkkNHAUosMG3qcUGUOdUfd2ckAgd8VdUtpG1g6n0K\n"
		+ "hUdS+ZpcmrHdNFXrg0SQTXwTeEppsmcEHPhFCW0F5My9tx0Kc6BNH2PZmAOaSaAb\n"
		+ "RHZSsNhxD4cGcMaqKcgaV/pK9eAmSuG6wNa8SP012wioCQarwwpH1JRU4LRUKC0e\n"
		+ "7PIB8Y/QuwLRVr9FCL9cTdhkLKAk8+BQRx4MR3QSlaGcdkTiM4o4sQTmKGOACGDa\n"
		+ "bE8Uh64E1AOwtJOGDbru3OCI4rql5bb327k+XqszIQKBgQD0xqy96zRLFf1gOVsw\n"
		+ "I/sErki79+8aytktpJvMdKqbuQhp31tp0mi9+Li778mLHoRy4xiUlTyNTxoooZ33\n"
		+ "cMBzloqcSW8yj7TSlPQ3jgg6wdAt53D/YQHqyecxY4RDXzha6AWQ26mfOtz8AjzE\n"
		+ "D8AVYqpF0EvnQbiYrCcJnwLY4QKBgQDA770g94qRJzN6+TfacgZny/Yb8oWr+qem\n"
		+ "BqXPq/3AjLkBpG8DAfDqLg2tjqLLzo8xVIqgtOEGz4JQk/JPxNFbkt6Fd7fFkbeg\n"
		+ "z1IjGWA0dy0OIuQgb9JbWBRquc2ARlaHDcN+v+Yb6cRYXjNfAccYUoHJEXt5cPfH\n"
		+ "10N0VbMWrQKBgHO6DufH8TRi1CWPWI6dJEvlPpwoL5LiPuX2gnaa3iK7y7+Ki4Sv\n"
		+ "pzfSBT1NtGMi7YoH1pJBMJy6vmphZvcbBtJfZW9YxMsJ6Hr7U6+EZl2pToy1dNY4\n"
		+ "/hgMl1LhcyILPfC07BS91idjRCGdyS8FJ1K1ED3rqkdO6kC8e8Rvun/hAoGAQ5w/\n"
		+ "lKvqfQ9VtQRclEpdAEazSfvk5+2AjmfJ90p4M9+cfXzYAh/OAuJ8nJNdbTpHZ6wO\n"
		+ "oF6CdNaG/iG6SkXYb9S58d+QIMX9qXa9e9tKoVgaC9giRVOqTaRCE1xlLUx4yf8C\n"
		+ "wQoSYzm6OpVYPzTqRhWzsXhU4qu5yOgglUXq6kkCgYEApohfsH1CUdf1L+rtDzpz\n"
		+ "lH1f24F7J+5JpkEd63x2TmP4uEalsHPHp3Mm9BjU1AkYVqoDpRhEnNCbMgX3RD9l\n"
		+ "3qgaL/n9zGi8Z4wrSLl+6j8e19I5NwMCaiB3hqwcbM09jwakT23CY2K11N+rQqGe\n"
		+ "uFJIRU0jQEiRp05YIfaEO+8=\n"
		+ "-----END PRIVATE KEY-----";

	/** 完整的 PEM 密钥对 */
	public static var keyPairPem(get, never): KeyPair;

	static function get_keyPairPem(): KeyPair {
		return { publicKey: publicKeyPem, privateKey: privateKeyPem };
	}

	/** JWK 格式公钥（JSON 字符串） */
	public static var publicKeyJwk(default, never): String = '{"kty":"RSA","n":"uHo73-jDyxP5LaHWmV1MBY6-rBtzt_j2VP6XJ6clR95iFF7g7bkIZqk3qdEqqgT9C1nbEK1Rp9gXxzRWCrrRrEM6ZJ--RCzNNh-J0vE09QIdZ01Vr5Uh57Wet95yZU2uzJ3SfQqRgvVR4bXdgRQObZJSSoShF_3_fV8QdFeqLqe_RorK1AHhWuwJFn9vJIRWYjdw3qo858lwC8M6xutee4wn5xxRM6ZSJgHRIZgYuyew4IquKFgtVYhXuqVB-C71cUDfT_1oFadKM35ztJniTsEwG88XvUVxAFjvt9YIUcIgaVqxLKS5NKrbZ8LEUEw8vZeIrTGU2D9NO38fDeLmDQ","e":"AQAB"}';

	/** JWK 格式私钥（JSON 字符串） */
	public static var privateKeyJwk(default, never): String = '{"kty":"RSA","n":"uHo73-jDyxP5LaHWmV1MBY6-rBtzt_j2VP6XJ6clR95iFF7g7bkIZqk3qdEqqgT9C1nbEK1Rp9gXxzRWCrrRrEM6ZJ--RCzNNh-J0vE09QIdZ01Vr5Uh57Wet95yZU2uzJ3SfQqRgvVR4bXdgRQObZJSSoShF_3_fV8QdFeqLqe_RorK1AHhWuwJFn9vJIRWYjdw3qo858lwC8M6xutee4wn5xxRM6ZSJgHRIZgYuyew4IquKFgtVYhXuqVB-C71cUDfT_1oFadKM35ztJniTsEwG88XvUVxAFjvt9YIUcIgaVqxLKS5NKrbZ8LEUEw8vZeIrTGU2D9NO38fDeLmDQ","e":"AQAB","d":"BxLFJwxzR2vZLv2Vb1UQGpo_mttEzsEu9sRtPy66o4_cdfhkvcPnIjXEsqm-7eNAYMlKkkNHAUosMG3qcUGUOdUfd2ckAgd8VdUtpG1g6n0KhUdS-ZpcmrHdNFXrg0SQTXwTeEppsmcEHPhFCW0F5My9tx0Kc6BNH2PZmAOaSaAbRHZSsNhxD4cGcMaqKcgaV_pK9eAmSuG6wNa8SP012wioCQarwwpH1JRU4LRUKC0e7PIB8Y_QuwLRVr9FCL9cTdhkLKAk8-BQRx4MR3QSlaGcdkTiM4o4sQTmKGOACGDabE8Uh64E1AOwtJOGDbru3OCI4rql5bb327k-XqszIQ","p":"9Masves0SxX9YDlbMCP7BK5Iu_fvGsrZLaSbzHSqm7kIad9badJovfi4u-_Jix6EcuMYlJU8jU8aKKGd93DAc5aKnElvMo-00pT0N44IOsHQLedw_2EB6snnMWOEQ184WugFkNupnzrc_AI8xA_AFWKqRdBL50G4mKwnCZ8C2OE","q":"wO-9IPeKkSczevk32nIGZ8v2G_KFq_qnpgalz6v9wIy5AaRvAwHw6i4NrY6iy86PMVSKoLThBs-CUJPyT8TRW5LehXe3xZG3oM9SIxlgNHctDiLkIG_SW1gUarnNgEZWhw3Dfr_mG-nEWF4zXwHHGFKByRF7eXD3x9dDdFWzFq0","dp":"c7oO58fxNGLUJY9Yjp0kS-U-nCgvkuI-5faCdpreIrvLv4qLhK-nN9IFPU20YyLtigfWkkEwnLq-amFm9xsG0l9lb1jEywnoevtTr4RmXalOjLV01jj-GAyXUuFzIgs98LTsFL3WJ2NEIZ3JLwUnUrUQPeuqR07qQLx7xG-6f-E","dq":"Q5w_lKvqfQ9VtQRclEpdAEazSfvk5-2AjmfJ90p4M9-cfXzYAh_OAuJ8nJNdbTpHZ6wOoF6CdNaG_iG6SkXYb9S58d-QIMX9qXa9e9tKoVgaC9giRVOqTaRCE1xlLUx4yf8CwQoSYzm6OpVYPzTqRhWzsXhU4qu5yOgglUXq6kk","qi":"pohfsH1CUdf1L-rtDzpzlH1f24F7J-5JpkEd63x2TmP4uEalsHPHp3Mm9BjU1AkYVqoDpRhEnNCbMgX3RD9l3qgaL_n9zGi8Z4wrSLl-6j8e19I5NwMCaiB3hqwcbM09jwakT23CY2K11N-rQqGeuFJIRU0jQEiRp05YIfaEO-8"}';

	/** 完整的 JWK 密钥对 */
	public static var keyPairJwk(get, never): KeyPair;

	static function get_keyPairJwk(): KeyPair {
		return { publicKey: publicKeyJwk, privateKey: privateKeyJwk };
	}
}
