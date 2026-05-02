package haxe.ras.cli;

import haxe.ras.RSA;
import sys.io.File;
import sys.FileSystem;

class Main {
	static function main() {
		var args = Sys.args();

		if (args.length == 0 || args[0] == "--help" || args[0] == "-h") {
			printHelp();
			return;
		}

		var cmd = args.shift();
		switch cmd {
			case "create":
				cmdCreate(args);
			case "init":
				cmdInit(args);
			default:
				Sys.println('未知命令: $cmd');
				Sys.println('运行 "haxelib run haxe-ras --help" 查看用法。');
				Sys.exit(1);
		}
	}

	static function cmdInit(args: Array<String>) {
		var npmCmd = Sys.systemName() == "Windows" ? "npm.cmd" : "npm";
		var nullRedirect = Sys.systemName() == "Windows" ? "> NUL 2>&1" : "> /dev/null 2>&1";

		// 检查 npm 是否安装（静默检测）
		var npmCheck = Sys.command(npmCmd + " --version " + nullRedirect);
		if (npmCheck != 0) {
			Sys.println("错误: 未检测到 npm。请先安装 Node.js (包含 npm):");
			Sys.println("  https://nodejs.org/");
			Sys.exit(1);
		}

		Sys.println("检测到 npm，正在初始化项目...");

		// 如果不存在 package.json，创建一个最小配置
		var cwd = Sys.getCwd();
		var pkgPath = cwd + "/package.json";
		if (!FileSystem.exists(pkgPath)) {
			Sys.println("创建 package.json...");
			var pkg = "{\n  \"name\": \"haxe-ras-project\",\n  \"version\": \"1.0.0\",\n  \"private\": true\n}";
			File.saveContent(pkgPath, pkg);
		} else {
			Sys.println("package.json 已存在");
		}

		// 安装依赖
		Sys.println("运行 npm install...");
		var exitCode = Sys.command(npmCmd, ["install"]);
		if (exitCode == 0) {
			Sys.println("初始化完成。");
		} else {
			Sys.println("npm install 失败，退出码: " + exitCode);
			Sys.exit(1);
		}
	}

	static function cmdCreate(args: Array<String>) {
		var bits = 2048;
		var outPrefix: Null<String> = null;

		var i = 0;
		while (i < args.length) {
			switch args[i] {
				case "--bits":
					i++;
					bits = Std.parseInt(args[i]);
					if (bits < 1024 || bits > 8192) {
						Sys.println('错误: 密钥长度应在 1024-8192 之间');
						Sys.exit(1);
					}
				case "--out", "-o":
					i++;
					outPrefix = args[i];
				default:
					Sys.println('未知参数: ${args[i]}');
					Sys.exit(1);
			}
			i++;
		}

		Sys.println('正在生成 ${bits}-bit RSA 密钥对...');
		var rsa = new RSA();
		var keyPair = rsa.generateKeyPair(bits);

		if (outPrefix != null) {
			var pubPath = outPrefix + ".pub";
			var privPath = outPrefix + ".priv";
			File.saveContent(pubPath, keyPair.publicKey);
			File.saveContent(privPath, keyPair.privateKey);
			Sys.println('公钥已保存到: $pubPath');
			Sys.println('私钥已保存到: $privPath');
		} else {
			Sys.println("=== 公钥 (SPKI/PEM) ===");
			Sys.println(keyPair.publicKey);
			Sys.println("=== 私钥 (PKCS#8/PEM) ===");
			Sys.println(keyPair.privateKey);
		}
	}

	static function printHelp() {
		Sys.println("haxe-ras - Haxe 跨平台 RSA 加密工具");
		Sys.println("");
		Sys.println("用法: haxelib run haxe-ras <命令> [选项]");
		Sys.println("");
		Sys.println("命令:");
		Sys.println("  create       生成 RSA 密钥对");
		Sys.println("  init         初始化项目环境（检测 npm 并安装依赖）");
		Sys.println("");
		Sys.println("create 选项:");
		Sys.println("  --bits <n>   密钥长度（默认 2048，范围 1024-8192）");
		Sys.println("  --out, -o <前缀>  保存到文件（生成 <前缀>.pub 和 <前缀>.priv）");
		Sys.println("");
		Sys.println("示例:");
		Sys.println("  haxelib run haxe-ras init                       # 初始化项目");
		Sys.println("  haxelib run haxe-ras create                     # 输出到标准输出");
		Sys.println("  haxelib run haxe-ras create --bits 4096         # 4096 位密钥");
		Sys.println("  haxelib run haxe-ras create -o ./keys/mykey    # 保存到文件");
	}
}
