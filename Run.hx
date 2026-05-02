class Run {
	static function main() {
		var runPath = Sys.programPath();
		var cliPath = StringTools.replace(runPath, "run.n", "bin/cli.js");
		var args = Sys.args();
		// haxelib run 会在末尾追加库路径，如果最后一个参数是路径则移除
		if (args.length > 0 && sys.FileSystem.exists(args[args.length - 1])) {
			args.pop();
		}
		Sys.command("node " + cliPath + " " + args.join(" "));
	}
}
