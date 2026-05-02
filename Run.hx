class Run {
	static function main() {
		var runPath = Sys.programPath();
		var cliPath = StringTools.replace(runPath, "run.n", "bin/cli.js");
		Sys.command("node " + cliPath + " " + Sys.args().join(" "));
	}
}
