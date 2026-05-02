package haxe.ras;

#if (js && nodejs)
	typedef RSA = haxe.ras.backend.jsnode.RSA;
#elseif (js && !nodejs)
	typedef RSA = haxe.ras.backend.jsbrowser.RSA;
#else
	#error "haxe-ras 当前版本仅支持 JS 目标（Node.js: -D nodejs，浏览器: 不定义 nodejs）。"
#end
