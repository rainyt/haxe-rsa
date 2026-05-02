package haxe.ras;

#if (js && nodejs)
typedef RSA = haxe.ras.backend.jsnode.RSA;
#elseif (js && !nodejs)
typedef RSA = haxe.ras.backend.jsbrowser.RSA;
#elseif cpp
typedef RSA = haxe.ras.backend.hxcpp.RSA;
#elseif jvm
typedef RSA = haxe.ras.backend.jvm.RSA;
#else
#error "haxe-ras 当前仅支持 JS（Node.js / 浏览器）、C++（hxcpp）和 Java（JVM）目标。"
#end
