package haxe.rsa;

#if (js && nodejs)
typedef RSA = haxe.rsa.backend.jsnode.RSA;
#elseif (js && !nodejs)
typedef RSA = haxe.rsa.backend.jsbrowser.RSA;
#elseif cpp
typedef RSA = haxe.rsa.backend.hxcpp.RSA;
#elseif jvm
typedef RSA = haxe.rsa.backend.jvm.RSA;
#else
#error "haxe-ras 当前仅支持 JS（Node.js / 浏览器）、C++（hxcpp）和 Java（JVM）目标。"
#end
