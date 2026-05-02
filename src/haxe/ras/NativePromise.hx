package haxe.ras;

#if js
private typedef NativePromiseData<T> = js.lib.Promise<T>;
#else
private typedef NativePromiseData<T> = Dynamic;
#end

/**
 * 跨平台 Promise 类型
 *
 * JS 目标映射到 `js.lib.Promise<T>`，非 JS 目标映射到 `Dynamic`。
 * 非 JS 平台的异步方法会直接抛错，此类型仅用于统一接口签名。
 */
abstract NativePromise<T>(NativePromiseData<T>) {
	@:from
	static inline function fromData<T>(v: NativePromiseData<T>): NativePromise<T> {
		return cast v;
	}

	@:to
	function toData(): NativePromiseData<T> {
		return cast this;
	}

	#if js
	public function then<S>(onResolved: T -> S, ?onRejected: Dynamic -> S): NativePromise<S> {
		var p: js.lib.Promise<T> = cast this;
		return cast p.then(onResolved, onRejected);
	}

	public function catchError(onRejected: Dynamic -> Void): NativePromise<T> {
		var p: js.lib.Promise<T> = cast this;
		return cast p.catchError(onRejected);
	}
	#end
}
