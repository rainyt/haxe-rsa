package haxe.rsa;

#if (cpp || sys || jvm)

/**
 * 非 JS 平台的简易 Promise 实现
 *
 * 纯状态机，不依赖 Timer 或事件循环。
 * 异步 API 使用者通过 Timer.delay 延迟 executor 执行来驱动异步行为。
 */
class PromiseImpl<T> {
	static inline var PENDING = 0;
	static inline var RESOLVED = 1;
	static inline var REJECTED = 2;

	var _state: Int = PENDING;
	var _value: Null<T>;
	var _error: Dynamic;
	var _callbacks: Array<{resolve: T->Void, reject: Dynamic->Void}> = [];

	public function new(executor: (T->Void, Dynamic->Void)->Void) {
		var self = this;
		_execute(executor);
	}

	function _execute(executor: (T->Void, Dynamic->Void)->Void) {
		var self = this;
		try {
			executor(
				function(v: T) {
					if (self._state == PENDING) {
						self._state = RESOLVED;
						self._value = v;
						self._flush();
					}
				},
				function(e: Dynamic) {
					if (self._state == PENDING) {
						self._state = REJECTED;
						self._error = e;
						self._flush();
					}
				}
			);
		} catch (e: Dynamic) {
			if (self._state == PENDING) {
				self._state = REJECTED;
				self._error = e;
				self._flush();
			}
		}
	}

	function _flush() {
		var cbs = _callbacks;
		_callbacks = [];
		for (cb in cbs) {
			if (_state == RESOLVED) {
				try { cb.resolve(_value); } catch (e: Dynamic) { /* eaten */ }
			} else {
				try { cb.reject(_error); } catch (e: Dynamic) { /* eaten */ }
			}
		}
	}

	public function then<S>(onResolved: T->S, ?onRejected: Dynamic->S): PromiseImpl<S> {
		var self = this;
		return new PromiseImpl(function(resolve, reject) {
			function handleResolve(v: T) {
				try {
					resolve(onResolved(v));
				} catch (e: Dynamic) {
					reject(e);
				}
			}
			function handleReject(e: Dynamic) {
				if (onRejected != null) {
					try {
						resolve(onRejected(e));
					} catch (e2: Dynamic) {
						reject(e2);
					}
				} else {
					reject(e);
				}
			}

			if (self._state == RESOLVED) {
				handleResolve(self._value);
			} else if (self._state == REJECTED) {
				handleReject(self._error);
			} else {
				self._callbacks.push({resolve: handleResolve, reject: handleReject});
			}
		});
	}

	public function catchError(onRejected: Dynamic->Void): PromiseImpl<T> {
		var self = this;
		return new PromiseImpl(function(resolve, reject) {
			function handleResolve(v: T) { resolve(v); }
			function handleReject(e: Dynamic) {
				try {
					onRejected(e);
					reject(e); // 仍然 reject 以维持类型
				} catch (e2: Dynamic) {
					reject(e2);
				}
			}

			if (self._state == RESOLVED) {
				handleResolve(self._value);
			} else if (self._state == REJECTED) {
				handleReject(self._error);
			} else {
				self._callbacks.push({resolve: handleResolve, reject: handleReject});
			}
		});
	}

	public static function resolve<U>(value: U): PromiseImpl<U> {
		return new PromiseImpl(function(resolve, reject) resolve(value));
	}

	public static function reject<U>(error: Dynamic): PromiseImpl<U> {
		return new PromiseImpl(function(resolve, reject) reject(error));
	}
}

#end
