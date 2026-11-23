"""Extension points.

* waterfall events (``tools/pre-execute``, ``tools/execute``,
  ``tools/post-execute``, ``agent/pre-step``): each handler receives the value
  and a ``next`` callable and must call ``next(value)`` to delegate;
* serial events (``agent/turn-stopping``): handlers run in order, the first
  non-None answer wins.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable

Handler = Callable[..., Any]


class HookBus:
    def __init__(self):
        self._h: dict[str, list[tuple[int, Handler]]] = defaultdict(list)

    def on(self, name: str, fn: Handler, priority: int = 0) -> Callable[[], None]:
        self._h[name].append((priority, fn))
        self._h[name].sort(key=lambda x: -x[0])

        def dispose():
            self._h[name] = [h for h in self._h[name] if h[1] is not fn]
        return dispose

    def waterfall(self, name: str, value: Any, ctx: Any, final: Callable[[Any], Any]) -> Any:
        handlers = [fn for _, fn in self._h.get(name, [])]

        def run(i: int, v: Any) -> Any:
            if i >= len(handlers):
                return final(v)
            return handlers[i](v, ctx, lambda nv: run(i + 1, nv))
        return run(0, value)

    def serial(self, name: str, ctx: Any) -> Any:
        for _, fn in self._h.get(name, []):
            res = fn(ctx)
            if res is not None:
                return res
        return None
