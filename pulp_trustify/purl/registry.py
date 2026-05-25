from __future__ import annotations

from typing import Callable

_parsers: dict[str, Callable[[str], str | None]] = {}


def register(ecosystem: str) -> Callable:
    def decorator(
        func: Callable[[str], str | None],
    ) -> Callable[[str], str | None]:
        _parsers[ecosystem] = func
        return func

    return decorator


def url_to_purl(path: str) -> str | None:
    for parser in _parsers.values():
        result = parser(path)
        if result is not None:
            return result
    return None
