from __future__ import annotations

from typing import Callable

_parsers: dict[str, Callable[[str], str | None]] = {}
_content_parsers: dict[str, Callable[[object], str | None]] = {}


def register(ecosystem: str) -> Callable:
    """Register a URL-to-PURL parser for a package ecosystem."""

    def decorator(
        func: Callable[[str], str | None],
    ) -> Callable[[str], str | None]:
        _parsers[ecosystem] = func
        return func

    return decorator


def url_to_purl(path: str) -> str | None:
    """Convert a URL path to a PURL using registered parsers."""
    for parser in _parsers.values():
        result = parser(path)
        if result is not None:
            return result
    return None


def register_content(ecosystem: str) -> Callable:
    """Register a content-to-PURL parser for a package ecosystem."""

    def decorator(
        func: Callable[[object], str | None],
    ) -> Callable[[object], str | None]:
        _content_parsers[ecosystem] = func
        return func

    return decorator


def content_to_purl(content: object) -> str | None:
    """Convert a content object to a PURL using registered parsers."""
    for parser in _content_parsers.values():
        result = parser(content)
        if result is not None:
            return result
    return None
