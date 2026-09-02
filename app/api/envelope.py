"""API response envelope helpers.

Every endpoint returns the design's common success envelope
(03-api-contracts.md §6): a single top-level ``data`` object. Errors use the
mirror ``{"error": {"code", "message"}}`` shape, emitted centrally by the
:class:`~app.errors.AppError` handler in :mod:`app.main` — endpoints never build
error bodies themselves, which keeps the failure semantics privacy-safe and
consistent across every route (R18.4).

Keeping the success wrapper in one place means a route handler returns only its
*payload* (a Pydantic model or a plain ``dict``) and the wrapper guarantees the
consistent ``{"data": ...}`` shape without each handler repeating it.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


def envelope(payload: Any) -> dict[str, Any]:
    """Wrap a handler payload in the ``{"data": ...}`` success envelope.

    A :class:`~pydantic.BaseModel` payload is serialised with
    ``model_dump(mode="json")`` so UUIDs / datetimes become JSON-native values;
    any other value (a plain ``dict`` for tokens/acknowledgements) is passed
    through unchanged. The result is always a mapping with exactly one
    top-level ``data`` key.
    """
    if isinstance(payload, BaseModel):
        data: Any = payload.model_dump(mode="json")
    else:
        data = payload
    return {"data": data}


__all__ = ["envelope"]
