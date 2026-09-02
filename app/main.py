"""FastAPI application factory.

Builds the ASGI app, mounts the aggregate API router, and installs the
privacy-safe exception handlers that map every failure to the response envelope
described in the design's Error Handling section:

* :class:`~app.errors.AppError` — the typed service/authorization errors, each
  carrying its own ``http_status`` (401/403/404/409/422) and actionable
  ``code``.
* :class:`~fastapi.exceptions.RequestValidationError` — FastAPI/Pydantic request
  validation failures, normalised to ``422 VALIDATION_ERROR`` so a malformed
  body / unknown field / bad path param never leaks FastAPI's default
  ``{"detail": [...]}`` field-level shape.

Bodies never disclose ownership, account existence, resource existence where
that would leak, or internal schema structure (06-authorization-matrix.md §18);
the human-readable ``message`` stays generic while ``code`` drives client
branching, applied uniformly across every endpoint (R18.4).
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api import api_router
from app.api.dependencies import REQUEST_ID_STATE_ATTR
from app.api.pipeline import REQUEST_ID_HEADER, extract_request_id
from app.errors import AppError, ValidationError


def _error_body(code: str, message: str) -> dict[str, dict[str, str]]:
    """Shape the API error envelope (03-api-contracts.md §6)."""
    return {"error": {"code": code, "message": message}}


def create_app() -> FastAPI:
    """Construct and configure the FastAPI application."""
    app = FastAPI(
        title="Healthy Couple — Foundation",
        version="0.1.0",
        description=(
            "Foundation slice: authentication & sessions, accounts, couples & "
            "invitations, and the server-side authorization / privacy layer."
        ),
    )

    @app.middleware("http")
    async def _request_id_middleware(request: Request, call_next):
        """Establish a per-request correlation id at the front of the pipeline.

        Propagates a client-supplied ``X-Request-ID`` or generates a uuid4,
        stashes it on ``request.state`` so dependencies/services share one id for
        audit correlation (R17.5), and echoes it back on the response so a caller
        can correlate its own logs. Runs before the route's rate-limit / auth
        dependencies (rate limit -> auth -> authz).
        """
        request_id = extract_request_id(request.headers.get(REQUEST_ID_HEADER))
        setattr(request.state, REQUEST_ID_STATE_ATTR, request_id)
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request_id
        return response

    @app.exception_handler(AppError)
    async def _handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        # Generic, privacy-safe body; `code` drives client branching. Echo the
        # request id so failures stay correlatable with the audit trail (R17.5).
        request_id = getattr(request.state, REQUEST_ID_STATE_ATTR, None)
        headers = {REQUEST_ID_HEADER: request_id} if request_id else None
        return JSONResponse(
            status_code=exc.http_status,
            content=_error_body(exc.code, exc.message),
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Normalise FastAPI/Pydantic validation errors into the privacy-safe envelope.

        FastAPI's default 422 handler returns ``{"detail": [...]}`` which leaks
        field names, types, and constraints to the caller.  The design's error
        table maps all malformed/missing input to ``422 VALIDATION_ERROR`` with a
        generic message (R1.3, R18.4).  This handler replaces the default so
        *every* 422 — missing body fields, ``extra="forbid"`` violations, bad
        path-param types — uses the same ``{"error": {"code", "message"}}``
        envelope as the rest of the API, disclosing nothing about internal
        schema structure.
        """
        ve = ValidationError()
        request_id = getattr(request.state, REQUEST_ID_STATE_ATTR, None)
        headers = {REQUEST_ID_HEADER: request_id} if request_id else None
        return JSONResponse(
            status_code=ve.http_status,
            content=_error_body(ve.code, ve.message),
            headers=headers,
        )

    app.include_router(api_router)

    return app


# Module-level ASGI app for `uvicorn app.main:app`.
app = create_app()


__all__ = ["create_app", "app"]
