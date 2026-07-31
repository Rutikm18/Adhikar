from __future__ import annotations

import re
import uuid

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

MAX_HTTP_BODY_BYTES = 256 * 1024
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class PlatformSecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        request_id = request.headers.get("X-Request-ID", "")
        if not _REQUEST_ID.fullmatch(request_id):
            request_id = uuid.uuid4().hex
        request.state.request_id = request_id

        content_length = request.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > MAX_HTTP_BODY_BYTES:
                    response = JSONResponse(
                        status_code=413,
                        content={
                            "detail": {
                                "code": "REQUEST_TOO_LARGE",
                                "message": "Request body exceeds 256 KiB.",
                            }
                        },
                    )
                    return self._secure(response, request_id, request.url.path)
            except ValueError:
                response = JSONResponse(
                    status_code=400,
                    content={"detail": {"code": "INVALID_CONTENT_LENGTH"}},
                )
                return self._secure(response, request_id, request.url.path)

        response = await call_next(request)
        return self._secure(response, request_id, request.url.path)

    @staticmethod
    def _secure(response: Response, request_id: str, path: str) -> Response:
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'self'; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "img-src 'self' data:; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'"
        )
        if path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        elif path.startswith("/assets/"):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return response
