from __future__ import annotations

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api import create_api_router
from app.config import Settings, settings as default_settings
from app.harness import Harness
from app.middleware import PlatformSecurityMiddleware
from app.runtime import ApplicationServices, build_services


def create_app(
    settings: Settings | None = None,
    *,
    harness: Harness | None = None,
    services: ApplicationServices | None = None,
) -> FastAPI:
    selected_settings = settings or default_settings
    selected_services = services or build_services(selected_settings, harness=harness)
    application = FastAPI(
        title="Adhikar DPR Triage Console",
        version="1.0.0",
        description="Human-approved triage controls aligned to DPDP obligations.",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.state.services = selected_services
    application.add_middleware(PlatformSecurityMiddleware)

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(_request, exc: RequestValidationError):
        safe_errors = [
            {
                "location": list(error["loc"]),
                "message": error["msg"],
                "type": error["type"],
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content={
                "detail": {
                    "code": "VALIDATION_ERROR",
                    "errors": safe_errors,
                }
            },
        )

    application.include_router(create_api_router(selected_services))
    return application

