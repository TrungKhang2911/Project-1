from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.core.db_adapter import KnowledgeBaseLoadError, KnowledgeBaseRepository
from app.core.kb_manager import (
    KnowledgeBaseManager,
    UnknownComponentError,
    UnknownControlError,
)

logger = logging.getLogger(__name__)


def _configured_origins() -> list[str]:
    configured = os.getenv(
        "CORS_ORIGINS", "http://localhost:3000,http://localhost:5173"
    )
    return [origin.strip() for origin in configured.split(",") if origin.strip()]


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    repository = KnowledgeBaseRepository()
    knowledge_base = repository.get_knowledge_base()
    application.state.kb_repository = repository
    application.state.kb_manager = KnowledgeBaseManager(knowledge_base)
    logger.info(
        "Loaded risk knowledge base version %s with %d components",
        knowledge_base.metadata.version,
        len(knowledge_base.components),
    )
    yield


app = FastAPI(
    title="AI System Security Risk Assessment API",
    description=(
        "Deterministic risk assessment using the configured knowledge base "
        "and context-aware mitigation weights."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_configured_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(router)


@app.exception_handler(UnknownComponentError)
async def unknown_component_handler(
    request: Request, exc: UnknownComponentError
) -> JSONResponse:
    logger.info("Rejected unknown component at %s: %s", request.url.path, exc)
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.exception_handler(UnknownControlError)
async def unknown_control_handler(
    request: Request, exc: UnknownControlError
) -> JSONResponse:
    logger.info("Rejected unknown control at %s: %s", request.url.path, exc)
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.exception_handler(KnowledgeBaseLoadError)
async def knowledge_base_handler(
    request: Request, exc: KnowledgeBaseLoadError
) -> JSONResponse:
    logger.error("Knowledge base unavailable at %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=503,
        content={"detail": "The risk knowledge base is unavailable."},
    )


@app.exception_handler(RequestValidationError)
async def request_validation_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    logger.debug("Request validation failed at %s", request.url.path)
    return JSONResponse(
        status_code=422,
        content={"detail": jsonable_encoder(exc.errors())},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    logger.exception("Unhandled API error at %s", request.url.path, exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred."},
    )
