from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.kb_manager import KnowledgeBaseManager
from app.schemas.kb_schema import (
    AssessmentRequest,
    AssessmentResponse,
    ComponentsResponse,
)

router = APIRouter(prefix="/api/v1", tags=["Risk Assessment"])


def get_kb_manager(request: Request) -> KnowledgeBaseManager:
    manager = getattr(request.app.state, "kb_manager", None)
    if not isinstance(manager, KnowledgeBaseManager):
        raise RuntimeError("The knowledge base manager is not initialized.")
    return manager


@router.post("/assess", response_model=AssessmentResponse)
def assess_architecture(
    payload: AssessmentRequest,
    manager: KnowledgeBaseManager = Depends(get_kb_manager),
) -> AssessmentResponse:
    return manager.assess(payload)


@router.get("/components", response_model=ComponentsResponse)
def list_components(
    manager: KnowledgeBaseManager = Depends(get_kb_manager),
) -> ComponentsResponse:
    return manager.get_components()
