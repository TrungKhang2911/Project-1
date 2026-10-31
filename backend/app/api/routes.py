from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.hybrid_manager import HybridRiskManager
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


def get_hybrid_manager(request: Request) -> HybridRiskManager:
    manager = getattr(request.app.state, "hybrid_manager", None)
    if not isinstance(manager, HybridRiskManager):
        raise RuntimeError("The hybrid risk manager is not initialized.")
    return manager


@router.post("/assess", response_model=AssessmentResponse)
async def assess_architecture(
    payload: AssessmentRequest,
    manager: HybridRiskManager = Depends(get_hybrid_manager),
) -> AssessmentResponse:
    return await manager.assess_hybrid_architecture(payload)


@router.get("/components", response_model=ComponentsResponse)
def list_components(
    manager: KnowledgeBaseManager = Depends(get_kb_manager),
) -> ComponentsResponse:
    return manager.get_components()
