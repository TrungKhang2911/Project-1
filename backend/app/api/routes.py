from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from app.core.assessment_store import (
    AssessmentStore,
    format_csv_report,
    format_markdown_report,
)
from app.core.hybrid_manager import HybridRiskManager
from app.core.kb_manager import KnowledgeBaseManager
from app.core.pattern_detector import PatternDetector
from app.schemas.agentic_schema import (
    ClassificationResponse,
    QuestionnaireAnswers,
    SavedAssessmentCreate,
    SavedAssessmentRecord,
    SavedAssessmentsListResponse,
)
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


def get_pattern_detector(request: Request) -> PatternDetector:
    detector = getattr(request.app.state, "pattern_detector", None)
    if not isinstance(detector, PatternDetector):
        raise RuntimeError("The agentic pattern detector is not initialized.")
    return detector


def get_assessment_store(request: Request) -> AssessmentStore:
    store = getattr(request.app.state, "assessment_store", None)
    if not isinstance(store, AssessmentStore):
        raise RuntimeError("The assessment store is not initialized.")
    return store


@router.post("/agentic/classify", response_model=ClassificationResponse)
async def classify_agentic_architecture(
    payload: QuestionnaireAnswers,
    detector: PatternDetector = Depends(get_pattern_detector),
) -> ClassificationResponse:
    """Map plain-language questionnaire answers to agentic design patterns."""
    return ClassificationResponse(detection=await detector.detect(payload))


@router.post("/agentic/records", response_model=SavedAssessmentRecord, status_code=201)
def save_assessment_record(
    payload: SavedAssessmentCreate,
    store: AssessmentStore = Depends(get_assessment_store),
) -> SavedAssessmentRecord:
    """Persist an evaluated assessment so it can be reviewed or exported later."""
    return store.save(payload)


@router.get("/agentic/records", response_model=SavedAssessmentsListResponse)
def list_assessment_records(
    store: AssessmentStore = Depends(get_assessment_store),
) -> SavedAssessmentsListResponse:
    return SavedAssessmentsListResponse(records=store.list_records())


@router.get("/agentic/records/{assessment_id}", response_model=SavedAssessmentRecord)
def get_assessment_record(
    assessment_id: str,
    store: AssessmentStore = Depends(get_assessment_store),
) -> SavedAssessmentRecord:
    record = store.get(assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment record not found.")
    return record


@router.delete("/agentic/records/{assessment_id}", status_code=204)
def delete_assessment_record(
    assessment_id: str,
    store: AssessmentStore = Depends(get_assessment_store),
) -> None:
    if not store.delete(assessment_id):
        raise HTTPException(status_code=404, detail="Assessment record not found.")


@router.get("/agentic/records/{assessment_id}/export")
def export_assessment_record(
    assessment_id: str,
    format: Literal["json", "md", "csv"] = Query(default="md"),
    store: AssessmentStore = Depends(get_assessment_store),
) -> PlainTextResponse:
    record = store.get(assessment_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Assessment record not found.")
    if format == "json":
        return PlainTextResponse(
            content=record.model_dump_json(indent=2),
            media_type="application/json; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="risk-report-{assessment_id}.json"'
            },
        )
    if format == "csv":
        return PlainTextResponse(
            content=format_csv_report(record),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="risk-report-{assessment_id}.csv"'
            },
        )
    return PlainTextResponse(
        content=format_markdown_report(record),
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="risk-report-{assessment_id}.md"'
        },
    )


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
