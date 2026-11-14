from __future__ import annotations

import asyncio
import json
from pathlib import Path

from app.core.hybrid_manager import HybridRiskManager
from app.core.kb_manager import KnowledgeBaseManager
from app.schemas.kb_schema import (
    AssessmentRequest,
    EvaluatedRiskResult,
    KnowledgeBaseDocument,
    NodeInput,
)


KB_PATH = Path(__file__).resolve().parents[1] / "app" / "data" / "rule_store.json"


class FakeLLMRiskAnalyzer:
    async def analyze(
        self, _request: AssessmentRequest
    ) -> list[EvaluatedRiskResult]:
        return [
            EvaluatedRiskResult(
                source_component="Custom component",
                risk_id="AI-01",
                risk_name="Novel risk",
                nist_categories=["GOVERN"],
                attack_scenario="An architecture-specific attack path.",
                inherent_score=25,
                residual_likelihood=5,
                residual_impact=5,
                residual_score=1,
                severity_level="Low",
                recommended_action="Add a dedicated security control.",
                missing_mitigations=[],
            )
        ]

    async def analyze_custom_component(
        self, node: NodeInput
    ) -> list[EvaluatedRiskResult]:
        return [
            EvaluatedRiskResult(
                source_component=node.custom_description or "Custom component",
                risk_id="CUSTOM-01",
                risk_name="Custom component risk",
                nist_categories=["GOVERN"],
                attack_scenario="An attack against the custom component.",
                inherent_score=16,
                residual_likelihood=3,
                residual_impact=4,
                residual_score=12,
                severity_level="High",
                recommended_action="Apply the recommended mitigation.",
                missing_mitigations=["Apply the recommended mitigation."],
            )
        ]


def test_hybrid_assessment_merges_and_recalculates_scores() -> None:
    with KB_PATH.open("r", encoding="utf-8") as file:
        knowledge_base = KnowledgeBaseDocument.model_validate(json.load(file))
    manager = HybridRiskManager(
        KnowledgeBaseManager(knowledge_base),
        FakeLLMRiskAnalyzer(),
    )
    request = AssessmentRequest(
        architecture=[{"node_type": "Model", "is_public": True, "controls": []}]
    )

    response = asyncio.run(manager.assess_hybrid_architecture(request))
    ai_risk = next(risk for risk in response.results if risk.risk_id == "AI-01")

    assert len(response.results) == 3
    assert ai_risk.residual_score == 25
    assert ai_risk.severity_level == "Critical"
    assert response.overall_risk_score == 25
    assert response.overall_severity == "Critical"
    assert response.risk_matrix_summary[4][4] == 1


def test_custom_component_is_assessed_by_llm_without_static_rules() -> None:
    with KB_PATH.open("r", encoding="utf-8") as file:
        knowledge_base = KnowledgeBaseDocument.model_validate(json.load(file))
    manager = HybridRiskManager(
        KnowledgeBaseManager(knowledge_base),
        FakeLLMRiskAnalyzer(),
    )
    request = AssessmentRequest(
        architecture=[
            {
                "node_type": "Other",
                "custom_description": "Internal Redis cache",
                "is_public": False,
                "controls": [],
            }
        ]
    )

    response = asyncio.run(manager.assess_hybrid_architecture(request))
    custom_risk = response.results[0]

    assert custom_risk.risk_id == "CUSTOM-01"
    assert custom_risk.source_component == "Internal Redis cache"
    assert custom_risk.residual_score == 12
    assert response.overall_risk_score == 12
    assert response.risk_matrix_summary[2][3] == 1
