from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from app.core.kb_manager import KnowledgeBaseManager, UnknownControlError
from app.schemas.kb_schema import AssessmentRequest, KnowledgeBaseDocument


KB_PATH = Path(__file__).resolve().parents[1] / "app" / "data" / "rule_store.json"


@pytest.fixture
def kb_data() -> dict[str, Any]:
    with KB_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


@pytest.fixture
def manager(kb_data: dict[str, Any]) -> KnowledgeBaseManager:
    return KnowledgeBaseManager(KnowledgeBaseDocument.model_validate(kb_data))


def test_genai_rag_unprotected(manager: KnowledgeBaseManager) -> None:
    response = manager.assess(
        AssessmentRequest(
            architecture=[
                {"node_type": "Model", "is_public": True, "controls": []},
                {"node_type": "Vector DB", "is_public": False, "controls": []},
            ]
        )
    )
    results = {result.risk_id: result for result in response.results}

    assert results["LLM01"].inherent_score == 16
    assert results["LLM01"].residual_score == 16
    assert results["LLM01"].severity_level == "High"
    assert results["LLM01"].missing_mitigations == [
        "[CTRL_SYS_PROMPT_SEP] Tách biệt rõ ràng System Prompt và dữ liệu đầu vào của người dùng.",
        "[CTRL_GUARDRAILS] Triển khai bộ lọc đầu vào/đầu ra (AI Guardrails) để chặn từ khóa độc hại.",
    ]

    assert results["LLM06"].inherent_score == 12
    assert results["LLM06"].residual_score == 12
    assert results["LLM06"].severity_level == "High"
    assert len(results["LLM06"].missing_mitigations) == 1
    assert results["LLM06"].missing_mitigations[0].startswith(
        "[CTRL_PII_MASKING]"
    )

    assert results["LLM03"].inherent_score == 15
    assert results["LLM03"].residual_score == 10
    assert results["LLM03"].severity_level == "Medium"
    assert [item.split("]", maxsplit=1)[0] + "]" for item in results["LLM03"].missing_mitigations] == [
        "[CTRL_VECTOR_RBAC]",
        "[CTRL_RAG_VALIDATION]",
    ]
    assert response.risk_matrix_summary[3][3] == 1
    assert response.risk_matrix_summary[2][3] == 1
    assert response.risk_matrix_summary[1][4] == 1


def test_predictive_ml_mitigated(
    manager: KnowledgeBaseManager,
) -> None:
    baseline = manager.assess(
        AssessmentRequest(
            architecture=[
                {
                    "node_type": "Predictive Model",
                    "is_public": True,
                    "controls": [],
                }
            ]
        )
    )
    mitigated = manager.assess(
        AssessmentRequest(
            architecture=[
                {
                    "node_type": "Predictive Model",
                    "is_public": True,
                    "controls": [
                        "CTRL_ADVERSARIAL_TRAIN",
                        "CTRL_INPUT_DENOISING",
                    ],
                }
            ]
        )
    )

    baseline_ml01 = next(item for item in baseline.results if item.risk_id == "ML01")
    mitigated_ml01 = next(
        item for item in mitigated.results if item.risk_id == "ML01"
    )
    assert baseline_ml01.inherent_score == 16
    assert baseline_ml01.residual_score == 16
    assert mitigated_ml01.inherent_score == 16
    assert mitigated_ml01.residual_likelihood == round(4 * (1 - 0.35 - 0.25))
    assert mitigated_ml01.residual_score == 8
    assert mitigated_ml01.severity_level == "Medium"
    assert mitigated_ml01.missing_mitigations == []


def test_max_discount_cap(kb_data: dict[str, Any]) -> None:
    modified_data = copy.deepcopy(kb_data)
    mitigations = modified_data["components"]["Model"]["risks"][0][
        "technical_mitigations"
    ]
    mitigations[0]["discount_weight"] = 0.45
    mitigations[1]["discount_weight"] = 0.45
    manager = KnowledgeBaseManager(modified_data)

    response = manager.assess(
        AssessmentRequest(
            architecture=[
                {
                    "node_type": "Model",
                    "is_public": True,
                    "controls": ["CTRL_SYS_PROMPT_SEP", "CTRL_GUARDRAILS"],
                }
            ]
        )
    )
    prompt_injection = next(
        item for item in response.results if item.risk_id == "LLM01"
    )

    risk = manager.kb.components["Model"].risks[0]
    assert manager.calculate_total_discount(
        risk, {"CTRL_SYS_PROMPT_SEP", "CTRL_GUARDRAILS"}
    ) == 0.80
    assert prompt_injection.residual_likelihood == max(1, round(4 * (1 - 0.80)))
    assert prompt_injection.residual_score == 4


def test_rejects_control_not_defined_for_component(
    manager: KnowledgeBaseManager,
) -> None:
    with pytest.raises(UnknownControlError):
        manager.assess(
            AssessmentRequest(
                architecture=[
                    {
                        "node_type": "Model",
                        "is_public": True,
                        "controls": ["CTRL_RATE_LIMITING"],
                    }
                ]
            )
        )


def test_custom_component_requires_description() -> None:
    with pytest.raises(ValueError, match="custom_description is required"):
        AssessmentRequest(
            architecture=[
                {"node_type": "Other", "is_public": False, "controls": []}
            ]
        )


def test_custom_component_rejects_predefined_controls() -> None:
    with pytest.raises(ValueError, match="cannot use predefined security controls"):
        AssessmentRequest(
            architecture=[
                {
                    "node_type": "Other",
                    "custom_description": "Internal Redis cache",
                    "is_public": False,
                    "controls": ["CTRL_GUARDRAILS"],
                }
            ]
        )
