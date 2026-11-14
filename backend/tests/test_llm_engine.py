from __future__ import annotations

import asyncio
import json
from typing import Any

from pydantic import SecretStr

from app.core.config import Settings
from app.core import llm_engine
from app.core.llm_engine import LLMRiskAnalyzer
from app.schemas.kb_schema import AssessmentRequest, EvaluatedRiskResult, NodeInput


def _risk_payload(risk_id: str) -> dict[str, Any]:
    return EvaluatedRiskResult(
        source_component="Model",
        risk_id=risk_id,
        risk_name="Novel risk",
        nist_categories=["GOVERN"],
        attack_scenario="An architecture-specific attack path.",
        inherent_score=16,
        residual_likelihood=3,
        residual_impact=4,
        residual_score=12,
        severity_level="High",
        recommended_action="Add a dedicated security control.",
        missing_mitigations=[],
    ).model_dump()


def test_llm_analyzer_uses_schema_and_assigns_backend_risk_ids(
    monkeypatch: Any,
) -> None:
    captured_request: dict[str, Any] = {}
    response_body = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": json.dumps([_risk_payload("model-id")])}]
                }
            }
        ]
    }

    class MockResponse:
        status_code = 200

        def json(self) -> dict[str, Any]:
            return response_body

        def raise_for_status(self) -> None:
            return None

    class MockClient:
        def __init__(self, timeout: float) -> None:
            assert timeout == LLMRiskAnalyzer.REQUEST_TIMEOUT_SECONDS

        async def __aenter__(self) -> MockClient:
            return self

        async def __aexit__(
            self, _exc_type: Any, _exc_value: Any, _traceback: Any
        ) -> None:
            return None

        async def post(
            self, url: str, headers: dict[str, str], json: dict[str, Any]
        ) -> MockResponse:
            captured_request["url"] = url
            captured_request["headers"] = headers
            captured_request["payload"] = json
            return MockResponse()

    monkeypatch.setattr(llm_engine.httpx, "AsyncClient", MockClient)
    analyzer = LLMRiskAnalyzer(
        Settings(
            LLM_API_KEY=SecretStr("test-key"),
            LLM_MODEL_NAME="gemini-3.8-flash",
        )
    )
    request = AssessmentRequest(
        architecture=[{"node_type": "Model", "is_public": True, "controls": []}]
    )

    risks = asyncio.run(analyzer.analyze(request))

    assert risks[0].risk_id == "AI-01"
    assert captured_request["headers"] == {"x-goog-api-key": "test-key"}
    schema = captured_request["payload"]["generationConfig"]["responseSchema"]
    assert schema["type"] == "ARRAY"
    assert set(schema["items"]["required"]) == set(_risk_payload("model-id"))


def test_llm_analyzer_returns_no_risks_for_rate_limit(
    monkeypatch: Any,
) -> None:
    class MockResponse:
        status_code = 429

        def raise_for_status(self) -> None:
            raise AssertionError("rate-limited responses should not be parsed")

    class MockClient:
        def __init__(self, timeout: float) -> None:
            assert timeout > 0

        async def __aenter__(self) -> MockClient:
            return self

        async def __aexit__(
            self, _exc_type: Any, _exc_value: Any, _traceback: Any
        ) -> None:
            return None

        async def post(self, **_kwargs: Any) -> MockResponse:
            return MockResponse()

    monkeypatch.setattr(llm_engine.httpx, "AsyncClient", MockClient)
    analyzer = LLMRiskAnalyzer(
        Settings(
            LLM_API_KEY=SecretStr("test-key"),
            LLM_MODEL_NAME="gemini-test",
        )
    )
    request = AssessmentRequest(
        architecture=[{"node_type": "Model", "is_public": True, "controls": []}]
    )

    assert asyncio.run(analyzer.analyze(request)) == []


def test_custom_component_prompt_uses_structured_schema_and_description(
    monkeypatch: Any,
) -> None:
    captured_request: dict[str, Any] = {}
    response_body = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": json.dumps([_risk_payload("CUSTOM-99")])}]
                }
            }
        ]
    }

    class MockResponse:
        status_code = 200

        def json(self) -> dict[str, Any]:
            return response_body

        def raise_for_status(self) -> None:
            return None

    class MockClient:
        def __init__(self, timeout: float) -> None:
            assert timeout == LLMRiskAnalyzer.REQUEST_TIMEOUT_SECONDS

        async def __aenter__(self) -> MockClient:
            return self

        async def __aexit__(
            self, _exc_type: Any, _exc_value: Any, _traceback: Any
        ) -> None:
            return None

        async def post(
            self, url: str, headers: dict[str, str], json: dict[str, Any]
        ) -> MockResponse:
            captured_request["payload"] = json
            return MockResponse()

    monkeypatch.setattr(llm_engine.httpx, "AsyncClient", MockClient)
    analyzer = LLMRiskAnalyzer(
        Settings(
            LLM_API_KEY=SecretStr("test-key"),
            LLM_MODEL_NAME="gemini-test",
        )
    )
    node = NodeInput(
        node_type="Other",
        custom_description="Internal Redis cache",
        is_public=False,
        controls=[],
    )

    risks = asyncio.run(analyzer.analyze_custom_component(node))

    assert len(risks) == 1
    assert risks[0].risk_id == "CUSTOM-99"
    assert risks[0].source_component == "Internal Redis cache"
    generation_config = captured_request["payload"]["generationConfig"]
    schema = generation_config["responseSchema"]
    assert schema["type"] == "ARRAY"
    assert schema["minItems"] == 1
    assert schema["maxItems"] == 2
    assert set(schema["items"]["required"]) == set(_risk_payload("CUSTOM-01"))
    system_prompt = captured_request["payload"]["systemInstruction"]["parts"][0][
        "text"
    ]
    assert "Internal Redis cache" in system_prompt
    assert "residual_score" in system_prompt
