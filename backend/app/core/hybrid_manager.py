from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import Protocol

from app.core.kb_manager import KnowledgeBaseManager
from app.schemas.kb_schema import (
    AssessmentRequest,
    AssessmentResponse,
    EvaluatedRiskResult,
    NodeInput,
)


class RiskAnalyzer(Protocol):
    async def analyze(
        self, request: AssessmentRequest
    ) -> list[EvaluatedRiskResult]: ...

    async def analyze_custom_component(
        self, node: NodeInput
    ) -> list[EvaluatedRiskResult]: ...


class CustomComponentAnalysisError(RuntimeError):
    """Raised when a custom architecture node could not be assessed by the LLM."""


class HybridRiskManager:
    """Runs deterministic and LLM risk analysis concurrently."""

    def __init__(
        self,
        kb_manager: KnowledgeBaseManager,
        llm_analyzer: RiskAnalyzer,
    ) -> None:
        self.kb_manager = kb_manager
        self.llm_analyzer = llm_analyzer

    async def assess_hybrid_architecture(
        self, req: AssessmentRequest
    ) -> AssessmentResponse:
        known_nodes = [
            node for node in req.architecture if node.node_type.casefold() != "other"
        ]
        custom_nodes = [
            node for node in req.architecture if node.node_type.casefold() == "other"
        ]
        static_results, ai_results = await asyncio.gather(
            self._assess_static_nodes(known_nodes),
            self._assess_llm_nodes(known_nodes, custom_nodes),
        )

        merged_results: list[EvaluatedRiskResult] = []
        for risk in [*static_results, *ai_results]:
            merged_results.append(self._normalize_risk(risk))
        results = merged_results
        risk_matrix = [[0 for _ in range(5)] for _ in range(5)]
        for risk in results:
            risk_matrix[risk.residual_likelihood - 1][risk.residual_impact - 1] += 1

        overall_risk_score = max(risk.residual_score for risk in results)
        overall_severity, _ = self.kb_manager.classify_severity(overall_risk_score)
        return AssessmentResponse(
            results=results,
            overall_risk_score=overall_risk_score,
            overall_severity=overall_severity,
            risk_matrix_summary=risk_matrix,
        )

    async def _assess_static_nodes(
        self, nodes: list[NodeInput]
    ) -> list[EvaluatedRiskResult]:
        if not nodes:
            return []
        request = AssessmentRequest(architecture=nodes)
        response = await asyncio.to_thread(self.kb_manager.assess, request)
        return response.results

    async def _assess_llm_nodes(
        self, known_nodes: list[NodeInput], custom_nodes: list[NodeInput]
    ) -> list[EvaluatedRiskResult]:
        analysis_tasks: list[Awaitable[list[EvaluatedRiskResult]]] = []
        if known_nodes:
            analysis_tasks.append(
                self.llm_analyzer.analyze(
                    AssessmentRequest(architecture=known_nodes)
                )
            )
        analysis_tasks.extend(
            self.llm_analyzer.analyze_custom_component(node)
            for node in custom_nodes
        )
        batches = await asyncio.gather(*analysis_tasks)
        custom_batch_offset = 1 if known_nodes else 0
        for node, batch in zip(custom_nodes, batches[custom_batch_offset:]):
            if not batch:
                raise CustomComponentAnalysisError(
                    "LLM analysis did not produce risks for custom component "
                    f"{node.custom_description!r}. Check LLM_API_KEY and the "
                    "provider response."
                )
        results = [risk for batch in batches for risk in batch]
        if known_nodes:
            results[: len(batches[0])] = [
                risk.model_copy(
                    update={"risk_id": f"AI-{index:02d}"}
                )
                for index, risk in enumerate(batches[0], start=1)
            ]
        return results

    def _normalize_risk(self, risk: EvaluatedRiskResult) -> EvaluatedRiskResult:
        residual_score = risk.residual_likelihood * risk.residual_impact
        severity_level, _ = self.kb_manager.classify_severity(residual_score)
        return risk.model_copy(
            update={
                "residual_score": residual_score,
                "severity_level": severity_level,
            }
        )
