from __future__ import annotations

import asyncio

from app.core.kb_manager import KnowledgeBaseManager
from app.core.llm_engine import LLMRiskAnalyzer
from app.schemas.kb_schema import (
    AssessmentRequest,
    AssessmentResponse,
)


class HybridRiskManager:
    """Runs deterministic and LLM risk analysis concurrently and combines results."""

    def __init__(
        self,
        kb_manager: KnowledgeBaseManager,
        llm_analyzer: LLMRiskAnalyzer,
    ) -> None:
        self.kb_manager = kb_manager
        self.llm_analyzer = llm_analyzer

    async def assess_hybrid_architecture(
        self, req: AssessmentRequest
    ) -> AssessmentResponse:
        static_response, ai_results = await asyncio.gather(
            asyncio.to_thread(self.kb_manager.assess, req),
            self.llm_analyzer.analyze(req),
        )
        merged_results = [*static_response.results, *ai_results]
        overall_risk_score = max(
            result.residual_score for result in merged_results
        )
        overall_severity, _ = self.kb_manager.classify_severity(overall_risk_score)
        risk_matrix = [[0 for _ in range(5)] for _ in range(5)]
        for result in merged_results:
            risk_matrix[result.residual_likelihood - 1][
                result.residual_impact - 1
            ] += 1

        return AssessmentResponse(
            results=merged_results,
            overall_risk_score=overall_risk_score,
            overall_severity=overall_severity,
            risk_matrix_summary=risk_matrix,
        )