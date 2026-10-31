from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.schemas.kb_schema import (
    AssessmentRequest,
    AssessmentResponse,
    ComponentOption,
    ComponentsResponse,
    ControlOption,
    EvaluatedRiskResult,
    KnowledgeBaseDocument,
    RiskRule,
)


class UnknownComponentError(ValueError):
    """Raised when an assessment node does not map to a known component."""


class UnknownControlError(ValueError):
    """Raised when a node references a control absent from that component."""


class KnowledgeBaseManager:
    """Deterministic, context-aware risk interpolation over a validated KB."""

    DISCOUNT_CAP = 0.80

    def __init__(
        self, knowledge_base: KnowledgeBaseDocument | Mapping[str, Any]
    ) -> None:
        self.kb = (
            knowledge_base
            if isinstance(knowledge_base, KnowledgeBaseDocument)
            else KnowledgeBaseDocument.model_validate(knowledge_base)
        )
        self._alias_lookup: dict[str, str] = {}
        for component_key, component in self.kb.components.items():
            self._alias_lookup[component_key.strip().casefold()] = component_key
            for alias in component.aliases:
                self._alias_lookup[alias.strip().casefold()] = component_key

    def assess(self, request: AssessmentRequest) -> AssessmentResponse:
        results: list[EvaluatedRiskResult] = []
        risk_matrix = [[0 for _ in range(5)] for _ in range(5)]

        for node in request.architecture:
            component_key = self._alias_lookup.get(node.node_type.strip().casefold())
            if component_key is None:
                raise UnknownComponentError(
                    f"Unknown component type: {node.node_type!r}."
                )

            component = self.kb.components[component_key]
            active_controls = {control_id.upper() for control_id in node.controls}
            component_controls = {
                mitigation.control_id.upper()
                for risk in component.risks
                for mitigation in risk.technical_mitigations
            }
            unknown_controls = active_controls - component_controls
            if unknown_controls:
                raise UnknownControlError(
                    f"Controls are not defined for component {component_key!r}: "
                    f"{', '.join(sorted(unknown_controls))}."
                )
            for risk in component.risks:
                applicable_controls = {
                    mitigation.control_id.upper()
                    for mitigation in risk.technical_mitigations
                }
                applied_controls = active_controls & applicable_controls
                total_discount = self.calculate_total_discount(
                    risk, applied_controls
                )

                context_likelihood = (
                    risk.base_likelihood
                    if node.is_public
                    else max(1, risk.base_likelihood - 1)
                )
                residual_likelihood = max(
                    1, round(context_likelihood * (1.0 - total_discount))
                )
                residual_score = residual_likelihood * risk.base_impact
                severity_level, recommended_action = self.classify_severity(
                    residual_score
                )
                missing_mitigations = [
                    f"[{mitigation.control_id}] {mitigation.description}"
                    for mitigation in risk.technical_mitigations
                    if mitigation.control_id.upper() not in active_controls
                ]

                results.append(
                    EvaluatedRiskResult(
                        source_component=component.display_name,
                        risk_id=risk.risk_id,
                        risk_name=risk.risk_name,
                        nist_categories=[
                            mapping.category_id for mapping in risk.nist_mappings
                        ],
                        attack_scenario=risk.attack_scenario,
                        inherent_score=risk.base_likelihood * risk.base_impact,
                        residual_likelihood=residual_likelihood,
                        residual_impact=risk.base_impact,
                        residual_score=residual_score,
                        severity_level=severity_level,
                        recommended_action=recommended_action,
                        missing_mitigations=missing_mitigations,
                    )
                )
                risk_matrix[residual_likelihood - 1][risk.base_impact - 1] += 1

        if not results:
            raise ValueError("The assessment produced no risk results.")

        overall_risk_score = max(result.residual_score for result in results)
        overall_severity, _ = self.classify_severity(overall_risk_score)
        return AssessmentResponse(
            results=results,
            overall_risk_score=overall_risk_score,
            overall_severity=overall_severity,
            risk_matrix_summary=risk_matrix,
        )

    def classify_severity(self, score: int) -> tuple[str, str]:
        for level, threshold in self.kb.severity_thresholds.items():
            if threshold.min <= score <= threshold.max:
                return level, threshold.action
        raise ValueError(f"No severity threshold contains score {score}.")

    def calculate_total_discount(
        self, risk: RiskRule, active_controls: set[str]
    ) -> float:
        discount_sum = sum(
            mitigation.discount_weight
            for mitigation in risk.technical_mitigations
            if mitigation.control_id.upper() in active_controls
        )
        return min(self.DISCOUNT_CAP, discount_sum)

    def get_components(self) -> ComponentsResponse:
        components: list[ComponentOption] = []
        for component_key, component in self.kb.components.items():
            controls: dict[str, str] = {}
            for risk in component.risks:
                for mitigation in risk.technical_mitigations:
                    controls.setdefault(
                        mitigation.control_id, mitigation.description
                    )
            components.append(
                ComponentOption(
                    node_type=component_key,
                    display_name=component.display_name,
                    controls=[
                        ControlOption(control_id=control_id, description=description)
                        for control_id, description in sorted(controls.items())
                    ],
                )
            )
        return ComponentsResponse(components=components)
