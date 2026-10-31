from __future__ import annotations

from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class NodeInput(StrictModel):
    node_type: str = Field(min_length=1)
    is_public: bool
    controls: list[str] = Field(default_factory=list)

    @field_validator("node_type")
    @classmethod
    def normalize_node_type(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("node_type must not be empty")
        return normalized

    @field_validator("controls")
    @classmethod
    def normalize_controls(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for value in values:
            control_id = value.strip().upper()
            if not control_id:
                raise ValueError("control identifiers must not be empty")
            if control_id not in seen:
                normalized.append(control_id)
                seen.add(control_id)
        return normalized


class AssessmentRequest(StrictModel):
    architecture: Annotated[list[NodeInput], Field(min_length=1)]


class EvaluatedRiskResult(StrictModel):
    source_component: str
    risk_id: str
    risk_name: str
    nist_categories: list[str]
    attack_scenario: str
    inherent_score: int = Field(ge=1, le=25)
    residual_likelihood: int = Field(ge=1, le=5)
    residual_impact: int = Field(ge=1, le=5)
    residual_score: int = Field(ge=1, le=25)
    severity_level: str
    recommended_action: str
    missing_mitigations: list[str]


class AssessmentResponse(StrictModel):
    results: list[EvaluatedRiskResult]
    overall_risk_score: int = Field(
        ge=1,
        le=25,
        description="Highest residual risk score across all evaluated risks.",
    )
    overall_severity: str = Field(
        description="Severity corresponding to the highest residual risk score."
    )
    risk_matrix_summary: list[list[int]] = Field(
        description=(
            "5x5 counts indexed by likelihood minus one for rows and impact minus "
            "one for columns."
        )
    )

    @field_validator("risk_matrix_summary")
    @classmethod
    def validate_risk_matrix(cls, matrix: list[list[int]]) -> list[list[int]]:
        if len(matrix) != 5 or any(len(row) != 5 for row in matrix):
            raise ValueError("risk_matrix_summary must be a 5x5 matrix")
        if any(value < 0 for row in matrix for value in row):
            raise ValueError("risk matrix counts must not be negative")
        return matrix


class NISTMapping(StrictModel):
    category_id: str = Field(min_length=1)
    description: str = Field(min_length=1)


class TechnicalMitigation(StrictModel):
    control_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    discount_weight: float = Field(ge=0.0, le=1.0)

    @field_validator("control_id")
    @classmethod
    def normalize_control_id(cls, value: str) -> str:
        return value.strip().upper()


class RiskRule(StrictModel):
    risk_id: str = Field(min_length=1)
    risk_name: str = Field(min_length=1)
    nist_mappings: list[NISTMapping]
    attack_scenario: str
    base_likelihood: int = Field(ge=1, le=5)
    base_impact: int = Field(ge=1, le=5)
    technical_mitigations: list[TechnicalMitigation]


class ComponentKnowledge(StrictModel):
    display_name: str = Field(min_length=1)
    aliases: list[str] = Field(default_factory=list)
    risks: Annotated[list[RiskRule], Field(min_length=1)]


class SeverityThreshold(StrictModel):
    min: int = Field(ge=1, le=25)
    max: int = Field(ge=1, le=25)
    action: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_bounds(self) -> SeverityThreshold:
        if self.min > self.max:
            raise ValueError("severity threshold min must not exceed max")
        return self


class KBMetadata(StrictModel):
    version: str = Field(min_length=1)
    project: str = Field(min_length=1)
    standards: list[str]


class KnowledgeBaseDocument(StrictModel):
    metadata: KBMetadata
    severity_thresholds: dict[str, SeverityThreshold]
    components: dict[str, ComponentKnowledge]

    @model_validator(mode="after")
    def validate_knowledge_base(self) -> KnowledgeBaseDocument:
        required_severities = {"Low", "Medium", "High", "Critical"}
        if set(self.severity_thresholds) != required_severities:
            raise ValueError(
                "severity_thresholds must define Low, Medium, High, and Critical"
            )

        ordered = sorted(
            self.severity_thresholds.values(),
            key=lambda threshold: threshold.min,
        )
        if ordered[0].min != 1 or ordered[-1].max != 25:
            raise ValueError("severity thresholds must cover scores 1 through 25")
        for previous, current in zip(ordered, ordered[1:]):
            if previous.max + 1 != current.min:
                raise ValueError("severity thresholds must be contiguous")

        aliases: dict[str, str] = {}
        for component_key, component in self.components.items():
            for name in [component_key, *component.aliases]:
                normalized = name.strip().casefold()
                if not normalized:
                    raise ValueError("component keys and aliases must not be empty")
                existing = aliases.get(normalized)
                if existing is not None and existing != component_key:
                    raise ValueError(
                        f"component alias {name!r} maps to multiple components"
                    )
                aliases[normalized] = component_key
        if not self.components:
            raise ValueError("knowledge base must contain at least one component")
        return self


class ControlOption(StrictModel):
    control_id: str
    description: str


class ComponentOption(StrictModel):
    node_type: str
    display_name: str
    controls: list[ControlOption]


class ComponentsResponse(StrictModel):
    components: list[ComponentOption]


class ErrorResponse(StrictModel):
    detail: str
