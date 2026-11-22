"""Schemas for the plain-language questionnaire and agentic pattern detection.

End users never see the pattern names defined here. They answer simple
questions (``QuestionnaireAnswers``); the backend maps those answers to the
agentic AI design patterns described in Google Cloud's "Choose a design
pattern for your agentic AI system" guide (``PatternDetection``). The frontend
then turns the detected patterns into a plain-language risk report.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator

from app.schemas.kb_schema import StrictModel


class Purpose(StrEnum):
    CUSTOMER_SUPPORT = "customer_support"
    CONTENT = "content"
    DATA_ANALYSIS = "data_analysis"
    TASK_AUTOMATION = "task_automation"
    CODING = "coding"
    OTHER = "other"


class Collaboration(StrEnum):
    ALONE = "alone"
    PIPELINE = "pipeline"
    PARALLEL = "parallel"
    MANAGER = "manager"
    TEAM_CHAT = "team_chat"
    UNSURE = "unsure"


class Autonomy(StrEnum):
    ANSWER_ONLY = "answer_only"
    APPROVAL_REQUIRED = "approval_required"
    PARTIAL_AUTO = "partial_auto"
    FULL_AUTO = "full_auto"


class Resource(StrEnum):
    INTERNAL_DOCS = "internal_docs"
    WEB_SEARCH = "web_search"
    EXTERNAL_TOOLS = "external_tools"
    COMPANY_DATA = "company_data"


class Audience(StrEnum):
    INTERNAL = "internal"
    PUBLIC = "public"


class SensitiveData(StrEnum):
    PERSONAL = "personal"
    FINANCIAL = "financial"
    CONFIDENTIAL = "confidential"


class AgenticPattern(StrEnum):
    SINGLE_AGENT = "SINGLE_AGENT"
    REACT = "REACT"
    SEQUENTIAL = "SEQUENTIAL"
    PARALLEL = "PARALLEL"
    COORDINATOR = "COORDINATOR"
    HIERARCHICAL = "HIERARCHICAL"
    SWARM = "SWARM"
    HUMAN_IN_THE_LOOP = "HUMAN_IN_THE_LOOP"


ARCHITECTURE_PATTERNS: tuple[AgenticPattern, ...] = tuple(
    pattern for pattern in AgenticPattern if pattern is not AgenticPattern.HUMAN_IN_THE_LOOP
)
MULTI_AGENT_PATTERNS: frozenset[AgenticPattern] = frozenset(
    {
        AgenticPattern.SEQUENTIAL,
        AgenticPattern.PARALLEL,
        AgenticPattern.COORDINATOR,
        AgenticPattern.HIERARCHICAL,
        AgenticPattern.SWARM,
    }
)


class HumanOversight(StrEnum):
    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"


OVERSIGHT_RANK: dict[HumanOversight, int] = {
    HumanOversight.NONE: 0,
    HumanOversight.PARTIAL: 1,
    HumanOversight.FULL: 2,
}


def _dedupe(values: list[StrEnum]) -> list[StrEnum]:
    return list(dict.fromkeys(values))


class QuestionnaireAnswers(StrictModel):
    system_name: str | None = Field(default=None, max_length=120)
    purpose: Purpose
    purpose_details: str | None = Field(default=None, max_length=500)
    scenarios: list[str] = Field(default_factory=list, max_length=5)
    collaboration: Collaboration
    autonomy: Autonomy
    resources: list[Resource] = Field(default_factory=list, max_length=len(Resource))
    audience: Audience
    sensitive_data: list[SensitiveData] = Field(
        default_factory=list, max_length=len(SensitiveData)
    )

    @field_validator("system_name", "purpose_details")
    @classmethod
    def blank_details_to_none(cls, value: str | None) -> str | None:
        return value or None

    @field_validator("scenarios")
    @classmethod
    def clean_scenarios(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in values:
            stripped = item.strip()
            if stripped:
                if len(stripped) > 300:
                    raise ValueError("each scenario must be at most 300 characters")
                if stripped not in cleaned:
                    cleaned.append(stripped)
        return cleaned

    @field_validator("resources", "sensitive_data")
    @classmethod
    def dedupe_choices(cls, values: list[StrEnum]) -> list[StrEnum]:
        return _dedupe(values)


class LLMPatternClassification(StrictModel):
    """Raw structured output expected from the classifier LLM."""

    primary_pattern: AgenticPattern
    secondary_patterns: list[AgenticPattern] = Field(default_factory=list, max_length=6)
    human_oversight: HumanOversight
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(max_length=1200)
    plain_summary: str = Field(min_length=1, max_length=400)
    ai_insights: list[str] = Field(default_factory=list, max_length=5)

    @field_validator("primary_pattern")
    @classmethod
    def primary_must_be_architecture(cls, value: AgenticPattern) -> AgenticPattern:
        if value is AgenticPattern.HUMAN_IN_THE_LOOP:
            raise ValueError("HUMAN_IN_THE_LOOP is a modifier, not a primary pattern")
        return value


class PatternDetection(StrictModel):
    primary_pattern: AgenticPattern
    patterns: list[AgenticPattern] = Field(
        description="All applicable patterns, including the primary pattern and "
        "HUMAN_IN_THE_LOOP when a person approves actions."
    )
    rule_patterns: list[AgenticPattern] = Field(
        default_factory=list,
        description="Patterns deterministically derived from questionnaire rules.",
    )
    llm_added_patterns: list[AgenticPattern] = Field(
        default_factory=list,
        description="Additional patterns inferred exclusively by the LLM from free-text.",
    )
    ai_insights: list[str] = Field(
        default_factory=list,
        description="Contextual security insights generated from free-text and scenarios.",
    )
    human_oversight: HumanOversight
    is_multi_agent: bool
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(
        default="",
        description="Technical explanation of why these Google Cloud agentic patterns apply.",
    )
    plain_summary: str
    source: Literal["llm", "rules"]


class ClassificationResponse(StrictModel):
    detection: PatternDetection


class SavedRiskItem(StrictModel):
    id: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=1, max_length=200)
    explanation: str = Field(min_length=1, max_length=1000)
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    score: int = Field(ge=1, le=25)
    severity: Literal["Low", "Medium", "High", "Critical"]
    severityLabel: str = Field(min_length=1, max_length=50)
    recommendations: list[str] = Field(default_factory=list, max_length=10)
    adjustments: list[str] = Field(default_factory=list, max_length=10)


class SavedAssessmentCreate(StrictModel):
    answers: QuestionnaireAnswers
    detection: PatternDetection
    overall_score: int = Field(ge=1, le=25)
    overall_severity: Literal["Low", "Medium", "High", "Critical"]
    overall_severity_label: str = Field(min_length=1, max_length=50)
    oversight_note: str = Field(min_length=1, max_length=500)
    top_actions: list[str] = Field(default_factory=list, max_length=10)
    risks: list[SavedRiskItem] = Field(min_length=1, max_length=30)


class SavedAssessmentRecord(SavedAssessmentCreate):
    assessment_id: str = Field(min_length=1, max_length=64)
    created_at: str = Field(min_length=1, max_length=64)


class SavedAssessmentsListResponse(StrictModel):
    records: list[SavedAssessmentRecord]


RiskKindLiteral = Literal[
    "injection", "action", "leak", "integrity", "control", "cost"
]


class CustomFlowNodeRequest(StrictModel):
    """Input for Gemini-assisted analysis of a user-defined graph node."""

    layer: Literal[1, 2, 3]
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=3, max_length=1000)
    language: Literal["vi", "en"] = "vi"


class CustomEmittedRiskSuggestion(StrictModel):
    risk_id: str = Field(min_length=1, max_length=60)
    title: str = Field(min_length=1, max_length=200)
    kind: RiskKindLiteral
    base_l: int = Field(ge=1, le=5)
    base_i: int = Field(ge=1, le=5)
    owasp: list[str] = Field(default_factory=list, max_length=5)
    nist: list[str] = Field(default_factory=list, max_length=5)
    applicable_controls: list[str] = Field(default_factory=list, max_length=12)


class CustomFlowNodeSuggestion(StrictModel):
    suggested_code: str = Field(min_length=1, max_length=60)
    layer: Literal[1, 2, 3]
    rationale: str = Field(min_length=1, max_length=1000)
    source: Literal["llm", "fallback"]
    delta_l: int = Field(default=0, ge=-3, le=3)
    delta_i: int = Field(default=0, ge=-3, le=3)
    mult_l: float = Field(default=1.0, ge=0.5, le=2.0)
    mult_i: float = Field(default=1.0, ge=0.5, le=2.0)
    discount_w: float = Field(default=0.0, ge=0.0, le=0.8)
    control_delta_i: int = Field(default=0, ge=-2, le=0)
    target_kinds: list[RiskKindLiteral] = Field(default_factory=list, max_length=6)
    emitted_risk: CustomEmittedRiskSuggestion | None = None


class CustomFlowNodeResponse(StrictModel):
    suggestion: CustomFlowNodeSuggestion


class GraphNodeSummary(StrictModel):
    id: str = Field(min_length=1, max_length=80)
    layer: Literal[1, 2, 3]
    code: str = Field(min_length=1, max_length=60)
    label: str = Field(min_length=1, max_length=160)
    subtitle: str = Field(default="", max_length=300)
    is_custom: bool = False
    delta_l: int = Field(default=0, ge=-3, le=3)
    delta_i: int = Field(default=0, ge=-3, le=3)
    discount_w: float = Field(default=0.0, ge=0.0, le=0.8)


class GraphEdgeSummary(StrictModel):
    from_id: str = Field(min_length=1, max_length=80)
    to_id: str = Field(min_length=1, max_length=80)


class GraphAnalysisRequest(StrictModel):
    nodes: list[GraphNodeSummary] = Field(min_length=1, max_length=40)
    edges: list[GraphEdgeSummary] = Field(default_factory=list, max_length=120)
    existing_risk_ids: list[str] = Field(default_factory=list, max_length=40)
    language: Literal["vi", "en"] = "vi"


class GraphEmergentRisk(StrictModel):
    risk_id: str = Field(min_length=1, max_length=60)
    title: str = Field(min_length=1, max_length=200)
    kind: RiskKindLiteral
    base_l: int = Field(ge=1, le=5)
    base_i: int = Field(ge=1, le=5)
    final_l: int = Field(ge=1, le=5)
    final_i: int = Field(ge=1, le=5)
    owasp: list[str] = Field(default_factory=list, max_length=5)
    nist: list[str] = Field(default_factory=list, max_length=5)
    involved_node_ids: list[str] = Field(default_factory=list, max_length=15)
    rationale: str = Field(min_length=1, max_length=600)


class GraphAnalysisResult(StrictModel):
    source: Literal["llm", "fallback"]
    executive_summary: str = Field(min_length=1, max_length=1000)
    ai_risks: list[GraphEmergentRisk] = Field(default_factory=list, max_length=4)


class GraphAnalysisResponse(StrictModel):
    analysis: GraphAnalysisResult
