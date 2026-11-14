"""Maps plain-language questionnaire answers to agentic AI design patterns.

Detection runs in two layers:

1. ``detect_with_rules`` - deterministic mapping of the structured answers.
   Always available, used as the fallback, and used as a safety floor.
2. ``PatternDetector.detect`` - asks the LLM (Gemini structured output) to
   refine the result using the free-text description, then merges it with the
   rule result conservatively: the LLM can add patterns or lower the level of
   human oversight, but it can never remove a rule-detected pattern or claim
   more oversight than the user selected. A prompt injection in the free text
   therefore cannot make the assessment look safer than the answers imply.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import ValidationError

from app.core.agentic_prompts import PATTERN_CLASSIFIER_SYSTEM_PROMPT
from app.core.config import Settings
from app.schemas.agentic_schema import (
    ARCHITECTURE_PATTERNS,
    MULTI_AGENT_PATTERNS,
    OVERSIGHT_RANK,
    AgenticPattern,
    Autonomy,
    Collaboration,
    HumanOversight,
    LLMPatternClassification,
    PatternDetection,
    QuestionnaireAnswers,
    Resource,
)

logger = logging.getLogger(__name__)

_TOOL_RESOURCES = frozenset(
    {Resource.EXTERNAL_TOOLS, Resource.WEB_SEARCH, Resource.COMPANY_DATA}
)
_COLLABORATION_PATTERNS: dict[Collaboration, AgenticPattern] = {
    Collaboration.PIPELINE: AgenticPattern.SEQUENTIAL,
    Collaboration.PARALLEL: AgenticPattern.PARALLEL,
    Collaboration.MANAGER: AgenticPattern.COORDINATOR,
    Collaboration.TEAM_CHAT: AgenticPattern.SWARM,
}
_AUTONOMY_OVERSIGHT: dict[Autonomy, HumanOversight] = {
    Autonomy.ANSWER_ONLY: HumanOversight.NONE,
    Autonomy.APPROVAL_REQUIRED: HumanOversight.FULL,
    Autonomy.PARTIAL_AUTO: HumanOversight.PARTIAL,
    Autonomy.FULL_AUTO: HumanOversight.NONE,
}
_COLLABORATION_SUMMARY: dict[Collaboration, str] = {
    Collaboration.ALONE: "Ứng dụng của bạn có một AI tự xử lý toàn bộ công việc",
    Collaboration.PIPELINE: "Ứng dụng của bạn có nhiều AI làm việc lần lượt như một dây chuyền",
    Collaboration.PARALLEL: "Ứng dụng của bạn có nhiều AI làm cùng lúc các phần việc khác nhau rồi gộp kết quả",
    Collaboration.MANAGER: "Ứng dụng của bạn có một AI 'trưởng nhóm' chia việc cho các AI khác",
    Collaboration.TEAM_CHAT: "Ứng dụng của bạn có nhiều AI tự trao đổi, bàn bạc với nhau",
    Collaboration.UNSURE: "Ứng dụng của bạn dùng AI để hỗ trợ công việc",
}
_AUTONOMY_SUMMARY: dict[Autonomy, str] = {
    Autonomy.ANSWER_ONLY: "chỉ trả lời và gợi ý, không tự làm gì",
    Autonomy.APPROVAL_REQUIRED: "luôn chờ người bấm 'Đồng ý' trước khi làm",
    Autonomy.PARTIAL_AUTO: "tự làm việc nhỏ và hỏi ý kiến trước việc quan trọng",
    Autonomy.FULL_AUTO: "tự thực hiện hành động mà không cần hỏi ai",
}


def uses_tools(answers: QuestionnaireAnswers) -> bool:
    return bool(_TOOL_RESOURCES.intersection(answers.resources)) or (
        answers.autonomy is not Autonomy.ANSWER_ONLY
    )


def _ordered(patterns: set[AgenticPattern]) -> list[AgenticPattern]:
    """Stable order matching the enum definition."""
    return [pattern for pattern in AgenticPattern if pattern in patterns]


def _finalize(
    primary: AgenticPattern,
    patterns: set[AgenticPattern],
    oversight: HumanOversight,
    confidence: float,
    rationale: str,
    plain_summary: str,
    source: str,
) -> PatternDetection:
    patterns = {primary, *patterns} - {AgenticPattern.HUMAN_IN_THE_LOOP}
    if oversight is not HumanOversight.NONE:
        patterns.add(AgenticPattern.HUMAN_IN_THE_LOOP)
    return PatternDetection(
        primary_pattern=primary,
        patterns=_ordered(patterns),
        human_oversight=oversight,
        is_multi_agent=bool(MULTI_AGENT_PATTERNS.intersection(patterns)),
        confidence=round(confidence, 2),
        rationale=rationale,
        plain_summary=plain_summary,
        source=source,  # type: ignore[arg-type]
    )


def build_plain_summary(answers: QuestionnaireAnswers) -> str:
    return (
        f"{_COLLABORATION_SUMMARY[answers.collaboration]}, "
        f"{_AUTONOMY_SUMMARY[answers.autonomy]}."
    )


def detect_with_rules(answers: QuestionnaireAnswers) -> PatternDetection:
    tools = uses_tools(answers)
    single_agent_pattern = (
        AgenticPattern.REACT if tools else AgenticPattern.SINGLE_AGENT
    )
    primary = _COLLABORATION_PATTERNS.get(answers.collaboration, single_agent_pattern)
    patterns = {primary}
    if primary in MULTI_AGENT_PATTERNS and tools:
        # Sub-agents that call tools each run their own reason-act loop.
        patterns.add(AgenticPattern.REACT)
    confidence = 0.4 if answers.collaboration is Collaboration.UNSURE else 0.85
    oversight = _AUTONOMY_OVERSIGHT[answers.autonomy]
    rationale = (
        f"Mapped collaboration={answers.collaboration.value} and "
        f"autonomy={answers.autonomy.value} (tools={tools}) to primary pattern "
        f"{primary.value} with human_oversight={oversight.value}."
    )
    return _finalize(
        primary,
        patterns,
        oversight,
        confidence,
        rationale,
        build_plain_summary(answers),
        "rules",
    )


def merge_detections(
    rules: PatternDetection, llm: LLMPatternClassification
) -> PatternDetection:
    """Combine LLM output with the rule floor; never reduce the attack surface."""
    llm_patterns = {llm.primary_pattern, *llm.secondary_patterns}
    oversight = min(
        rules.human_oversight,
        llm.human_oversight,
        key=OVERSIGHT_RANK.__getitem__,
    )
    primary = llm.primary_pattern
    # Do not let the LLM demote a multi-agent system to a single agent.
    if primary not in MULTI_AGENT_PATTERNS and rules.primary_pattern in MULTI_AGENT_PATTERNS:
        primary = rules.primary_pattern
    return _finalize(
        primary,
        set(rules.patterns) | llm_patterns,
        oversight,
        llm.confidence,
        llm.rationale.strip() or rules.rationale,
        llm.plain_summary.strip(),
        "llm",
    )


def build_user_message(answers: QuestionnaireAnswers) -> str:
    payload = answers.model_dump(mode="json", exclude_none=True)
    return (
        "Classify the AI application described by these answers.\n"
        f"<user_answers>\n{json.dumps(payload, ensure_ascii=False)}\n</user_answers>"
    )


_PATTERN_ENUM = [pattern.value for pattern in ARCHITECTURE_PATTERNS]
_ALL_PATTERN_ENUM = [pattern.value for pattern in AgenticPattern]
CLASSIFICATION_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "primary_pattern": {"type": "STRING", "enum": _PATTERN_ENUM},
        "secondary_patterns": {
            "type": "ARRAY",
            "items": {"type": "STRING", "enum": _ALL_PATTERN_ENUM},
            "maxItems": 6,
        },
        "human_oversight": {
            "type": "STRING",
            "enum": [level.value for level in HumanOversight],
        },
        "confidence": {"type": "NUMBER", "minimum": 0, "maximum": 1},
        "rationale": {"type": "STRING"},
        "plain_summary": {"type": "STRING"},
    },
    "required": [
        "primary_pattern",
        "secondary_patterns",
        "human_oversight",
        "confidence",
        "rationale",
        "plain_summary",
    ],
}


class PatternDetector:
    API_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
    REQUEST_TIMEOUT_SECONDS = 20.0

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()

    async def detect(self, answers: QuestionnaireAnswers) -> PatternDetection:
        rules = detect_with_rules(answers)
        llm = await self._classify_with_llm(answers)
        if llm is None:
            return rules
        logger.info(
            "Agentic pattern classified as %s (confidence %.2f): %s",
            llm.primary_pattern.value,
            llm.confidence,
            llm.rationale,
        )
        return merge_detections(rules, llm)

    async def _classify_with_llm(
        self, answers: QuestionnaireAnswers
    ) -> LLMPatternClassification | None:
        api_key = self.settings.LLM_API_KEY
        model_name = self.settings.LLM_MODEL_NAME.strip()
        if api_key is None or not api_key.get_secret_value().strip() or not model_name:
            logger.info("LLM not configured; using rule-based pattern detection.")
            return None

        url = f"{self.API_BASE_URL}/{quote(model_name, safe='')}:generateContent"
        payload = {
            "systemInstruction": {"parts": [{"text": PATTERN_CLASSIFIER_SYSTEM_PROMPT}]},
            "contents": [
                {"role": "user", "parts": [{"text": build_user_message(answers)}]}
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": CLASSIFICATION_RESPONSE_SCHEMA,
                "temperature": 0.0,
            },
        }
        try:
            async with httpx.AsyncClient(timeout=self.REQUEST_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    url,
                    headers={"x-goog-api-key": api_key.get_secret_value()},
                    json=payload,
                )
            response.raise_for_status()
            text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
            return LLMPatternClassification.model_validate_json(text)
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "Pattern classification failed with HTTP status %d; using rules.",
                exc.response.status_code,
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "Pattern classification request failed (%s); using rules.",
                type(exc).__name__,
            )
        except (ValueError, TypeError, KeyError, IndexError, ValidationError) as exc:
            logger.warning(
                "Pattern classifier returned an invalid response (%s); using rules.",
                type(exc).__name__,
            )
        return None

