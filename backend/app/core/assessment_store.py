"""Persistent storage and export formatting for completed risk assessments."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from uuid import uuid4

from app.schemas.agentic_schema import SavedAssessmentCreate, SavedAssessmentRecord


class AssessmentStore:
    """Thread-safe JSON file store for saved agentic risk assessments."""

    MAX_RECORDS = 200

    def __init__(self, file_path: Path | None = None) -> None:
        self.file_path = (
            file_path
            or Path(__file__).resolve().parents[1] / "data" / "saved_assessments.json"
        )
        self._lock = RLock()

    def save(self, payload: SavedAssessmentCreate) -> SavedAssessmentRecord:
        record = SavedAssessmentRecord(
            assessment_id=uuid4().hex[:12],
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **payload.model_dump(),
        )
        with self._lock:
            records = self._load_all()
            records.insert(0, record)
            self._write_all(records[: self.MAX_RECORDS])
        return record

    def list_records(self) -> list[SavedAssessmentRecord]:
        with self._lock:
            return self._load_all()

    def get(self, assessment_id: str) -> SavedAssessmentRecord | None:
        with self._lock:
            for record in self._load_all():
                if record.assessment_id == assessment_id:
                    return record
        return None

    def delete(self, assessment_id: str) -> bool:
        with self._lock:
            records = self._load_all()
            remaining = [r for r in records if r.assessment_id != assessment_id]
            if len(remaining) == len(records):
                return False
            self._write_all(remaining)
            return True

    def _load_all(self) -> list[SavedAssessmentRecord]:
        if not self.file_path.exists():
            return []
        try:
            raw = json.loads(self.file_path.read_text(encoding="utf-8"))
            if not isinstance(raw, list):
                return []
            return [SavedAssessmentRecord.model_validate(item) for item in raw]
        except (OSError, ValueError):
            return []

    def _write_all(self, records: list[SavedAssessmentRecord]) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        serialized = [record.model_dump(mode="json") for record in records]
        self.file_path.write_text(
            json.dumps(serialized, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


def format_markdown_report(record: SavedAssessmentRecord) -> str:
    """Render a saved assessment as a human-readable Markdown document."""
    system_title = record.answers.system_name or "Ứng dụng AI chưa đặt tên"
    lines: list[str] = [
        f"# Báo cáo Đánh giá Rủi ro Hệ thống AI: {system_title}",
        "",
        f"- **Mã bản ghi:** `{record.assessment_id}`",
        f"- **Thời gian lưu:** {record.created_at}",
        f"- **Mức rủi ro tổng thể:** {record.overall_severity_label} ({record.overall_score}/25)",
        f"- **Mô hình tích hợp AI (Google Cloud Agentic Pattern):** `{record.detection.primary_pattern.value}`",
        f"- **Tất cả mẫu hình phát hiện:** {', '.join(f'`{p.value}`' for p in record.detection.patterns)}",
        f"- **Mức độ giám sát con người (Human-in-the-loop):** `{record.detection.human_oversight.value}`",
        "",
        "## 1. Mô tả hệ thống & Kịch bản vận hành (Đích đánh giá)",
        "",
        f"- **Nhiệm vụ chính:** `{record.answers.purpose.value}`",
    ]
    if record.answers.purpose_details:
        lines.append(f"- **Mô tả chi tiết hệ thống:** {record.answers.purpose_details}")
    if record.answers.scenarios:
        lines.append("- **Các kịch bản vận hành (Use-case scenarios):**")
        for idx, scenario in enumerate(record.answers.scenarios, start=1):
            lines.append(f"  {idx}. {scenario}")
    lines.extend(
        [
            "",
            "## 2. Tóm tắt kiến trúc & Cơ chế kiểm duyệt",
            "",
            f"- **Tóm tắt hoạt động:** {record.detection.plain_summary}",
            f"- **Đánh giá giám sát:** {record.oversight_note}",
        ]
    )
    if record.detection.rationale:
        lines.append(f"- **Ghi chú kỹ thuật (Pattern rationale):** {record.detection.rationale}")

    if record.top_actions:
        lines.extend(["", "## 3. Khuyến nghị ưu tiên cần làm ngay", ""])
        for idx, action in enumerate(record.top_actions, start=1):
            lines.append(f"{idx}. {action}")

    lines.extend(["", "## 4. Danh sách rủi ro chi tiết", ""])
    for idx, risk in enumerate(record.risks, start=1):
        lines.extend(
            [
                f"### 4.{idx}. {risk.title} — Mức độ: {risk.severityLabel} ({risk.score}/25, L={risk.likelihood}×I={risk.impact})",
                "",
                risk.explanation,
                "",
                "**Khuyến nghị xử lý:**",
            ]
        )
        for rec in risk.recommendations:
            lines.append(f"- {rec}")
        if risk.adjustments:
            lines.append("")
            lines.append("**Ghi chú điều chỉnh mức độ:**")
            for note in risk.adjustments:
                lines.append(f"- *{note}*")
        lines.append("")

    return "\n".join(lines)


def format_csv_report(record: SavedAssessmentRecord) -> str:
    """Render a saved assessment's risks as a UTF-8 CSV (with BOM for Excel)."""
    buffer = io.StringIO()
    buffer.write("\ufeff")
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "Assessment ID",
            "System Name",
            "Created At",
            "Primary Pattern",
            "Detected Patterns",
            "Risk ID",
            "Risk Title",
            "Severity",
            "Score (25)",
            "Likelihood (5)",
            "Impact (5)",
            "Explanation",
            "Recommendations",
        ]
    )
    patterns_str = "; ".join(p.value for p in record.detection.patterns)
    system_name = record.answers.system_name or "Ứng dụng AI"
    for risk in record.risks:
        writer.writerow(
            [
                record.assessment_id,
                system_name,
                record.created_at,
                record.detection.primary_pattern.value,
                patterns_str,
                risk.id,
                risk.title,
                risk.severityLabel,
                risk.score,
                risk.likelihood,
                risk.impact,
                risk.explanation,
                " | ".join(risk.recommendations),
            ]
        )
    return buffer.getvalue()

