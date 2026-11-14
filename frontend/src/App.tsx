import { useEffect, useState } from "react";

import {
  buildRiskReport,
  PATTERN_DISPLAY_INFO,
  type RiskReport as RiskReportData,
} from "./agentic/riskMap";
import { AssessmentWizard } from "./components/AssessmentWizard";
import { RiskReport } from "./components/RiskReport";
import type {
  ClassificationResponse,
  QuestionnaireAnswers,
  SavedAssessmentCreate,
  SavedAssessmentRecord,
  SavedAssessmentsListResponse,
} from "./types";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "") ?? "http://localhost:8000";

async function classify(answers: QuestionnaireAnswers): Promise<ClassificationResponse> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/v1/agentic/classify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(answers),
    });
  } catch {
    throw new Error("Không kết nối được tới máy chủ đánh giá. Vui lòng thử lại sau.");
  }
  if (!response.ok) {
    throw new Error(
      response.status === 422
        ? "Câu trả lời chưa hợp lệ. Vui lòng kiểm tra lại."
        : `Máy chủ đang gặp sự cố (mã ${response.status}). Vui lòng thử lại sau.`,
    );
  }
  return (await response.json()) as ClassificationResponse;
}

function toSavePayload(report: RiskReportData): SavedAssessmentCreate {
  return {
    answers: report.answers,
    detection: report.detection,
    overall_score: report.overallScore,
    overall_severity: report.overallSeverity,
    overall_severity_label: report.overallSeverityLabel,
    oversight_note: report.oversightNote,
    top_actions: report.topActions,
    risks: report.risks.map((risk) => ({
      id: risk.id,
      title: risk.title,
      explanation: risk.explanation,
      likelihood: risk.likelihood,
      impact: risk.impact,
      score: risk.score,
      severity: risk.severity,
      severityLabel: risk.severityLabel,
      recommendations: risk.recommendations,
      adjustments: risk.adjustments,
    })),
  };
}

export function App(): JSX.Element {
  const [report, setReport] = useState<RiskReportData | null>(null);
  const [savedId, setSavedId] = useState<string | null>(null);
  const [history, setHistory] = useState<SavedAssessmentRecord[]>([]);
  const [wizardKey, setWizardKey] = useState(0);

  async function refreshHistory(): Promise<void> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/agentic/records`);
      if (!response.ok) return;
      const data = (await response.json()) as SavedAssessmentsListResponse;
      setHistory(data.records);
    } catch {
      // History is optional if backend is offline.
    }
  }

  useEffect(() => {
    void refreshHistory();
  }, []);

  async function persistReport(currentReport: RiskReportData): Promise<string> {
    const response = await fetch(`${API_BASE_URL}/api/v1/agentic/records`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(toSavePayload(currentReport)),
    });
    if (!response.ok) {
      throw new Error("Không thể lưu kết quả đánh giá trên máy chủ.");
    }
    const saved = (await response.json()) as SavedAssessmentRecord;
    setSavedId(saved.assessment_id);
    setHistory((prev) => [
      saved,
      ...prev.filter((item) => item.assessment_id !== saved.assessment_id),
    ]);
    return saved.assessment_id;
  }

  async function submitAnswers(answers: QuestionnaireAnswers): Promise<void> {
    const { detection } = await classify(answers);
    const built = buildRiskReport(detection, answers);
    setReport(built);
    setSavedId(null);
    // Automatically record the assessment so it can be exported or reopened later.
    try {
      await persistReport(built);
    } catch {
      // User can still view report and retry saving manually.
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function openSavedRecord(record: SavedAssessmentRecord): void {
    setReport(buildRiskReport(record.detection, record.answers));
    setSavedId(record.assessment_id);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function deleteSavedRecord(assessmentId: string): Promise<void> {
    try {
      await fetch(`${API_BASE_URL}/api/v1/agentic/records/${encodeURIComponent(assessmentId)}`, {
        method: "DELETE",
      });
    } finally {
      setHistory((prev) => prev.filter((item) => item.assessment_id !== assessmentId));
      if (savedId === assessmentId) {
        setSavedId(null);
      }
    }
  }

  function restart(): void {
    setReport(null);
    setSavedId(null);
    setWizardKey((key) => key + 1);
  }

  return (
    <main className="app-shell app-shell--narrow">
      <header className="app-header">
        <p className="app-header__eyebrow">Kiểm tra an toàn hệ thống AI</p>
        <h1>Ứng dụng AI của bạn có an toàn không?</h1>
        <p>
          Mô tả hệ thống và kịch bản sử dụng bằng ngôn ngữ đời thường. Hệ thống sẽ tự động
          nhận diện mô hình tích hợp AI (theo chuẩn Google Cloud Agentic Patterns), chỉ ra rủi
          ro và lưu lại kết quả để xuất báo cáo.
        </p>
      </header>
      {report === null ? (
        <AssessmentWizard key={wizardKey} onSubmit={submitAnswers} />
      ) : (
        <RiskReport
          report={report}
          savedId={savedId}
          apiBaseUrl={API_BASE_URL}
          onSave={() => persistReport(report)}
          onRestart={restart}
        />
      )}

      {history.length > 0 && (
        <section className="history-panel" aria-labelledby="history-heading">
          <div className="history-panel__header">
            <h2 id="history-heading">Lịch sử các lần đánh giá đã lưu ({history.length})</h2>
            <small>Chọn một bản ghi để xem lại hoặc kết xuất báo cáo (Markdown / CSV / JSON)</small>
          </div>
          <ul className="history-list">
            {history.map((item) => {
              const patternInfo = PATTERN_DISPLAY_INFO[item.detection.primary_pattern];
              const isCurrent = savedId === item.assessment_id;
              return (
                <li
                  key={item.assessment_id}
                  className={`history-item${isCurrent ? " history-item--active" : ""}`}
                >
                  <div className="history-item__info">
                    <strong>
                      {item.answers.system_name ?? "Ứng dụng AI chưa đặt tên"}{" "}
                      <span className="pattern-pill">{item.detection.primary_pattern}</span>
                    </strong>
                    <small>
                      {patternInfo.friendlyName} · Mức rủi ro:{" "}
                      <strong>{item.overall_severity_label}</strong> ({item.overall_score}/25) ·{" "}
                      {new Date(item.created_at).toLocaleString("vi-VN")}
                    </small>
                  </div>
                  <div className="history-item__actions">
                    <button
                      type="button"
                      className="button-secondary"
                      onClick={() => openSavedRecord(item)}
                    >
                      Xem lại
                    </button>
                    <a
                      className="button-link"
                      href={`${API_BASE_URL}/api/v1/agentic/records/${encodeURIComponent(item.assessment_id)}/export?format=md`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Xuất MD
                    </a>
                    <a
                      className="button-link"
                      href={`${API_BASE_URL}/api/v1/agentic/records/${encodeURIComponent(item.assessment_id)}/export?format=csv`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Xuất CSV
                    </a>
                    <button
                      type="button"
                      className="link-button"
                      onClick={() => void deleteSavedRecord(item.assessment_id)}
                    >
                      Xoá
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        </section>
      )}
    </main>
  );
}
