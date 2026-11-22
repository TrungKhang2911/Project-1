import { useEffect, useState } from "react";

import {
  loadPreferences,
  savePreferences,
  UI_STRINGS,
} from "./agentic/preferences";
import {
  buildRiskReport,
  getSeverityLabel,
  localizePatternInfo,
  PATTERN_DISPLAY_INFO,
  type RiskReport as RiskReportData,
} from "./agentic/riskMap";
import { AssessmentWizard } from "./components/AssessmentWizard";
import { DevWorkbench } from "./components/DevWorkbench";
import { RiskReport } from "./components/RiskReport";
import { SettingsBar } from "./components/SettingsBar";
import type {
  ClassificationResponse,
  Language,
  QuestionnaireAnswers,
  SavedAssessmentCreate,
  SavedAssessmentRecord,
  SavedAssessmentsListResponse,
  UserPreferences,
} from "./types";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "") ?? "http://localhost:8000";

async function classify(
  answers: QuestionnaireAnswers,
  language: Language,
): Promise<ClassificationResponse> {
  const isEn = language === "en";
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/v1/agentic/classify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(answers),
    });
  } catch {
    throw new Error(
      isEn
        ? "Unable to connect to the assessment server. Please try again later."
        : "Không kết nối được tới máy chủ đánh giá. Vui lòng thử lại sau.",
    );
  }
  if (!response.ok) {
    throw new Error(
      response.status === 422
        ? isEn
          ? "Invalid input data. Please review your answers."
          : "Câu trả lời chưa hợp lệ. Vui lòng kiểm tra lại."
        : isEn
          ? `Server error (status ${response.status}). Please try again later.`
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
  const [preferences, setPreferences] = useState<UserPreferences>(() => loadPreferences());
  const [report, setReport] = useState<RiskReportData | null>(null);
  const [savedId, setSavedId] = useState<string | null>(null);
  const [history, setHistory] = useState<SavedAssessmentRecord[]>([]);
  const [wizardKey, setWizardKey] = useState(0);

  const strings = UI_STRINGS[preferences.language];
  const isDevMode = preferences.mode === "dev";

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", preferences.theme);
    savePreferences(preferences);
  }, [preferences]);

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
      throw new Error(
        preferences.language === "en"
          ? "Unable to save assessment record on the server."
          : "Không thể lưu kết quả đánh giá trên máy chủ.",
      );
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
    const { detection } = await classify(answers, preferences.language);
    const built = buildRiskReport(detection, answers, [], preferences.language);
    setReport(built);
    setSavedId(null);
    try {
      await persistReport(built);
    } catch {
      // User can still view report and retry saving manually.
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function handleDevReportGenerated(built: RiskReportData): Promise<void> {
    setReport(built);
    setSavedId(null);
    try {
      await persistReport(built);
    } catch {
      // Offline fallback
    }
  }

  function openSavedRecord(record: SavedAssessmentRecord): void {
    setPreferences((prev) => ({ ...prev, mode: "normal" }));
    setReport(buildRiskReport(record.detection, record.answers, [], preferences.language));
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
    <main className={`app-shell${isDevMode ? "" : " app-shell--narrow"}`}>
      <SettingsBar preferences={preferences} onChange={setPreferences} />

      <header className="app-header">
        <p className="app-header__eyebrow">
          {isDevMode ? strings.eyebrowDev : strings.eyebrowNormal}
        </p>
        <h1>{isDevMode ? strings.titleDev : strings.titleNormal}</h1>
        <p>{isDevMode ? strings.subtitleDev : strings.subtitleNormal}</p>
      </header>

      {isDevMode ? (
        <DevWorkbench
          apiBaseUrl={API_BASE_URL}
          language={preferences.language}
          onReportGenerated={handleDevReportGenerated}
        />
      ) : report === null ? (
        <AssessmentWizard
          key={`${wizardKey}-${preferences.language}`}
          language={preferences.language}
          onSubmit={submitAnswers}
        />
      ) : (
        <RiskReport
          report={report}
          savedId={savedId}
          apiBaseUrl={API_BASE_URL}
          language={preferences.language}
          onSave={() => persistReport(report)}
          onRestart={restart}
        />
      )}

      {history.length > 0 && (
        <section className="history-panel" aria-labelledby="history-heading">
          <div className="history-panel__header">
            <h2 id="history-heading">{strings.historyHeading(history.length)}</h2>
            <small>{strings.historySub}</small>
          </div>
          <ul className="history-list">
            {history.map((item) => {
              const patternInfo = localizePatternInfo(
                PATTERN_DISPLAY_INFO[item.detection.primary_pattern],
                preferences.language,
              );
              const severityLabel = getSeverityLabel(
                item.overall_severity,
                preferences.language,
              );
              const isCurrent = savedId === item.assessment_id;
              return (
                <li
                  key={item.assessment_id}
                  className={`history-item${isCurrent ? " history-item--active" : ""}`}
                >
                  <div className="history-item__info">
                    <strong>
                      {item.answers.system_name ?? strings.unnamedSystem}{" "}
                      <span className="pattern-pill">{item.detection.primary_pattern}</span>
                    </strong>
                    <small>
                      {patternInfo.friendlyName} ·{" "}
                      <strong>{severityLabel}</strong> ({item.overall_score}/25) ·{" "}
                      {new Date(item.created_at).toLocaleString(
                        preferences.language === "en" ? "en-US" : "vi-VN",
                      )}
                    </small>
                  </div>
                  <div className="history-item__actions">
                    <button
                      type="button"
                      className="button-secondary"
                      onClick={() => openSavedRecord(item)}
                    >
                      {strings.viewRecordBtn}
                    </button>
                    <a
                      className="button-link"
                      href={`${API_BASE_URL}/api/v1/agentic/records/${encodeURIComponent(item.assessment_id)}/export?format=md`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      ↓ MD
                    </a>
                    <a
                      className="button-link"
                      href={`${API_BASE_URL}/api/v1/agentic/records/${encodeURIComponent(item.assessment_id)}/export?format=csv`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      ↓ CSV
                    </a>
                    <button
                      type="button"
                      className="link-button"
                      onClick={() => void deleteSavedRecord(item.assessment_id)}
                    >
                      {strings.deleteBtn}
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
