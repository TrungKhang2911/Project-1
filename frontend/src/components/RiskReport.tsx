import { useState } from "react";

import { UI_STRINGS } from "../agentic/preferences";
import {
  buildRiskReport,
  getSeverityLabel,
  type ReportedRisk,
  type RiskReport as RiskReportData,
  type Severity,
} from "../agentic/riskMap";
import type { AgenticPattern, Language } from "../types";

interface RiskReportProps {
  report: RiskReportData;
  savedId: string | null;
  apiBaseUrl: string;
  language?: Language;
  onSave: () => Promise<string>;
  onRestart: () => void;
}

const SEVERITY_STYLE: Record<Severity, { color: string; text: string; bg: string }> = {
  Low: { color: "#15803d", text: "#ffffff", bg: "#dcfce7" },
  Medium: { color: "#b45309", text: "#ffffff", bg: "#fef3c7" },
  High: { color: "#c2410c", text: "#ffffff", bg: "#ffedd5" },
  Critical: { color: "#b91c1c", text: "#ffffff", bg: "#fee2e2" },
};

const OVERALL_MESSAGE: Record<Language, Record<Severity, string>> = {
  vi: {
    Low: "Mức độ rủi ro thấp. Duy trì giám sát và rà soát định kỳ.",
    Medium: "Mức độ rủi ro trung bình. Cần áp dụng các biện pháp kiểm soát cơ bản trước khi mở rộng quy mô.",
    High: "Mức độ rủi ro cao. Cần khắc phục các điểm yếu trọng yếu trước khi vận hành chính thức.",
    Critical:
      "Mức độ rủi ro nghiêm trọng. Khuyến nghị tạm dừng triển khai để điều chỉnh kiến trúc và phân quyền.",
  },
  en: {
    Low: "Low overall risk. Maintain routine monitoring and periodic security reviews.",
    Medium: "Medium overall risk. Apply baseline security controls before scaling deployment.",
    High: "High overall risk. Address priority vulnerabilities before production launch.",
    Critical:
      "Critical overall risk. Pause deployment and redesign agent permissions and guardrails.",
  },
};

const SEVERITY_ORDER: Severity[] = ["Critical", "High", "Medium", "Low"];

function SeverityDot({ severity }: { severity: Severity }): JSX.Element {
  return (
    <span
      className={`severity-dot${severity === "Critical" ? " severity-dot--pulse" : ""}`}
      style={{ backgroundColor: SEVERITY_STYLE[severity].color }}
      aria-hidden="true"
    />
  );
}

function SeverityBadge({
  severity,
  language,
}: {
  severity: Severity;
  language: Language;
}): JSX.Element {
  const style = SEVERITY_STYLE[severity];
  return (
    <span className="severity-badge" style={{ backgroundColor: style.color, color: style.text }}>
      {getSeverityLabel(severity, language)}
    </span>
  );
}

function SourceBadge({
  kind,
  label,
}: {
  kind: "system" | "ai" | "hybrid";
  label: string;
}): JSX.Element {
  const icon = kind === "ai" ? "✦" : kind === "hybrid" ? "✦/▣" : "▣";
  return (
    <span className={`source-badge source-badge--${kind}`}>
      <span className="source-badge__icon" aria-hidden="true">
        {icon}
      </span>
      <span>{label}</span>
    </span>
  );
}

function RiskItem({
  risk,
  index,
  whatToDoLabel,
  language,
}: {
  risk: ReportedRisk;
  index: number;
  whatToDoLabel: string;
  language: Language;
}): JSX.Element {
  const isEn = language === "en";
  const isAiInferred = risk.origin === "ai_inferred_pattern";
  const isDedicatedAiRisk = risk.id.startsWith("AI-");
  return (
    <article
      className={`report-risk${isAiInferred ? " report-risk--ai" : " report-risk--system"}`}
      style={{
        borderLeftColor: SEVERITY_STYLE[risk.severity].color,
        animationDelay: `${index * 60}ms`,
      }}
    >
      <header>
        <div>
          <h4>
            <SeverityDot severity={risk.severity} />
            <span>
              {isDedicatedAiRisk ? `${risk.id}: ${risk.title}` : risk.title}
            </span>
          </h4>
          <div className="report-risk__origin-row">
            {isDedicatedAiRisk ? (
              <>
                <SourceBadge
                  kind="ai"
                  label={isEn ? "AI Analysis" : "Đánh giá của AI"}
                />
                <SourceBadge
                  kind="system"
                  label={`${risk.likelihood}×${risk.impact} = ${risk.score}/25`}
                />
              </>
            ) : isAiInferred ? (
              <>
                <SourceBadge
                  kind="ai"
                  label={isEn ? "AI-detected pattern" : "Mẫu hình do AI phát hiện"}
                />
                <SourceBadge
                  kind="system"
                  label={isEn ? "System 5×5 scoring" : "Điểm chuẩn hệ thống"}
                />
              </>
            ) : (
              <SourceBadge
                kind="system"
                label={isEn ? "System rule" : "Quy tắc hệ thống"}
              />
            )}
          </div>
        </div>
        <SeverityBadge severity={risk.severity} language={language} />
      </header>
      <p>{risk.explanation}</p>

      <div className="report-risk__actions">
        <strong>{whatToDoLabel}</strong>
        <ul>
          {risk.recommendations.map((recommendation) => (
            <li key={recommendation}>{recommendation}</li>
          ))}
        </ul>
      </div>

      {risk.adjustments.length > 0 && (
        <ul className="report-risk__notes">
          {risk.adjustments.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}
    </article>
  );
}

export function RiskReport({
  report: rawReport,
  savedId,
  apiBaseUrl,
  language = "vi",
  onSave,
  onRestart,
}: RiskReportProps): JSX.Element {
  const strings = UI_STRINGS[language];
  const isEn = language === "en";
  const report = buildRiskReport(rawReport.detection, rawReport.answers, [], language);
  const [saving, setSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);
  const [riskFilter, setRiskFilter] = useState<"all" | "system" | "ai">("all");
  const overall = SEVERITY_STYLE[report.overallSeverity];
  const systemTitle = report.answers.system_name ?? strings.unnamedSystem;

  const isLlmActive = report.detection.source === "llm";
  const llmAddedSet = new Set<AgenticPattern>(report.detection.llm_added_patterns ?? []);
  const aiAnalysis = report.aiAnalysis;
  const systemRiskCount = report.risks.filter((r) => r.origin === "system_rule").length;
  const aiTriggeredRiskCount = report.risks.filter(
    (r) => r.origin === "ai_inferred_pattern",
  ).length;

  const filteredRisks = report.risks.filter((risk) => {
    if (riskFilter === "system") return risk.origin === "system_rule";
    if (riskFilter === "ai") return risk.origin === "ai_inferred_pattern";
    return true;
  });

  async function handleSave(): Promise<string | null> {
    if (savedId) return savedId;
    setSaving(true);
    setSaveMessage(null);
    try {
      const id = await onSave();
      setSaveMessage(
        isEn ? `Assessment saved (ID: ${id}).` : `Đã lưu báo cáo (Mã: ${id}).`,
      );
      return id;
    } catch (err: unknown) {
      setSaveMessage(
        err instanceof Error
          ? err.message
          : isEn
            ? "Unable to save report right now."
            : "Không thể lưu kết quả lúc này.",
      );
      return null;
    } finally {
      setSaving(false);
    }
  }

  async function handleExport(format: "md" | "json" | "csv"): Promise<void> {
    const id = savedId ?? (await handleSave());
    if (!id) return;
    window.open(
      `${apiBaseUrl}/api/v1/agentic/records/${encodeURIComponent(id)}/export?format=${format}`,
      "_blank",
      "noopener,noreferrer",
    );
  }

  return (
    <section className="report" aria-live="polite" aria-labelledby="report-heading">
      <header className="report__header">
        <div>
          <h2 id="report-heading">{strings.reportHeading(systemTitle)}</h2>
          {savedId && <small className="report__saved-tag">{strings.savedTag(savedId)}</small>}
        </div>
        <div className="report__toolbar">
          <button
            type="button"
            className="button-secondary"
            onClick={() => void handleSave()}
            disabled={saving || savedId !== null}
          >
            {savedId ? strings.savedBtn : saving ? strings.savingBtn : strings.saveBtn}
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={() => void handleExport("md")}
          >
            {strings.exportMd}
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={() => void handleExport("csv")}
          >
            {strings.exportCsv}
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={() => void handleExport("json")}
          >
            {strings.exportJson}
          </button>
          <button type="button" onClick={onRestart}>
            {strings.newAssessmentBtn}
          </button>
        </div>
      </header>

      {saveMessage && <p className="report__save-banner">{saveMessage}</p>}

      <div className="report__overall" style={{ borderColor: overall.color }}>
        <div className="report__section-top">
          <p className="report__overall-label">{strings.overallRiskLabel}</p>
          <SourceBadge
            kind="system"
            label={isEn ? "System 5×5 Matrix" : "Hệ thống · Ma trận 5×5"}
          />
        </div>
        <p className="report__overall-value" style={{ color: overall.color }}>
          <SeverityDot severity={report.overallSeverity} />
          <span>
            {report.overallSeverityLabel} ({report.overallScore}/25)
          </span>
        </p>
        <p>{OVERALL_MESSAGE[language][report.overallSeverity]}</p>
        <ul
          className="report__counts"
          aria-label={isEn ? "Risks by severity" : "Số rủi ro theo mức độ"}
        >
          {SEVERITY_ORDER.filter((severity) => report.countsBySeverity[severity] > 0).map(
            (severity) => (
              <li key={severity}>
                <SeverityDot severity={severity} />
                <span>
                  {report.countsBySeverity[severity]}{" "}
                  {getSeverityLabel(severity, language).toLowerCase()}
                </span>
              </li>
            ),
          )}
        </ul>
      </div>

      <div className="report__pattern-box">
        <div className="report__pattern-header">
          <div>
            <span className="report__pattern-eyebrow">{strings.patternBoxEyebrow}</span>
            <h3>
              {report.primaryPatternInfo.friendlyName}{" "}
              <small>({report.primaryPatternInfo.googleCloudName})</small>
            </h3>
          </div>
          <div className="report__pattern-badges">
            {isLlmActive && llmAddedSet.has(report.detection.primary_pattern) ? (
              <SourceBadge
                kind="ai"
                label={isEn ? "AI-Inferred" : "AI suy luận"}
              />
            ) : isLlmActive ? (
              <SourceBadge
                kind="hybrid"
                label={isEn ? "System + AI" : "Hệ thống + AI"}
              />
            ) : (
              <SourceBadge
                kind="system"
                label={isEn ? "System Rule" : "Quy tắc hệ thống"}
              />
            )}
            <span className="pattern-pill">{report.primaryPatternInfo.code}</span>
          </div>
        </div>
        <p>{report.primaryPatternInfo.description}</p>
        {report.detectedPatternsInfo.length > 1 && (
          <div className="report__subpatterns">
            <strong>{strings.combinedPatternsLabel}</strong>
            <ul>
              {report.detectedPatternsInfo.map((item) => {
                const addedByAi = isLlmActive && llmAddedSet.has(item.code);
                return (
                  <li key={item.code}>
                    <div className="report__subpattern-item">
                      <div>
                        <strong>{item.friendlyName}</strong> ({item.googleCloudName}):{" "}
                        {item.description}
                      </div>
                      <SourceBadge
                        kind={addedByAi ? "ai" : "system"}
                        label={
                          addedByAi
                            ? isEn
                              ? "AI-inferred"
                              : "AI bổ sung"
                            : isEn
                              ? "System rule"
                              : "Quy tắc hệ thống"
                        }
                      />
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </div>

      <div className="report__summary">
        <div className="report__section-top">
          <h3>{strings.systemSummaryTitle}</h3>
          <SourceBadge
            kind={isLlmActive ? "ai" : "system"}
            label={
              isLlmActive
                ? isEn
                  ? "AI Summary"
                  : "Tóm tắt bởi AI"
                : isEn
                  ? "System Summary"
                  : "Tóm tắt hệ thống"
            }
          />
        </div>
        <p className={isLlmActive ? "ai-highlight-text" : undefined}>{report.summary}</p>
        {report.answers.purpose_details && (
          <p>
            <strong>{strings.detailedDescLabel}</strong> {report.answers.purpose_details}
          </p>
        )}
        {report.answers.scenarios && report.answers.scenarios.length > 0 && (
          <div>
            <strong>{strings.recordedScenariosLabel}</strong>
            <ol className="report__scenario-list">
              {report.answers.scenarios.map((scenario) => (
                <li key={scenario}>{scenario}</li>
              ))}
            </ol>
          </div>
        )}
        <p className="report__oversight">
          <SourceBadge
            kind="system"
            label={isEn ? "System Policy" : "Quy tắc hệ thống"}
          />{" "}
          <span>{report.oversightNote}</span>
        </p>
      </div>

      {/* High-level AI Overview (without duplicating the individual AI risk cards below) */}
      <section
        className="report__ai-box ai-surface"
        aria-label={isEn ? "AI Executive Overview" : "Đánh giá tổng quan từ AI"}
      >
        <div className="report__section-top">
          <div>
            <span className="report__pattern-eyebrow">
              {isEn ? "AI EXECUTIVE OVERVIEW" : "TỔNG QUAN TỪ AI"}
            </span>
            <h3>
              {isEn
                ? "✦ AI Contextual & Scenario Overview"
                : "✦ Đánh giá tổng quan ngữ cảnh & kịch bản từ AI"}
            </h3>
          </div>
          <SourceBadge
            kind="ai"
            label={`${aiAnalysis.engineLabel} · ${Math.round(aiAnalysis.confidence * 100)}%`}
          />
        </div>

        <p className="ai-highlight-text">{aiAnalysis.executiveSummary}</p>

        <ul className="report__ai-insights">
          {aiAnalysis.scenarioObservations.map((insight) => (
            <li key={insight}>{insight}</li>
          ))}
        </ul>
      </section>

      {report.topActions.length > 0 && (
        <div className="report__top-actions">
          <div className="report__section-top">
            <h3>{strings.topActionsTitle}</h3>
            <SourceBadge
              kind="system"
              label={isEn ? "System Priority" : "Hệ thống xếp hạng"}
            />
          </div>
          <ol>
            {report.topActions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ol>
        </div>
      )}

      <div className="report__risks">
        <div className="report__risks-header">
          <h3>{strings.riskDetailsTitle}</h3>
          <div className="source-filter-bar" role="group" aria-label="Filter risks by source">
            <button
              type="button"
              className={`source-filter-btn${riskFilter === "all" ? " source-filter-btn--active" : ""}`}
              onClick={() => setRiskFilter("all")}
            >
              {isEn ? `All (${report.risks.length})` : `Tất cả (${report.risks.length})`}
            </button>
            <button
              type="button"
              className={`source-filter-btn${riskFilter === "system" ? " source-filter-btn--active" : ""}`}
              onClick={() => setRiskFilter("system")}
            >
              ▣ {isEn ? `System (${systemRiskCount})` : `Hệ thống (${systemRiskCount})`}
            </button>
            <button
              type="button"
              className={`source-filter-btn${riskFilter === "ai" ? " source-filter-btn--active" : ""}`}
              onClick={() => setRiskFilter("ai")}
            >
              ✦ {isEn ? `AI Analysis (${aiTriggeredRiskCount})` : `Phân tích AI (${aiTriggeredRiskCount})`}
            </button>
          </div>
        </div>
        {filteredRisks.length === 0 ? (
          <p className="report__empty-filter">
            {isEn
              ? "No risks match this source filter."
              : "Không có mục nào thuộc bộ lọc hiện tại."}
          </p>
        ) : (
          filteredRisks.map((risk, index) => (
            <RiskItem
              key={risk.id}
              risk={risk}
              index={index}
              whatToDoLabel={strings.whatToDoLabel}
              language={language}
            />
          ))
        )}
      </div>

      <details className="report__technical">
        <summary>{strings.techDetailsSummary}</summary>
        <p>
          <strong>Primary pattern:</strong> {report.technical.primaryPattern}
          <br />
          <strong>Detected patterns:</strong> {report.technical.patterns.join(", ")}
          <br />
          <strong>Classifier source:</strong>{" "}
          {report.technical.source === "llm"
            ? "✦ Gemini LLM + ▣ System Rule Floor"
            : "✦ AI Contextual Analyzer + ▣ System Rule Engine"}{" "}
          (confidence {Math.round(aiAnalysis.confidence * 100)}%)
          {report.technical.rationale && (
            <>
              <br />
              <strong>Pattern rationale:</strong> {report.technical.rationale}
            </>
          )}
        </p>
        <table>
          <thead>
            <tr>
              <th scope="col">Risk</th>
              <th scope="col">Source</th>
              <th scope="col">L×I</th>
              <th scope="col">References</th>
              <th scope="col">Triggered by</th>
            </tr>
          </thead>
          <tbody>
            {report.risks.map((risk) => (
              <tr key={risk.id}>
                <td>
                  <code>{risk.id}</code> — {risk.technical.name}
                </td>
                <td>
                  {risk.origin === "ai_inferred_pattern"
                    ? "✦ AI Analysis + ▣ System Score"
                    : "▣ System Rule"}
                </td>
                <td>
                  {risk.likelihood}×{risk.impact} = {risk.score} (base {risk.technical.baseScore})
                </td>
                <td>{risk.technical.references.join("; ")}</td>
                <td>{risk.technical.triggeredBy.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </section>
  );
}
