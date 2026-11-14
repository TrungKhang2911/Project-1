import { useState } from "react";

import type { ReportedRisk, RiskReport as RiskReportData, Severity } from "../agentic/riskMap";
import { SEVERITY_LABELS } from "../agentic/riskMap";

interface RiskReportProps {
  report: RiskReportData;
  savedId: string | null;
  apiBaseUrl: string;
  onSave: () => Promise<string>;
  onRestart: () => void;
}

const SEVERITY_STYLE: Record<Severity, { color: string; text: string; bg: string }> = {
  Low: { color: "#15803d", text: "#ffffff", bg: "#dcfce7" },
  Medium: { color: "#b45309", text: "#ffffff", bg: "#fef3c7" },
  High: { color: "#c2410c", text: "#ffffff", bg: "#ffedd5" },
  Critical: { color: "#b91c1c", text: "#ffffff", bg: "#fee2e2" },
};

const OVERALL_MESSAGE: Record<Severity, string> = {
  Low: "Ứng dụng của bạn có mức rủi ro thấp. Hãy tiếp tục theo dõi định kỳ.",
  Medium: "Ứng dụng của bạn có một số rủi ro cần xử lý bằng các biện pháp cơ bản.",
  High: "Ứng dụng của bạn có rủi ro cao. Nên khắc phục trước khi đưa vào sử dụng chính thức.",
  Critical:
    "Ứng dụng của bạn có rủi ro nghiêm trọng. Nên tạm dừng triển khai và điều chỉnh lại cách AI hoạt động.",
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

function SeverityBadge({ severity }: { severity: Severity }): JSX.Element {
  const style = SEVERITY_STYLE[severity];
  return (
    <span className="severity-badge" style={{ backgroundColor: style.color, color: style.text }}>
      Mức độ: {SEVERITY_LABELS[severity]}
    </span>
  );
}

function RiskItem({ risk, index }: { risk: ReportedRisk; index: number }): JSX.Element {
  return (
    <article
      className="report-risk"
      style={{
        borderLeftColor: SEVERITY_STYLE[risk.severity].color,
        animationDelay: `${index * 60}ms`,
      }}
    >
      <header>
        <h4>
          <SeverityDot severity={risk.severity} />
          <span>{risk.title}</span>
        </h4>
        <SeverityBadge severity={risk.severity} />
      </header>
      <p>{risk.explanation}</p>

      <div className="report-risk__actions">
        <strong>Bạn nên làm gì?</strong>
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
  report,
  savedId,
  apiBaseUrl,
  onSave,
  onRestart,
}: RiskReportProps): JSX.Element {
  const [saving, setSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);
  const overall = SEVERITY_STYLE[report.overallSeverity];
  const systemTitle = report.answers.system_name ?? "Ứng dụng AI của bạn";

  async function handleSave(): Promise<string | null> {
    if (savedId) return savedId;
    setSaving(true);
    setSaveMessage(null);
    try {
      const id = await onSave();
      setSaveMessage(`Đã lưu kết quả đánh giá (Mã: ${id}).`);
      return id;
    } catch (err: unknown) {
      setSaveMessage(err instanceof Error ? err.message : "Không thể lưu kết quả lúc này.");
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
          <h2 id="report-heading">Kết quả đánh giá: {systemTitle}</h2>
          {savedId && <small className="report__saved-tag">Mã hồ sơ đã lưu: #{savedId}</small>}
        </div>
        <div className="report__toolbar">
          <button
            type="button"
            className="button-secondary"
            onClick={() => void handleSave()}
            disabled={saving || savedId !== null}
          >
            {savedId ? "✓ Đã lưu" : saving ? "Đang lưu…" : "Lưu kết quả"}
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={() => void handleExport("md")}
          >
            ↓ Xuất Markdown
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={() => void handleExport("csv")}
          >
            ↓ Xuất CSV
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={() => void handleExport("json")}
          >
            ↓ Xuất JSON
          </button>
          <button type="button" onClick={onRestart}>
            Đánh giá mới
          </button>
        </div>
      </header>

      {saveMessage && <p className="report__save-banner">{saveMessage}</p>}

      <div className="report__overall" style={{ borderColor: overall.color }}>
        <p className="report__overall-label">Mức rủi ro chung</p>
        <p className="report__overall-value" style={{ color: overall.color }}>
          <SeverityDot severity={report.overallSeverity} />
          <span>
            {report.overallSeverityLabel} ({report.overallScore}/25)
          </span>
        </p>
        <p>{OVERALL_MESSAGE[report.overallSeverity]}</p>
        <ul className="report__counts" aria-label="Số rủi ro theo mức độ">
          {SEVERITY_ORDER.filter((severity) => report.countsBySeverity[severity] > 0).map(
            (severity) => (
              <li key={severity}>
                <SeverityDot severity={severity} />
                <span>
                  {report.countsBySeverity[severity]} {SEVERITY_LABELS[severity].toLowerCase()}
                </span>
              </li>
            ),
          )}
        </ul>
      </div>

      {/* Ghi nhận mô hình mẫu tích hợp AI (Google Cloud Agentic AI System Patterns) */}
      <div className="report__pattern-box">
        <div className="report__pattern-header">
          <div>
            <span className="report__pattern-eyebrow">
              Mô hình mẫu tích hợp AI được ghi nhận (Google Cloud Agentic Pattern)
            </span>
            <h3>
              {report.primaryPatternInfo.friendlyName}{" "}
              <small>({report.primaryPatternInfo.googleCloudName})</small>
            </h3>
          </div>
          <span className="pattern-pill">{report.primaryPatternInfo.code}</span>
        </div>
        <p>{report.primaryPatternInfo.description}</p>
        {report.detectedPatternsInfo.length > 1 && (
          <div className="report__subpatterns">
            <strong>Các mẫu hình kết hợp trong hệ thống:</strong>
            <ul>
              {report.detectedPatternsInfo.map((item) => (
                <li key={item.code}>
                  <strong>{item.friendlyName}</strong> ({item.googleCloudName}): {item.description}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <div className="report__summary">
        <h3>Mô tả hệ thống &amp; kịch bản vận hành (Đích đánh giá)</h3>
        <p>{report.summary}</p>
        {report.answers.purpose_details && (
          <p>
            <strong>Mô tả chi tiết:</strong> {report.answers.purpose_details}
          </p>
        )}
        {report.answers.scenarios && report.answers.scenarios.length > 0 && (
          <div>
            <strong>Các kịch bản vận hành đã ghi nhận:</strong>
            <ol className="report__scenario-list">
              {report.answers.scenarios.map((scenario) => (
                <li key={scenario}>{scenario}</li>
              ))}
            </ol>
          </div>
        )}
        <p className="report__oversight">{report.oversightNote}</p>
      </div>

      {report.topActions.length > 0 && (
        <div className="report__top-actions">
          <h3>Việc nên làm ngay</h3>
          <ol>
            {report.topActions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ol>
        </div>
      )}

      <div className="report__risks">
        <h3>Chi tiết từng rủi ro</h3>
        {report.risks.map((risk, index) => (
          <RiskItem key={risk.id} risk={risk} index={index} />
        ))}
      </div>

      <details className="report__technical">
        <summary>Thông tin dành cho đội kỹ thuật (OWASP / NIST / Pattern Mapping)</summary>
        <p>
          <strong>Primary pattern:</strong> {report.technical.primaryPattern}
          <br />
          <strong>Detected patterns:</strong> {report.technical.patterns.join(", ")}
          <br />
          <strong>Classifier:</strong> {report.technical.source === "llm" ? "LLM + rules" : "Rules only"}{" "}
          (confidence {Math.round(report.technical.confidence * 100)}%)
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
              <th scope="col">L×I</th>
              <th scope="col">References</th>
              <th scope="col">Triggered by</th>
            </tr>
          </thead>
          <tbody>
            {report.risks.map((risk) => (
              <tr key={risk.id}>
                <td>{risk.technical.name}</td>
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
