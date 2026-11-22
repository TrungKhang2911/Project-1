import { useState } from "react";

import type { AssessmentResponse, EvaluatedRiskResult, Language } from "../types";

interface RiskDashboardProps {
  assessment: AssessmentResponse | null;
  language?: Language;
}

const SEVERITY_COLORS: Record<string, string> = {
  Low: "#2e7d32",
  Medium: "#edb600",
  High: "#ed6c02",
  Critical: "#c62828",
};

function getSeverity(score: number): "Low" | "Medium" | "High" | "Critical" {
  if (score <= 5) return "Low";
  if (score <= 11) return "Medium";
  if (score <= 19) return "High";
  return "Critical";
}

export function isAiGeneratedRisk(risk: EvaluatedRiskResult): boolean {
  const id = risk.risk_id.toUpperCase();
  return id.startsWith("AI-") || id.startsWith("CUSTOM-");
}

function RiskOriginBadge({
  risk,
  isEn,
}: {
  risk: EvaluatedRiskResult;
  isEn: boolean;
}): JSX.Element {
  const id = risk.risk_id.toUpperCase();
  if (id.startsWith("AI-")) {
    return (
      <span className="source-badge source-badge--ai">
        <span className="source-badge__icon" aria-hidden="true">
          ✦
        </span>
        <span>{isEn ? "AI Analysis · Cross-Node" : "Phân tích AI · Liên thành phần"}</span>
      </span>
    );
  }
  if (id.startsWith("CUSTOM-")) {
    return (
      <span className="source-badge source-badge--ai">
        <span className="source-badge__icon" aria-hidden="true">
          ✦
        </span>
        <span>{isEn ? "AI Analysis · Custom Node" : "Phân tích AI · Thành phần tùy chỉnh"}</span>
      </span>
    );
  }
  return (
    <span className="source-badge source-badge--system">
      <span className="source-badge__icon" aria-hidden="true">
        ▣
      </span>
      <span>{isEn ? "System Rule" : "Quy tắc hệ thống"}</span>
    </span>
  );
}

function RiskMatrix({
  matrix,
  isEn,
}: {
  matrix: number[][];
  isEn: boolean;
}): JSX.Element {
  return (
    <table className="risk-matrix">
      <caption>
        {isEn
          ? "Risk Matrix (Likelihood × Impact)"
          : "Ma trận rủi ro (Khả năng × Mức ảnh hưởng)"}
      </caption>
      <thead>
        <tr>
          <th scope="col">{isEn ? "Likelihood / Impact" : "Khả năng / Ảnh hưởng"}</th>
          {[1, 2, 3, 4, 5].map((impact) => (
            <th scope="col" key={impact}>
              {impact}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {[5, 4, 3, 2, 1].map((likelihood) => (
          <tr key={likelihood}>
            <th scope="row">{likelihood}</th>
            {[1, 2, 3, 4, 5].map((impact) => {
              const score = likelihood * impact;
              const severity = getSeverity(score);
              const count = matrix[likelihood - 1]?.[impact - 1] ?? 0;
              return (
                <td
                  key={impact}
                  style={{
                    backgroundColor: SEVERITY_COLORS[severity],
                    color: severity === "Medium" ? "#1f1f1f" : "#ffffff",
                  }}
                  aria-label={`${count} risks at likelihood ${likelihood}, impact ${impact}, ${severity}`}
                >
                  {count}
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RiskDetails({
  risk,
  isEn,
}: {
  risk: EvaluatedRiskResult;
  isEn: boolean;
}): JSX.Element {
  const aiGenerated = isAiGeneratedRisk(risk);
  return (
    <article className={`risk-card ${aiGenerated ? "risk-card--ai" : "risk-card--system"}`}>
      <header>
        <div>
          <div className="risk-card__badge-row">
            <RiskOriginBadge risk={risk} isEn={isEn} />
          </div>
          <h3>
            {risk.risk_id}: {risk.risk_name}
          </h3>
        </div>
        <span
          className="risk-card__severity"
          style={{ backgroundColor: SEVERITY_COLORS[risk.severity_level] }}
        >
          {risk.severity_level} · {risk.residual_score}/25
        </span>
      </header>
      <p>
        <strong>{isEn ? "Component:" : "Thành phần:"}</strong> {risk.source_component}
      </p>
      <p>
        <strong>{isEn ? "Inherent score:" : "Điểm gốc:"}</strong> {risk.inherent_score}/25 →{" "}
        <strong>{isEn ? "Residual score:" : "Điểm còn lại:"}</strong> {risk.residual_score}/25 (L=
        {risk.residual_likelihood} × I={risk.residual_impact})
      </p>
      <p>{risk.attack_scenario}</p>
      <p>
        <strong>NIST AI RMF:</strong> {risk.nist_categories.join(", ")}
      </p>
      <p>
        <strong>{isEn ? "Recommended action:" : "Khuyến nghị:"}</strong> {risk.recommended_action}
      </p>
      {risk.missing_mitigations.length > 0 ? (
        <div>
          <strong>{isEn ? "Missing controls" : "Kiểm soát còn thiếu"}</strong>
          <ul>
            {risk.missing_mitigations.map((mitigation) => (
              <li key={mitigation}>{mitigation}</li>
            ))}
          </ul>
        </div>
      ) : (
        <p>
          {isEn
            ? "All defined controls for this risk are applied."
            : "Đã áp dụng đầy đủ các kiểm soát được định nghĩa cho rủi ro này."}
        </p>
      )}
    </article>
  );
}

export function RiskDashboard({
  assessment,
  language = "vi",
}: RiskDashboardProps): JSX.Element {
  const isEn = language === "en";
  const [sourceFilter, setSourceFilter] = useState<"all" | "system" | "ai">("all");

  if (assessment === null) {
    return (
      <section aria-live="polite">
        {isEn
          ? "Submit an architecture configuration to view the risk assessment."
          : "Gửi cấu hình kiến trúc để xem kết quả đánh giá rủi ro."}
      </section>
    );
  }

  const systemRisks = assessment.results.filter((r) => !isAiGeneratedRisk(r));
  const aiRisks = assessment.results.filter((r) => isAiGeneratedRisk(r));
  const displayedRisks =
    sourceFilter === "system"
      ? systemRisks
      : sourceFilter === "ai"
        ? aiRisks
        : assessment.results;

  return (
    <section className="risk-dashboard" aria-live="polite">
      <div className="report__section-top">
        <h2>{isEn ? "Quantitative Risk Assessment" : "Kết quả định lượng"}</h2>
        <div className="risk-dashboard__badges">
          <span className="source-badge source-badge--system">
            <span className="source-badge__icon" aria-hidden="true">
              ▣
            </span>
            <span>
              {isEn ? `System: ${systemRisks.length}` : `Hệ thống: ${systemRisks.length}`}
            </span>
          </span>
          <span className="source-badge source-badge--ai">
            <span className="source-badge__icon" aria-hidden="true">
              ✦
            </span>
            <span>
              {isEn ? `AI Analysis: ${aiRisks.length}` : `Phân tích AI: ${aiRisks.length}`}
            </span>
          </span>
        </div>
      </div>

      <div
        className="risk-dashboard__summary"
        style={{ borderColor: SEVERITY_COLORS[assessment.overall_severity] }}
      >
        <p>
          {isEn ? "Overall risk score:" : "Điểm rủi ro tổng thể:"}{" "}
          <strong>{assessment.overall_risk_score}/25</strong>
        </p>
        <p>
          {isEn ? "Severity:" : "Mức độ:"}{" "}
          <strong style={{ color: SEVERITY_COLORS[assessment.overall_severity] }}>
            {assessment.overall_severity}
          </strong>
        </p>
        <small>
          {isEn ? (
            <>
              ▣ Scores computed via System 5×5 Matrix · ✦ Cross-node &amp; custom component risks (
              <code>AI-*</code>, <code>CUSTOM-*</code>) generated by LLM.
            </>
          ) : (
            <>
              ▣ Điểm số tính theo ma trận hệ thống · ✦ Rủi ro liên thành phần hoặc tùy chỉnh (mã{" "}
              <code>AI-*</code>, <code>CUSTOM-*</code>) do LLM phân tích.
            </>
          )}
        </small>
      </div>

      <RiskMatrix matrix={assessment.risk_matrix_summary} isEn={isEn} />

      <div className="report__risks-header">
        <h3>
          {isEn
            ? `Evaluated Risks (${displayedRisks.length})`
            : `Danh sách rủi ro (${displayedRisks.length})`}
        </h3>
        <div className="source-filter-bar" role="group" aria-label="Filter evaluated risks">
          <button
            type="button"
            className={`source-filter-btn${sourceFilter === "all" ? " source-filter-btn--active" : ""}`}
            onClick={() => setSourceFilter("all")}
          >
            {isEn
              ? `All (${assessment.results.length})`
              : `Tất cả (${assessment.results.length})`}
          </button>
          <button
            type="button"
            className={`source-filter-btn${sourceFilter === "system" ? " source-filter-btn--active" : ""}`}
            onClick={() => setSourceFilter("system")}
          >
            ▣ {isEn ? `System (${systemRisks.length})` : `Hệ thống (${systemRisks.length})`}
          </button>
          <button
            type="button"
            className={`source-filter-btn${sourceFilter === "ai" ? " source-filter-btn--active" : ""}`}
            onClick={() => setSourceFilter("ai")}
          >
            ✦ {isEn ? `AI Analysis (${aiRisks.length})` : `Phân tích AI (${aiRisks.length})`}
          </button>
        </div>
      </div>

      <div className="risk-dashboard__results">
        {displayedRisks.length === 0 ? (
          <p className="report__empty-filter">
            {isEn
              ? "No items match the current source filter."
              : "Không có mục nào thuộc bộ lọc hiện tại."}
          </p>
        ) : (
          displayedRisks.map((risk, index) => (
            <RiskDetails
              key={`${risk.source_component}-${risk.risk_id}-${index}`}
              risk={risk}
              isEn={isEn}
            />
          ))
        )}
      </div>
    </section>
  );
}
