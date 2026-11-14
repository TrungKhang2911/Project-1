import { useState } from "react";

import {
  buildRiskReport,
  PATTERN_DISPLAY_INFO,
  TECHNICAL_CONTROLS,
  type ReportedRisk,
  type RiskReport as RiskReportData,
  type Severity,
} from "../agentic/riskMap";
import { ArchitectureInput } from "./ArchitectureInput";
import { RiskDashboard } from "./RiskDashboard";
import type {
  AgenticPattern,
  AssessmentRequest,
  AssessmentResponse,
  Audience,
  HumanOversight,
  Language,
  PatternDetection,
  QuestionnaireAnswers,
  Resource,
  SensitiveData,
} from "../types";

interface DevWorkbenchProps {
  apiBaseUrl: string;
  language: Language;
  onReportGenerated: (report: RiskReportData) => Promise<void>;
}

const PRIMARY_PATTERNS: Array<Exclude<AgenticPattern, "HUMAN_IN_THE_LOOP">> = [
  "SINGLE_AGENT",
  "REACT",
  "SEQUENTIAL",
  "PARALLEL",
  "COORDINATOR",
  "HIERARCHICAL",
  "SWARM",
];

const SEVERITY_COLORS: Record<Severity, string> = {
  Low: "#15803d",
  Medium: "#b45309",
  High: "#c2410c",
  Critical: "#b91c1c",
};

function buildMatrixFromRisks(risks: ReportedRisk[]): number[][] {
  const matrix = Array.from({ length: 5 }, () => [0, 0, 0, 0, 0]);
  for (const risk of risks) {
    matrix[risk.likelihood - 1][risk.impact - 1] += 1;
  }
  return matrix;
}

export function DevWorkbench({
  apiBaseUrl,
  language,
  onReportGenerated,
}: DevWorkbenchProps): JSX.Element {
  const isEn = language === "en";
  const [subTab, setSubTab] = useState<"pattern" | "nodes">("pattern");
  const [systemName, setSystemName] = useState("Multi-Agent Enterprise Assistant");
  const [archNotes, setArchNotes] = useState(
    "Coordinator agent decomposes user requests and delegates to SQL/RAG and Email tool sub-agents.",
  );
  const [primaryPattern, setPrimaryPattern] =
    useState<Exclude<AgenticPattern, "HUMAN_IN_THE_LOOP">>("COORDINATOR");
  const [secondaryPatterns, setSecondaryPatterns] = useState<AgenticPattern[]>([
    "REACT",
    "HUMAN_IN_THE_LOOP",
  ]);
  const [oversight, setOversight] = useState<HumanOversight>("partial");
  const [audience, setAudience] = useState<Audience>("public");
  const [resources, setResources] = useState<Resource[]>([
    "internal_docs",
    "external_tools",
    "company_data",
  ]);
  const [sensitiveData, setSensitiveData] = useState<SensitiveData[]>([
    "personal",
    "confidential",
  ]);
  const [activeControls, setActiveControls] = useState<string[]>([
    "CTRL_SYS_PROMPT_SEP",
    "CTRL_GUARDRAILS",
  ]);

  const [academicReport, setAcademicReport] = useState<RiskReportData | null>(null);
  const [nodeAssessment, setNodeAssessment] = useState<AssessmentResponse | null>(null);

  function toggleArrayItem<T extends string>(
    list: T[],
    value: T,
    setter: (next: T[]) => void,
  ): void {
    setter(list.includes(value) ? list.filter((item) => item !== value) : [...list, value]);
  }

  async function runAcademicEvaluation(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    const patternsSet = new Set<AgenticPattern>([primaryPattern, ...secondaryPatterns]);
    if (oversight !== "none") {
      patternsSet.add("HUMAN_IN_THE_LOOP");
    } else {
      patternsSet.delete("HUMAN_IN_THE_LOOP");
    }
    const orderedPatterns = [...patternsSet];

    const syntheticAnswers: QuestionnaireAnswers = {
      system_name: systemName.trim() || "Agentic AI System",
      purpose: "task_automation",
      purpose_details: `[Dev Mode Specification] ${archNotes.trim()} | Active Controls: [${activeControls.join(", ") || "NONE"}]`,
      scenarios: [
        `Primary topology: ${primaryPattern} with composite patterns [${orderedPatterns.join(", ")}]`,
        `Human-in-the-loop governance: ${oversight}; Exposure: ${audience}; Active Controls: ${activeControls.length}`,
      ],
      collaboration:
        primaryPattern === "SEQUENTIAL"
          ? "pipeline"
          : primaryPattern === "PARALLEL"
            ? "parallel"
            : primaryPattern === "COORDINATOR" || primaryPattern === "HIERARCHICAL"
              ? "manager"
              : primaryPattern === "SWARM"
                ? "team_chat"
                : "alone",
      autonomy:
        oversight === "full"
          ? "approval_required"
          : oversight === "partial"
            ? "partial_auto"
            : "full_auto",
      resources,
      audience,
      sensitive_data: sensitiveData,
    };

    const detection: PatternDetection = {
      primary_pattern: primaryPattern,
      patterns: orderedPatterns,
      human_oversight: oversight,
      is_multi_agent: ["SEQUENTIAL", "PARALLEL", "COORDINATOR", "HIERARCHICAL", "SWARM"].includes(
        primaryPattern,
      ),
      confidence: 1.0,
      rationale: `Explicit Dev Mode architecture: primary=${primaryPattern}, composite=[${orderedPatterns.join(", ")}], oversight=${oversight}, exposure=${audience}, controls=[${activeControls.join(", ")}]. Automatically mapped to OWASP LLM Top 10 (2025), OWASP Agentic AI Threats, and NIST AI RMF 1.0.`,
      plain_summary: `${PATTERN_DISPLAY_INFO[primaryPattern].friendlyName} (${PATTERN_DISPLAY_INFO[primaryPattern].googleCloudName}).`,
      source: "rules",
    };

    const finalReport = buildRiskReport(detection, syntheticAnswers, activeControls);
    setAcademicReport(finalReport);
    await onReportGenerated(finalReport);
  }

  async function submitNodeAssessment(request: AssessmentRequest): Promise<void> {
    const response = await fetch(`${apiBaseUrl}/api/v1/assess`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!response.ok) {
      throw new Error(`Node assessment failed (${response.status}).`);
    }
    const result = (await response.json()) as AssessmentResponse;
    setNodeAssessment(result);
  }

  const allControls = Object.values(TECHNICAL_CONTROLS);

  // Derive unique OWASP and NIST standards triggered across evaluated risks
  const derivedOwaspStandards = academicReport
    ? [...new Set(academicReport.risks.flatMap((r) => r.technical.owasp))]
    : [];
  const derivedNistSubcategories = academicReport
    ? [...new Set(academicReport.risks.flatMap((r) => r.technical.nist))]
    : [];

  return (
    <div className="dev-workbench">
      <div className="dev-workbench__tabs" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={subTab === "pattern"}
          className={`seg-btn${subTab === "pattern" ? " seg-btn--active" : ""}`}
          onClick={() => setSubTab("pattern")}
        >
          01 ·{" "}
          {isEn
            ? "Agentic Pattern & Security Controls Specification"
            : "Đặc tả Kiến trúc Agentic Pattern & Kiểm soát Kỹ thuật"}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={subTab === "nodes"}
          className={`seg-btn${subTab === "nodes" ? " seg-btn--active" : ""}`}
          onClick={() => setSubTab("nodes")}
        >
          02 ·{" "}
          {isEn
            ? "Component Node Knowledge Base (/api/v1/assess)"
            : "Đánh giá theo Node Kiến trúc & Controls (/api/v1/assess)"}
        </button>
      </div>

      {subTab === "nodes" ? (
        <div className="app-layout">
          <ArchitectureInput apiBaseUrl={apiBaseUrl} onAssess={submitNodeAssessment} />
          <RiskDashboard assessment={nodeAssessment} />
        </div>
      ) : (
        <div className="dev-workbench__grid">
          <form className="wizard dev-form" onSubmit={(e) => void runAcademicEvaluation(e)}>
            <header className="dev-form__header">
              <h2>
                {isEn
                  ? "1. Agentic Architecture & Technical Controls Input"
                  : "1. Khai báo Kiến trúc Agentic AI & Các Biện pháp Kiểm soát Kỹ thuật"}
              </h2>
              <p className="wizard__helper">
                {isEn
                  ? "Specify the target system's Google Cloud Agentic AI design patterns, data/tool boundaries, and deployed security controls. The engine automatically derives OWASP LLM Top 10 (2025), OWASP Agentic AI, and NIST AI RMF 1.0 mappings."
                  : "Khai báo mẫu thiết kế Agentic AI (theo chuẩn Google Cloud), luồng dữ liệu/công cụ và các biện pháp kiểm soát bảo mật đã triển khai. Hệ thống sẽ tự động suy diễn và ánh xạ sang tiêu chuẩn OWASP LLM Top 10 (2025), OWASP Agentic AI và NIST AI RMF 1.0."}
              </p>
            </header>

            <div className="dev-form__two-col">
              <label>
                <span>
                  {isEn ? "Target System Identifier" : "Tên định danh hệ thống (Target System)"}
                </span>
                <input
                  type="text"
                  className="wizard__text-input"
                  value={systemName}
                  onChange={(e) => setSystemName(e.target.value)}
                  required
                />
              </label>

              <label>
                <span>
                  {isEn
                    ? "Primary Agentic Design Pattern (Google Cloud)"
                    : "Mẫu kiến trúc chính (Primary Google Cloud Pattern)"}
                </span>
                <select
                  value={primaryPattern}
                  onChange={(e) =>
                    setPrimaryPattern(
                      e.target.value as Exclude<AgenticPattern, "HUMAN_IN_THE_LOOP">,
                    )
                  }
                >
                  {PRIMARY_PATTERNS.map((pat) => (
                    <option key={pat} value={pat}>
                      {pat} — {PATTERN_DISPLAY_INFO[pat].googleCloudName}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            <label>
              <span>
                {isEn
                  ? "Formal Architecture, Inter-Agent Topology & Trust Boundaries"
                  : "Đặc tả chi tiết kiến trúc, giao thức liên-agent & ranh giới tin cậy (Trust Boundaries)"}
              </span>
              <textarea
                rows={3}
                value={archNotes}
                onChange={(e) => setArchNotes(e.target.value)}
              />
            </label>

            <fieldset className="dev-fieldset">
              <legend>
                {isEn
                  ? "Secondary / Composite Agentic Patterns"
                  : "Các mẫu hình kết hợp trong hệ thống (Composite Agentic Patterns)"}
              </legend>
              <div className="dev-check-grid">
                {(
                  [
                    "REACT",
                    "SEQUENTIAL",
                    "PARALLEL",
                    "COORDINATOR",
                    "HIERARCHICAL",
                    "SWARM",
                    "HUMAN_IN_THE_LOOP",
                  ] as AgenticPattern[]
                ).map((pat) => (
                  <label key={pat} className="dev-check-item">
                    <input
                      type="checkbox"
                      checked={secondaryPatterns.includes(pat)}
                      onChange={() =>
                        toggleArrayItem(secondaryPatterns, pat, setSecondaryPatterns)
                      }
                    />
                    <span>
                      <code>{pat}</code> — {PATTERN_DISPLAY_INFO[pat].friendlyName}
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>

            <div className="dev-form__two-col">
              <label>
                <span>
                  {isEn
                    ? "Human-in-the-Loop (HITL) Checkpoint Policy"
                    : "Cơ chế kiểm duyệt con người (HITL Checkpoint Policy)"}
                </span>
                <select
                  value={oversight}
                  onChange={(e) => setOversight(e.target.value as HumanOversight)}
                >
                  <option value="none">none — Autonomous execution (ΔL_action = +1)</option>
                  <option value="partial">
                    partial — Checkpoint on high-impact actions (ΔL_action = -1)
                  </option>
                  <option value="full">
                    full — Mandatory approval per action (ΔL_action = -2)
                  </option>
                </select>
              </label>

              <label>
                <span>
                  {isEn
                    ? "Attack Surface / Network Exposure"
                    : "Phơi nhiễm bề mặt tấn công (Network Exposure)"}
                </span>
                <select
                  value={audience}
                  onChange={(e) => setAudience(e.target.value as Audience)}
                >
                  <option value="public">
                    Public / Untrusted External Users (ΔL_exposure = +1)
                  </option>
                  <option value="internal">
                    Internal Authenticated Network (ΔL_exposure = 0)
                  </option>
                </select>
              </label>
            </div>

            <div className="dev-form__two-col">
              <fieldset className="dev-fieldset">
                <legend>
                  {isEn
                    ? "Connected Tooling & Retrieval Corpora (RAG / MCP)"
                    : "Kết nối Công cụ & Nguồn tri thức (RAG / Vector DB / MCP)"}
                </legend>
                {(
                  [
                    ["internal_docs", "Internal Vector DB / RAG Corpus"],
                    ["web_search", "Untrusted Web Search / Grounding"],
                    ["external_tools", "External Tool Invocation (MCP / Function Calling)"],
                    ["company_data", "Enterprise Transactional DB (Read/Write)"],
                  ] as Array<[Resource, string]>
                ).map(([val, label]) => (
                  <label key={val} className="dev-check-item">
                    <input
                      type="checkbox"
                      checked={resources.includes(val)}
                      onChange={() => toggleArrayItem(resources, val, setResources)}
                    />
                    <span>
                      <code>{val}</code> — {label}
                    </span>
                  </label>
                ))}
              </fieldset>

              <fieldset className="dev-fieldset">
                <legend>
                  {isEn
                    ? "Data Sensitivity Classification"
                    : "Phân loại Độ nhạy cảm Dữ liệu (Data Classification)"}
                </legend>
                {(
                  [
                    ["personal", "PII / Personal Identifiable Data (ΔI_leak = +1)"],
                    ["financial", "PCI / Financial & Payment Ledger (ΔI_action = +1)"],
                    ["confidential", "Proprietary IP / Trade Secrets (ΔI_leak = +1)"],
                  ] as Array<[SensitiveData, string]>
                ).map(([val, label]) => (
                  <label key={val} className="dev-check-item">
                    <input
                      type="checkbox"
                      checked={sensitiveData.includes(val)}
                      onChange={() => toggleArrayItem(sensitiveData, val, setSensitiveData)}
                    />
                    <span>
                      <code>{val}</code> — {label}
                    </span>
                  </label>
                ))}
              </fieldset>
            </div>

            <fieldset className="dev-fieldset">
              <legend>
                {isEn
                  ? `Deployed Technical Security Controls (${activeControls.length}/${allControls.length} selected — Discount Cap 80%)`
                  : `Các Biện pháp Kiểm soát Kỹ thuật đã triển khai (${activeControls.length}/${allControls.length} đang bật — Trần giảm thiểu 80%)`}
              </legend>
              <div className="dev-controls-grid">
                {allControls.map((ctrl) => {
                  const checked = activeControls.includes(ctrl.id);
                  return (
                    <label
                      key={ctrl.id}
                      className={`dev-control-card${checked ? " dev-control-card--active" : ""}`}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() =>
                          toggleArrayItem(activeControls, ctrl.id, setActiveControls)
                        }
                      />
                      <div>
                        <div className="dev-control-card__top">
                          <code>{ctrl.id}</code>
                          <span className="pattern-pill">
                            w = {(ctrl.weight * 100).toFixed(0)}%
                          </span>
                        </div>
                        <strong>{ctrl.name}</strong>
                        <small>{ctrl.description}</small>
                      </div>
                    </label>
                  );
                })}
              </div>
            </fieldset>

            <div className="wizard__nav">
              <span className="dev-formula-hint">
                Model:{" "}
                <code>
                  L_final = max(1, round(L_context × (1 - min(0.80, Σ w_applied)))), R_residual = L_final × I_context
                </code>
              </span>
              <button type="submit">
                {isEn
                  ? "Derive OWASP / NIST Mappings & Compute Risk →"
                  : "Suy diễn ánh xạ OWASP / NIST & Tính điểm định lượng →"}
              </button>
            </div>
          </form>

          {academicReport && (
            <section className="report dev-academic-report" aria-live="polite">
              <header className="report__header">
                <div>
                  <span className="report__pattern-eyebrow">
                    Academic &amp; Normative Security Evaluation (OWASP LLM 2025 · NIST AI RMF 1.0)
                  </span>
                  <h2>{academicReport.answers.system_name}</h2>
                </div>
                <span
                  className="severity-badge"
                  style={{
                    backgroundColor: SEVERITY_COLORS[academicReport.overallSeverity],
                    color: "#fff",
                  }}
                >
                  Max Residual: {academicReport.overallScore}/25 ({academicReport.overallSeverity})
                </span>
              </header>

              <div className="dev-academic-meta">
                <div>
                  <strong>Primary Agentic Pattern:</strong>{" "}
                  <code>{academicReport.detection.primary_pattern}</code> —{" "}
                  {academicReport.primaryPatternInfo.googleCloudName}
                </div>
                <div>
                  <strong>Composite Pattern Vector:</strong>{" "}
                  <code>[{academicReport.detection.patterns.join(", ")}]</code>
                </div>
                <div>
                  <strong>Derived OWASP Standards Triggered ({derivedOwaspStandards.length}):</strong>{" "}
                  {derivedOwaspStandards.map((std) => (
                    <span key={std} className="std-tag">
                      {std}
                    </span>
                  ))}
                </div>
                <div>
                  <strong>Derived NIST AI RMF 1.0 Subcategories ({derivedNistSubcategories.length}):</strong>{" "}
                  {derivedNistSubcategories.map((sub) => (
                    <span key={sub} className="std-tag std-tag--nist">
                      {sub}
                    </span>
                  ))}
                </div>
              </div>

              <div className="dev-matrix-and-stats">
                <RiskDashboard
                  assessment={{
                    results: academicReport.risks.map((r) => ({
                      source_component: r.technical.triggeredBy.join(", "),
                      risk_id: r.id,
                      risk_name: `${r.technical.name} (${r.title})`,
                      nist_categories: r.technical.nist,
                      attack_scenario: `${r.explanation} [OWASP: ${r.technical.owasp.join(", ")}]`,
                      inherent_score: r.technical.baseScore,
                      residual_likelihood: r.likelihood,
                      residual_impact: r.impact,
                      residual_score: r.score,
                      severity_level: r.severity,
                      recommended_action: r.recommendations[0] ?? "",
                      missing_mitigations: r.technical.missingControlIds.map(
                        (cid) =>
                          `[${cid}] ${TECHNICAL_CONTROLS[cid]?.name ?? cid} (w=${((TECHNICAL_CONTROLS[cid]?.weight ?? 0) * 100).toFixed(0)}%)`,
                      ),
                    })),
                    overall_risk_score: academicReport.overallScore,
                    overall_severity: academicReport.overallSeverity,
                    risk_matrix_summary: buildMatrixFromRisks(academicReport.risks),
                  }}
                />
              </div>

              <div className="report__technical">
                <h3>
                  {isEn
                    ? "Normative Traceability Matrix: Agentic Pattern → OWASP LLM / NIST AI RMF → Residual Score"
                    : "Ma trận Truy vết Học thuật: Agentic Pattern → Tiêu chuẩn OWASP / NIST → Điểm Rủi ro Còn lại"}
                </h3>
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Risk Vector</th>
                      <th scope="col">Pattern / Resource Trigger</th>
                      <th scope="col">Inherent → Context → Residual</th>
                      <th scope="col">OWASP LLM / Agentic Mapping</th>
                      <th scope="col">NIST AI RMF 1.0</th>
                      <th scope="col">Control Coverage (Applied / Missing)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {academicReport.risks.map((risk) => (
                      <tr key={risk.id}>
                        <td>
                          <code>{risk.id}</code>
                          <br />
                          <strong>{risk.technical.name}</strong>
                          <br />
                          <small>{risk.title}</small>
                        </td>
                        <td>
                          {risk.technical.triggeredBy.map((src) => (
                            <div key={src}>
                              <code>{src}</code>
                            </div>
                          ))}
                        </td>
                        <td>
                          <div>
                            Inherent: <code>L₀={risk.technical.baseLikelihood} × I₀={risk.technical.baseImpact} = {risk.technical.baseScore}</code>
                          </div>
                          <div>
                            Context: <code>L_ctx={risk.technical.contextLikelihood}, W={(risk.technical.discountWeight * 100).toFixed(0)}%</code>
                          </div>
                          <div>
                            <strong>
                              Residual: L={risk.likelihood} × I={risk.impact} = {risk.score}/25 ({risk.severity})
                            </strong>
                          </div>
                        </td>
                        <td>
                          {risk.technical.owasp.map((item) => (
                            <div key={item}>
                              <span className="std-tag">{item}</span>
                            </div>
                          ))}
                        </td>
                        <td>
                          {risk.technical.nist.map((item) => (
                            <span key={item} className="std-tag std-tag--nist">
                              {item}
                            </span>
                          ))}
                        </td>
                        <td>
                          {risk.technical.appliedControlIds.length > 0 && (
                            <div>
                              <strong>Applied:</strong>{" "}
                              {risk.technical.appliedControlIds.map((id) => (
                                <code key={id} className="ctrl-applied">
                                  ✓ {id}
                                </code>
                              ))}
                            </div>
                          )}
                          {risk.technical.missingControlIds.length > 0 ? (
                            <div>
                              <strong>Missing:</strong>{" "}
                              {risk.technical.missingControlIds.map((id) => (
                                <code key={id} className="ctrl-missing">
                                  ! {id}
                                </code>
                              ))}
                            </div>
                          ) : (
                            <small>All mapped controls applied</small>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </div>
      )}
    </div>
  );
}
