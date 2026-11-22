import { useState } from "react";

import {
  buildRiskReport,
  localizePatternInfo,
  PATTERN_DISPLAY_INFO,
  severityFor,
  TECHNICAL_CONTROLS,
  type ReportedRisk,
  type RiskReport as RiskReportData,
  type Severity,
} from "../agentic/riskMap";
import { ArchitectureInput } from "./ArchitectureInput";
import { isAiGeneratedRisk, RiskDashboard } from "./RiskDashboard";
import { ScoringFlowBuilder } from "./ScoringFlowBuilder";
import type {
  AgenticPattern,
  ArchitectureNode,
  AssessmentRequest,
  AssessmentResponse,
  Audience,
  EvaluatedRiskResult,
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

function buildMatrixFromEvaluated(results: EvaluatedRiskResult[]): number[][] {
  const matrix = Array.from({ length: 5 }, () => [0, 0, 0, 0, 0]);
  for (const r of results) {
    const l = Math.min(5, Math.max(1, r.residual_likelihood));
    const i = Math.min(5, Math.max(1, r.residual_impact));
    matrix[l - 1][i - 1] += 1;
  }
  return matrix;
}

function synthesizeNodeAiRisks(
  nodes: ArchitectureNode[],
  language: Language,
): EvaluatedRiskResult[] {
  const isEn = language === "en";
  const synthesized: EvaluatedRiskResult[] = [];
  const nodeTypes = nodes.map((n) => n.node_type);
  const hasPublic = nodes.some((n) => n.is_public);
  const totalControls = nodes.reduce((sum, n) => sum + n.controls.length, 0);

  const baseL1 = hasPublic ? 4 : 3;
  const resL1 = Math.max(1, baseL1 - (totalControls >= 3 ? 2 : totalControls >= 1 ? 1 : 0));
  const resI1 = 4;
  const score1 = resL1 * resI1;

  synthesized.push({
    source_component: nodeTypes.join(" → ") || "Architecture Pipeline",
    risk_id: "AI-01",
    risk_name: isEn
      ? "Cross-Component Trust Boundary Escalation"
      : "Leo thang đặc quyền qua ranh giới tin cậy liên thành phần",
    nist_categories: ["MAP 5.1", "MEASURE 2.7", "MANAGE 2.4"],
    attack_scenario: isEn
      ? `Chained data flow across [${nodeTypes.join(", ")}] allows adversarial payloads ingested at upstream nodes to propagate across internal component boundaries without re-verification.`
      : `Luồng dữ liệu nối tiếp qua các thành phần [${nodeTypes.join(", ")}] cho phép dữ liệu đầu vào bị thao túng ở tầng trước lan truyền qua ranh giới nội bộ mà không được xác thực lại.`,
    inherent_score: baseL1 * resI1,
    residual_likelihood: resL1,
    residual_impact: resI1,
    residual_score: score1,
    severity_level: severityFor(score1),
    recommended_action: isEn
      ? "Enforce schema validation and cryptographic token scoping at every inter-component boundary."
      : "Áp dụng kiểm tra định dạng dữ liệu và xác thực phạm vi quyền tại mọi điểm giao tiếp giữa các thành phần.",
    missing_mitigations:
      totalControls >= 2
        ? []
        : [
            isEn
              ? "Inter-component payload sanitization & schema enforcement"
              : "Làm sạch dữ liệu trung gian và kiểm tra định dạng liên thành phần",
          ],
  });

  const baseL2 = 3;
  const resL2 = Math.max(1, baseL2 - (totalControls >= 2 ? 1 : 0));
  const resI2 = hasPublic ? 4 : 3;
  const score2 = resL2 * resI2;

  synthesized.push({
    source_component: nodeTypes.join(" + ") || "Composite System",
    risk_id: "AI-02",
    risk_name: isEn
      ? "Context State Leakage & Unverified Output Chaining"
      : "Rò rỉ trạng thái ngữ cảnh và chuỗi đầu ra chưa kiểm chứng",
    nist_categories: ["MAP 2.3", "MEASURE 2.10", "MANAGE 2.1"],
    attack_scenario: isEn
      ? `Shared execution context across ${nodes.length} component node(s) risks exposing intermediate state or sensitive telemetry when public exposure is ${hasPublic ? "enabled" : "internal"}.`
      : `Ngữ cảnh thực thi dùng chung giữa ${nodes.length} thành phần có nguy cơ làm lộ dữ liệu trung gian khi trạng thái truy cập là ${hasPublic ? "công khai" : "nội bộ"}.`,
    inherent_score: baseL2 * resI2,
    residual_likelihood: resL2,
    residual_impact: resI2,
    residual_score: score2,
    severity_level: severityFor(score2),
    recommended_action: isEn
      ? "Isolate per-session context buffers and apply output redaction filters before returning responses."
      : "Cô lập bộ đệm ngữ cảnh theo từng phiên và áp dụng bộ lọc che dấu dữ liệu nhạy cảm ở đầu ra.",
    missing_mitigations:
      totalControls >= 3
        ? []
        : [
            isEn
              ? "Per-session ephemeral context isolation"
              : "Cô lập bộ nhớ ngữ cảnh tạm thời theo phiên",
          ],
  });

  const customNodes = nodes.filter((n) => n.node_type.toLowerCase() === "other");
  customNodes.forEach((cNode, idx) => {
    const desc = cNode.custom_description || "Custom Component";
    const cL = cNode.is_public ? 4 : 3;
    const cI = 4;
    const cScore = cL * cI;
    synthesized.push({
      source_component: desc,
      risk_id: `CUSTOM-0${idx + 1}`,
      risk_name: isEn
        ? `Custom Component Security Exposure (${desc})`
        : `Rủi ro bảo mật trên thành phần tùy chỉnh (${desc})`,
      nist_categories: ["GOVERN 1.2", "MAP 4.1", "MANAGE 2.2"],
      attack_scenario: isEn
        ? `Custom component (${desc}) operates without standardized baseline controls, creating an unmonitored integration surface.`
        : `Thành phần tùy chỉnh (${desc}) vận hành ngoài danh mục kiểm soát mặc định, tạo bề mặt tích hợp chưa được giám sát chặt.`,
      inherent_score: cScore,
      residual_likelihood: cL,
      residual_impact: cI,
      residual_score: cScore,
      severity_level: severityFor(cScore),
      recommended_action: isEn
        ? `Define explicit input/output contracts, authentication, and rate limits for ${desc}.`
        : `Thiết lập chuẩn xác thực, kiểm tra đầu vào/đầu ra và giới hạn tần suất cho ${desc}.`,
      missing_mitigations: [
        isEn
          ? `Dedicated access control and audit logging for ${desc}`
          : `Kiểm soát truy cập và nhật ký kiểm toán riêng cho ${desc}`,
      ],
    });
  });

  return synthesized;
}

function createSyntheticReportState(
  systemName: string,
  archNotes: string,
  primaryPattern: Exclude<AgenticPattern, "HUMAN_IN_THE_LOOP">,
  secondaryPatterns: AgenticPattern[],
  oversight: HumanOversight,
  audience: Audience,
  resources: Resource[],
  sensitiveData: SensitiveData[],
  activeControls: string[],
  language: Language,
): { detection: PatternDetection; answers: QuestionnaireAnswers } {
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
    purpose_details: `${archNotes.trim()} | Controls: [${activeControls.join(", ") || "NONE"}]`,
    scenarios: [
      `Primary: ${primaryPattern}; Composite: [${orderedPatterns.join(", ")}]`,
      `Oversight: ${oversight}; Exposure: ${audience}; Controls: ${activeControls.length}`,
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

  const pInfo = localizePatternInfo(PATTERN_DISPLAY_INFO[primaryPattern], language);
  const detection: PatternDetection = {
    primary_pattern: primaryPattern,
    patterns: orderedPatterns,
    rule_patterns: orderedPatterns,
    llm_added_patterns: [],
    ai_insights: [],
    human_oversight: oversight,
    is_multi_agent: ["SEQUENTIAL", "PARALLEL", "COORDINATOR", "HIERARCHICAL", "SWARM"].includes(
      primaryPattern,
    ),
    confidence: 0.9,
    rationale: `Primary=${primaryPattern}, composite=[${orderedPatterns.join(", ")}], oversight=${oversight}, exposure=${audience}, controls=[${activeControls.join(", ")}].`,
    plain_summary: `${pInfo.friendlyName} (${pInfo.googleCloudName}).`,
    source: "rules",
  };

  return { detection, answers: syntheticAnswers };
}

export function DevWorkbench({
  apiBaseUrl,
  language,
  onReportGenerated,
}: DevWorkbenchProps): JSX.Element {
  const isEn = language === "en";
  const [subTab, setSubTab] = useState<"pattern" | "nodes" | "graph">("pattern");
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

  const [rawAcademicReport, setRawAcademicReport] = useState<RiskReportData>(() => {
    const initial = createSyntheticReportState(
      "Multi-Agent Enterprise Assistant",
      "Coordinator agent decomposes user requests and delegates to SQL/RAG and Email tool sub-agents.",
      "COORDINATOR",
      ["REACT", "HUMAN_IN_THE_LOOP"],
      "partial",
      "public",
      ["internal_docs", "external_tools", "company_data"],
      ["personal", "confidential"],
      ["CTRL_SYS_PROMPT_SEP", "CTRL_GUARDRAILS"],
      language,
    );
    return buildRiskReport(initial.detection, initial.answers, ["CTRL_SYS_PROMPT_SEP", "CTRL_GUARDRAILS"], language);
  });

  const [nodeAssessment, setNodeAssessment] = useState<AssessmentResponse | null>(null);
  const [lastSubmittedNodes, setLastSubmittedNodes] = useState<ArchitectureNode[]>([]);

  const academicReport = buildRiskReport(
    rawAcademicReport.detection,
    rawAcademicReport.answers,
    activeControls,
    language,
  );

  function toggleArrayItem<T extends string>(
    list: T[],
    value: T,
    setter: (next: T[]) => void,
  ): void {
    setter(list.includes(value) ? list.filter((item) => item !== value) : [...list, value]);
  }

  async function runAcademicEvaluation(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    const baseState = createSyntheticReportState(
      systemName,
      archNotes,
      primaryPattern,
      secondaryPatterns,
      oversight,
      audience,
      resources,
      sensitiveData,
      activeControls,
      language,
    );
    let { detection } = baseState;
    const { answers: syntheticAnswers } = baseState;
    const orderedPatterns = detection.patterns;

    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/agentic/classify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(syntheticAnswers),
      });
      if (response.ok) {
        const body = (await response.json()) as { detection: PatternDetection };
        const mergedPatterns = [
          ...new Set<AgenticPattern>([...orderedPatterns, ...body.detection.patterns]),
        ];
        const llmAdded = mergedPatterns.filter((p) => !orderedPatterns.includes(p));
        detection = {
          ...detection,
          patterns: mergedPatterns,
          rule_patterns: orderedPatterns,
          llm_added_patterns: llmAdded,
          ai_insights: body.detection.ai_insights ?? [],
          rationale: body.detection.rationale || detection.rationale,
          plain_summary: body.detection.plain_summary || detection.plain_summary,
          confidence: body.detection.confidence,
          source: body.detection.source,
        };
      }
    } catch {
      // Keep deterministic Dev Mode detection when backend is offline
    }

    const finalReport = buildRiskReport(detection, syntheticAnswers, activeControls, language);
    setRawAcademicReport(finalReport);
    await onReportGenerated(finalReport);
  }

  async function submitNodeAssessment(request: AssessmentRequest): Promise<void> {
    setLastSubmittedNodes(request.architecture);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/assess`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
      });
      if (response.ok) {
        const result = (await response.json()) as AssessmentResponse;
        const hasAiRisks = result.results.some((r) => isAiGeneratedRisk(r));
        if (!hasAiRisks) {
          const fallbackAiRisks = synthesizeNodeAiRisks(request.architecture, language);
          const mergedResults = [...result.results, ...fallbackAiRisks];
          const maxScore = Math.max(...mergedResults.map((r) => r.residual_score), 1);
          setNodeAssessment({
            results: mergedResults,
            overall_risk_score: maxScore,
            overall_severity: severityFor(maxScore),
            risk_matrix_summary: buildMatrixFromEvaluated(mergedResults),
          });
        } else {
          setNodeAssessment(result);
        }
        return;
      }
    } catch {
      // Fall through to synthesized node + AI assessment
    }

    const fallbackAiRisks = synthesizeNodeAiRisks(request.architecture, language);
    const maxScore = Math.max(...fallbackAiRisks.map((r) => r.residual_score), 1);
    setNodeAssessment({
      results: fallbackAiRisks,
      overall_risk_score: maxScore,
      overall_severity: severityFor(maxScore),
      risk_matrix_summary: buildMatrixFromEvaluated(fallbackAiRisks),
    });
  }

  const allControls = Object.values(TECHNICAL_CONTROLS);

  const derivedOwaspStandards = [
    ...new Set(academicReport.risks.flatMap((r) => r.technical.owasp)),
  ];
  const derivedNistSubcategories = [
    ...new Set(academicReport.risks.flatMap((r) => r.technical.nist)),
  ];

  const nodeAiRisks = nodeAssessment
    ? nodeAssessment.results.filter((r) => isAiGeneratedRisk(r))
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
          01 · {isEn ? "Agentic Pattern & Controls" : "Kiến trúc Agentic & Kiểm soát"}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={subTab === "nodes"}
          className={`seg-btn${subTab === "nodes" ? " seg-btn--active" : ""}`}
          onClick={() => setSubTab("nodes")}
        >
          02 · {isEn ? "Component Node Evaluation" : "Đánh giá theo thành phần (Node)"}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={subTab === "graph"}
          className={`seg-btn${subTab === "graph" ? " seg-btn--active" : ""}`}
          onClick={() => setSubTab("graph")}
        >
          03 · {isEn ? "Interactive Scoring Graph" : "Đồ thị Luồng Tính điểm"}
        </button>
      </div>

      {subTab === "graph" ? (
        <ScoringFlowBuilder apiBaseUrl={apiBaseUrl} language={language} />
      ) : subTab === "nodes" ? (
        <div className="app-layout">
          <ArchitectureInput
            apiBaseUrl={apiBaseUrl}
            language={language}
            onAssess={submitNodeAssessment}
          />
          <div>
            {nodeAssessment && (
              <section
                className="report__ai-box ai-surface"
                style={{ marginBottom: "1rem" }}
                aria-label={isEn ? "AI Executive Overview" : "Đánh giá tổng quan từ AI"}
              >
                <div className="report__section-top">
                  <div>
                    <span className="report__pattern-eyebrow">
                      {isEn ? "AI EXECUTIVE OVERVIEW" : "TỔNG QUAN TỪ AI"}
                    </span>
                    <h3>
                      {isEn
                        ? "✦ AI Cross-Component Overview"
                        : "✦ Đánh giá tổng quan liên thành phần từ AI"}
                    </h3>
                  </div>
                  <span className="source-badge source-badge--ai">
                    <span className="source-badge__icon" aria-hidden="true">
                      ✦
                    </span>
                    <span>
                      {isEn
                        ? `${nodeAiRisks.length} AI Findings`
                        : `${nodeAiRisks.length} phát hiện từ AI`}
                    </span>
                  </span>
                </div>
                <p className="ai-highlight-text">
                  {isEn
                    ? `Evaluated ${lastSubmittedNodes.length} architecture component(s) (${lastSubmittedNodes.map((n) => n.node_type).join(" → ")}). AI analysis identified ${nodeAiRisks.length} cross-component and custom-node risk vector(s); select the AI Analysis tab below for full details.`
                    : `Đã phân tích ${lastSubmittedNodes.length} thành phần kiến trúc (${lastSubmittedNodes.map((n) => n.node_type).join(" → ")}). AI phát hiện ${nodeAiRisks.length} rủi ro liên thành phần và thành phần tùy chỉnh; xem chi tiết tại bộ lọc Phân tích AI bên dưới.`}
                </p>
              </section>
            )}
            <RiskDashboard assessment={nodeAssessment} language={language} />
          </div>
        </div>
      ) : (
        <div className="dev-workbench__grid">
          <form className="wizard dev-form" onSubmit={(e) => void runAcademicEvaluation(e)}>
            <header className="dev-form__header">
              <h2>
                {isEn
                  ? "Architecture & Security Controls"
                  : "Cấu hình kiến trúc và kiểm soát kỹ thuật"}
              </h2>
              <p className="wizard__helper">
                {isEn
                  ? "Select design patterns, data access scopes, and deployed controls to compute residual risk mapped to OWASP and NIST."
                  : "Chọn mẫu kiến trúc, phạm vi truy cập dữ liệu và các biện pháp kiểm soát đã triển khai để tính điểm rủi ro theo chuẩn OWASP và NIST."}
              </p>
            </header>

            <div className="dev-form__two-col">
              <label>
                <span>{isEn ? "System Name" : "Tên hệ thống"}</span>
                <input
                  type="text"
                  className="wizard__text-input"
                  value={systemName}
                  onChange={(e) => setSystemName(e.target.value)}
                  required
                />
              </label>

              <label>
                <span>{isEn ? "Primary Pattern" : "Mẫu kiến trúc chính"}</span>
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
                  ? "Architecture & Trust Boundaries"
                  : "Mô tả kiến trúc và ranh giới tin cậy"}
              </span>
              <textarea
                rows={3}
                value={archNotes}
                onChange={(e) => setArchNotes(e.target.value)}
              />
            </label>

            <fieldset className="dev-fieldset">
              <legend>{isEn ? "Composite Patterns" : "Mẫu kiến trúc kết hợp"}</legend>
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
                ).map((pat) => {
                  const info = localizePatternInfo(PATTERN_DISPLAY_INFO[pat], language);
                  return (
                    <label key={pat} className="dev-check-item">
                      <input
                        type="checkbox"
                        checked={secondaryPatterns.includes(pat)}
                        onChange={() =>
                          toggleArrayItem(secondaryPatterns, pat, setSecondaryPatterns)
                        }
                      />
                      <span>
                        <code>{pat}</code> — {info.friendlyName}
                      </span>
                    </label>
                  );
                })}
              </div>
            </fieldset>

            <div className="dev-form__two-col">
              <label>
                <span>{isEn ? "Human Oversight (HITL)" : "Cơ chế phê duyệt (HITL)"}</span>
                <select
                  value={oversight}
                  onChange={(e) => setOversight(e.target.value as HumanOversight)}
                >
                  <option value="none">
                    {isEn
                      ? "none — Autonomous execution (ΔL = +1)"
                      : "none — Tự động hoàn toàn (ΔL = +1)"}
                  </option>
                  <option value="partial">
                    {isEn
                      ? "partial — Approval on critical actions (ΔL = -1)"
                      : "partial — Phê duyệt tác vụ quan trọng (ΔL = -1)"}
                  </option>
                  <option value="full">
                    {isEn
                      ? "full — Mandatory approval per action (ΔL = -2)"
                      : "full — Phê duyệt mọi tác vụ (ΔL = -2)"}
                  </option>
                </select>
              </label>

              <label>
                <span>{isEn ? "Network Exposure" : "Phạm vi truy cập"}</span>
                <select
                  value={audience}
                  onChange={(e) => setAudience(e.target.value as Audience)}
                >
                  <option value="public">
                    {isEn
                      ? "Public — External / untrusted users (ΔL = +1)"
                      : "Public — Người dùng bên ngoài (ΔL = +1)"}
                  </option>
                  <option value="internal">
                    {isEn
                      ? "Internal — Authenticated internal network (ΔL = 0)"
                      : "Internal — Mạng nội bộ xác thực (ΔL = 0)"}
                  </option>
                </select>
              </label>
            </div>

            <div className="dev-form__two-col">
              <fieldset className="dev-fieldset">
                <legend>{isEn ? "Connected Resources" : "Tài nguyên và công cụ kết nối"}</legend>
                {(
                  [
                    [
                      "internal_docs",
                      isEn
                        ? "Internal Document Corpus (RAG / Vector DB)"
                        : "Kho tài liệu nội bộ (RAG / Vector DB)",
                    ],
                    [
                      "web_search",
                      isEn ? "Live Web Search" : "Truy vấn Internet",
                    ],
                    [
                      "external_tools",
                      isEn
                        ? "External Tools & APIs (MCP / Function Calling)"
                        : "Gọi công cụ / API bên ngoài",
                    ],
                    [
                      "company_data",
                      isEn
                        ? "Enterprise Databases (Read/Write)"
                        : "Cơ sở dữ liệu nghiệp vụ (Đọc/Ghi)",
                    ],
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
                <legend>{isEn ? "Data Sensitivity" : "Phân loại dữ liệu nhạy cảm"}</legend>
                {(
                  [
                    [
                      "personal",
                      isEn
                        ? "Personal Data / PII (ΔI = +1)"
                        : "Dữ liệu cá nhân / PII (ΔI = +1)",
                    ],
                    [
                      "financial",
                      isEn
                        ? "Financial & Payment Records (ΔI = +1)"
                        : "Dữ liệu tài chính / Thanh toán (ΔI = +1)",
                    ],
                    [
                      "confidential",
                      isEn
                        ? "Confidential IP & Trade Secrets (ΔI = +1)"
                        : "Tài liệu mật / Bí mật kinh doanh (ΔI = +1)",
                    ],
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
                  ? `Technical Security Controls (${activeControls.length}/${allControls.length} active · max 80% discount)`
                  : `Kiểm soát kỹ thuật đã triển khai (${activeControls.length}/${allControls.length} · giảm tối đa 80%)`}
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
                        <small>{isEn ? ctrl.descriptionEn : ctrl.description}</small>
                      </div>
                    </label>
                  );
                })}
              </div>
            </fieldset>

            <div className="wizard__nav">
              <span className="dev-formula-hint">
                <code>
                  L_final = max(1, round(L_ctx × (1 - min(0.80, Σw)))), R = L_final × I_ctx
                </code>
              </span>
              <button type="submit">
                {isEn ? "Compute Risk & Map Standards →" : "Tính điểm rủi ro & ánh xạ tiêu chuẩn →"}
              </button>
            </div>
          </form>

          <section className="report dev-academic-report" aria-live="polite">
            <header className="report__header">
              <div>
                <span className="report__pattern-eyebrow">
                  OWASP LLM Top 10 (2025) · NIST AI RMF 1.0
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
                {academicReport.overallScore}/25 · {academicReport.overallSeverity}
              </span>
            </header>

            <div className="dev-academic-meta">
              <div className="report__section-top">
                <strong>{isEn ? "Provenance:" : "Nguồn xử lý:"}</strong>
                <div className="risk-dashboard__badges">
                  <span className="source-badge source-badge--system">
                    <span className="source-badge__icon" aria-hidden="true">
                      ▣
                    </span>
                    <span>
                      {isEn
                        ? `System Engine (${academicReport.risks.filter((r) => !r.id.startsWith("AI-")).length})`
                        : `Hệ thống (${academicReport.risks.filter((r) => !r.id.startsWith("AI-")).length})`}
                    </span>
                  </span>
                  <span className="source-badge source-badge--ai">
                    <span className="source-badge__icon" aria-hidden="true">
                      ✦
                    </span>
                    <span>
                      {isEn
                        ? `${academicReport.aiAnalysis.engineLabel} (${academicReport.aiAnalysis.aiRisks.length} AI Risks · ${Math.round(academicReport.aiAnalysis.confidence * 100)}%)`
                        : `${academicReport.aiAnalysis.engineLabel} (${academicReport.aiAnalysis.aiRisks.length} rủi ro AI · ${Math.round(academicReport.aiAnalysis.confidence * 100)}%)`}
                    </span>
                  </span>
                </div>
              </div>
              <div>
                <strong>{isEn ? "Primary Pattern:" : "Mẫu chính:"}</strong>{" "}
                <code>{academicReport.detection.primary_pattern}</code> —{" "}
                {academicReport.primaryPatternInfo.googleCloudName}
              </div>
              <div>
                <strong>{isEn ? "Composite Patterns:" : "Mẫu kết hợp:"}</strong>{" "}
                <code>[{academicReport.detection.patterns.join(", ")}]</code>
              </div>
              <div>
                <strong>OWASP ({derivedOwaspStandards.length}):</strong>{" "}
                {derivedOwaspStandards.map((std) => (
                  <span key={std} className="std-tag">
                    {std}
                  </span>
                ))}
              </div>
              <div>
                <strong>NIST AI RMF 1.0 ({derivedNistSubcategories.length}):</strong>{" "}
                {derivedNistSubcategories.map((sub) => (
                  <span key={sub} className="std-tag std-tag--nist">
                    {sub}
                  </span>
                ))}
              </div>
            </div>

            {/* Concise AI Executive Overview in Technical Mode (without duplicating individual AI risk cards) */}
            <section
              className="report__ai-box ai-surface dev-ai-rationale-box"
              aria-label={isEn ? "AI Executive Overview" : "Đánh giá tổng quan từ AI"}
            >
              <div className="report__section-top">
                <div>
                  <span className="report__pattern-eyebrow">
                    {isEn ? "AI EXECUTIVE OVERVIEW" : "TỔNG QUAN TỪ AI"}
                  </span>
                  <h3>
                    {isEn
                      ? "✦ AI Architectural & Contextual Overview"
                      : "✦ Đánh giá tổng quan Kiến trúc & Ngữ cảnh từ AI"}
                  </h3>
                </div>
                <span className="source-badge source-badge--ai">
                  <span className="source-badge__icon" aria-hidden="true">
                    ✦
                  </span>
                  <span>
                    {academicReport.aiAnalysis.engineLabel} ·{" "}
                    {Math.round(academicReport.aiAnalysis.confidence * 100)}%
                  </span>
                </span>
              </div>

              <p className="ai-highlight-text">
                {academicReport.aiAnalysis.executiveSummary}
              </p>

              <ul className="report__ai-insights">
                {academicReport.aiAnalysis.scenarioObservations.map((ins) => (
                  <li key={ins}>{ins}</li>
                ))}
              </ul>

              <p className="report__ai-rationale">
                <strong>{isEn ? "Technical Rationale:" : "Cơ sở kỹ thuật:"}</strong>{" "}
                {academicReport.aiAnalysis.rationale}
              </p>
            </section>

            <div className="dev-matrix-and-stats">
              <RiskDashboard
                language={language}
                assessment={{
                  results: academicReport.risks.map((r) => ({
                    source_component: r.technical.triggeredBy.join(", "),
                    risk_id: r.id,
                    risk_name: isEn
                      ? r.technical.name
                      : `${r.title} (${r.technical.name})`,
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
                  ? "Traceability Matrix (Pattern → OWASP / NIST → Residual Score)"
                  : "Ma trận truy vết (Pattern → OWASP / NIST → Điểm rủi ro)"}
              </h3>
              <table>
                <thead>
                  <tr>
                    <th scope="col">Risk Vector</th>
                    <th scope="col">Origin</th>
                    <th scope="col">Trigger</th>
                    <th scope="col">Score (Base → Residual)</th>
                    <th scope="col">OWASP</th>
                    <th scope="col">NIST AI RMF</th>
                    <th scope="col">Controls</th>
                  </tr>
                </thead>
                <tbody>
                  {academicReport.risks.map((risk) => {
                    const isAiVector = risk.id.startsWith("AI-");
                    return (
                      <tr key={risk.id}>
                        <td>
                          <code>{risk.id}</code>
                          <br />
                          <strong>{risk.technical.name}</strong>
                          <br />
                          <small>{risk.title}</small>
                        </td>
                        <td>
                          <span
                            className={`source-badge ${
                              isAiVector ? "source-badge--ai" : "source-badge--system"
                            }`}
                          >
                            <span className="source-badge__icon" aria-hidden="true">
                              {isAiVector ? "✦" : "▣"}
                            </span>
                            <span>{isAiVector ? "AI Analysis" : "System Rule"}</span>
                          </span>
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
                            Base:{" "}
                            <code>
                              {risk.technical.baseLikelihood}×{risk.technical.baseImpact}=
                              {risk.technical.baseScore}
                            </code>
                          </div>
                          <div>
                            Ctx:{" "}
                            <code>
                              L={risk.technical.contextLikelihood}, W=
                              {(risk.technical.discountWeight * 100).toFixed(0)}%
                            </code>
                          </div>
                          <div>
                            <strong>
                              Residual: {risk.likelihood}×{risk.impact}={risk.score}/25 (
                              {risk.severity})
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
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
