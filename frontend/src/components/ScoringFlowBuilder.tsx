import { useEffect, useMemo, useRef, useState } from "react";

import {
  BASELINE_RISKS,
  getSeverityLabel,
  PATTERN_DISPLAY_INFO,
  PATTERN_RISKS,
  RESOURCE_RISKS,
  severityFor,
  TECHNICAL_CONTROLS,
  type RiskKind,
  type RiskTemplate,
  type Severity,
} from "../agentic/riskMap";
import type { AgenticPattern, Language, Resource } from "../types";

interface ScoringFlowBuilderProps {
  apiBaseUrl: string;
  language: Language;
}

export type FlowLayer = 1 | 2 | 3;

export interface CustomRiskEmit {
  id: string;
  title: string;
  titleEn: string;
  kind: RiskKind;
  baseL: number;
  baseI: number;
  owasp: string[];
  nist: string[];
  applicableControls: string[];
}

export interface FlowNodeData {
  id: string;
  layer: FlowLayer;
  code: string;
  label: string;
  labelEn: string;
  subtitle: string;
  subtitleEn: string;
  isCustom?: boolean;
  aiSuggested?: boolean;
  emittedRisks?: CustomRiskEmit[];
  deltaL?: number;
  deltaI?: number;
  multL?: number;
  multI?: number;
  discountW?: number;
  controlDeltaI?: number;
  targetKinds?: RiskKind[] | "all";
  /** 2D World coordinates on the infinite canvas */
  x: number;
  y: number;
}

export interface FlowEdge {
  id: string;
  fromId: string;
  toId: string;
}

export interface ComputedRiskTrace {
  riskId: string;
  title: string;
  kind: RiskKind;
  owasp: string[];
  nist: string[];
  sourceNodes: FlowNodeData[];
  contextNodes: FlowNodeData[];
  controlNodes: FlowNodeData[];
  baseL: number;
  baseI: number;
  baseScore: number;
  sumDeltaL: number;
  sumDeltaI: number;
  ctxFormulaL: string;
  ctxFormulaI: string;
  ctxL: number;
  ctxI: number;
  ctxScore: number;
  rawDiscountW: number;
  cappedDiscountW: number;
  ctrlDeltaI: number;
  finalFormulaL: string;
  finalFormulaI: string;
  finalL: number;
  finalI: number;
  finalScore: number;
  severity: Severity;
  isAiGraphRisk?: boolean;
  aiSource?: "llm" | "fallback";
  aiRationale?: string;
}

interface GraphAiAnalysisState {
  source: "llm" | "fallback";
  executive_summary: string;
  ai_risks: Array<{
    risk_id: string;
    title: string;
    kind: RiskKind;
    base_l: number;
    base_i: number;
    final_l: number;
    final_i: number;
    owasp: string[];
    nist: string[];
    involved_node_ids: string[];
    rationale: string;
  }>;
}

const NODE_WIDTH = 290;
const PORT_OFFSET_Y = 72;
const LAYER_DEFAULT_X: Record<1 | 2 | 3 | 4, number> = {
  1: 60,
  2: 520,
  3: 980,
  4: 1460,
};

const SEVERITY_COLORS: Record<Severity, string> = {
  Low: "#15803d",
  Medium: "#b45309",
  High: "#c2410c",
  Critical: "#b91c1c",
};

const ALL_RISK_KINDS: RiskKind[] = [
  "injection",
  "action",
  "leak",
  "integrity",
  "control",
  "cost",
];

const clamp5 = (v: number): number => Math.min(5, Math.max(1, Math.round(v)));

function templateToEmit(t: RiskTemplate): CustomRiskEmit {
  return {
    id: t.id,
    title: t.title,
    titleEn: t.titleEn,
    kind: t.kind,
    baseL: t.likelihood,
    baseI: t.impact,
    owasp: t.technical.owasp,
    nist: t.technical.nist,
    applicableControls: t.technical.mitigationControlIds,
  };
}

function buildTemplateLibrary(): FlowNodeData[] {
  const templates: FlowNodeData[] = [];

  const patterns: AgenticPattern[] = [
    "SINGLE_AGENT",
    "REACT",
    "SEQUENTIAL",
    "PARALLEL",
    "COORDINATOR",
    "HIERARCHICAL",
    "SWARM",
    "HUMAN_IN_THE_LOOP",
  ];
  for (const pat of patterns) {
    const info = PATTERN_DISPLAY_INFO[pat];
    const emits = PATTERN_RISKS[pat].map(templateToEmit);
    templates.push({
      id: `TPL_PAT_${pat}`,
      layer: 1,
      code: pat,
      label: info.friendlyName,
      labelEn: info.friendlyNameEn,
      subtitle: `Mẫu kiến trúc · Kích hoạt ${emits.length} rủi ro`,
      subtitleEn: `Agentic Pattern · Emits ${emits.length} risk(s)`,
      emittedRisks: emits,
      x: LAYER_DEFAULT_X[1],
      y: 100,
    });
  }

  const resourceMeta: Array<{
    key: Resource;
    label: string;
    labelEn: string;
  }> = [
    {
      key: "internal_docs",
      label: "Kho tài liệu nội bộ (RAG / Vector DB)",
      labelEn: "Internal Document Corpus (RAG / Vector DB)",
    },
    {
      key: "web_search",
      label: "Truy vấn Internet (Live Web Search)",
      labelEn: "Live Web Search Grounding",
    },
    {
      key: "external_tools",
      label: "Công cụ & API bên ngoài (MCP / Function Calling)",
      labelEn: "External Tools & APIs (MCP / Function Calling)",
    },
    {
      key: "company_data",
      label: "Cơ sở dữ liệu nghiệp vụ (SQL / Enterprise DB)",
      labelEn: "Enterprise Database (Read/Write)",
    },
  ];

  for (const res of resourceMeta) {
    const emits = RESOURCE_RISKS[res.key].map(templateToEmit);
    templates.push({
      id: `TPL_RES_${res.key}`,
      layer: 1,
      code: `RES:${res.key}`,
      label: res.label,
      labelEn: res.labelEn,
      subtitle: `Tài nguyên kết nối · Kích hoạt ${emits.length} rủi ro`,
      subtitleEn: `Connected Resource · Emits ${emits.length} risk(s)`,
      emittedRisks: emits,
      x: LAYER_DEFAULT_X[1],
      y: 100,
    });
  }

  templates.push({
    id: "TPL_BASE_LLM",
    layer: 1,
    code: "BASELINE:LLM",
    label: "Mô hình ngôn ngữ nền tảng (Core LLM)",
    labelEn: "Foundation LLM Baseline",
    subtitle: "Mặc định · Kích hoạt rủi ro ảo giác / sai lệch",
    subtitleEn: "Baseline · Emits Misinformation risk",
    emittedRisks: BASELINE_RISKS.map(templateToEmit),
    x: LAYER_DEFAULT_X[1],
    y: 100,
  });

  const contextTemplates: Array<Omit<FlowNodeData, "layer" | "x" | "y">> = [
    {
      id: "TPL_CTX_PUBLIC",
      code: "CTX:PUBLIC",
      label: "Mở công khai (Public Exposure)",
      labelEn: "Public Network Exposure",
      subtitle: "Tăng ΔL=+1 (Injection/Leak) & Sinh rủi ro kịch bản công khai (AI-01)",
      subtitleEn: "Adds ΔL=+1 (Injection/Leak) & Emits Public Scenario Risk (AI-01)",
      deltaL: 1,
      deltaI: 0,
      multL: 1,
      multI: 1,
      targetKinds: ["injection", "leak"],
      emittedRisks: [
        {
          id: "AI-01",
          title: "Thao túng ngữ cảnh theo kịch bản vận hành công khai",
          titleEn: "Public Scenario & Workflow Context Manipulation",
          kind: "injection",
          baseL: 3,
          baseI: 4,
          owasp: ["OWASP LLM01:2025 Prompt Injection", "OWASP Agentic AI: Goal Manipulation"],
          nist: ["MAP 5.1", "MEASURE 2.7"],
          applicableControls: ["CTRL_SYS_PROMPT_SEP", "CTRL_GUARDRAILS"],
        },
      ],
    },
    {
      id: "TPL_CTX_INTERNAL",
      code: "CTX:INTERNAL",
      label: "Mạng nội bộ xác thực (Internal Auth)",
      labelEn: "Authenticated Internal Network",
      subtitle: "Giữ nguyên khả năng xảy ra gốc (ΔL = 0)",
      subtitleEn: "Maintains baseline likelihood (ΔL = 0)",
      deltaL: 0,
      deltaI: 0,
      multL: 1,
      multI: 1,
      targetKinds: "all",
    },
    {
      id: "TPL_CTX_HITL_NONE",
      code: "CTX:HITL_NONE",
      label: "Tự động hoàn toàn (Full Autonomy)",
      labelEn: "Autonomous Execution (No HITL)",
      subtitle: "Tăng ΔL=+1 (Action) & Sinh rủi ro lệch hướng tự trị (AI-03)",
      subtitleEn: "Adds ΔL=+1 (Action) & Emits Autonomous Drift Risk (AI-03)",
      deltaL: 1,
      deltaI: 0,
      multL: 1,
      multI: 1,
      targetKinds: ["action"],
      emittedRisks: [
        {
          id: "AI-03",
          title: "Rủi ro lệch hướng quyết định tự trị và lỗ hổng giám sát",
          titleEn: "Autonomous Decision Drift & Governance Gap",
          kind: "control",
          baseL: 4,
          baseI: 4,
          owasp: ["OWASP LLM06:2025 Excessive Agency", "OWASP LLM10:2025 Unbounded Consumption"],
          nist: ["GOVERN 1.4", "MANAGE 4.1"],
          applicableControls: [
            "CTRL_DETERMINISTIC_ROUTER",
            "CTRL_SCOPED_DELEGATION",
            "CTRL_IMMUTABLE_TRACE_LOG",
          ],
        },
      ],
    },
    {
      id: "TPL_CTX_HITL_PARTIAL",
      code: "CTX:HITL_PARTIAL",
      label: "Phê duyệt tác vụ quan trọng (Partial HITL)",
      labelEn: "Partial Human-in-the-Loop Approval",
      subtitle: "Giảm ΔL=-1 (Action) & Sinh rủi ro quá tải phê duyệt (APPROVAL_FATIGUE)",
      subtitleEn: "Reduces ΔL=-1 (Action) & Emits HITL Approval Fatigue Risk",
      deltaL: -1,
      deltaI: 0,
      multL: 1,
      multI: 1,
      targetKinds: ["action"],
      emittedRisks: [
        {
          id: "APPROVAL_FATIGUE",
          title: "Giảm hiệu quả phê duyệt thủ công (Approval Fatigue)",
          titleEn: "Human-in-the-Loop Approval Fatigue",
          kind: "control",
          baseL: 3,
          baseI: 2,
          owasp: ["OWASP LLM09:2025 Misinformation (Overreliance)"],
          nist: ["GOVERN 3.2", "MANAGE 2.4"],
          applicableControls: ["CTRL_DETERMINISTIC_ROUTER"],
        },
      ],
    },
    {
      id: "TPL_CTX_HITL_FULL",
      code: "CTX:HITL_FULL",
      label: "Phê duyệt mọi tác vụ (Mandatory HITL)",
      labelEn: "Mandatory Human Approval per Action",
      subtitle: "Giảm ΔL=-2 (Action) & Sinh rủi ro quá tải phê duyệt (APPROVAL_FATIGUE)",
      subtitleEn: "Reduces ΔL=-2 (Action) & Emits HITL Approval Fatigue Risk",
      deltaL: -2,
      deltaI: 0,
      multL: 1,
      multI: 1,
      targetKinds: ["action"],
      emittedRisks: [
        {
          id: "APPROVAL_FATIGUE",
          title: "Giảm hiệu quả phê duyệt thủ công (Approval Fatigue)",
          titleEn: "Human-in-the-Loop Approval Fatigue",
          kind: "control",
          baseL: 4,
          baseI: 2,
          owasp: ["OWASP LLM09:2025 Misinformation (Overreliance)"],
          nist: ["GOVERN 3.2", "MANAGE 2.4"],
          applicableControls: ["CTRL_DETERMINISTIC_ROUTER"],
        },
      ],
    },
    {
      id: "TPL_CTX_DATA_PII",
      code: "CTX:PII_DATA",
      label: "Dữ liệu cá nhân / PII",
      labelEn: "Personal Data / PII Processing",
      subtitle: "Tăng ΔI=+1 (Leak) & Sinh rủi ro chuỗi liên kết dữ liệu (AI-02)",
      subtitleEn: "Adds ΔI=+1 (Leak) & Emits Cross-Boundary PII Risk (AI-02)",
      deltaL: 0,
      deltaI: 1,
      multL: 1,
      multI: 1,
      targetKinds: ["leak"],
      emittedRisks: [
        {
          id: "AI-02",
          title: "Rủi ro chuỗi liên kết dữ liệu nhạy cảm và công cụ liên thành phần",
          titleEn: "Cross-Boundary Sensitive Data & Tool Chaining Risk",
          kind: "leak",
          baseL: 3,
          baseI: 4,
          owasp: ["OWASP LLM02:2025 Sensitive Information Disclosure"],
          nist: ["MAP 2.3", "MEASURE 2.10"],
          applicableControls: ["CTRL_TOOL_ALLOWLIST", "CTRL_DLP_REDACTION", "CTRL_RAG_ACL"],
        },
      ],
    },
    {
      id: "TPL_CTX_DATA_FIN",
      code: "CTX:FINANCIAL",
      label: "Dữ liệu tài chính & Thanh toán",
      labelEn: "Financial & Payment Records",
      subtitle: "Tăng ΔI=+1 (Action/Leak) & Sinh rủi ro liên kết dữ liệu tài chính (AI-02)",
      subtitleEn: "Adds ΔI=+1 (Action/Leak) & Emits Financial Chaining Risk (AI-02)",
      deltaL: 0,
      deltaI: 1,
      multL: 1,
      multI: 1,
      targetKinds: ["action", "leak"],
      emittedRisks: [
        {
          id: "AI-02",
          title: "Rủi ro chuỗi liên kết dữ liệu nhạy cảm và công cụ liên thành phần",
          titleEn: "Cross-Boundary Sensitive Data & Tool Chaining Risk",
          kind: "leak",
          baseL: 3,
          baseI: 4,
          owasp: [
            "OWASP LLM02:2025 Sensitive Information Disclosure",
            "OWASP LLM06:2025 Excessive Agency",
          ],
          nist: ["MAP 2.3", "MANAGE 2.4"],
          applicableControls: ["CTRL_TOOL_ALLOWLIST", "CTRL_DLP_REDACTION", "CTRL_RAG_ACL"],
        },
      ],
    },
    {
      id: "TPL_CTX_EXT_INGEST",
      code: "CTX:UNTRUSTED_FEED",
      label: "Tiếp nhận tài liệu / Web bên ngoài",
      labelEn: "Untrusted External Document/Web Feed",
      subtitle: "Tăng 1 bậc khả năng xảy ra cho Action & Integrity",
      subtitleEn: "Increases Likelihood by 1 for Action & Integrity",
      deltaL: 1,
      deltaI: 0,
      multL: 1,
      multI: 1,
      targetKinds: ["action", "integrity"],
    },
  ];

  for (const ct of contextTemplates) {
    templates.push({
      ...ct,
      layer: 2,
      x: LAYER_DEFAULT_X[2],
      y: 100,
    });
  }

  // Built-in "No Control / Direct Pass-through" node in Layer 3 that also emits an Unmitigated Governance Gap risk
  templates.push({
    id: "TPL_CTRL_NONE",
    layer: 3,
    code: "CTRL_NONE_BYPASS",
    label: "Chưa áp dụng kiểm soát (Unmitigated Bypass)",
    labelEn: "No Security Control Applied (Unmitigated Pass-Through)",
    subtitle: "Không giảm trừ (w = 0%) & Phát sinh rủi ro thiếu chốt chặn kiểm soát",
    subtitleEn: "Zero discount (w = 0%) & Emits Unmitigated Control Gap risk",
    discountW: 0,
    controlDeltaI: 0,
    targetKinds: "all",
    x: LAYER_DEFAULT_X[3],
    y: 100,
    emittedRisks: [
      {
        id: "CTRL_GAP_EXPOSURE",
        title: "Thiếu hụt chốt chặn kiểm soát kỹ thuật trên luồng thực thi",
        titleEn: "Unmitigated Technical Control Gap in Execution Pipeline",
        kind: "control",
        baseL: 4,
        baseI: 4,
        owasp: ["OWASP LLM06:2025 Excessive Agency"],
        nist: ["GOVERN 1.4", "MANAGE 2.4"],
        applicableControls: ["CTRL_GUARDRAILS", "CTRL_TOOL_ALLOWLIST"],
      },
    ],
  });

  for (const ctrl of Object.values(TECHNICAL_CONTROLS)) {
    const extraEmit: CustomRiskEmit[] | undefined =
      ctrl.id === "CTRL_IMMUTABLE_TRACE_LOG"
        ? [
            {
              id: "LOG_PII_RETENTION",
              title: "Rủi ro lưu trữ lộ dữ liệu nhạy cảm trong nhật ký kiểm toán bất biến",
              titleEn: "Sensitive Data Retention in Immutable Telemetry Logs",
              kind: "leak",
              baseL: 2,
              baseI: 3,
              owasp: ["OWASP LLM02:2025 Sensitive Information Disclosure"],
              nist: ["MEASURE 2.10", "MANAGE 2.1"],
              applicableControls: ["CTRL_DLP_REDACTION"],
            },
          ]
        : undefined;
    templates.push({
      id: `TPL_CTRL_${ctrl.id}`,
      layer: 3,
      code: ctrl.id,
      label: ctrl.name,
      labelEn: ctrl.name,
      subtitle: ctrl.description,
      subtitleEn: ctrl.descriptionEn,
      discountW: ctrl.weight,
      controlDeltaI: 0,
      targetKinds: "all",
      emittedRisks: extraEmit,
      x: LAYER_DEFAULT_X[3],
      y: 100,
    });
  }

  return templates;
}

const TEMPLATE_LIBRARY = buildTemplateLibrary();

function createInitialPreset(): {
  nodes: FlowNodeData[];
  edges: FlowEdge[];
  layerHeaders: Record<1 | 2 | 3 | 4, { x: number; y: number }>;
} {
  const findTpl = (id: string): FlowNodeData => {
    const found = TEMPLATE_LIBRARY.find((t) => t.id === id);
    if (!found) throw new Error(`Missing template ${id}`);
    return { ...found };
  };

  const n1_react: FlowNodeData = {
    ...findTpl("TPL_PAT_REACT"),
    id: "L1_REACT",
    x: LAYER_DEFAULT_X[1],
    y: 110,
  };
  const n1_rag: FlowNodeData = {
    ...findTpl("TPL_RES_internal_docs"),
    id: "L1_RAG",
    x: LAYER_DEFAULT_X[1],
    y: 350,
  };

  const n2_pub: FlowNodeData = {
    ...findTpl("TPL_CTX_PUBLIC"),
    id: "L2_PUBLIC",
    x: LAYER_DEFAULT_X[2],
    y: 100,
  };
  const n2_hitl: FlowNodeData = {
    ...findTpl("TPL_CTX_HITL_PARTIAL"),
    id: "L2_HITL",
    x: LAYER_DEFAULT_X[2],
    y: 320,
  };
  const n2_fin: FlowNodeData = {
    ...findTpl("TPL_CTX_DATA_FIN"),
    id: "L2_FIN",
    x: LAYER_DEFAULT_X[2],
    y: 540,
  };

  const n3_guard: FlowNodeData = {
    ...findTpl("TPL_CTRL_CTRL_GUARDRAILS"),
    id: "L3_GUARD",
    x: LAYER_DEFAULT_X[3],
    y: 100,
  };
  const n3_allow: FlowNodeData = {
    ...findTpl("TPL_CTRL_CTRL_TOOL_ALLOWLIST"),
    id: "L3_ALLOW",
    x: LAYER_DEFAULT_X[3],
    y: 320,
  };
  const n3_acl: FlowNodeData = {
    ...findTpl("TPL_CTRL_CTRL_RAG_ACL"),
    id: "L3_ACL",
    x: LAYER_DEFAULT_X[3],
    y: 540,
  };

  const edges: FlowEdge[] = [
    { id: "e1", fromId: "L1_REACT", toId: "L2_PUBLIC" },
    { id: "e2", fromId: "L1_REACT", toId: "L2_HITL" },
    { id: "e3", fromId: "L1_RAG", toId: "L2_PUBLIC" },
    { id: "e4", fromId: "L1_RAG", toId: "L2_FIN" },
    { id: "e5", fromId: "L2_PUBLIC", toId: "L3_GUARD" },
    { id: "e6", fromId: "L2_HITL", toId: "L3_ALLOW" },
    { id: "e7", fromId: "L2_FIN", toId: "L3_ACL" },
  ];

  return {
    nodes: [n1_react, n1_rag, n2_pub, n2_hitl, n2_fin, n3_guard, n3_allow, n3_acl],
    edges,
    layerHeaders: {
      1: { x: LAYER_DEFAULT_X[1], y: 20 },
      2: { x: LAYER_DEFAULT_X[2], y: 20 },
      3: { x: LAYER_DEFAULT_X[3], y: 20 },
      4: { x: LAYER_DEFAULT_X[4], y: 20 },
    },
  };
}

function formatNodeFormulaBadge(node: FlowNodeData): string {
  const emitsCount = (node.emittedRisks ?? []).length;
  if (node.layer === 1) {
    const risks = node.emittedRisks ?? [];
    if (risks.length === 0) return "L0=1, I0=1";
    const maxL = Math.max(...risks.map((r) => r.baseL));
    const maxI = Math.max(...risks.map((r) => r.baseI));
    return `Emit ${risks.length} · max(L0=${maxL}, I0=${maxI})`;
  }
  if (node.layer === 2) {
    const parts: string[] = [];
    if (node.multL && node.multL !== 1) parts.push(`L×${node.multL}`);
    if (node.deltaL && node.deltaL !== 0) {
      parts.push(`ΔL=${node.deltaL > 0 ? `+${node.deltaL}` : node.deltaL}`);
    }
    if (node.multI && node.multI !== 1) parts.push(`I×${node.multI}`);
    if (node.deltaI && node.deltaI !== 0) {
      parts.push(`ΔI=${node.deltaI > 0 ? `+${node.deltaI}` : node.deltaI}`);
    }
    const baseText = parts.length > 0 ? parts.join(", ") : "ΔL=0, ΔI=0";
    return emitsCount > 0 ? `${baseText} · +Emit ${emitsCount}` : baseText;
  }
  const wPct = Math.round((node.discountW ?? 0) * 100);
  const di = node.controlDeltaI ?? 0;
  const ctrlText = di !== 0 ? `w = -${wPct}% L, ΔI = ${di}` : `w = -${wPct}% L`;
  return emitsCount > 0 ? `${ctrlText} · +Emit ${emitsCount}` : ctrlText;
}

export function ScoringFlowBuilder({
  apiBaseUrl,
  language,
}: ScoringFlowBuilderProps): JSX.Element {
  const isEn = language === "en";
  const initial = useMemo(() => createInitialPreset(), []);
  const [nodes, setNodes] = useState<FlowNodeData[]>(initial.nodes);
  const [edges, setEdges] = useState<FlowEdge[]>(initial.edges);
  const [layerHeaders, setLayerHeaders] = useState<
    Record<1 | 2 | 3 | 4, { x: number; y: number }>
  >(initial.layerHeaders);
  const [l4Positions, setL4Positions] = useState<Record<string, { x: number; y: number }>>({});

  // Infinite Canvas Viewport State (Pan & Zoom)
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 20, y: 15 });
  const [zoom, setZoom] = useState<number>(0.85);
  const [showAllWireFormulas, setShowAllWireFormulas] = useState<boolean>(false);

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [focusedRiskId, setFocusedRiskId] = useState<string | null>(null);
  const [paletteLayer, setPaletteLayer] = useState<FlowLayer>(1);
  const [showCustomModal, setShowCustomModal] = useState<boolean>(false);

  // Level 2: Click-to-Evaluate + Checkbox "Include Gemini AI in Evaluation"
  const [isEvaluated, setIsEvaluated] = useState<boolean>(false);
  const [useAiEvaluation, setUseAiEvaluation] = useState<boolean>(true);
  const [isEvaluatingGraph, setIsEvaluatingGraph] = useState<boolean>(false);
  const [graphAiResult, setGraphAiResult] = useState<GraphAiAnalysisState | null>(null);

  // Live Press-Hold-Drag Wire State
  const [activeWireDrag, setActiveWireDrag] = useState<{
    fromNodeId: string;
    startX: number;
    startY: number;
    currX: number;
    currY: number;
    hoveredTargetId: string | null;
  } | null>(null);

  const viewportRef = useRef<HTMLDivElement | null>(null);

  // Unified pointer interaction ref for Panning, Node Dragging, Layer Dragging, and Wire Dragging
  const interactionRef = useRef<
    | {
        mode: "pan";
        startClientX: number;
        startClientY: number;
        initialPanX: number;
        initialPanY: number;
      }
    | {
        mode: "drag-node";
        nodeId: string;
        startClientX: number;
        startClientY: number;
        initialX: number;
        initialY: number;
      }
    | {
        mode: "drag-l4";
        riskId: string;
        startClientX: number;
        startClientY: number;
        initialX: number;
        initialY: number;
      }
    | {
        mode: "drag-layer";
        layerNum: 1 | 2 | 3 | 4;
        startClientX: number;
        startClientY: number;
        initialHeader: { x: number; y: number };
        initialNodeCoords: Record<string, { x: number; y: number }>;
      }
    | {
        mode: "wire";
        fromNodeId: string;
        startX: number;
        startY: number;
      }
    | null
  >(null);

  // Custom node form state
  const [customLayer, setCustomLayer] = useState<FlowLayer>(1);
  const [customCode, setCustomCode] = useState("CUSTOM_NODE_01");
  const [customLabel, setCustomLabel] = useState("");
  const [customSubtitle, setCustomSubtitle] = useState("");
  const [customRiskId, setCustomRiskId] = useState("CUSTOM_RISK_01");
  const [customRiskTitle, setCustomRiskTitle] = useState("");
  const [customRiskKind, setCustomRiskKind] = useState<RiskKind>("action");
  const [customBaseL, setCustomBaseL] = useState<number>(4);
  const [customBaseI, setCustomBaseI] = useState<number>(4);
  const [customOwasp, setCustomOwasp] = useState("OWASP LLM06:2025 Excessive Agency");
  const [customNist, setCustomNist] = useState("MAP 3.5, MANAGE 2.4");
  const [customDeltaL, setCustomDeltaL] = useState<number>(1);
  const [customDeltaI, setCustomDeltaI] = useState<number>(0);
  const [customMultL, setCustomMultL] = useState<number>(1);
  const [customMultI, setCustomMultI] = useState<number>(1);
  const [customDiscountPct, setCustomDiscountPct] = useState<number>(35);
  const [customCtrlDeltaI, setCustomCtrlDeltaI] = useState<number>(0);
  const [customScopeAll, setCustomScopeAll] = useState<boolean>(true);
  const [customTargetKinds, setCustomTargetKinds] = useState<RiskKind[]>([
    "injection",
    "action",
  ]);
  const [customAlsoEmitRisk, setCustomAlsoEmitRisk] = useState<boolean>(false);
  const [customApplicableControls, setCustomApplicableControls] = useState<string[]>([]);
  const [aiAnalyzing, setAiAnalyzing] = useState<boolean>(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiRationale, setAiRationale] = useState<{
    text: string;
    source: "llm" | "fallback";
  } | null>(null);

  // Determine complete L1 -> L2 -> L3 chains (Option C: Layer 4 only shows risks from complete L1->L2->L3 chains!)
  const completeChains = useMemo(() => {
    const l1Nodes = nodes.filter((n) => n.layer === 1);
    const l2Nodes = nodes.filter((n) => n.layer === 2);
    const l3Nodes = nodes.filter((n) => n.layer === 3);

    const l1Map = new Map(l1Nodes.map((n) => [n.id, n]));
    const l2Map = new Map(l2Nodes.map((n) => [n.id, n]));
    const l3Map = new Map(l3Nodes.map((n) => [n.id, n]));

    const triples: Array<{ n1: FlowNodeData; n2: FlowNodeData; n3: FlowNodeData }> = [];
    const activeNodeIds = new Set<string>();

    for (const e12 of edges) {
      const n1 = l1Map.get(e12.fromId);
      const n2 = l2Map.get(e12.toId);
      if (!n1 || !n2) continue;

      for (const e23 of edges) {
        if (e23.fromId !== n2.id) continue;
        const n3 = l3Map.get(e23.toId);
        if (!n3) continue;

        triples.push({ n1, n2, n3 });
        activeNodeIds.add(n1.id);
        activeNodeIds.add(n2.id);
        activeNodeIds.add(n3.id);
      }
    }

    return { triples, activeNodeIds };
  }, [nodes, edges]);

  // Compute all Layer 4 risk traces STRICTLY from completed L1 -> L2 -> L3 chains, including risks emitted by Layer 1, Layer 2, and Layer 3!
  const computedRisks = useMemo<ComputedRiskTrace[]>(() => {
    const { triples } = completeChains;
    if (triples.length === 0) return [];

    // Collect emitted risks from ANY node (Layer 1, Layer 2, or Layer 3) that participates in at least one complete (n1, n2, n3) chain
    const riskRegistry = new Map<
      string,
      {
        emit: CustomRiskEmit;
        originNodes: Map<string, FlowNodeData>;
        matchingTriples: Array<{ n1: FlowNodeData; n2: FlowNodeData; n3: FlowNodeData }>;
      }
    >();

    const registerEmit = (
      emit: CustomRiskEmit,
      originNode: FlowNodeData,
      triple: { n1: FlowNodeData; n2: FlowNodeData; n3: FlowNodeData },
    ): void => {
      const existing = riskRegistry.get(emit.id);
      if (existing) {
        existing.originNodes.set(originNode.id, originNode);
        existing.matchingTriples.push(triple);
      } else {
        riskRegistry.set(emit.id, {
          emit,
          originNodes: new Map([[originNode.id, originNode]]),
          matchingTriples: [triple],
        });
      }
    };

    for (const triple of triples) {
      for (const emit of triple.n1.emittedRisks ?? []) {
        registerEmit(emit, triple.n1, triple);
      }
      for (const emit of triple.n2.emittedRisks ?? []) {
        registerEmit(emit, triple.n2, triple);
      }
      for (const emit of triple.n3.emittedRisks ?? []) {
        registerEmit(emit, triple.n3, triple);
      }
    }

    const traces: ComputedRiskTrace[] = [];

    for (const [riskId, { emit, originNodes, matchingTriples }] of riskRegistry.entries()) {
      const sourceNodes = [...originNodes.values()];

      // Unique Layer 2 and Layer 3 nodes along the complete chains for this risk
      const chainL2Map = new Map<string, FlowNodeData>();
      const chainL3Map = new Map<string, FlowNodeData>();
      for (const t of matchingTriples) {
        chainL2Map.set(t.n2.id, t.n2);
        chainL3Map.set(t.n3.id, t.n3);
        // Also include any sibling Layer 3 controls connected to t.n2 so controls on the same branch can mitigate Layer 2/3 emitted risks
        for (const e23 of edges) {
          if (e23.fromId === t.n2.id) {
            const sibL3 = nodes.find((n) => n.layer === 3 && n.id === e23.toId);
            if (sibL3) chainL3Map.set(sibL3.id, sibL3);
          }
        }
      }

      const activeContextNodes: FlowNodeData[] = [];
      for (const l2 of chainL2Map.values()) {
        const matchesKind =
          !l2.targetKinds ||
          l2.targetKinds === "all" ||
          l2.targetKinds.includes(emit.kind);
        if (matchesKind) {
          activeContextNodes.push(l2);
        }
      }

      const activeControlNodes: FlowNodeData[] = [];
      for (const l3 of chainL3Map.values()) {
        if ((l3.discountW ?? 0) === 0 && (l3.controlDeltaI ?? 0) === 0) continue;
        const matchesKind =
          !l3.targetKinds ||
          l3.targetKinds === "all" ||
          l3.targetKinds.includes(emit.kind);
        const isApplicableBuiltIn =
          l3.isCustom ||
          emit.applicableControls.length === 0 ||
          emit.applicableControls.includes(l3.code);
        if (matchesKind && isApplicableBuiltIn) {
          activeControlNodes.push(l3);
        }
      }

      const baseL = emit.baseL;
      const baseI = emit.baseI;
      const baseScore = baseL * baseI;

      let workingL = baseL;
      let workingI = baseI;
      let sumDeltaL = 0;
      let sumDeltaI = 0;
      const lTerms: string[] = [`${baseL}`];
      const iTerms: string[] = [`${baseI}`];

      for (const ctx of activeContextNodes) {
        const mL = ctx.multL ?? 1;
        const dL = ctx.deltaL ?? 0;
        const mI = ctx.multI ?? 1;
        const dI = ctx.deltaI ?? 0;
        if (mL !== 1) {
          workingL = workingL * mL;
          lTerms.push(`×${mL}`);
        }
        if (dL !== 0) {
          workingL += dL;
          sumDeltaL += dL;
          lTerms.push(dL > 0 ? `+${dL}` : `${dL}`);
        }
        if (mI !== 1) {
          workingI = workingI * mI;
          iTerms.push(`×${mI}`);
        }
        if (dI !== 0) {
          workingI += dI;
          sumDeltaI += dI;
          iTerms.push(dI > 0 ? `+${dI}` : `${dI}`);
        }
      }

      const ctxL = clamp5(workingL);
      const ctxI = clamp5(workingI);
      const ctxScore = ctxL * ctxI;
      const ctxFormulaL =
        lTerms.length > 1 ? `clamp(${lTerms.join(" ")}) = ${ctxL}` : `${baseL}`;
      const ctxFormulaI =
        iTerms.length > 1 ? `clamp(${iTerms.join(" ")}) = ${ctxI}` : `${baseI}`;

      const rawDiscountW = activeControlNodes.reduce(
        (sum, c) => sum + (c.discountW ?? 0),
        0,
      );
      const cappedDiscountW = Math.min(0.8, rawDiscountW);
      const ctrlDeltaI = activeControlNodes.reduce(
        (sum, c) => sum + (c.controlDeltaI ?? 0),
        0,
      );

      const finalL = clamp5(ctxL * (1 - cappedDiscountW));
      const finalI = clamp5(ctxI + ctrlDeltaI);
      const finalScore = finalL * finalI;
      const severity = severityFor(finalScore);

      const finalFormulaL =
        cappedDiscountW > 0
          ? `max(1, round(${ctxL} × (1 - ${cappedDiscountW.toFixed(2)}))) = ${finalL}`
          : `${ctxL} (W=0%)`;
      const finalFormulaI =
        ctrlDeltaI !== 0
          ? `clamp(${ctxI} ${ctrlDeltaI > 0 ? `+${ctrlDeltaI}` : ctrlDeltaI}) = ${finalI}`
          : `${ctxI}`;

      traces.push({
        riskId,
        title: isEn ? emit.titleEn : emit.title,
        kind: emit.kind,
        owasp: emit.owasp,
        nist: emit.nist,
        sourceNodes,
        contextNodes: activeContextNodes,
        controlNodes: activeControlNodes,
        baseL,
        baseI,
        baseScore,
        sumDeltaL,
        sumDeltaI,
        ctxFormulaL,
        ctxFormulaI,
        ctxL,
        ctxI,
        ctxScore,
        rawDiscountW,
        cappedDiscountW,
        ctrlDeltaI,
        finalFormulaL,
        finalFormulaI,
        finalL,
        finalI,
        finalScore,
        severity,
      });
    }

    // Merge Level-2 Gemini AI emergent cross-chain risks when AI evaluation is enabled
    if (isEvaluated && useAiEvaluation && graphAiResult && graphAiResult.ai_risks.length > 0) {
      const nodeMap = new Map(nodes.map((n) => [n.id, n]));
      for (const aiRisk of graphAiResult.ai_risks) {
        const involvedNodes = aiRisk.involved_node_ids
          .map((nid) => nodeMap.get(nid))
          .filter((n): n is FlowNodeData => Boolean(n));
        const srcNodes = involvedNodes.filter((n) => n.layer === 1);
        const ctxNodes = involvedNodes.filter((n) => n.layer === 2);
        const ctrlNodes = involvedNodes.filter((n) => n.layer === 3);
        const finalScore = aiRisk.final_l * aiRisk.final_i;
        traces.push({
          riskId: aiRisk.risk_id,
          title: aiRisk.title,
          kind: aiRisk.kind,
          owasp: aiRisk.owasp,
          nist: aiRisk.nist,
          sourceNodes: srcNodes.length > 0 ? srcNodes : involvedNodes.slice(0, 1),
          contextNodes: ctxNodes,
          controlNodes: ctrlNodes,
          baseL: aiRisk.base_l,
          baseI: aiRisk.base_i,
          baseScore: aiRisk.base_l * aiRisk.base_i,
          sumDeltaL: 0,
          sumDeltaI: 0,
          ctxFormulaL: `AI(${aiRisk.base_l})`,
          ctxFormulaI: `AI(${aiRisk.base_i})`,
          ctxL: aiRisk.base_l,
          ctxI: aiRisk.base_i,
          ctxScore: aiRisk.base_l * aiRisk.base_i,
          rawDiscountW: 0,
          cappedDiscountW: 0,
          ctrlDeltaI: 0,
          finalFormulaL: `Gemini AI ⇒ L=${aiRisk.final_l}`,
          finalFormulaI: `Gemini AI ⇒ I=${aiRisk.final_i}`,
          finalL: aiRisk.final_l,
          finalI: aiRisk.final_i,
          finalScore,
          severity: severityFor(finalScore),
          isAiGraphRisk: true,
          aiSource: graphAiResult.source,
          aiRationale: aiRisk.rationale,
        });
      }
    }

    traces.sort((a, b) => b.finalScore - a.finalScore || b.baseScore - a.baseScore);
    return traces;
  }, [completeChains, edges, nodes, isEn, isEvaluated, useAiEvaluation, graphAiResult]);

  async function handleRunGraphEvaluation(): Promise<void> {
    setFocusedRiskId(null);
    if (!useAiEvaluation) {
      setGraphAiResult(null);
      setIsEvaluated(true);
      return;
    }

    setIsEvaluatingGraph(true);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/agentic/analyze-graph`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          nodes: nodes.map((n) => ({
            id: n.id,
            layer: n.layer,
            code: n.code,
            label: isEn ? n.labelEn : n.label,
            subtitle: isEn ? n.subtitleEn : n.subtitle,
            is_custom: Boolean(n.isCustom),
            delta_l: n.deltaL ?? 0,
            delta_i: n.deltaI ?? 0,
            discount_w: n.discountW ?? 0,
          })),
          edges: edges.map((e) => ({ from_id: e.fromId, to_id: e.toId })),
          existing_risk_ids: computedRisks
            .filter((r) => !r.isAiGraphRisk)
            .map((r) => r.riskId),
          language,
        }),
      });
      if (response.ok) {
        const data = (await response.json()) as { analysis: GraphAiAnalysisState };
        setGraphAiResult(data.analysis);
      } else {
        setGraphAiResult(null);
      }
    } catch {
      setGraphAiResult(null);
    } finally {
      setIsEvaluatingGraph(false);
      setIsEvaluated(true);
    }
  }

  const activeFocusRisk = useMemo<ComputedRiskTrace | null>(() => {
    if (!focusedRiskId || computedRisks.length === 0) return null;
    return computedRisks.find((r) => r.riskId === focusedRiskId) ?? null;
  }, [computedRisks, focusedRiskId]);

  /** Get Layer 4 node 2D coordinates (freely draggable or auto-positioned in Layer 4) */
  function getL4NodePos(riskId: string, index: number): { x: number; y: number } {
    const custom = l4Positions[riskId];
    if (custom) return custom;
    return {
      x: layerHeaders[4].x,
      y: layerHeaders[4].y + 85 + index * 205,
    };
  }

  /** Pure-math 2D World Coordinates for Output & Input Sockets (Zero lag, works at any zoom/pan) */
  const socketCoords = useMemo(() => {
    const out: Record<string, { x: number; y: number }> = {};
    const inn: Record<string, { x: number; y: number; layer: number }> = {};

    for (const n of nodes) {
      out[n.id] = {
        x: n.x + NODE_WIDTH,
        y: n.y + PORT_OFFSET_Y,
      };
      if (n.layer > 1) {
        inn[n.id] = {
          x: n.x,
          y: n.y + PORT_OFFSET_Y,
          layer: n.layer,
        };
      }
    }

    computedRisks.forEach((trace, idx) => {
      const pos = l4Positions[trace.riskId] ?? {
        x: layerHeaders[4].x,
        y: layerHeaders[4].y + 85 + idx * 205,
      };
      inn[`L4_${trace.riskId}`] = {
        x: pos.x,
        y: pos.y + PORT_OFFSET_Y,
        layer: 4,
      };
    });

    return { out, in: inn };
  }, [nodes, computedRisks, l4Positions, layerHeaders]);

  /** Convert screen clientX/clientY to infinite canvas world (x, y) */
  function clientToWorld(clientX: number, clientY: number): { x: number; y: number } {
    const vp = viewportRef.current;
    if (!vp) return { x: 0, y: 0 };
    const rect = vp.getBoundingClientRect();
    return {
      x: (clientX - rect.left - pan.x) / zoom,
      y: (clientY - rect.top - pan.y) / zoom,
    };
  }

  // Global mousemove / mouseup listeners for panning, node dragging, layer dragging, and press-hold-drag wiring
  useEffect(() => {
    function handleMouseMove(e: MouseEvent): void {
      const act = interactionRef.current;
      if (!act) return;

      if (act.mode === "pan") {
        const dx = e.clientX - act.startClientX;
        const dy = e.clientY - act.startClientY;
        setPan({
          x: act.initialPanX + dx,
          y: act.initialPanY + dy,
        });
        return;
      }

      if (act.mode === "drag-node") {
        const dx = (e.clientX - act.startClientX) / zoom;
        const dy = (e.clientY - act.startClientY) / zoom;
        setNodes((prev) =>
          prev.map((n) =>
            n.id === act.nodeId
              ? { ...n, x: Math.round(act.initialX + dx), y: Math.round(act.initialY + dy) }
              : n,
          ),
        );
        return;
      }

      if (act.mode === "drag-l4") {
        const dx = (e.clientX - act.startClientX) / zoom;
        const dy = (e.clientY - act.startClientY) / zoom;
        setL4Positions((prev) => ({
          ...prev,
          [act.riskId]: {
            x: Math.round(act.initialX + dx),
            y: Math.round(act.initialY + dy),
          },
        }));
        return;
      }

      if (act.mode === "drag-layer") {
        const dx = Math.round((e.clientX - act.startClientX) / zoom);
        const dy = Math.round((e.clientY - act.startClientY) / zoom);
        setLayerHeaders((prev) => ({
          ...prev,
          [act.layerNum]: {
            x: act.initialHeader.x + dx,
            y: act.initialHeader.y + dy,
          },
        }));
        if (act.layerNum === 4) {
          setL4Positions((prev) => {
            const next = { ...prev };
            for (const [rId, pos] of Object.entries(act.initialNodeCoords)) {
              next[rId] = { x: pos.x + dx, y: pos.y + dy };
            }
            return next;
          });
        } else {
          setNodes((prev) =>
            prev.map((n) =>
              n.layer === act.layerNum && act.initialNodeCoords[n.id]
                ? {
                    ...n,
                    x: act.initialNodeCoords[n.id].x + dx,
                    y: act.initialNodeCoords[n.id].y + dy,
                  }
                : n,
            ),
          );
        }
        return;
      }

      if (act.mode === "wire") {
        const worldPt = clientToWorld(e.clientX, e.clientY);
        const srcNode = nodes.find((n) => n.id === act.fromNodeId);
        const srcLayer = srcNode ? srcNode.layer : 1;

        // Magnetic snap detection to any valid downstream Input Socket within 46px
        let closestTargetId: string | null = null;
        let minDist = 46;

        for (const [targetId, coord] of Object.entries(socketCoords.in)) {
          if (targetId === act.fromNodeId) continue;
          if (targetId.startsWith("L4_")) continue; // Layer 4 is auto-synthesized from L1..L3
          if (coord.layer <= srcLayer) continue;
          const dist = Math.hypot(worldPt.x - coord.x, worldPt.y - coord.y);
          if (dist < minDist) {
            minDist = dist;
            closestTargetId = targetId;
          }
        }

        // Also check if cursor is inside the bounding box of a valid downstream node
        if (!closestTargetId) {
          for (const candidate of nodes) {
            if (candidate.layer <= srcLayer) continue;
            if (
              worldPt.x >= candidate.x - 16 &&
              worldPt.x <= candidate.x + NODE_WIDTH + 16 &&
              worldPt.y >= candidate.y - 10 &&
              worldPt.y <= candidate.y + 155
            ) {
              closestTargetId = candidate.id;
              break;
            }
          }
        }

        const snapCoord = closestTargetId ? socketCoords.in[closestTargetId] : null;
        setActiveWireDrag({
          fromNodeId: act.fromNodeId,
          startX: act.startX,
          startY: act.startY,
          currX: snapCoord ? snapCoord.x : worldPt.x,
          currY: snapCoord ? snapCoord.y : worldPt.y,
          hoveredTargetId: closestTargetId,
        });
      }
    }

    function handleMouseUp(e: MouseEvent): void {
      const act = interactionRef.current;
      if (act && act.mode === "pan") {
        // Only clear highlight & selection on a true click (movement < 5px), NOT when holding & dragging to pan!
        const movedDist = Math.hypot(
          e.clientX - act.startClientX,
          e.clientY - act.startClientY,
        );
        if (movedDist < 5) {
          setFocusedRiskId(null);
          setSelectedNodeId(null);
        }
      } else if (act && act.mode === "wire") {
        setActiveWireDrag((currentDrag) => {
          if (currentDrag && currentDrag.hoveredTargetId) {
            const fromId = currentDrag.fromNodeId;
            const toId = currentDrag.hoveredTargetId;
            setEdges((prev) => {
              if (prev.some((edge) => edge.fromId === fromId && edge.toId === toId)) {
                return prev;
              }
              return [
                ...prev,
                {
                  id: `e_${fromId}_${toId}_${Date.now().toString().slice(-3)}`,
                  fromId,
                  toId,
                },
              ];
            });
          }
          return null;
        });
      }
      interactionRef.current = null;
    }

    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseup", handleMouseUp);
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, [zoom, pan, nodes, socketCoords]);

  // Native non-passive wheel listener on the canvas viewport so wheel-zoom NEVER scrolls the page
  useEffect(() => {
    const vp = viewportRef.current;
    if (!vp) return;

    function onNativeWheel(e: WheelEvent): void {
      e.preventDefault();
      e.stopPropagation();
      const currentEl = viewportRef.current;
      if (!currentEl) return;
      const rect = currentEl.getBoundingClientRect();
      const cx = e.clientX - rect.left;
      const cy = e.clientY - rect.top;

      const factor = e.deltaY < 0 ? 1.1 : 0.9;
      setZoom((prevZoom) => {
        const nextZoom = Math.min(1.8, Math.max(0.35, Number((prevZoom * factor).toFixed(3))));
        setPan((prevPan) => {
          const wx = (cx - prevPan.x) / prevZoom;
          const wy = (cy - prevPan.y) / prevZoom;
          return {
            x: Math.round(cx - wx * nextZoom),
            y: Math.round(cy - wy * nextZoom),
          };
        });
        return nextZoom;
      });
    }

    vp.addEventListener("wheel", onNativeWheel, { passive: false });
    return () => {
      vp.removeEventListener("wheel", onNativeWheel);
    };
  }, []);

  function handleCanvasMouseDown(e: React.MouseEvent<HTMLDivElement>): void {
    // Start panning on mousedown; highlight only clears on mouseup if mouse did NOT drag
    const target = e.target as HTMLElement;
    if (
      target.classList.contains("flow-infinite-viewport") ||
      target.classList.contains("flow-infinite-world") ||
      target.tagName === "svg"
    ) {
      interactionRef.current = {
        mode: "pan",
        startClientX: e.clientX,
        startClientY: e.clientY,
        initialPanX: pan.x,
        initialPanY: pan.y,
      };
    }
  }

  function startNodeDrag(e: React.MouseEvent, node: FlowNodeData): void {
    e.stopPropagation();
    const tag = (e.target as HTMLElement).tagName;
    if (tag === "BUTTON" || tag === "INPUT" || tag === "SELECT") return;
    setSelectedNodeId(node.id);
    // If clicking a node that is NOT part of the currently highlighted risk path, clear the risk highlight
    if (
      activeFocusRisk &&
      !activeFocusRisk.sourceNodes.some((s) => s.id === node.id) &&
      !activeFocusRisk.contextNodes.some((c) => c.id === node.id) &&
      !activeFocusRisk.controlNodes.some((k) => k.id === node.id)
    ) {
      setFocusedRiskId(null);
    }
    interactionRef.current = {
      mode: "drag-node",
      nodeId: node.id,
      startClientX: e.clientX,
      startClientY: e.clientY,
      initialX: node.x,
      initialY: node.y,
    };
  }

  function startL4NodeDrag(
    e: React.MouseEvent,
    riskId: string,
    pos: { x: number; y: number },
  ): void {
    e.stopPropagation();
    if ((e.target as HTMLElement).tagName === "BUTTON") return;
    setFocusedRiskId(riskId);
    interactionRef.current = {
      mode: "drag-l4",
      riskId,
      startClientX: e.clientX,
      startClientY: e.clientY,
      initialX: pos.x,
      initialY: pos.y,
    };
  }

  function startLayerDrag(e: React.MouseEvent, layerNum: 1 | 2 | 3 | 4): void {
    e.stopPropagation();
    const initialNodeCoords: Record<string, { x: number; y: number }> = {};
    if (layerNum === 4) {
      computedRisks.forEach((trace, idx) => {
        initialNodeCoords[trace.riskId] = getL4NodePos(trace.riskId, idx);
      });
    } else {
      for (const n of nodes) {
        if (n.layer === layerNum) {
          initialNodeCoords[n.id] = { x: n.x, y: n.y };
        }
      }
    }
    interactionRef.current = {
      mode: "drag-layer",
      layerNum,
      startClientX: e.clientX,
      startClientY: e.clientY,
      initialHeader: { ...layerHeaders[layerNum] },
      initialNodeCoords,
    };
  }

  /** Press and hold on an Output Socket (OUT ●) to drag a wire to another node's Input Socket (● IN) */
  function startWireDragFromOutput(e: React.MouseEvent, node: FlowNodeData): void {
    e.stopPropagation();
    e.preventDefault();
    const startPt = socketCoords.out[node.id] ?? {
      x: node.x + NODE_WIDTH,
      y: node.y + PORT_OFFSET_Y,
    };
    interactionRef.current = {
      mode: "wire",
      fromNodeId: node.id,
      startX: startPt.x,
      startY: startPt.y,
    };
    setActiveWireDrag({
      fromNodeId: node.id,
      startX: startPt.x,
      startY: startPt.y,
      currX: startPt.x + 24,
      currY: startPt.y,
      hoveredTargetId: null,
    });
  }

  function addNodeFromTemplate(tpl: FlowNodeData): void {
    const sameLayerNodes = nodes.filter((n) => n.layer === tpl.layer);
    const maxY =
      sameLayerNodes.length > 0
        ? Math.max(...sameLayerNodes.map((n) => n.y)) + 215
        : layerHeaders[tpl.layer].y + 85;
    const newId = `N${tpl.layer}_${tpl.code.replace(/[^A-Z0-9_]/gi, "_")}_${Date.now().toString().slice(-3)}`;
    const clone: FlowNodeData = {
      ...tpl,
      id: newId,
      x: layerHeaders[tpl.layer].x,
      y: maxY,
    };
    setNodes((prev) => [...prev, clone]);
    setSelectedNodeId(newId);
  }

  function removeNode(nodeId: string): void {
    setNodes((prev) => prev.filter((n) => n.id !== nodeId));
    setEdges((prev) => prev.filter((e) => e.fromId !== nodeId && e.toId !== nodeId));
    if (selectedNodeId === nodeId) setSelectedNodeId(null);
  }

  function removeEdge(edgeId: string): void {
    setEdges((prev) => prev.filter((e) => e.id !== edgeId));
  }

  function autoLayoutLayers(): void {
    const nextHeaders: Record<1 | 2 | 3 | 4, { x: number; y: number }> = {
      1: { x: LAYER_DEFAULT_X[1], y: 20 },
      2: { x: LAYER_DEFAULT_X[2], y: 20 },
      3: { x: LAYER_DEFAULT_X[3], y: 20 },
      4: { x: LAYER_DEFAULT_X[4], y: 20 },
    };
    setLayerHeaders(nextHeaders);
    setL4Positions({});
    const counters: Record<FlowLayer, number> = { 1: 0, 2: 0, 3: 0 };
    setNodes((prev) =>
      prev.map((n) => {
        const idx = counters[n.layer]++;
        return {
          ...n,
          x: nextHeaders[n.layer].x,
          y: 105 + idx * 215,
        };
      }),
    );
  }

  function autoWireAllLayers(): void {
    const l1 = nodes.filter((n) => n.layer === 1);
    const l2 = nodes.filter((n) => n.layer === 2);
    const l3 = nodes.filter((n) => n.layer === 3);
    const nextEdges: FlowEdge[] = [];
    for (const n1 of l1) {
      for (const n2 of l2) {
        nextEdges.push({
          id: `ew_${n1.id}_${n2.id}`,
          fromId: n1.id,
          toId: n2.id,
        });
      }
    }
    for (const n2 of l2) {
      for (const n3 of l3) {
        nextEdges.push({
          id: `ew_${n2.id}_${n3.id}`,
          fromId: n2.id,
          toId: n3.id,
        });
      }
    }
    setEdges(nextEdges);
  }

  function resetToPreset(): void {
    const preset = createInitialPreset();
    setNodes(preset.nodes);
    setEdges(preset.edges);
    setLayerHeaders(preset.layerHeaders);
    setL4Positions({});
    setSelectedNodeId(null);
    setFocusedRiskId(null);
    setIsEvaluated(false);
    setGraphAiResult(null);
    setPan({ x: 20, y: 15 });
    setZoom(0.85);
  }

  async function handleSuggestWithGemini(): Promise<void> {
    if (!customLabel.trim() || !customSubtitle.trim()) {
      setAiError(
        isEn
          ? "Please enter both a Node Name and a Description so Gemini can analyze it."
          : "Vui lòng nhập Tên nút và Mô tả chi tiết để Gemini có đủ ngữ cảnh phân tích.",
      );
      return;
    }
    setAiAnalyzing(true);
    setAiError(null);
    setAiRationale(null);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/agentic/analyze-custom-node`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          layer: customLayer,
          name: customLabel.trim(),
          description: customSubtitle.trim(),
          language,
        }),
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = (await response.json()) as {
        suggestion: {
          suggested_code: string;
          layer: FlowLayer;
          rationale: string;
          source: "llm" | "fallback";
          delta_l: number;
          delta_i: number;
          mult_l: number;
          mult_i: number;
          discount_w: number;
          control_delta_i: number;
          target_kinds: RiskKind[];
          emitted_risk: {
            risk_id: string;
            title: string;
            kind: RiskKind;
            base_l: number;
            base_i: number;
            owasp: string[];
            nist: string[];
            applicable_controls: string[];
          } | null;
        };
      };
      const s = data.suggestion;
      setCustomCode(s.suggested_code);
      setAiRationale({ text: s.rationale, source: s.source });

      if (s.layer === 2) {
        setCustomDeltaL(s.delta_l);
        setCustomDeltaI(s.delta_i);
        setCustomMultL(s.mult_l);
        setCustomMultI(s.mult_i);
      } else if (s.layer === 3) {
        setCustomDiscountPct(Math.round(s.discount_w * 100));
        setCustomCtrlDeltaI(s.control_delta_i);
      }

      if (s.target_kinds && s.target_kinds.length > 0) {
        setCustomScopeAll(false);
        setCustomTargetKinds(s.target_kinds);
      } else {
        setCustomScopeAll(true);
      }

      if (s.emitted_risk) {
        setCustomAlsoEmitRisk(true);
        setCustomRiskId(s.emitted_risk.risk_id);
        setCustomRiskTitle(s.emitted_risk.title);
        setCustomRiskKind(s.emitted_risk.kind);
        setCustomBaseL(s.emitted_risk.base_l);
        setCustomBaseI(s.emitted_risk.base_i);
        setCustomOwasp(s.emitted_risk.owasp.join(", "));
        setCustomNist(s.emitted_risk.nist.join(", "));
        setCustomApplicableControls(s.emitted_risk.applicable_controls);
      } else if (s.layer !== 1) {
        setCustomAlsoEmitRisk(false);
        setCustomApplicableControls([]);
      }
    } catch (err: unknown) {
      setAiError(
        err instanceof Error
          ? isEn
            ? `Unable to reach backend AI analyzer (${err.message}). You can still fill parameters manually.`
            : `Không kết nối được dịch vụ phân tích AI (${err.message}). Bạn vẫn có thể tự điền tham số thủ công.`
          : isEn
            ? "AI analysis request failed."
            : "Yêu cầu phân tích AI thất bại.",
      );
    } finally {
      setAiAnalyzing(false);
    }
  }

  function handleCreateCustomNode(e: React.FormEvent): void {
    e.preventDefault();
    const id = `CUSTOM_L${customLayer}_${Date.now().toString().slice(-4)}`;
    const cleanCode = customCode.trim() || id;
    const cleanLabel =
      customLabel.trim() ||
      (isEn ? `Custom Layer ${customLayer} Node` : `Nút tùy chỉnh Lớp ${customLayer}`);

    const sameLayerNodes = nodes.filter((n) => n.layer === customLayer);
    const nextY =
      sameLayerNodes.length > 0
        ? Math.max(...sameLayerNodes.map((n) => n.y)) + 215
        : layerHeaders[customLayer].y + 85;

    const optionalEmittedRisk: CustomRiskEmit[] | undefined =
      customLayer === 1 || customAlsoEmitRisk
        ? [
            {
              id:
                customRiskId.trim().toUpperCase() ||
                `CUSTOM_R_${Date.now().toString().slice(-3)}`,
              title:
                customRiskTitle.trim() ||
                (isEn ? `Risk from ${cleanLabel}` : `Rủi ro phát sinh từ ${cleanLabel}`),
              titleEn:
                customRiskTitle.trim() ||
                (isEn ? `Risk from ${cleanLabel}` : `Rủi ro phát sinh từ ${cleanLabel}`),
              kind: customRiskKind,
              baseL: clamp5(customBaseL),
              baseI: clamp5(customBaseI),
              owasp: customOwasp
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean),
              nist: customNist
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean),
              applicableControls: customApplicableControls,
            },
          ]
        : undefined;

    const wasAiSuggested = aiRationale?.source === "llm";

    let newNode: FlowNodeData;
    if (customLayer === 1) {
      newNode = {
        id,
        layer: 1,
        code: cleanCode,
        label: cleanLabel,
        labelEn: cleanLabel,
        subtitle:
          customSubtitle.trim() || `Nút tự định nghĩa · Gốc L=${customBaseL}, I=${customBaseI}`,
        subtitleEn:
          customSubtitle.trim() || `Custom Asset Node · Base L=${customBaseL}, I=${customBaseI}`,
        isCustom: true,
        aiSuggested: wasAiSuggested,
        x: layerHeaders[1].x,
        y: nextY,
        emittedRisks: optionalEmittedRisk,
      };
    } else if (customLayer === 2) {
      newNode = {
        id,
        layer: 2,
        code: cleanCode,
        label: cleanLabel,
        labelEn: cleanLabel,
        subtitle:
          customSubtitle.trim() ||
          `Ngữ cảnh tùy chỉnh (L×${customMultL} + ${customDeltaL}, I×${customMultI} + ${customDeltaI})`,
        subtitleEn:
          customSubtitle.trim() ||
          `Custom Context (L×${customMultL} + ${customDeltaL}, I×${customMultI} + ${customDeltaI})`,
        isCustom: true,
        aiSuggested: wasAiSuggested,
        x: layerHeaders[2].x,
        y: nextY,
        deltaL: customDeltaL,
        deltaI: customDeltaI,
        multL: customMultL,
        multI: customMultI,
        targetKinds: customScopeAll ? "all" : customTargetKinds,
        emittedRisks: optionalEmittedRisk,
      };
    } else {
      const w = Math.min(0.8, Math.max(0, customDiscountPct / 100));
      newNode = {
        id,
        layer: 3,
        code: cleanCode,
        label: cleanLabel,
        labelEn: cleanLabel,
        subtitle:
          customSubtitle.trim() ||
          `Kiểm soát tùy chỉnh (Giảm ${Math.round(w * 100)}% L, ΔI = ${customCtrlDeltaI})`,
        subtitleEn:
          customSubtitle.trim() ||
          `Custom Control (-${Math.round(w * 100)}% L, ΔI = ${customCtrlDeltaI})`,
        isCustom: true,
        aiSuggested: wasAiSuggested,
        x: layerHeaders[3].x,
        y: nextY,
        discountW: w,
        controlDeltaI: customCtrlDeltaI,
        targetKinds: customScopeAll ? "all" : customTargetKinds,
        emittedRisks: optionalEmittedRisk,
      };
    }

    setNodes((prev) => [...prev, newNode]);
    setSelectedNodeId(newNode.id);
    setShowCustomModal(false);
    setCustomLabel("");
    setCustomSubtitle("");
    setCustomApplicableControls([]);
    setAiRationale(null);
    setAiError(null);
  }

  function getNodeOutputPortSummary(node: FlowNodeData): {
    formulaText: string;
    paramText: string;
  } {
    if (node.layer === 1) {
      const emits = node.emittedRisks ?? [];
      if (emits.length === 0) return { formulaText: "L0, I0", paramText: "L=1, I=1" };
      const focusedEmit =
        (activeFocusRisk && emits.find((e) => e.id === activeFocusRisk.riskId)) ||
        emits[0];
      return {
        formulaText: `L_base=${focusedEmit.baseL}, I_base=${focusedEmit.baseI}`,
        paramText: `L=${focusedEmit.baseL}, I=${focusedEmit.baseI} (R0=${focusedEmit.baseL * focusedEmit.baseI})`,
      };
    }

    if (node.layer === 2) {
      const inEdgeFromIds = new Set(
        edges.filter((e) => e.toId === node.id).map((e) => e.fromId),
      );
      const feedingL1 = nodes.filter((n) => n.layer === 1 && inEdgeFromIds.has(n.id));
      const feedingEmits = feedingL1.flatMap((n) => n.emittedRisks ?? []);
      const sampleEmit =
        (activeFocusRisk &&
          feedingEmits.find((e) => e.id === activeFocusRisk.riskId)) ||
        feedingEmits[0];

      const inL = sampleEmit ? sampleEmit.baseL : 3;
      const inI = sampleEmit ? sampleEmit.baseI : 4;
      const mL = node.multL ?? 1;
      const dL = node.deltaL ?? 0;
      const mI = node.multI ?? 1;
      const dI = node.deltaI ?? 0;
      const outL = clamp5(inL * mL + dL);
      const outI = clamp5(inI * mI + dI);

      const fL =
        mL !== 1
          ? `clamp(${inL}×${mL}${dL >= 0 ? `+${dL}` : dL})`
          : `clamp(${inL}${dL >= 0 ? `+${dL}` : dL})`;
      const fI =
        dI !== 0 || mI !== 1
          ? `clamp(${inI}${dI >= 0 ? `+${dI}` : dI})`
          : `${inI}`;

      return {
        formulaText: `L_ctx=${fL}, I_ctx=${fI}`,
        paramText: `L_ctx=${outL}, I_ctx=${outI} (R=${outL * outI})`,
      };
    }

    const w = node.discountW ?? 0;
    const di = node.controlDeltaI ?? 0;
    const refL = activeFocusRisk ? activeFocusRisk.ctxL : 4;
    const refI = activeFocusRisk ? activeFocusRisk.ctxI : 4;
    const outL = clamp5(refL * (1 - w));
    const outI = clamp5(refI + di);
    return {
      formulaText: `L_out=round(${refL}×(1-${w.toFixed(2)}))`,
      paramText: `L_final=${outL}, I=${outI} (R=${outL * outI})`,
    };
  }

  function getEdgeFormulaLabel(edge: FlowEdge): {
    formula: string;
    result: string;
    isHighlighted: boolean;
  } {
    const src = nodes.find((n) => n.id === edge.fromId);
    const dst = nodes.find((n) => n.id === edge.toId);
    if (!src || !dst) {
      return { formula: "", result: "", isHighlighted: false };
    }

    const isConnectedToSelected =
      selectedNodeId === src.id || selectedNodeId === dst.id;

    const isPartOfFocusedRisk = Boolean(
      activeFocusRisk &&
        ((src.layer === 1 &&
          activeFocusRisk.sourceNodes.some((s) => s.id === src.id) &&
          activeFocusRisk.contextNodes.some((c) => c.id === dst.id)) ||
          (src.layer === 2 &&
            activeFocusRisk.contextNodes.some((c) => c.id === src.id) &&
            activeFocusRisk.controlNodes.some((k) => k.id === dst.id)) ||
          (src.layer === 1 &&
            dst.layer === 3 &&
            activeFocusRisk.sourceNodes.some((s) => s.id === src.id) &&
            activeFocusRisk.controlNodes.some((k) => k.id === dst.id))),
    );

    const isHighlighted = isConnectedToSelected || isPartOfFocusedRisk;

    if (src.layer === 1 && dst.layer === 2) {
      const emits = src.emittedRisks ?? [];
      const em =
        (activeFocusRisk && emits.find((e) => e.id === activeFocusRisk.riskId)) ||
        emits[0];
      const l0 = em ? em.baseL : 3;
      const i0 = em ? em.baseI : 4;
      const dL = dst.deltaL ?? 0;
      const dI = dst.deltaI ?? 0;
      const l1 = clamp5(l0 * (dst.multL ?? 1) + dL);
      const i1 = clamp5(i0 * (dst.multI ?? 1) + dI);
      const opL = dL !== 0 ? (dL > 0 ? `+${dL}` : `${dL}`) : "+0";
      const opI = dI !== 0 ? (dI > 0 ? `+${dI}` : `${dI}`) : "";
      return {
        formula: `L=clamp(${l0}${opL})${opI ? `, I=clamp(${i0}${opI})` : ""}`,
        result: `(${l0},${i0}) → (${l1},${i1}) · R=${l1 * i1}`,
        isHighlighted,
      };
    }

    if (dst.layer === 3) {
      const lCtx = activeFocusRisk ? activeFocusRisk.ctxL : 4;
      const iCtx = activeFocusRisk ? activeFocusRisk.ctxI : 4;
      const w = dst.discountW ?? 0;
      const lOut = clamp5(lCtx * (1 - w));
      const iOut = clamp5(iCtx + (dst.controlDeltaI ?? 0));
      return {
        formula: `L=round(${lCtx}×(1-${w.toFixed(2)}))`,
        result: `L:${lCtx}→${lOut}, I:${iOut} · R=${lOut * iOut}`,
        isHighlighted,
      };
    }

    return { formula: "pass", result: "", isHighlighted };
  }

  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) ?? null,
    [nodes, selectedNodeId],
  );

  const overallScore =
    computedRisks.length > 0
      ? Math.max(...computedRisks.map((r) => r.finalScore))
      : 1;
  const overallSeverity = severityFor(overallScore);

  return (
    <div className="flow-builder">
      {/* Top Toolbar */}
      <header className="flow-builder__header">
        <div>
          <h2>
            {isEn
              ? "4-Layer Risk Scoring Graph"
              : "Đồ thị Luồng Tính điểm 4 Lớp"}
          </h2>
        </div>
        <div className="flow-builder__actions">
          <label className="flow-ai-toggle">
            <input
              type="checkbox"
              checked={useAiEvaluation}
              onChange={(e) => setUseAiEvaluation(e.target.checked)}
            />
            <span>
              ✦ {isEn ? "Include Gemini AI" : "Kết hợp Gemini AI"}
            </span>
          </label>
          <button
            type="button"
            className="flow-eval-btn"
            onClick={() => void handleRunGraphEvaluation()}
            disabled={isEvaluatingGraph}
          >
            {isEvaluatingGraph
              ? isEn
                ? "✦ Evaluating..."
                : "✦ Đang đánh giá..."
              : isEvaluated
                ? isEn
                  ? "▶ Re-Evaluate"
                  : "▶ Đánh giá lại"
                : isEn
                  ? "▶ Run Evaluation"
                  : "▶ Đánh giá"}
          </button>
          {isEvaluated && (
            <button
              type="button"
              className="button-secondary"
              onClick={() => {
                setIsEvaluated(false);
                setFocusedRiskId(null);
              }}
            >
              {isEn ? "Hide Results" : "Ẩn kết quả"}
            </button>
          )}
          <button
            type="button"
            className="button-secondary"
            onClick={() => setShowCustomModal((v) => !v)}
          >
            + {isEn ? "Custom Node" : "Tạo nút mới"}
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={autoLayoutLayers}
          >
            {isEn ? "Align Layers" : "Sắp xếp 4 lớp"}
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={autoWireAllLayers}
          >
            {isEn ? "Connect All" : "Nối toàn bộ"}
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={() => {
              setEdges([]);
              setIsEvaluated(false);
              setGraphAiResult(null);
              setFocusedRiskId(null);
            }}
          >
            {isEn ? "Clear Wires" : "Xóa hết dây"}
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={resetToPreset}
          >
            {isEn ? "Reset Preset" : "Khôi phục mẫu"}
          </button>
        </div>
      </header>

      {/* Custom Node & Parameter Formula Builder */}
      {showCustomModal && (
        <form className="flow-custom-panel" onSubmit={handleCreateCustomNode}>
          <div className="report__section-top">
            <h3>
              {isEn
                ? "Create Custom Node & Parameter Formula"
                : "Tự định nghĩa Nút mới & Công thức tính tham số"}
            </h3>
            <button
              type="button"
              className="button-secondary"
              onClick={() => setShowCustomModal(false)}
            >
              {isEn ? "Close" : "Đóng"}
            </button>
          </div>

          <div className="dev-form__three-col">
            <label>
              <span>{isEn ? "Target Layer" : "Chọn Lớp (Layer)"}</span>
              <select
                value={customLayer}
                onChange={(e) => setCustomLayer(Number(e.target.value) as FlowLayer)}
              >
                <option value={1}>
                  {isEn
                    ? "Layer 1 — Architecture / Asset Trigger (Emits Base L0, I0)"
                    : "Lớp 1 — Nguồn kích hoạt / Thành phần (Phát tham số gốc L0, I0)"}
                </option>
                <option value={2}>
                  {isEn
                    ? "Layer 2 — Operational Context Modifier (Transforms L_ctx, I_ctx)"
                    : "Lớp 2 — Biến đổi Ngữ cảnh vận hành (Biến đổi L_ctx, I_ctx)"}
                </option>
                <option value={3}>
                  {isEn
                    ? "Layer 3 — Security Control (Applies Discount w% on L)"
                    : "Lớp 3 — Kiểm soát kỹ thuật (Khấu trừ trọng số w% trên L)"}
                </option>
              </select>
            </label>

            <label>
              <span>{isEn ? "Node Code / Identifier" : "Mã định danh nút (Code)"}</span>
              <input
                type="text"
                className="wizard__text-input"
                value={customCode}
                onChange={(e) => setCustomCode(e.target.value)}
                required
              />
            </label>

            <label>
              <span>{isEn ? "Node Display Name" : "Tên hiển thị của nút"}</span>
              <input
                type="text"
                className="wizard__text-input"
                value={customLabel}
                onChange={(e) => setCustomLabel(e.target.value)}
                placeholder={
                  isEn
                    ? "e.g. Internal MCP Tool Server"
                    : "VD: Máy chủ MCP nội bộ / Mạng cô lập Air-gapped"
                }
                required
              />
            </label>
          </div>

          <div className="flow-ai-assist-box">
            <label>
              <span>
                {isEn
                  ? "Describe this node in plain language (for Gemini AI Risk & Formula Suggestion)"
                  : "Mô tả chi tiết hoạt động của nút (để Gemini AI tự phân tích rủi ro & đề xuất công thức)"}
              </span>
              <textarea
                rows={2}
                value={customSubtitle}
                onChange={(e) => setCustomSubtitle(e.target.value)}
                placeholder={
                  isEn
                    ? "e.g. Connects directly to SAP ERP via MCP to create purchase orders automatically without manual confirmation."
                    : "VD: Kết nối trực tiếp vào hệ thống SAP ERP qua MCP để tự động tạo đơn đặt hàng mà không qua xác nhận thủ công."
                }
              />
            </label>
            <div className="flow-ai-assist-box__bar">
              <button
                type="button"
                className="flow-ai-suggest-btn"
                onClick={() => void handleSuggestWithGemini()}
                disabled={aiAnalyzing}
              >
                ✦{" "}
                {aiAnalyzing
                  ? isEn
                    ? "Analyzing with Gemini AI..."
                    : "Đang phân tích bằng Gemini AI..."
                  : isEn
                    ? "Analyze & Auto-Fill Parameters with Gemini AI"
                    : "Phân tích & Đề xuất rủi ro bằng Gemini AI"}
              </button>
              {customApplicableControls.length > 0 && (
                <small className="dev-formula-hint">
                  {isEn ? "Mapped Controls: " : "Kiểm soát Lớp 3 tương thích: "}
                  <code>{customApplicableControls.join(", ")}</code>
                </small>
              )}
            </div>
            {aiError && <p className="flow-ai-error">{aiError}</p>}
            {aiRationale && (
              <div className="flow-ai-rationale">
                <span
                  className={`source-badge ${
                    aiRationale.source === "llm" ? "source-badge--ai" : "source-badge--system"
                  }`}
                >
                  <span className="source-badge__icon" aria-hidden="true">
                    {aiRationale.source === "llm" ? "✦" : "▣"}
                  </span>
                  <span>
                    {aiRationale.source === "llm"
                      ? isEn
                        ? "Gemini LLM Suggestion"
                        : "Đề xuất từ Gemini AI"
                      : isEn
                        ? "Heuristic Fallback (API offline)"
                        : "Phân tích dự phòng (API chưa bật)"}
                  </span>
                </span>
                <p>{aiRationale.text}</p>
              </div>
            )}
          </div>

          {customLayer === 1 && (
            <div className="flow-custom-panel__formula-box">
              <strong>
                {isEn
                  ? "Layer 1 Output Parameter Formula: Out = (L_base, I_base) → R_base = L_base × I_base"
                  : "Công thức tham số đầu ra Lớp 1: Out = (L_base, I_base) → R_base = L_base × I_base"}
              </strong>
              <div className="dev-form__three-col">
                <label>
                  <span>{isEn ? "Emitted Risk ID" : "Mã rủi ro phát sinh"}</span>
                  <input
                    type="text"
                    className="wizard__text-input"
                    value={customRiskId}
                    onChange={(e) => setCustomRiskId(e.target.value)}
                    required
                  />
                </label>
                <label>
                  <span>{isEn ? "Emitted Risk Name" : "Tên rủi ro phát sinh"}</span>
                  <input
                    type="text"
                    className="wizard__text-input"
                    value={customRiskTitle}
                    onChange={(e) => setCustomRiskTitle(e.target.value)}
                    required
                  />
                </label>
                <label>
                  <span>{isEn ? "Risk Category (Kind)" : "Nhóm bản chất rủi ro (Kind)"}</span>
                  <select
                    value={customRiskKind}
                    onChange={(e) => setCustomRiskKind(e.target.value as RiskKind)}
                  >
                    {ALL_RISK_KINDS.map((k) => (
                      <option key={k} value={k}>
                        {k}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <div className="dev-form__two-col">
                <label>
                  <span>
                    {isEn
                      ? `Base Likelihood L_base (1–5): ${customBaseL}`
                      : `Khả năng xảy ra gốc L_base (1–5): ${customBaseL}`}
                  </span>
                  <input
                    type="range"
                    min={1}
                    max={5}
                    step={1}
                    value={customBaseL}
                    onChange={(e) => setCustomBaseL(Number(e.target.value))}
                  />
                </label>
                <label>
                  <span>
                    {isEn
                      ? `Base Impact I_base (1–5): ${customBaseI}`
                      : `Mức độ ảnh hưởng gốc I_base (1–5): ${customBaseI}`}
                  </span>
                  <input
                    type="range"
                    min={1}
                    max={5}
                    step={1}
                    value={customBaseI}
                    onChange={(e) => setCustomBaseI(Number(e.target.value))}
                  />
                </label>
              </div>
              <div className="dev-form__two-col">
                <label>
                  <span>{isEn ? "OWASP Mapping" : "Ánh xạ chuẩn OWASP"}</span>
                  <input
                    type="text"
                    className="wizard__text-input"
                    value={customOwasp}
                    onChange={(e) => setCustomOwasp(e.target.value)}
                  />
                </label>
                <label>
                  <span>{isEn ? "NIST AI RMF Mapping" : "Ánh xạ chuẩn NIST AI RMF"}</span>
                  <input
                    type="text"
                    className="wizard__text-input"
                    value={customNist}
                    onChange={(e) => setCustomNist(e.target.value)}
                  />
                </label>
              </div>
            </div>
          )}

          {customLayer === 2 && (
            <div className="flow-custom-panel__formula-box">
              <strong>
                {isEn
                  ? `Layer 2 Transformation Formula: L_out = clamp(round(L_in × ${customMultL} + (${customDeltaL})), 1, 5), I_out = clamp(round(I_in × ${customMultI} + (${customDeltaI})), 1, 5)`
                  : `Công thức biến đổi Lớp 2: L_out = clamp(round(L_in × ${customMultL} + (${customDeltaL})), 1, 5), I_out = clamp(round(I_in × ${customMultI} + (${customDeltaI})), 1, 5)`}
              </strong>
              <div className="dev-form__two-col">
                <label>
                  <span>
                    {isEn
                      ? `Likelihood Shift ΔL (-3 to +3): ${customDeltaL > 0 ? `+${customDeltaL}` : customDeltaL}`
                      : `Độ lệch Khả năng xảy ra ΔL (-3 đến +3): ${customDeltaL > 0 ? `+${customDeltaL}` : customDeltaL}`}
                  </span>
                  <input
                    type="range"
                    min={-3}
                    max={3}
                    step={1}
                    value={customDeltaL}
                    onChange={(e) => setCustomDeltaL(Number(e.target.value))}
                  />
                </label>
                <label>
                  <span>
                    {isEn
                      ? `Impact Shift ΔI (-3 to +3): ${customDeltaI > 0 ? `+${customDeltaI}` : customDeltaI}`
                      : `Độ lệch Mức ảnh hưởng ΔI (-3 đến +3): ${customDeltaI > 0 ? `+${customDeltaI}` : customDeltaI}`}
                  </span>
                  <input
                    type="range"
                    min={-3}
                    max={3}
                    step={1}
                    value={customDeltaI}
                    onChange={(e) => setCustomDeltaI(Number(e.target.value))}
                  />
                </label>
              </div>
              <div className="dev-form__two-col">
                <label>
                  <span>
                    {isEn
                      ? `Likelihood Multiplier m_L (0.5 to 2.0): ×${customMultL}`
                      : `Hệ số nhân Khả năng xảy ra m_L (0.5 đến 2.0): ×${customMultL}`}
                  </span>
                  <input
                    type="number"
                    min={0.5}
                    max={2.0}
                    step={0.1}
                    className="wizard__text-input"
                    value={customMultL}
                    onChange={(e) => setCustomMultL(Number(e.target.value) || 1)}
                  />
                </label>
                <label>
                  <span>
                    {isEn
                      ? `Impact Multiplier m_I (0.5 to 2.0): ×${customMultI}`
                      : `Hệ số nhân Mức ảnh hưởng m_I (0.5 đến 2.0): ×${customMultI}`}
                  </span>
                  <input
                    type="number"
                    min={0.5}
                    max={2.0}
                    step={0.1}
                    className="wizard__text-input"
                    value={customMultI}
                    onChange={(e) => setCustomMultI(Number(e.target.value) || 1)}
                  />
                </label>
              </div>
            </div>
          )}

          {customLayer === 3 && (
            <div className="flow-custom-panel__formula-box">
              <strong>
                {isEn
                  ? `Layer 3 Control Formula: W = min(0.80, Σw), L_final = max(1, round(L_ctx × (1 - ${(customDiscountPct / 100).toFixed(2)}))), I_final = clamp(I_ctx + (${customCtrlDeltaI}), 1, 5)`
                  : `Công thức khấu trừ Lớp 3: W = min(0.80, Σw), L_final = max(1, round(L_ctx × (1 - ${(customDiscountPct / 100).toFixed(2)}))), I_final = clamp(I_ctx + (${customCtrlDeltaI}), 1, 5)`}
              </strong>
              <div className="dev-form__two-col">
                <label>
                  <span>
                    {isEn
                      ? `Likelihood Reduction Weight w (5% – 80%): ${customDiscountPct}%`
                      : `Trọng số giảm Khả năng xảy ra w (5% – 80%): ${customDiscountPct}%`}
                  </span>
                  <input
                    type="range"
                    min={5}
                    max={80}
                    step={5}
                    value={customDiscountPct}
                    onChange={(e) => setCustomDiscountPct(Number(e.target.value))}
                  />
                </label>
                <label>
                  <span>
                    {isEn
                      ? `Optional Impact Shift ΔI (-2 to 0): ${customCtrlDeltaI}`
                      : `Giảm mức độ thiệt hại ΔI (-2 đến 0): ${customCtrlDeltaI}`}
                  </span>
                  <input
                    type="range"
                    min={-2}
                    max={0}
                    step={1}
                    value={customCtrlDeltaI}
                    onChange={(e) => setCustomCtrlDeltaI(Number(e.target.value))}
                  />
                </label>
              </div>
            </div>
          )}

          {(customLayer === 2 || customLayer === 3) && (
            <div className="flow-custom-panel__scope">
              <label className="dev-check-item">
                <input
                  type="checkbox"
                  checked={customScopeAll}
                  onChange={(e) => setCustomScopeAll(e.target.checked)}
                />
                <span>
                  {isEn
                    ? "Apply formula to ALL connected risk categories"
                    : "Áp dụng công thức cho TẤT CẢ nhóm rủi ro được nối dây"}
                </span>
              </label>
              {!customScopeAll && (
                <div className="flow-kind-chips">
                  {ALL_RISK_KINDS.map((k) => {
                    const active = customTargetKinds.includes(k);
                    return (
                      <label key={k} className="dev-check-item">
                        <input
                          type="checkbox"
                          checked={active}
                          onChange={() =>
                            setCustomTargetKinds((prev) =>
                              prev.includes(k)
                                ? prev.filter((item) => item !== k)
                                : [...prev, k],
                            )
                          }
                        />
                        <code>{k}</code>
                      </label>
                    );
                  })}
                </div>
              )}

              <label className="dev-check-item">
                <input
                  type="checkbox"
                  checked={customAlsoEmitRisk}
                  onChange={(e) => setCustomAlsoEmitRisk(e.target.checked)}
                />
                <span>
                  {isEn
                    ? `Also emit a new risk from this Layer ${customLayer} node into Layer 4 when connected in a complete L1→L2→L3 chain`
                    : `Nút Lớp ${customLayer} này đồng thời tự sinh thêm rủi ro mới đẩy sang Lớp 4 khi được nối đủ chuỗi L1→L2→L3`}
                </span>
              </label>
            </div>
          )}

          {(customLayer === 1 || customAlsoEmitRisk) && customLayer !== 1 && (
            <div className="flow-custom-panel__formula-box">
              <strong>
                {isEn
                  ? `New Risk Emitted by Layer ${customLayer} Node: Out = (L_base=${customBaseL}, I_base=${customBaseI})`
                  : `Rủi ro mới phát sinh từ nút Lớp ${customLayer}: Out = (L_base=${customBaseL}, I_base=${customBaseI})`}
              </strong>
              <div className="dev-form__three-col">
                <label>
                  <span>{isEn ? "Emitted Risk ID" : "Mã rủi ro phát sinh"}</span>
                  <input
                    type="text"
                    className="wizard__text-input"
                    value={customRiskId}
                    onChange={(e) => setCustomRiskId(e.target.value)}
                    required
                  />
                </label>
                <label>
                  <span>{isEn ? "Emitted Risk Name" : "Tên rủi ro phát sinh"}</span>
                  <input
                    type="text"
                    className="wizard__text-input"
                    value={customRiskTitle}
                    onChange={(e) => setCustomRiskTitle(e.target.value)}
                    required
                  />
                </label>
                <label>
                  <span>{isEn ? "Risk Category (Kind)" : "Nhóm bản chất rủi ro (Kind)"}</span>
                  <select
                    value={customRiskKind}
                    onChange={(e) => setCustomRiskKind(e.target.value as RiskKind)}
                  >
                    {ALL_RISK_KINDS.map((k) => (
                      <option key={k} value={k}>
                        {k}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <div className="dev-form__two-col">
                <label>
                  <span>
                    {isEn
                      ? `Base Likelihood L_base (1–5): ${customBaseL}`
                      : `Khả năng xảy ra gốc L_base (1–5): ${customBaseL}`}
                  </span>
                  <input
                    type="range"
                    min={1}
                    max={5}
                    step={1}
                    value={customBaseL}
                    onChange={(e) => setCustomBaseL(Number(e.target.value))}
                  />
                </label>
                <label>
                  <span>
                    {isEn
                      ? `Base Impact I_base (1–5): ${customBaseI}`
                      : `Mức độ ảnh hưởng gốc I_base (1–5): ${customBaseI}`}
                  </span>
                  <input
                    type="range"
                    min={1}
                    max={5}
                    step={1}
                    value={customBaseI}
                    onChange={(e) => setCustomBaseI(Number(e.target.value))}
                  />
                </label>
              </div>
            </div>
          )}

          <div className="wizard__nav">
            <span className="dev-formula-hint">
              {isEn
                ? "Custom nodes appear on the canvas and can be freely dragged and wired."
                : "Nút tự định nghĩa sẽ xuất hiện trên không gian vẽ để kéo thả và nối dây tự do."}
            </span>
            <button type="submit">
              {isEn ? "Add Custom Node to Canvas →" : "Thêm nút vào Không gian vẽ →"}
            </button>
          </div>
        </form>
      )}

      {/* Built-in Component & Control Palette */}
      <section className="flow-palette" aria-label="Node Template Palette">
        <div className="flow-palette__header">
          <strong>
            {isEn
              ? "Component & Rule Palette (Click + to spawn onto canvas):"
              : "Thư viện Nút mẫu có sẵn (Bấm + để thả nút vào không gian vẽ):"}
          </strong>
          <div className="source-filter-bar">
            <button
              type="button"
              className={`source-filter-btn${paletteLayer === 1 ? " source-filter-btn--active" : ""}`}
              onClick={() => setPaletteLayer(1)}
            >
              {isEn ? "Layer 1 · Architecture & Assets" : "Lớp 1 · Kiến trúc & Tài nguyên"}
            </button>
            <button
              type="button"
              className={`source-filter-btn${paletteLayer === 2 ? " source-filter-btn--active" : ""}`}
              onClick={() => setPaletteLayer(2)}
            >
              {isEn ? "Layer 2 · Context Modifiers" : "Lớp 2 · Biến đổi Ngữ cảnh"}
            </button>
            <button
              type="button"
              className={`source-filter-btn${paletteLayer === 3 ? " source-filter-btn--active" : ""}`}
              onClick={() => setPaletteLayer(3)}
            >
              {isEn ? "Layer 3 · Security Controls" : "Lớp 3 · Kiểm soát Kỹ thuật"}
            </button>
          </div>
        </div>
        <div className="flow-palette__chips">
          {TEMPLATE_LIBRARY.filter((t) => t.layer === paletteLayer).map((tpl) => (
            <button
              key={tpl.id}
              type="button"
              className="flow-chip"
              onClick={() => addNodeFromTemplate(tpl)}
              title={isEn ? tpl.subtitleEn : tpl.subtitle}
            >
              <span className="flow-chip__code">{tpl.code}</span>
              <span className="flow-chip__name">{isEn ? tpl.labelEn : tpl.label}</span>
              <span className="flow-chip__formula">{formatNodeFormulaBadge(tpl)}</span>
              <span className="flow-chip__add">+</span>
            </button>
          ))}
        </div>
      </section>

      {/* Fixed-Height Overall System Risk Score Bar (Never shifts canvas position!) */}
      <div
        className="flow-overall-summary"
        style={{
          borderLeftColor:
            isEvaluated && computedRisks.length > 0
              ? SEVERITY_COLORS[overallSeverity]
              : "#64748b",
        }}
      >
        <div>
          <span className="report__pattern-eyebrow">
            {isEn ? "OVERALL SYSTEM RISK" : "ĐIỂM RỦI RO TỔNG HỆ THỐNG"}
          </span>
          <h3>
            {!isEvaluated
              ? isEn
                ? "Pending Evaluation"
                : "Chưa đánh giá"
              : computedRisks.length > 0
                ? `${overallScore}/25 · ${getSeverityLabel(overallSeverity, language)}`
                : isEn
                  ? "No risk results"
                  : "Chưa có kết quả rủi ro"}
          </h3>
        </div>
        {isEvaluated && computedRisks.length > 0 && (
          <span
            className="flow-overall-summary__pill"
            style={{
              borderColor: SEVERITY_COLORS[overallSeverity],
              color: SEVERITY_COLORS[overallSeverity],
            }}
          >
            <span
              className="severity-dot"
              style={{ backgroundColor: SEVERITY_COLORS[overallSeverity] }}
            />
            {overallScore}/25 · {getSeverityLabel(overallSeverity, language)}
          </span>
        )}
      </div>

      {/* INFINITE 2D VIEWPORT WITH PAN, ZOOM, FREE DRAG & PRESS-HOLD-DRAG WIRING */}
      <div
        className="flow-infinite-viewport"
        ref={viewportRef}
        onMouseDown={handleCanvasMouseDown}
      >
        {/* Floating Viewport HUD Controls */}
        <div className="flow-hud-controls" onMouseDown={(e) => e.stopPropagation()}>
          <button
            type="button"
            className="flow-hud-btn"
            onClick={() => setZoom((z) => Math.max(0.35, Number((z - 0.1).toFixed(2))))}
            title={isEn ? "Zoom Out" : "Thu nhỏ"}
          >
            −
          </button>
          <span className="flow-hud-zoom">{Math.round(zoom * 100)}%</span>
          <button
            type="button"
            className="flow-hud-btn"
            onClick={() => setZoom((z) => Math.min(1.8, Number((z + 0.1).toFixed(2))))}
            title={isEn ? "Zoom In" : "Phóng to"}
          >
            +
          </button>
          <button
            type="button"
            className="flow-hud-btn"
            onClick={() => {
              setPan({ x: 20, y: 15 });
              setZoom(0.85);
            }}
          >
            {isEn ? "Fit View" : "Toàn cảnh"}
          </button>
          <button
            type="button"
            className={`flow-hud-btn${showAllWireFormulas ? " flow-hud-btn--active" : ""}`}
            onClick={() => setShowAllWireFormulas((v) => !v)}
          >
            {showAllWireFormulas
              ? isEn
                ? "Formulas: All"
                : "Công thức: Tất cả"
              : isEn
                ? "Formulas: Focused"
                : "Công thức: Theo nhánh"}
          </button>
        </div>

        {/* Transformed 2D World Space */}
        <div
          className="flow-infinite-world"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
          }}
        >
          {/* 1. BACKGROUND SVG LAYER (z-index: 2) — Non-highlighted wires only */}
          <svg className="flow-world-svg flow-world-svg--back" aria-hidden="true">
            {edges.map((edge, idx) => {
              const info = getEdgeFormulaLabel(edge);
              if (info.isHighlighted) return null;
              const p1 = socketCoords.out[edge.fromId];
              const p2 = socketCoords.in[edge.toId];
              if (!p1 || !p2) return null;
              const dx = Math.max(60, Math.abs(p2.x - p1.x) * 0.45);
              const path = `M ${p1.x} ${p1.y} C ${p1.x + dx} ${p1.y}, ${p2.x - dx} ${p2.y}, ${p2.x} ${p2.y}`;
              const t = 0.44 + ((idx % 3) - 1) * 0.08;
              const midX = p1.x + (p2.x - p1.x) * t;
              const midY = p1.y + (p2.y - p1.y) * t;

              return (
                <g
                  key={edge.id}
                  className="flow-wire-group"
                  onClick={(e) => {
                    e.stopPropagation();
                    removeEdge(edge.id);
                  }}
                >
                  <path d={path} className="flow-wire-hit" />
                  <path d={path} className="flow-wire-line" />
                  <circle cx={p1.x} cy={p1.y} r={3.5} className="flow-wire-dot" />
                  <circle cx={p2.x} cy={p2.y} r={3.5} className="flow-wire-dot" />

                  {showAllWireFormulas && info.result && (
                    <g transform={`translate(${midX}, ${midY})`}>
                      <rect
                        x={-92}
                        y={-19}
                        width={184}
                        height={36}
                        rx={7}
                        className="flow-wire-badge"
                      />
                      <text y={-4} textAnchor="middle" className="flow-wire-text-formula">
                        {info.formula}
                      </text>
                      <text y={11} textAnchor="middle" className="flow-wire-text-result">
                        {info.result}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}
          </svg>

          {/* 2. FOREGROUND HIGHLIGHTED SVG LAYER (z-index: 16) — Always renders on top of all nodes & banners */}
          <svg className="flow-world-svg flow-world-svg--front" aria-hidden="true">
            {/* Pass A: Highlighted wire curves first */}
            {edges.map((edge) => {
              const info = getEdgeFormulaLabel(edge);
              if (!info.isHighlighted) return null;
              const p1 = socketCoords.out[edge.fromId];
              const p2 = socketCoords.in[edge.toId];
              if (!p1 || !p2) return null;
              const dx = Math.max(60, Math.abs(p2.x - p1.x) * 0.45);
              const path = `M ${p1.x} ${p1.y} C ${p1.x + dx} ${p1.y}, ${p2.x - dx} ${p2.y}, ${p2.x} ${p2.y}`;

              return (
                <g
                  key={`line_${edge.id}`}
                  className="flow-wire-group flow-wire-group--active"
                  onClick={(e) => {
                    e.stopPropagation();
                    removeEdge(edge.id);
                  }}
                >
                  <path d={path} className="flow-wire-hit" />
                  <path d={path} className="flow-wire-line flow-wire-line--active" />
                  <circle cx={p1.x} cy={p1.y} r={5} className="flow-wire-dot flow-wire-dot--active" />
                  <circle cx={p2.x} cy={p2.y} r={5} className="flow-wire-dot flow-wire-dot--active" />
                </g>
              );
            })}

            {/* Layer 4 active trace wire curves (Only shown after clicking Run Evaluation) */}
            {isEvaluated &&
              activeFocusRisk &&
              (activeFocusRisk.controlNodes.length > 0
                ? activeFocusRisk.controlNodes
                : activeFocusRisk.contextNodes.length > 0
                  ? activeFocusRisk.contextNodes
                  : activeFocusRisk.sourceNodes
              ).map((feedingNode) => {
                const p1 = socketCoords.out[feedingNode.id];
                const p2 = socketCoords.in[`L4_${activeFocusRisk.riskId}`];
                if (!p1 || !p2) return null;
                const dx = Math.max(60, Math.abs(p2.x - p1.x) * 0.45);
                const path = `M ${p1.x} ${p1.y} C ${p1.x + dx} ${p1.y}, ${p2.x - dx} ${p2.y}, ${p2.x} ${p2.y}`;
                return (
                  <g
                    key={`l4line_${feedingNode.id}_${activeFocusRisk.riskId}`}
                    className="flow-wire-group flow-wire-group--active"
                  >
                    <path d={path} className="flow-wire-line flow-wire-line--active" />
                    <circle cx={p1.x} cy={p1.y} r={5} className="flow-wire-dot flow-wire-dot--active" />
                    <circle cx={p2.x} cy={p2.y} r={5} className="flow-wire-dot flow-wire-dot--active" />
                  </g>
                );
              })}

            {/* Pass B: Highlighted Formula Badges rendered AFTER all lines so no wire ever overlaps text */}
            {edges.map((edge, idx) => {
              const info = getEdgeFormulaLabel(edge);
              if (!info.isHighlighted || !info.result) return null;
              const p1 = socketCoords.out[edge.fromId];
              const p2 = socketCoords.in[edge.toId];
              if (!p1 || !p2) return null;
              const t = 0.44 + ((idx % 3) - 1) * 0.08;
              const midX = p1.x + (p2.x - p1.x) * t;
              const midY = p1.y + (p2.y - p1.y) * t;
              return (
                <g
                  key={`badge_${edge.id}`}
                  transform={`translate(${midX}, ${midY})`}
                  className="flow-wire-badge-group"
                  onClick={(e) => {
                    e.stopPropagation();
                    removeEdge(edge.id);
                  }}
                >
                  <rect
                    x={-94}
                    y={-20}
                    width={188}
                    height={38}
                    rx={7}
                    className="flow-wire-badge flow-wire-badge--active"
                  />
                  <text y={-4} textAnchor="middle" className="flow-wire-text-formula">
                    {info.formula}
                  </text>
                  <text y={11} textAnchor="middle" className="flow-wire-text-result">
                    {info.result}
                  </text>
                </g>
              );
            })}

            {isEvaluated &&
              activeFocusRisk &&
              (activeFocusRisk.controlNodes.length > 0
                ? activeFocusRisk.controlNodes
                : activeFocusRisk.contextNodes.length > 0
                  ? activeFocusRisk.contextNodes
                  : activeFocusRisk.sourceNodes
              ).map((feedingNode) => {
                const p1 = socketCoords.out[feedingNode.id];
                const p2 = socketCoords.in[`L4_${activeFocusRisk.riskId}`];
                if (!p1 || !p2) return null;
                const midX = (p1.x + p2.x) / 2;
                const midY = (p1.y + p2.y) / 2;
                return (
                  <g
                    key={`l4badge_${feedingNode.id}_${activeFocusRisk.riskId}`}
                    transform={`translate(${midX}, ${midY})`}
                    className="flow-wire-badge-group"
                  >
                    <rect
                      x={-90}
                      y={-20}
                      width={180}
                      height={38}
                      rx={7}
                      className="flow-wire-badge flow-wire-badge--active"
                    />
                    <text y={-4} textAnchor="middle" className="flow-wire-text-formula">
                      {`R = L_final(${activeFocusRisk.finalL}) × I(${activeFocusRisk.finalI})`}
                    </text>
                    <text y={11} textAnchor="middle" className="flow-wire-text-result">
                      {`Out: ${activeFocusRisk.finalScore}/25 (${activeFocusRisk.severity})`}
                    </text>
                  </g>
                );
              })}

            {/* LIVE RUBBER-BAND WIRE WHILE USER HOLDS & DRAGS FROM AN OUTPUT SOCKET */}
            {activeWireDrag && (
              <g className="flow-wire-dragging">
                <path
                  d={`M ${activeWireDrag.startX} ${activeWireDrag.startY} C ${
                    activeWireDrag.startX + 80
                  } ${activeWireDrag.startY}, ${activeWireDrag.currX - 80} ${
                    activeWireDrag.currY
                  }, ${activeWireDrag.currX} ${activeWireDrag.currY}`}
                  className="flow-wire-line flow-wire-line--dragging"
                />
                <circle
                  cx={activeWireDrag.currX}
                  cy={activeWireDrag.currY}
                  r={7}
                  className="flow-wire-cursor-dot"
                />
              </g>
            )}
          </svg>

          {/* DRAGGABLE LAYER GROUP HEADERS (Drag to move entire Layer at once!) */}
          {([1, 2, 3, 4] as const).map((layerNum) => {
            const pos = layerHeaders[layerNum];
            const title =
              layerNum === 1
                ? isEn
                  ? "Layer 1 · Architecture & Triggers"
                  : "Lớp 1 · Nguồn Kích hoạt & Kiến trúc"
                : layerNum === 2
                  ? isEn
                    ? "Layer 2 · Context Modifiers"
                    : "Lớp 2 · Biến đổi Ngữ cảnh"
                  : layerNum === 3
                    ? isEn
                      ? "Layer 3 · Security Controls"
                      : "Lớp 3 · Kiểm soát Kỹ thuật"
                    : isEn
                      ? `Layer 4 · Residual Output (${computedRisks.length})`
                      : `Lớp 4 · Đầu ra Rủi ro (${computedRisks.length})`;
            const formula =
              layerNum === 1
                ? "Out: (L_base, I_base)"
                : layerNum === 2
                  ? "L_ctx = clamp(L_base + ΣΔL)"
                  : layerNum === 3
                    ? "L_final = round(L_ctx × (1 - min(0.8, Σw)))"
                    : `R_final = L_final × I_ctx (Max ${overallScore}/25 · ${overallSeverity})`;

            return (
              <div
                key={`header_${layerNum}`}
                className="flow-layer-banner"
                style={{
                  left: `${pos.x}px`,
                  top: `${pos.y}px`,
                  width: `${NODE_WIDTH}px`,
                }}
                onMouseDown={(e) => startLayerDrag(e, layerNum)}
                title={
                  isEn
                    ? "Drag header to move all nodes in this layer together"
                    : "Kéo thanh tiêu đề này để di chuyển toàn bộ các nút trong Lớp"
                }
              >
                <span className="flow-column__step">0{layerNum}</span>
                <div>
                  <h4>{title}</h4>
                  <code>{formula}</code>
                </div>
              </div>
            );
          })}

          {/* FREELY DRAGGABLE NODES IN LAYERS 1, 2, 3 */}
          {nodes.map((node) => {
            const outSummary = getNodeOutputPortSummary(node);
            const isSelected = selectedNodeId === node.id;
            const isPartOfFocus = Boolean(
              activeFocusRisk &&
                (activeFocusRisk.sourceNodes.some((s) => s.id === node.id) ||
                  activeFocusRisk.contextNodes.some((c) => c.id === node.id) ||
                  activeFocusRisk.controlNodes.some((k) => k.id === node.id)),
            );

            const isValidDropTarget = Boolean(
              activeWireDrag &&
                (() => {
                  const src = nodes.find((n) => n.id === activeWireDrag.fromNodeId);
                  return src && node.layer > src.layer;
                })(),
            );
            const isSnappedTarget = activeWireDrag?.hoveredTargetId === node.id;

            return (
              <article
                key={node.id}
                className={`flow-node flow-node--abs flow-node--l${node.layer}${
                  isSelected ? " flow-node--selected" : ""
                }${isPartOfFocus ? " flow-node--focused" : activeFocusRisk ? " flow-node--dimmed" : ""}${
                  isSnappedTarget ? " flow-node--snap-target" : ""
                }`}
                style={{
                  left: `${node.x}px`,
                  top: `${node.y}px`,
                  width: `${NODE_WIDTH}px`,
                }}
                onMouseDown={(e) => startNodeDrag(e, node)}
              >
                {/* Dedicated Protruding Left INPUT Socket (● IN) */}
                {node.layer > 1 && (
                  <button
                    type="button"
                    className={`flow-socket flow-socket--in${
                      isValidDropTarget ? " flow-socket--valid" : ""
                    }${isSnappedTarget ? " flow-socket--snapped" : ""}`}
                    style={{ top: `${PORT_OFFSET_Y}px` }}
                    title={
                      isEn
                        ? "Input Socket: Drag a wire from an upstream Output socket and release here"
                        : "Nút Đầu vào (IN): Kéo dây từ nút Đầu ra (OUT) của nút lớp trước và thả vào đây"
                    }
                    onMouseDown={(e) => e.stopPropagation()}
                  >
                    <span className="flow-socket__dot" />
                    <span className="flow-socket__label">IN</span>
                  </button>
                )}

                {/* Dedicated Protruding Right OUTPUT Socket (OUT ●) — Press & Hold to drag wire! */}
                <button
                  type="button"
                  className={`flow-socket flow-socket--out${
                    activeWireDrag?.fromNodeId === node.id ? " flow-socket--dragging" : ""
                  }`}
                  style={{ top: `${PORT_OFFSET_Y}px` }}
                  onMouseDown={(e) => startWireDragFromOutput(e, node)}
                  title={
                    isEn
                      ? "Output Socket: Press, hold, and drag to another node's IN socket"
                      : "Nút Đầu ra (OUT): Nhấn giữ chuột và kéo sang nút IN của nút khác để nối dây"
                  }
                >
                  <span className="flow-socket__label">OUT</span>
                  <span className="flow-socket__dot" />
                </button>

                <div className="flow-node__top">
                  <div className="flow-node__badges">
                    <code>{node.code}</code>
                    {node.isCustom && (
                      <span className="source-badge source-badge--ai">
                        {node.aiSuggested ? "✦ AI Custom" : "Custom"}
                      </span>
                    )}
                  </div>
                  <button
                    type="button"
                    className="flow-node__remove"
                    onClick={(e) => {
                      e.stopPropagation();
                      removeNode(node.id);
                    }}
                    title={isEn ? "Remove node" : "Xóa nút"}
                  >
                    ×
                  </button>
                </div>

                <strong className="flow-node__title">
                  {isEn ? node.labelEn : node.label}
                </strong>
                <small className="flow-node__sub">
                  {isEn ? node.subtitleEn : node.subtitle}
                </small>

                <div className="flow-node__formula-pill">
                  <code>{formatNodeFormulaBadge(node)}</code>
                </div>

                <div className="flow-node__out-readout" title={outSummary.formulaText}>
                  <span>{isEn ? "Output params:" : "Tham số ra:"}</span>{" "}
                  <code>{outSummary.paramText}</code>
                </div>
              </article>
            );
          })}

          {/* FREELY DRAGGABLE LAYER 4 OUTPUT RISK NODES (Shown only after clicking Run Evaluation!) */}
          {!isEvaluated ? (
            <article
              className="flow-node flow-node--abs flow-node--l4-empty"
              style={{
                left: `${layerHeaders[4].x}px`,
                top: `${layerHeaders[4].y + 85}px`,
                width: `${NODE_WIDTH}px`,
              }}
            >
              <strong>
                {isEn ? "No Results Yet" : "Chưa có kết quả"}
              </strong>
              <button
                type="button"
                className="flow-eval-btn"
                disabled={isEvaluatingGraph}
                onClick={(e) => {
                  e.stopPropagation();
                  void handleRunGraphEvaluation();
                }}
              >
                {isEvaluatingGraph
                  ? isEn
                    ? "✦ Evaluating..."
                    : "✦ Đang đánh giá..."
                  : isEn
                    ? "▶ Run Evaluation"
                    : "▶ Đánh giá"}
              </button>
            </article>
          ) : computedRisks.length === 0 ? (
            <article
              className="flow-node flow-node--abs flow-node--l4-empty"
              style={{
                left: `${layerHeaders[4].x}px`,
                top: `${layerHeaders[4].y + 85}px`,
                width: `${NODE_WIDTH}px`,
              }}
            >
              <strong>
                {isEn ? "No Complete Wire Chain" : "Chưa nối đủ 3 lớp"}
              </strong>
            </article>
          ) : (
            computedRisks.map((trace, idx) => {
              const pos = getL4NodePos(trace.riskId, idx);
              const isFocused = activeFocusRisk?.riskId === trace.riskId;
              return (
                <article
                  key={trace.riskId}
                  className={`flow-node flow-node--abs flow-node--l4${
                    isFocused
                      ? " flow-node--focused"
                      : activeFocusRisk
                        ? " flow-node--dimmed"
                        : ""
                  }`}
                  style={{
                    left: `${pos.x}px`,
                    top: `${pos.y}px`,
                    width: `${NODE_WIDTH}px`,
                    borderLeftColor: SEVERITY_COLORS[trace.severity],
                  }}
                  onMouseDown={(e) => startL4NodeDrag(e, trace.riskId, pos)}
                >
                  {/* Protruding Left Input Socket for Layer 4 Risk Node */}
                  <button
                    type="button"
                    className={`flow-socket flow-socket--in${
                      isFocused ? " flow-socket--focused-out" : ""
                    }`}
                    style={{ top: `${PORT_OFFSET_Y}px` }}
                    onClick={(e) => {
                      e.stopPropagation();
                      setFocusedRiskId(trace.riskId);
                    }}
                  >
                    <span className="flow-socket__dot" />
                    <span className="flow-socket__label">IN</span>
                  </button>

                  <div className="flow-node__top">
                    <div className="flow-node__badges">
                      <code>{trace.riskId}</code>
                      {trace.isAiGraphRisk && (
                        <span className="source-badge source-badge--ai">
                          ✦ {trace.aiSource === "llm" ? "Gemini AI" : "AI Fallback"}
                        </span>
                      )}
                    </div>
                    <span
                      className="severity-badge"
                      style={{
                        backgroundColor: SEVERITY_COLORS[trace.severity],
                        color: "#fff",
                      }}
                    >
                      {trace.finalScore}/25 · {getSeverityLabel(trace.severity, language)}
                    </span>
                  </div>

                  <strong className="flow-node__title">{trace.title}</strong>

                  <div className="flow-l4-trace">
                    <div>
                      <span>1. Base ({trace.sourceNodes.map((s) => s.code).join(", ")}):</span>{" "}
                      <code>
                        L={trace.baseL}, I={trace.baseI} (R={trace.baseScore})
                      </code>
                    </div>
                    <div>
                      <span>2. Ctx:</span>{" "}
                      <code>
                        L={trace.ctxL}, I={trace.ctxI} (R={trace.ctxScore})
                      </code>
                    </div>
                    <div>
                      <span>3. Final:</span>{" "}
                      <code>
                        W={(trace.cappedDiscountW * 100).toFixed(0)}% → L={trace.finalL} × I=
                        {trace.finalI} = {trace.finalScore}/25
                      </code>
                    </div>
                  </div>
                </article>
              );
            })
          )}
        </div>
      </div>

      {/* Gemini AI Graph-Level Executive Verdict placed BELOW canvas so it never shifts canvas position */}
      {isEvaluated && useAiEvaluation && graphAiResult && (
        <section className="flow-ai-assist-box" aria-live="polite">
          <div className="report__section-top">
            <span
              className={`source-badge ${
                graphAiResult.source === "llm" ? "source-badge--ai" : "source-badge--system"
              }`}
            >
              <span className="source-badge__icon" aria-hidden="true">
                {graphAiResult.source === "llm" ? "✦" : "▣"}
              </span>
              <span>
                {graphAiResult.source === "llm"
                  ? isEn
                    ? "Gemini AI Graph Evaluation"
                    : "Đánh giá đồ thị từ Gemini AI"
                  : isEn
                    ? "AI Graph Evaluation (Heuristic Fallback)"
                    : "Đánh giá đồ thị AI (Chế độ dự phòng)"}
              </span>
            </span>
            <small className="dev-formula-hint">
              {isEn
                ? `Contributed ${graphAiResult.ai_risks.length} emergent cross-chain risk(s) to Layer 4`
                : `Đã đóng góp ${graphAiResult.ai_risks.length} rủi ro liên chuỗi vào Lớp 4`}
            </small>
          </div>
          <p style={{ margin: 0, fontSize: "0.88rem" }}>{graphAiResult.executive_summary}</p>
        </section>
      )}

      {/* Highlighted 4-Stage Equation Trace placed BELOW canvas */}
      {isEvaluated && activeFocusRisk && (
        <section className="flow-equation-banner" aria-live="polite">
          <div className="report__section-top">
            <div>
              <h3>
                {activeFocusRisk.riskId} — {activeFocusRisk.title}
              </h3>
            </div>
            <button
              type="button"
              className="button-secondary"
              onClick={() => setFocusedRiskId(null)}
            >
              {isEn ? "Close" : "Đóng"}
            </button>
          </div>

          <div className="flow-equation-steps">
            <div className="flow-eq-step">
              <span className="flow-eq-step__tag">
                {isEn ? "Stage 1 · Layer 1 Output" : "Chặng 1 · Đầu ra Lớp 1 (Gốc)"}
              </span>
              <code>
                L_base = {activeFocusRisk.baseL}, I_base = {activeFocusRisk.baseI} ⇒ R_base ={" "}
                {activeFocusRisk.baseScore}
              </code>
              <small>
                {isEn ? "Emitted by: " : "Phát ra từ nút: "}
                {activeFocusRisk.sourceNodes.map((n) => n.code).join(", ")}
              </small>
            </div>

            <span className="flow-eq-arrow" aria-hidden="true">
              →
            </span>

            <div className="flow-eq-step">
              <span className="flow-eq-step__tag">
                {isEn ? "Stage 2 · Layer 2 Output" : "Chặng 2 · Đầu ra Lớp 2 (Ngữ cảnh)"}
              </span>
              <code>
                L_ctx = {activeFocusRisk.ctxFormulaL} | I_ctx = {activeFocusRisk.ctxFormulaI} ⇒
                R_ctx = {activeFocusRisk.ctxScore}
              </code>
              <small>
                {activeFocusRisk.contextNodes.length > 0
                  ? `${isEn ? "Applied: " : "Qua nút: "}${activeFocusRisk.contextNodes.map((n) => `${n.code} (${formatNodeFormulaBadge(n)})`).join(", ")}`
                  : isEn
                    ? "No matching Layer 2 context nodes wired"
                    : "Chưa nối nút ngữ cảnh Lớp 2 nào tác động"}
              </small>
            </div>

            <span className="flow-eq-arrow" aria-hidden="true">
              →
            </span>

            <div className="flow-eq-step">
              <span className="flow-eq-step__tag">
                {isEn ? "Stage 3 · Layer 3 Output" : "Chặng 3 · Đầu ra Lớp 3 (Kiểm soát)"}
              </span>
              <code>
                W = min(0.80, {activeFocusRisk.rawDiscountW.toFixed(2)}) ={" "}
                {(activeFocusRisk.cappedDiscountW * 100).toFixed(0)}% | L_final ={" "}
                {activeFocusRisk.finalFormulaL}
              </code>
              <small>
                {activeFocusRisk.controlNodes.length > 0
                  ? `${isEn ? "Controls: " : "Qua kiểm soát: "}${activeFocusRisk.controlNodes.map((n) => `${n.code} (-${Math.round((n.discountW ?? 0) * 100)}%)`).join(", ")}`
                  : isEn
                    ? "No applicable Layer 3 controls wired (W = 0%)"
                    : "Chưa nối nút kiểm soát Lớp 3 hợp lệ (W = 0%)"}
              </small>
            </div>

            <span className="flow-eq-arrow" aria-hidden="true">
              →
            </span>

            <div className="flow-eq-step flow-eq-step--final">
              <span className="flow-eq-step__tag">
                {isEn ? "Stage 4 · Residual Output" : "Chặng 4 · Điểm Rủi ro Cuối"}
              </span>
              <code>
                R_final = L_final({activeFocusRisk.finalL}) × I_final({activeFocusRisk.finalI}) ={" "}
                {activeFocusRisk.finalScore}/25 ({activeFocusRisk.severity})
              </code>
              <small>{activeFocusRisk.owasp.join(" · ")}</small>
            </div>
          </div>
        </section>
      )}

      {/* Inline Live Node Parameter & Formula Editor for Selected Node */}
      {selectedNode && (
        <section className="flow-inspector" aria-live="polite">
          <div className="report__section-top">
            <div>
              <span className="report__pattern-eyebrow">
                {isEn
                  ? `NODE FORMULA INSPECTOR · LAYER ${selectedNode.layer}`
                  : `CHỈNH SỬA CÔNG THỨC & THAM SỐ NÚT · LỚP ${selectedNode.layer}`}
              </span>
              <h3>
                <code>{selectedNode.code}</code> —{" "}
                {isEn ? selectedNode.labelEn : selectedNode.label}
              </h3>
            </div>
            <button
              type="button"
              className="button-secondary"
              onClick={() => setSelectedNodeId(null)}
            >
              {isEn ? "Close Inspector" : "Đóng khung chỉnh sửa"}
            </button>
          </div>

          {selectedNode.layer === 1 && (
            <div className="flow-inspector__grid">
              {(selectedNode.emittedRisks ?? []).map((er, idx) => (
                <div key={er.id} className="flow-inspector__card">
                  <strong>
                    <code>{er.id}</code> — {isEn ? er.titleEn : er.title}
                  </strong>
                  <div className="dev-form__two-col">
                    <label>
                      <span>
                        L_base (1–5): <strong>{er.baseL}</strong>
                      </span>
                      <input
                        type="range"
                        min={1}
                        max={5}
                        step={1}
                        value={er.baseL}
                        onChange={(e) => {
                          const nextL = Number(e.target.value);
                          setNodes((prev) =>
                            prev.map((n) =>
                              n.id === selectedNode.id
                                ? {
                                    ...n,
                                    emittedRisks: (n.emittedRisks ?? []).map((item, i) =>
                                      i === idx ? { ...item, baseL: nextL } : item,
                                    ),
                                  }
                                : n,
                            ),
                          );
                        }}
                      />
                    </label>
                    <label>
                      <span>
                        I_base (1–5): <strong>{er.baseI}</strong>
                      </span>
                      <input
                        type="range"
                        min={1}
                        max={5}
                        step={1}
                        value={er.baseI}
                        onChange={(e) => {
                          const nextI = Number(e.target.value);
                          setNodes((prev) =>
                            prev.map((n) =>
                              n.id === selectedNode.id
                                ? {
                                    ...n,
                                    emittedRisks: (n.emittedRisks ?? []).map((item, i) =>
                                      i === idx ? { ...item, baseI: nextI } : item,
                                    ),
                                  }
                                : n,
                            ),
                          );
                        }}
                      />
                    </label>
                  </div>
                  <code>
                    Out: L_base={er.baseL} × I_base={er.baseI} = {er.baseL * er.baseI}/25
                  </code>
                </div>
              ))}
            </div>
          )}

          {selectedNode.layer === 2 && (
            <div className="dev-form__two-col">
              <label>
                <span>
                  {isEn ? "Likelihood Shift ΔL (-3..+3):" : "Độ lệch Khả năng xảy ra ΔL (-3..+3):"}{" "}
                  <strong>
                    {(selectedNode.deltaL ?? 0) > 0
                      ? `+${selectedNode.deltaL}`
                      : selectedNode.deltaL ?? 0}
                  </strong>
                </span>
                <input
                  type="range"
                  min={-3}
                  max={3}
                  step={1}
                  value={selectedNode.deltaL ?? 0}
                  onChange={(e) => {
                    const val = Number(e.target.value);
                    setNodes((prev) =>
                      prev.map((n) =>
                        n.id === selectedNode.id ? { ...n, deltaL: val } : n,
                      ),
                    );
                  }}
                />
              </label>
              <label>
                <span>
                  {isEn ? "Impact Shift ΔI (-3..+3):" : "Độ lệch Mức ảnh hưởng ΔI (-3..+3):"}{" "}
                  <strong>
                    {(selectedNode.deltaI ?? 0) > 0
                      ? `+${selectedNode.deltaI}`
                      : selectedNode.deltaI ?? 0}
                  </strong>
                </span>
                <input
                  type="range"
                  min={-3}
                  max={3}
                  step={1}
                  value={selectedNode.deltaI ?? 0}
                  onChange={(e) => {
                    const val = Number(e.target.value);
                    setNodes((prev) =>
                      prev.map((n) =>
                        n.id === selectedNode.id ? { ...n, deltaI: val } : n,
                      ),
                    );
                  }}
                />
              </label>
            </div>
          )}

          {selectedNode.layer === 3 && (
            <div className="dev-form__two-col">
              <label>
                <span>
                  {isEn
                    ? "Control Discount Weight w (5%..80%):"
                    : "Trọng số khấu trừ kiểm soát w (5%..80%):"}{" "}
                  <strong>{Math.round((selectedNode.discountW ?? 0.35) * 100)}%</strong>
                </span>
                <input
                  type="range"
                  min={5}
                  max={80}
                  step={5}
                  value={Math.round((selectedNode.discountW ?? 0.35) * 100)}
                  onChange={(e) => {
                    const w = Number(e.target.value) / 100;
                    setNodes((prev) =>
                      prev.map((n) =>
                        n.id === selectedNode.id ? { ...n, discountW: w } : n,
                      ),
                    );
                  }}
                />
              </label>
              <label>
                <span>
                  {isEn ? "Impact Reduction ΔI (-2..0):" : "Giảm mức ảnh hưởng ΔI (-2..0):"}{" "}
                  <strong>{selectedNode.controlDeltaI ?? 0}</strong>
                </span>
                <input
                  type="range"
                  min={-2}
                  max={0}
                  step={1}
                  value={selectedNode.controlDeltaI ?? 0}
                  onChange={(e) => {
                    const di = Number(e.target.value);
                    setNodes((prev) =>
                      prev.map((n) =>
                        n.id === selectedNode.id ? { ...n, controlDeltaI: di } : n,
                      ),
                    );
                  }}
                />
              </label>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
