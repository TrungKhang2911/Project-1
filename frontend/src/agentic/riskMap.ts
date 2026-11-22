/**
 * Agentic pattern -> security risk mapping (Bilingual VI / EN).
 *
 * Scoring follows the 5x5 model:
 *   score = likelihood (1-5) x impact (1-5)
 *   Low 1-5 | Medium 6-11 | High 12-19 | Critical 20-25
 */
import type {
  AgenticPattern,
  Autonomy,
  Collaboration,
  Language,
  PatternDetection,
  QuestionnaireAnswers,
  Resource,
} from "../types";

export type Severity = "Low" | "Medium" | "High" | "Critical";
type Level = 1 | 2 | 3 | 4 | 5;

export type RiskKind = "injection" | "action" | "leak" | "integrity" | "control" | "cost";

export interface TechnicalControlSpec {
  id: string;
  name: string;
  description: string;
  descriptionEn: string;
  weight: number;
}

export const TECHNICAL_CONTROLS: Record<string, TechnicalControlSpec> = {
  CTRL_SYS_PROMPT_SEP: {
    id: "CTRL_SYS_PROMPT_SEP",
    name: "System Prompt & Untrusted Data Delimitation",
    description: "Tách biệt chỉ thị hệ thống và dữ liệu đầu vào bằng cấu trúc phân cách và cô lập vai trò.",
    descriptionEn: "Strictly separate system instructions from untrusted user data using structured delimiters and role isolation.",
    weight: 0.25,
  },
  CTRL_GUARDRAILS: {
    id: "CTRL_GUARDRAILS",
    name: "Input / Output Semantic Guardrails",
    description: "Bộ lọc phát hiện thao túng chỉ thị, nội dung độc hại và kiểm duyệt đầu ra.",
    descriptionEn: "Semantic filters to detect prompt injection, policy violations, and unsafe model outputs.",
    weight: 0.35,
  },
  CTRL_TOOL_ALLOWLIST: {
    id: "CTRL_TOOL_ALLOWLIST",
    name: "Least-Privilege Tool Allowlist & Schema Validation",
    description: "Giới hạn danh sách công cụ tối thiểu cho từng tác nhân kèm kiểm tra định dạng tham số.",
    descriptionEn: "Restrict each agent to an explicit tool allowlist with strict JSON schema parameter validation.",
    weight: 0.35,
  },
  CTRL_STEP_BUDGET: {
    id: "CTRL_STEP_BUDGET",
    name: "Execution Step Cap & Token/Cost Quota",
    description: "Giới hạn số bước suy luận tối đa, thời gian chờ và hạn mức chi phí cho mỗi phiên.",
    descriptionEn: "Enforce maximum reasoning iterations, execution timeouts, and per-session token/cost quotas.",
    weight: 0.40,
  },
  CTRL_INTER_AGENT_VALIDATION: {
    id: "CTRL_INTER_AGENT_VALIDATION",
    name: "Inter-Agent Message Schema & Sanitization",
    description: "Xác thực định dạng và làm sạch dữ liệu trung gian khi truyền thông điệp giữa các tác nhân.",
    descriptionEn: "Validate message schemas and sanitize intermediate payloads passed between agents.",
    weight: 0.35,
  },
  CTRL_CONTEXT_ISOLATION: {
    id: "CTRL_CONTEXT_ISOLATION",
    name: "Per-Task Ephemeral Memory & Context Isolation",
    description: "Cô lập bộ nhớ ngữ cảnh giữa các luồng xử lý song song và giữa các phiên người dùng.",
    descriptionEn: "Isolate memory state across parallel sub-tasks and distinct user sessions.",
    weight: 0.40,
  },
  CTRL_SCOPED_DELEGATION: {
    id: "CTRL_SCOPED_DELEGATION",
    name: "Cryptographic Scoped Token Delegation",
    description: "Mỗi tác nhân con xác thực quyền tối thiểu theo token phạm vi hẹp, chống leo thang đặc quyền.",
    descriptionEn: "Enforce least-privilege scoped tokens per sub-agent to prevent confused-deputy privilege escalation.",
    weight: 0.40,
  },
  CTRL_DETERMINISTIC_ROUTER: {
    id: "CTRL_DETERMINISTIC_ROUTER",
    name: "Deterministic Guardrail Checkpoint on Routing",
    description: "Khóa luồng điều phối qua cổng kiểm tra cố định không thể bị ghi đè bởi mô hình.",
    descriptionEn: "Enforce deterministic policy checkpoints on routing decisions that cannot be bypassed by the LLM.",
    weight: 0.35,
  },
  CTRL_IMMUTABLE_TRACE_LOG: {
    id: "CTRL_IMMUTABLE_TRACE_LOG",
    name: "Immutable Multi-Agent Telemetry & Audit Trail",
    description: "Ghi nhật ký bất biến toàn bộ chuỗi suy luận, lời gọi công cụ và giao tiếp liên tác nhân.",
    descriptionEn: "Record tamper-evident audit logs for all reasoning steps, tool calls, and inter-agent messages.",
    weight: 0.35,
  },
  CTRL_RAG_INGEST_FILTER: {
    id: "CTRL_RAG_INGEST_FILTER",
    name: "Corpus Ingestion Sanitization & Provenance Signing",
    description: "Quét nội dung độc hại và xác thực nguồn gốc tài liệu trước khi đưa vào kho tri thức.",
    descriptionEn: "Scan ingested documents for indirect injection payloads and verify document provenance before indexing.",
    weight: 0.35,
  },
  CTRL_RAG_ACL: {
    id: "CTRL_RAG_ACL",
    name: "Document-Level ACL Enforcement on Vector Retrieval",
    description: "Áp dụng kiểm soát truy cập theo định danh người dùng ngay tại bước truy vấn tài liệu.",
    descriptionEn: "Enforce per-user document access control lists directly during vector retrieval queries.",
    weight: 0.45,
  },
  CTRL_DLP_REDACTION: {
    id: "CTRL_DLP_REDACTION",
    name: "PII/PCI Redaction & Read-Only DB Views",
    description: "Che dấu dữ liệu nhạy cảm và ưu tiên kết nối cơ sở dữ liệu ở chế độ chỉ đọc.",
    descriptionEn: "Mask sensitive PII/financial fields and restrict database connections to read-only views where possible.",
    weight: 0.40,
  },
};

export interface RiskTemplate {
  id: string;
  kind: RiskKind;
  title: string;
  titleEn: string;
  explanation: string;
  explanationEn: string;
  likelihood: Level;
  impact: Level;
  recommendations: string[];
  recommendationsEn: string[];
  boostWhenResources?: Resource[];
  technical: {
    name: string;
    owasp: string[];
    nist: string[];
    references: string[];
    mitigationControlIds: string[];
  };
}

/* ------------------------------------------------------------------ */
/* Risk catalogue                                                      */
/* ------------------------------------------------------------------ */

const RISKS = {
  PROMPT_INJECTION: {
    id: "PROMPT_INJECTION",
    kind: "injection",
    title: "Thao túng chỉ thị đầu vào",
    titleEn: "Direct Prompt Injection",
    explanation:
      "Người dùng có thể nhập nội dung được cấu trúc chủ đích nhằm vượt qua quy tắc kiểm soát, buộc hệ thống phản hồi trái phép hoặc tiết lộ cấu hình nội bộ.",
    explanationEn:
      "Adversarial inputs can override system instructions, causing the model to produce unauthorized responses or disclose internal configuration.",
    likelihood: 4,
    impact: 3,
    recommendations: [
      "Áp dụng bộ lọc kiểm duyệt đầu vào và đầu ra trước khi hiển thị kết quả.",
      "Thực hiện kiểm thử với các mẫu câu vượt rào phổ biến trước khi vận hành.",
      "Không lưu trữ mật khẩu hoặc khóa bí mật trong chỉ thị hệ thống.",
    ],
    recommendationsEn: [
      "Apply input and output validation guardrails before returning responses.",
      "Conduct adversarial testing against common injection patterns prior to deployment.",
      "Never store credentials or secrets inside system prompts.",
    ],
    technical: {
      name: "Direct prompt injection",
      owasp: ["OWASP LLM01:2025 Prompt Injection", "OWASP LLM07:2025 System Prompt Leakage"],
      nist: ["MAP 5.1", "MEASURE 2.7", "MANAGE 2.2"],
      references: ["OWASP LLM01:2025 Prompt Injection", "OWASP LLM07:2025 System Prompt Leakage"],
      mitigationControlIds: ["CTRL_SYS_PROMPT_SEP", "CTRL_GUARDRAILS"],
    },
  },
  TOOL_HIJACK: {
    id: "TOOL_HIJACK",
    kind: "action",
    title: "Thực thi công cụ ngoài ý muốn",
    titleEn: "Unauthorized Tool Execution",
    explanation:
      "Khi AI có quyền tự gọi công cụ hoặc thao tác dữ liệu, đầu vào độc hại có thể điều hướng hệ thống thực hiện tác vụ ngoài phạm vi cho phép.",
    explanationEn:
      "When an agent autonomously invokes tools or modifies data, crafted inputs can redirect it to execute unintended actions.",
    likelihood: 4,
    impact: 5,
    recommendations: [
      "Chỉ cấp quyền truy cập tối thiểu đối với các công cụ thực sự cần thiết.",
      "Yêu cầu phê duyệt thủ công đối với các tác vụ quan trọng như thanh toán, xóa dữ liệu hoặc gửi thư ra ngoài.",
      "Thiết lập hạn mức tần suất và giá trị cho từng loại thao tác.",
    ],
    recommendationsEn: [
      "Grant least-privilege access to only the tools strictly required.",
      "Require manual approval for high-impact actions such as payments, deletions, or external emails.",
      "Enforce rate limits and transaction thresholds on tool invocations.",
    ],
    boostWhenResources: ["web_search", "internal_docs"],
    technical: {
      name: "Prompt injection leading to unauthorized tool use (ReAct loop)",
      owasp: ["OWASP LLM01:2025 Prompt Injection", "OWASP LLM06:2025 Excessive Agency"],
      nist: ["MAP 3.5", "MEASURE 2.6", "MANAGE 2.4"],
      references: ["OWASP LLM01:2025 Prompt Injection", "OWASP LLM06:2025 Excessive Agency"],
      mitigationControlIds: ["CTRL_TOOL_ALLOWLIST", "CTRL_GUARDRAILS", "CTRL_SYS_PROMPT_SEP"],
    },
  },
  RUNAWAY_LOOP: {
    id: "RUNAWAY_LOOP",
    kind: "cost",
    title: "Vòng lặp thực thi không giới hạn",
    titleEn: "Unbounded Execution Loop",
    explanation:
      "Hệ thống tự lặp lại quá trình suy luận và gọi công cụ khi gặp tình huống bất thường, gây tiêu hao tài nguyên và làm chậm dịch vụ.",
    explanationEn:
      "An agent may repeatedly retry reasoning and tool calls when encountering unexpected states, exhausting compute budgets and degrading availability.",
    likelihood: 3,
    impact: 3,
    recommendations: [
      "Giới hạn số bước thực thi tối đa và thời gian chờ cho mỗi yêu cầu.",
      "Thiết lập hạn mức chi phí theo ngày và cảnh báo khi vượt ngưỡng.",
    ],
    recommendationsEn: [
      "Set strict maximum step counts and execution timeouts per request.",
      "Configure daily cost quotas and automated anomaly alerts.",
    ],
    technical: {
      name: "Unbounded agent loop / resource exhaustion",
      owasp: ["OWASP LLM10:2025 Unbounded Consumption"],
      nist: ["MEASURE 2.5", "MANAGE 2.3"],
      references: ["OWASP LLM10:2025 Unbounded Consumption"],
      mitigationControlIds: ["CTRL_STEP_BUDGET"],
    },
  },
  CASCADING_POISONING: {
    id: "CASCADING_POISONING",
    kind: "integrity",
    title: "Lan truyền dữ liệu sai lệch theo chuỗi",
    titleEn: "Cascading Pipeline Poisoning",
    explanation:
      "Trong quy trình nối tiếp, nếu bước đầu tiên tiếp nhận dữ liệu bị thao túng từ tài liệu hoặc trang web, sai lệch sẽ truyền dẫn qua các bước sau.",
    explanationEn:
      "In a sequential pipeline, untrusted or poisoned data ingested at an early stage propagates downstream and corrupts subsequent agent outputs.",
    likelihood: 3,
    impact: 4,
    recommendations: [
      "Xác thực và làm sạch kết quả trung gian trước khi chuyển sang bước tiếp theo.",
      "Kiểm soát độ tin cậy của nguồn dữ liệu đầu vào ngay từ bước đầu tiên.",
      "Ghi nhận nhật ký đầu ra tại từng bước để phục vụ đối soát sự cố.",
    ],
    recommendationsEn: [
      "Validate and sanitize intermediate outputs between sequential stages.",
      "Restrict initial ingestion to verified data sources.",
      "Log stage-by-stage outputs to support incident traceability.",
    ],
    boostWhenResources: ["internal_docs", "web_search"],
    technical: {
      name: "Cascading poisoning across sequential agents",
      owasp: ["OWASP LLM01:2025 Prompt Injection (Indirect)", "OWASP LLM04:2025 Data and Model Poisoning"],
      nist: ["MAP 4.1", "MEASURE 2.7", "MANAGE 3.1"],
      references: ["OWASP LLM01:2025 Prompt Injection (indirect)", "OWASP LLM04:2025 Data and Model Poisoning"],
      mitigationControlIds: ["CTRL_INTER_AGENT_VALIDATION", "CTRL_RAG_INGEST_FILTER", "CTRL_IMMUTABLE_TRACE_LOG"],
    },
  },
  CROSS_TASK_LEAK: {
    id: "CROSS_TASK_LEAK",
    kind: "leak",
    title: "Rò rỉ ngữ cảnh giữa các nhánh song song",
    titleEn: "Cross-Task Context Leakage",
    explanation:
      "Nhiều tác nhân xử lý đồng thời trên cùng vùng nhớ có thể làm lộ dữ liệu của tác vụ hoặc người dùng này sang kết quả của tác vụ khác.",
    explanationEn:
      "Concurrent agents sharing memory or context buffers may leak sensitive information across sub-tasks or user sessions.",
    likelihood: 3,
    impact: 4,
    recommendations: [
      "Cô lập vùng nhớ ngữ cảnh cho từng tác vụ và từng phiên người dùng.",
      "Rà soát và loại bỏ thông tin nhạy cảm tại bước tổng hợp kết quả.",
    ],
    recommendationsEn: [
      "Isolate memory and context state for each sub-task and user session.",
      "Redact sensitive fields during final output aggregation.",
    ],
    technical: {
      name: "Information leakage between parallel sub-tasks (shared context)",
      owasp: ["OWASP LLM02:2025 Sensitive Information Disclosure"],
      nist: ["MAP 2.3", "MEASURE 2.10", "MANAGE 2.1"],
      references: ["OWASP LLM02:2025 Sensitive Information Disclosure"],
      mitigationControlIds: ["CTRL_CONTEXT_ISOLATION", "CTRL_DLP_REDACTION"],
    },
  },
  MERGE_CORRUPTION: {
    id: "MERGE_CORRUPTION",
    kind: "integrity",
    title: "Sai lệch kết quả khi tổng hợp",
    titleEn: "Parallel Aggregation Integrity Failure",
    explanation:
      "Khi hợp nhất đầu ra từ nhiều nhánh xử lý song song, dữ liệu sai từ một nhánh có thể làm lệch toàn bộ kết quả cuối cùng.",
    explanationEn:
      "When synthesizing outputs from parallel agents, a single compromised or hallucinated branch can skew the merged result.",
    likelihood: 3,
    impact: 2,
    recommendations: ["Đối chiếu chéo kết quả giữa các nhánh và cảnh báo khi phát hiện mâu thuẫn."],
    recommendationsEn: ["Cross-validate parallel agent outputs and flag conflicting conclusions."],
    technical: {
      name: "Aggregation integrity in parallel fan-in",
      owasp: ["OWASP LLM09:2025 Misinformation"],
      nist: ["MEASURE 2.5", "MANAGE 2.2"],
      references: ["OWASP LLM09:2025 Misinformation"],
      mitigationControlIds: ["CTRL_INTER_AGENT_VALIDATION"],
    },
  },
  CROSS_AGENT_CONTAMINATION: {
    id: "CROSS_AGENT_CONTAMINATION",
    kind: "injection",
    title: "Rủi ro lây nhiễm chéo liên tác nhân",
    titleEn: "Inter-Agent Prompt Propagation",
    explanation:
      "Hệ thống có nhiều AI cùng xử lý công việc. Nếu một tác nhân bị thao túng, chỉ thị độc hại có thể lan sang các tác nhân khác và làm gián đoạn quy trình.",
    explanationEn:
      "In multi-agent workflows, a compromised agent can propagate adversarial instructions to peer or downstream agents via internal messages.",
    likelihood: 3,
    impact: 4,
    recommendations: [
      "Giới hạn quyền của từng AI theo đúng chức năng được giao.",
      "Kiểm tra tính hợp lệ của mọi thông điệp trao đổi nội bộ giữa các tác nhân.",
      "Thiết lập cơ chế tạm dừng nhanh tác nhân có dấu hiệu hoạt động bất thường.",
    ],
    recommendationsEn: [
      "Scope each agent's permissions strictly to its designated role.",
      "Treat inter-agent messages as untrusted input and validate schemas before execution.",
      "Implement circuit breakers to isolate anomalous agents.",
    ],
    technical: {
      name: "Inter-agent prompt injection propagation",
      owasp: ["OWASP LLM01:2025 Prompt Injection", "OWASP Agentic AI: Agent Communication Poisoning"],
      nist: ["GOVERN 1.2", "MAP 5.1", "MANAGE 2.4"],
      references: ["OWASP LLM01:2025 Prompt Injection", "OWASP Agentic AI: Agent Communication Poisoning"],
      mitigationControlIds: ["CTRL_INTER_AGENT_VALIDATION", "CTRL_SCOPED_DELEGATION"],
    },
  },
  PRIVILEGE_ESCALATION: {
    id: "PRIVILEGE_ESCALATION",
    kind: "action",
    title: "Leo thang đặc quyền qua phân công tác vụ",
    titleEn: "Delegation Privilege Escalation",
    explanation:
      "Tác nhân điều phối có thể bị điều hướng để chuyển yêu cầu sang một tác nhân khác có quyền hạn cao hơn, dẫn đến thực thi thao tác vượt thẩm quyền.",
    explanationEn:
      "A routing agent may be manipulated into delegating tasks to a higher-privilege sub-agent, bypassing caller authorization boundaries.",
    likelihood: 3,
    impact: 5,
    recommendations: [
      "Giới hạn quyền của từng AI ở mức tối thiểu cần thiết.",
      "Yêu cầu mỗi tác nhân tự xác thực quyền truy cập thay vì phụ thuộc hoàn toàn vào tác nhân điều phối.",
      "Không cho phép tác nhân điều phối tự cấp thêm quyền cho tác nhân con.",
    ],
    recommendationsEn: [
      "Enforce least-privilege permissions on every sub-agent.",
      "Require sub-agents to independently verify caller authorization tokens.",
      "Prevent coordinator agents from granting elevated permissions.",
    ],
    technical: {
      name: "Privilege escalation via delegation (confused deputy)",
      owasp: ["OWASP LLM06:2025 Excessive Agency", "OWASP Agentic AI: Privilege Compromise"],
      nist: ["GOVERN 1.4", "MAP 3.5", "MANAGE 2.4"],
      references: ["OWASP LLM06:2025 Excessive Agency", "OWASP Agentic AI: Privilege Compromise"],
      mitigationControlIds: ["CTRL_SCOPED_DELEGATION", "CTRL_TOOL_ALLOWLIST"],
    },
  },
  ROUTING_BYPASS: {
    id: "ROUTING_BYPASS",
    kind: "injection",
    title: "Thao túng luồng điều phối",
    titleEn: "Coordinator Routing Bypass",
    explanation:
      "Tác nhân điều phối quyết định luồng đi của từng yêu cầu. Đầu vào được thiết kế tinh vi có thể khiến hệ thống bỏ qua bước kiểm duyệt và chuyển thẳng yêu cầu đến tác nhân thực thi.",
    explanationEn:
      "Crafted inputs can mislead the coordinator into bypassing safety checks and routing requests directly to execution sub-agents.",
    likelihood: 3,
    impact: 4,
    recommendations: [
      "Thiết lập cổng kiểm tra an toàn cố định mà tác nhân AI không thể bỏ qua.",
      "Giới hạn điều phối trong danh sách luồng nghiệp vụ đã được định nghĩa sẵn.",
    ],
    recommendationsEn: [
      "Enforce mandatory deterministic safety checkpoints before task routing.",
      "Constrain routing targets to a predefined allowlist of workflows.",
    ],
    technical: {
      name: "Routing manipulation / guardrail bypass in coordinator",
      owasp: ["OWASP LLM01:2025 Prompt Injection", "OWASP LLM06:2025 Excessive Agency"],
      nist: ["MAP 5.2", "MEASURE 2.7", "MANAGE 2.2"],
      references: ["OWASP LLM01:2025 Prompt Injection", "OWASP LLM06:2025 Excessive Agency"],
      mitigationControlIds: ["CTRL_DETERMINISTIC_ROUTER", "CTRL_GUARDRAILS"],
    },
  },
  ACCOUNTABILITY_GAP: {
    id: "ACCOUNTABILITY_GAP",
    kind: "control",
    title: "Khó truy vết trách nhiệm quyết định",
    titleEn: "Swarm Decision Traceability Gap",
    explanation:
      "Các tác nhân tự trao đổi ngang hàng không qua điều phối trung tâm khiến việc xác định điểm phát sinh lỗi khi xảy ra sự cố trở nên khó khăn.",
    explanationEn:
      "Decentralized peer-to-peer handoffs make it difficult to attribute faulty decisions or reconstruct incident root causes.",
    likelihood: 3,
    impact: 3,
    recommendations: [
      "Ghi nhận nhật ký toàn bộ thông điệp trao đổi giữa các tác nhân.",
      "Giới hạn số vòng trao đổi và thiết lập điều kiện dừng rõ ràng.",
    ],
    recommendationsEn: [
      "Maintain immutable audit logs of all inter-agent handoffs and messages.",
      "Enforce maximum handoff rounds and explicit termination criteria.",
    ],
    technical: {
      name: "Non-deterministic emergent behaviour / weak auditability in swarm",
      owasp: ["OWASP Agentic AI: Repudiation & Untraceability"],
      nist: ["GOVERN 1.4", "MEASURE 2.8", "MANAGE 4.1"],
      references: ["NIST AI RMF GOVERN 1.4", "OWASP Agentic AI: Repudiation & Untraceability"],
      mitigationControlIds: ["CTRL_IMMUTABLE_TRACE_LOG", "CTRL_STEP_BUDGET"],
    },
  },
  APPROVAL_FATIGUE: {
    id: "APPROVAL_FATIGUE",
    kind: "control",
    title: "Giảm hiệu quả phê duyệt thủ công",
    titleEn: "Human-in-the-Loop Approval Fatigue",
    explanation:
      "Cơ chế chờ người phê duyệt giúp giảm rủi ro tự động hóa, nhưng nếu số lượng yêu cầu quá lớn, người duyệt dễ xác nhận theo quán tính mà không kiểm tra kỹ.",
    explanationEn:
      "High volumes of approval prompts can cause reviewers to rubber-stamp actions without verifying full operational context.",
    likelihood: 3,
    impact: 2,
    recommendations: [
      "Chỉ yêu cầu phê duyệt thủ công đối với các tác vụ có mức độ ảnh hưởng cao.",
      "Hiển thị tóm tắt rõ nội dung thao tác, đối tượng nhận và phạm vi tác động trên màn hình duyệt.",
    ],
    recommendationsEn: [
      "Reserve manual approval checkpoints for high-impact operations.",
      "Present clear action summaries, target recipients, and parameters in the review UI.",
    ],
    technical: {
      name: "Human-in-the-loop approval fatigue",
      owasp: ["OWASP LLM09:2025 Misinformation (Overreliance)", "OWASP Agentic AI: Overwhelming HITL"],
      nist: ["GOVERN 3.2", "MAP 3.4", "MANAGE 2.4"],
      references: ["OWASP LLM09:2025 Misinformation (overreliance)", "OWASP Agentic AI: Overwhelming Human-in-the-Loop"],
      mitigationControlIds: ["CTRL_DETERMINISTIC_ROUTER"],
    },
  },
  MISINFORMATION: {
    id: "MISINFORMATION",
    kind: "integrity",
    title: "Phản hồi thông tin thiếu chính xác",
    titleEn: "Inaccurate Output & Overreliance",
    explanation:
      "Mô hình có thể tạo ra thông tin sai lệch nhưng có văn phong thuyết phục, dẫn đến sai sót nếu người dùng áp dụng trực tiếp mà không đối chiếu.",
    explanationEn:
      "Models can generate plausible but factually incorrect statements, leading to operational errors if accepted without verification.",
    likelihood: 3,
    impact: 3,
    recommendations: [
      "Gắn nhãn rõ ràng đối với các nội dung do hệ thống AI tự động tạo ra.",
      "Yêu cầu trích dẫn nguồn dữ liệu gốc đối với các thông tin quan trọng.",
    ],
    recommendationsEn: [
      "Clearly label AI-generated content in user interfaces.",
      "Require source citations and verification for decision-critical outputs.",
    ],
    technical: {
      name: "Hallucination / overreliance",
      owasp: ["OWASP LLM09:2025 Misinformation"],
      nist: ["MEASURE 2.5", "MANAGE 2.2"],
      references: ["OWASP LLM09:2025 Misinformation"],
      mitigationControlIds: ["CTRL_GUARDRAILS"],
    },
  },
  POISONED_DOCS: {
    id: "POISONED_DOCS",
    kind: "injection",
    title: "Chèn chỉ thị độc hại qua tài liệu tra cứu",
    titleEn: "Indirect Injection via Retrieval Corpus",
    explanation:
      "Hệ thống tra cứu tài liệu nội bộ để trả lời. Nếu tài liệu bị chèn nội dung điều hướng ẩn, AI có thể thực thi theo chỉ thị đó thay vì quy tắc gốc.",
    explanationEn:
      "Adversarial instructions embedded inside retrieved internal documents can hijack model behavior during RAG processing.",
    likelihood: 3,
    impact: 4,
    recommendations: [
      "Kiểm soát chặt quyền thêm mới và chỉnh sửa tài liệu trong kho tri thức.",
      "Rà soát và làm sạch nội dung tài liệu trước khi đưa vào hệ thống tra cứu.",
    ],
    recommendationsEn: [
      "Enforce strict write permissions on document repositories.",
      "Sanitize and scan documents before indexing into the retrieval store.",
    ],
    technical: {
      name: "Indirect prompt injection / poisoning via retrieval corpus",
      owasp: [
        "OWASP LLM01:2025 Prompt Injection (Indirect)",
        "OWASP LLM04:2025 Data and Model Poisoning",
        "OWASP LLM08:2025 Vector and Embedding Weaknesses",
      ],
      nist: ["MAP 4.1", "MEASURE 2.7", "MANAGE 3.2"],
      references: [
        "OWASP LLM01:2025 Prompt Injection (indirect)",
        "OWASP LLM04:2025 Data and Model Poisoning",
        "OWASP LLM08:2025 Vector and Embedding Weaknesses",
      ],
      mitigationControlIds: ["CTRL_RAG_INGEST_FILTER", "CTRL_SYS_PROMPT_SEP"],
    },
  },
  DOC_ACCESS_LEAK: {
    id: "DOC_ACCESS_LEAK",
    kind: "leak",
    title: "Truy xuất tài liệu vượt thẩm quyền",
    titleEn: "Unauthorized Document Retrieval",
    explanation:
      "Hệ thống có thể trích xuất nội dung từ các tài liệu nội bộ như bảng lương hoặc hợp đồng mật cho người dùng không có quyền xem.",
    explanationEn:
      "Without per-user access controls on retrieval, the system may surface restricted records such as payroll or confidential contracts.",
    likelihood: 3,
    impact: 4,
    recommendations: [
      "Áp dụng phân quyền truy cập tài liệu theo đúng định danh của người gửi yêu cầu.",
      "Tách biệt kho tài liệu mật khỏi nguồn dữ liệu tra cứu chung.",
    ],
    recommendationsEn: [
      "Enforce caller-identity ACL checks during document retrieval.",
      "Segregate classified documents from shared retrieval indexes.",
    ],
    technical: {
      name: "Missing per-user authorization on retrieval",
      owasp: ["OWASP LLM02:2025 Sensitive Information Disclosure", "OWASP LLM08:2025 Vector and Embedding Weaknesses"],
      nist: ["MAP 2.3", "MEASURE 2.10", "MANAGE 2.1"],
      references: ["OWASP LLM02:2025 Sensitive Information Disclosure", "OWASP LLM08:2025 Vector and Embedding Weaknesses"],
      mitigationControlIds: ["CTRL_RAG_ACL", "CTRL_DLP_REDACTION"],
    },
  },
  MALICIOUS_WEB: {
    id: "MALICIOUS_WEB",
    kind: "injection",
    title: "Tiếp nhận nội dung độc hại từ Internet",
    titleEn: "Indirect Injection via Web Content",
    explanation:
      "Khi truy xuất dữ liệu từ trang web bên ngoài, hệ thống có thể đọc phải các đoạn văn bản ẩn được thiết kế để điều khiển hành vi của AI.",
    explanationEn:
      "Fetching live web pages exposes the agent to hidden instructions embedded in external sites.",
    likelihood: 4,
    impact: 3,
    recommendations: [
      "Xử lý dữ liệu từ Internet như nguồn không tin cậy, không tự động thực thi tác vụ chỉ dựa trên thông tin này.",
      "Giới hạn phạm vi truy vấn trong danh sách các tên miền đáng tin cậy.",
    ],
    recommendationsEn: [
      "Treat web-fetched content as untrusted data and never trigger actions solely from it.",
      "Restrict web grounding to an allowlist of verified domains where feasible.",
    ],
    technical: {
      name: "Indirect prompt injection via web content",
      owasp: ["OWASP LLM01:2025 Prompt Injection (Indirect)"],
      nist: ["MAP 4.1", "MEASURE 2.7", "MANAGE 3.1"],
      references: ["OWASP LLM01:2025 Prompt Injection (indirect)"],
      mitigationControlIds: ["CTRL_SYS_PROMPT_SEP", "CTRL_GUARDRAILS"],
    },
  },
  EXCESSIVE_AGENCY: {
    id: "EXCESSIVE_AGENCY",
    kind: "action",
    title: "Cấp quyền quá mức cho công cụ tích hợp",
    titleEn: "Excessive Tool Permissions",
    explanation:
      "Hệ thống được kết nối với email, lịch hoặc cổng thanh toán với quyền hạn rộng có thể gây thiệt hại thực tế nếu phát sinh lỗi xử lý.",
    explanationEn:
      "Connecting external services with broad permissions amplifies the impact of erroneous or manipulated agent actions.",
    likelihood: 3,
    impact: 5,
    recommendations: [
      "Áp dụng nguyên tắc đặc quyền tối thiểu, ví dụ chỉ cấp quyền đọc thay vì quyền xóa.",
      "Sử dụng tài khoản dịch vụ riêng biệt thay vì tài khoản quản trị hệ thống.",
      "Thiết lập hạn mức đối với các thao tác liên quan đến tài chính.",
    ],
    recommendationsEn: [
      "Enforce least-privilege scopes (e.g., read-only instead of write/delete).",
      "Use dedicated service accounts rather than administrative credentials.",
      "Enforce strict transaction limits on financial operations.",
    ],
    technical: {
      name: "Excessive functionality / permissions on connected tools",
      owasp: ["OWASP LLM06:2025 Excessive Agency"],
      nist: ["GOVERN 1.4", "MAP 3.5", "MANAGE 2.4"],
      references: ["OWASP LLM06:2025 Excessive Agency"],
      mitigationControlIds: ["CTRL_TOOL_ALLOWLIST", "CTRL_SCOPED_DELEGATION"],
    },
  },
  CUSTOMER_DATA_LEAK: {
    id: "CUSTOMER_DATA_LEAK",
    kind: "leak",
    title: "Rò rỉ hoặc ghi đè dữ liệu nghiệp vụ",
    titleEn: "Enterprise Data Exposure or Corruption",
    explanation:
      "Khi kết nối trực tiếp với cơ sở dữ liệu khách hàng và vận hành, hệ thống có nguy cơ bị khai thác để trích xuất thông tin trái phép hoặc cập nhật sai dữ liệu.",
    explanationEn:
      "Direct read/write access to enterprise databases risks unauthorized record disclosure or unintended data mutation.",
    likelihood: 3,
    impact: 4,
    recommendations: [
      "Che dấu hoặc ẩn thông tin định danh và dữ liệu thẻ trước khi chuyển cho AI xử lý.",
      "Ưu tiên kết nối ở chế độ chỉ đọc, kiểm soát chặt các lệnh ghi hoặc xóa.",
      "Ghi nhận nhật ký kiểm toán đối với mọi truy vấn dữ liệu.",
    ],
    recommendationsEn: [
      "Mask PII and payment fields before passing records into model context.",
      "Default to read-only database views and gate write/delete operations.",
      "Log all database queries for security auditing.",
    ],
    technical: {
      name: "Sensitive data exposure through data-connected agent",
      owasp: ["OWASP LLM02:2025 Sensitive Information Disclosure", "OWASP LLM06:2025 Excessive Agency"],
      nist: ["MAP 2.3", "MEASURE 2.10", "MANAGE 2.1"],
      references: ["OWASP LLM02:2025 Sensitive Information Disclosure", "OWASP LLM06:2025 Excessive Agency"],
      mitigationControlIds: ["CTRL_DLP_REDACTION", "CTRL_IMMUTABLE_TRACE_LOG"],
    },
  },
} satisfies Record<string, RiskTemplate>;

/* ------------------------------------------------------------------ */
/* Mappings                                                            */
/* ------------------------------------------------------------------ */

export const PATTERN_RISKS: Record<AgenticPattern, RiskTemplate[]> = {
  SINGLE_AGENT: [RISKS.PROMPT_INJECTION],
  REACT: [RISKS.PROMPT_INJECTION, RISKS.TOOL_HIJACK, RISKS.RUNAWAY_LOOP],
  SEQUENTIAL: [RISKS.CASCADING_POISONING],
  PARALLEL: [RISKS.CROSS_TASK_LEAK, RISKS.MERGE_CORRUPTION],
  COORDINATOR: [RISKS.PRIVILEGE_ESCALATION, RISKS.ROUTING_BYPASS, RISKS.CROSS_AGENT_CONTAMINATION],
  HIERARCHICAL: [RISKS.PRIVILEGE_ESCALATION, RISKS.ROUTING_BYPASS, RISKS.CROSS_AGENT_CONTAMINATION],
  SWARM: [
    RISKS.CROSS_AGENT_CONTAMINATION,
    RISKS.PRIVILEGE_ESCALATION,
    RISKS.ACCOUNTABILITY_GAP,
    RISKS.RUNAWAY_LOOP,
  ],
  HUMAN_IN_THE_LOOP: [RISKS.APPROVAL_FATIGUE],
};

export const RESOURCE_RISKS: Record<Resource, RiskTemplate[]> = {
  internal_docs: [RISKS.POISONED_DOCS, RISKS.DOC_ACCESS_LEAK],
  web_search: [RISKS.MALICIOUS_WEB],
  external_tools: [RISKS.EXCESSIVE_AGENCY],
  company_data: [RISKS.CUSTOMER_DATA_LEAK],
};

export const BASELINE_RISKS: RiskTemplate[] = [RISKS.MISINFORMATION];

export const PATTERN_TECH_NAMES: Record<AgenticPattern, string> = {
  SINGLE_AGENT: "Single-agent",
  REACT: "Single-agent / ReAct (reason-act loop)",
  SEQUENTIAL: "Multi-agent sequential",
  PARALLEL: "Multi-agent parallel",
  COORDINATOR: "Multi-agent coordinator",
  HIERARCHICAL: "Hierarchical task decomposition",
  SWARM: "Multi-agent swarm",
  HUMAN_IN_THE_LOOP: "Human-in-the-loop",
};

export interface PatternDisplayInfo {
  code: AgenticPattern;
  friendlyName: string;
  friendlyNameEn: string;
  googleCloudName: string;
  description: string;
  descriptionEn: string;
}

export const PATTERN_DISPLAY_INFO: Record<AgenticPattern, PatternDisplayInfo> = {
  SINGLE_AGENT: {
    code: "SINGLE_AGENT",
    friendlyName: "Tác nhân AI đơn lẻ",
    friendlyNameEn: "Standalone Single Agent",
    googleCloudName: "Single-agent system",
    description:
      "Một mô hình AI duy nhất tiếp nhận yêu cầu, tra cứu dữ liệu cố định và phản hồi trực tiếp cho người dùng.",
    descriptionEn:
      "A single model processes requests end-to-end with optional fixed retrieval and returns responses directly.",
  },
  REACT: {
    code: "REACT",
    friendlyName: "Tác nhân tự suy luận và gọi công cụ",
    friendlyNameEn: "Reasoning & Tool-Calling Agent (ReAct)",
    googleCloudName: "Single-agent with ReAct (Reason + Act loop)",
    description:
      "Tác nhân tự lập luận bước tiếp theo, chủ động gọi công cụ bên ngoài hoặc thao tác dữ liệu, đánh giá kết quả và lặp lại đến khi hoàn tất.",
    descriptionEn:
      "The agent iteratively reasons, invokes external tools or databases, observes results, and continues until task completion.",
  },
  SEQUENTIAL: {
    code: "SEQUENTIAL",
    friendlyName: "Đa tác nhân xử lý tuần tự",
    friendlyNameEn: "Sequential Multi-Agent Pipeline",
    googleCloudName: "Multi-agent Sequential pattern",
    description:
      "Các tác nhân thực hiện công việc theo trình tự cố định; đầu ra của bước trước là dữ liệu đầu vào trực tiếp cho bước kế tiếp.",
    descriptionEn:
      "Multiple agents execute in a fixed order where the output of one stage feeds directly into the next stage.",
  },
  PARALLEL: {
    code: "PARALLEL",
    friendlyName: "Đa tác nhân xử lý song song",
    friendlyNameEn: "Parallel Multi-Agent Execution",
    googleCloudName: "Multi-agent Parallel pattern",
    description:
      "Nhiều tác nhân đồng thời xử lý các nhánh công việc độc lập, sau đó hợp nhất kết quả tại bước tổng hợp cuối.",
    descriptionEn:
      "Multiple agents run concurrently on independent sub-tasks before aggregating their outputs into a final result.",
  },
  COORDINATOR: {
    code: "COORDINATOR",
    friendlyName: "Tác nhân điều phối trung tâm",
    friendlyNameEn: "Central Coordinator & Router",
    googleCloudName: "Multi-agent Coordinator / Router pattern",
    description:
      "Một tác nhân trung tâm phân tích yêu cầu để tự động phân luồng và giao việc cho các tác nhân chuyên biệt.",
    descriptionEn:
      "A central agent analyzes incoming requests, dynamically delegates sub-tasks to specialist agents, and synthesizes results.",
  },
  HIERARCHICAL: {
    code: "HIERARCHICAL",
    friendlyName: "Đa tác nhân phân cấp nhiều tầng",
    friendlyNameEn: "Hierarchical Multi-Level Delegation",
    googleCloudName: "Multi-agent Hierarchical task decomposition",
    description:
      "Cấu trúc phân tầng trong đó tác nhân cấp trên chia nhỏ mục tiêu cho tác nhân cấp dưới, và các tác nhân cấp dưới tiếp tục phân rã tác vụ.",
    descriptionEn:
      "A multi-tier architecture where supervisor agents decompose goals and sub-agents further delegate to deeper specialist tiers.",
  },
  SWARM: {
    code: "SWARM",
    friendlyName: "Mạng lưới tác nhân phối hợp ngang hàng",
    friendlyNameEn: "Decentralized Peer-to-Peer Swarm",
    googleCloudName: "Multi-agent Swarm / Collaborative network",
    description:
      "Các tác nhân ngang hàng trực tiếp chuyển tiếp thông tin và phối hợp xử lý mà không phụ thuộc vào một bộ điều phối duy nhất.",
    descriptionEn:
      "Peer agents communicate directly and hand off tasks collaboratively without a single central controller.",
  },
  HUMAN_IN_THE_LOOP: {
    code: "HUMAN_IN_THE_LOOP",
    friendlyName: "Kiểm soát phê duyệt bởi con người",
    friendlyNameEn: "Human-in-the-Loop (HITL) Checkpoint",
    googleCloudName: "Human-in-the-loop (HITL) checkpoint",
    description:
      "Quy trình tạm dừng tại các bước quan trọng để chờ người có thẩm quyền kiểm tra và xác nhận trước khi thực thi.",
    descriptionEn:
      "Execution pauses at defined checkpoints so an authorized reviewer can inspect and approve actions before they take effect.",
  },
};

export function localizePatternInfo(
  info: PatternDisplayInfo,
  language: Language,
): PatternDisplayInfo {
  if (language !== "en") return info;
  return {
    ...info,
    friendlyName: info.friendlyNameEn,
    description: info.descriptionEn,
  };
}

/* ------------------------------------------------------------------ */
/* Scoring                                                             */
/* ------------------------------------------------------------------ */

export const SEVERITY_LABELS: Record<Severity, string> = {
  Low: "Thấp",
  Medium: "Trung bình",
  High: "Cao",
  Critical: "Nghiêm trọng",
};

export const SEVERITY_LABELS_EN: Record<Severity, string> = {
  Low: "Low",
  Medium: "Medium",
  High: "High",
  Critical: "Critical",
};

export function getSeverityLabel(severity: Severity, language: Language = "vi"): string {
  return language === "en" ? SEVERITY_LABELS_EN[severity] : SEVERITY_LABELS[severity];
}

export function severityFor(score: number): Severity {
  if (score <= 5) return "Low";
  if (score <= 11) return "Medium";
  if (score <= 19) return "High";
  return "Critical";
}

const clamp = (value: number): Level => Math.min(5, Math.max(1, value)) as Level;

interface Adjustment {
  likelihood?: number;
  impact?: number;
  note: string;
}

function oversightAdjustment(
  detection: PatternDetection,
  answers: QuestionnaireAnswers,
  language: Language,
): Adjustment | null {
  const isEn = language === "en";
  switch (detection.human_oversight) {
    case "full":
      return {
        likelihood: -2,
        note: isEn
          ? "Reduced likelihood because all actions require manual approval."
          : "Giảm mức độ rủi ro do mọi tác vụ đều yêu cầu phê duyệt thủ công.",
      };
    case "partial":
      return {
        likelihood: -1,
        note: isEn
          ? "Partially reduced likelihood because high-impact actions require approval."
          : "Giảm một phần rủi ro do các tác vụ quan trọng có bước phê duyệt.",
      };
    case "none":
      if (answers.autonomy === "answer_only") {
        return {
          likelihood: -2,
          note: isEn
            ? "Reduced likelihood because the system only returns information without executing actions."
            : "Giảm mức độ rủi ro do hệ thống chỉ phản hồi thông tin, không tự thực thi tác vụ.",
        };
      }
      if (answers.autonomy === "full_auto") {
        return {
          likelihood: 1,
          note: isEn
            ? "Increased likelihood because actions execute autonomously without review."
            : "Tăng mức độ rủi ro do hệ thống thực thi tự động hoàn toàn.",
        };
      }
      return {
        note: isEn
          ? "Operational scenarios indicate autonomous action execution without approval."
          : "Theo mô tả kịch bản, hệ thống có thực thi tác vụ tự động không qua phê duyệt.",
      };
  }
}

function adjustmentsFor(
  risk: RiskTemplate,
  detection: PatternDetection,
  answers: QuestionnaireAnswers,
  language: Language,
): Adjustment[] {
  const isEn = language === "en";
  const adjustments: Adjustment[] = [];
  if (risk.kind === "action") {
    const oversight = oversightAdjustment(detection, answers, language);
    if (oversight) adjustments.push(oversight);
    if (answers.sensitive_data.includes("financial")) {
      adjustments.push({
        impact: 1,
        note: isEn
          ? "Increased impact due to financial data processing."
          : "Tăng mức độ ảnh hưởng do liên quan đến dữ liệu tài chính.",
      });
    }
  }
  if ((risk.kind === "injection" || risk.kind === "leak") && answers.audience === "public") {
    adjustments.push({
      likelihood: 1,
      note: isEn
        ? "Increased likelihood due to public user exposure."
        : "Tăng khả năng xảy ra do hệ thống mở cho người dùng bên ngoài.",
    });
  }
  if (risk.kind === "leak" && answers.sensitive_data.length > 0) {
    adjustments.push({
      impact: 1,
      note: isEn
        ? "Increased impact due to sensitive data exposure."
        : "Tăng mức độ ảnh hưởng do hệ thống xử lý dữ liệu nhạy cảm.",
    });
  }
  if (risk.boostWhenResources?.some((resource) => answers.resources.includes(resource))) {
    adjustments.push({
      likelihood: 1,
      note: isEn
        ? "Increased likelihood due to ingestion of external documents or web content."
        : "Tăng khả năng xảy ra do hệ thống tiếp nhận dữ liệu từ tài liệu hoặc Internet.",
    });
  }
  return adjustments;
}

/* ------------------------------------------------------------------ */
/* Report                                                              */
/* ------------------------------------------------------------------ */

export type RiskOrigin = "system_rule" | "ai_inferred_pattern";

export interface ReportedRisk {
  id: string;
  title: string;
  explanation: string;
  likelihood: Level;
  impact: Level;
  score: number;
  severity: Severity;
  severityLabel: string;
  recommendations: string[];
  adjustments: string[];
  origin: RiskOrigin;
  technical: {
    name: string;
    owasp: string[];
    nist: string[];
    references: string[];
    triggeredBy: string[];
    baseLikelihood: Level;
    contextLikelihood: Level;
    baseImpact: Level;
    baseScore: number;
    mitigationControlIds: string[];
    appliedControlIds: string[];
    missingControlIds: string[];
    discountWeight: number;
  };
}

export interface AiAnalysisSummary {
  engineLabel: string;
  confidence: number;
  executiveSummary: string;
  rationale: string;
  scenarioObservations: string[];
  aiRisks: ReportedRisk[];
}

export interface RiskReport {
  answers: QuestionnaireAnswers;
  detection: PatternDetection;
  primaryPatternInfo: PatternDisplayInfo;
  detectedPatternsInfo: PatternDisplayInfo[];
  summary: string;
  overallScore: number;
  overallSeverity: Severity;
  overallSeverityLabel: string;
  oversightNote: string;
  risks: ReportedRisk[];
  aiAnalysis: AiAnalysisSummary;
  topActions: string[];
  countsBySeverity: Record<Severity, number>;
  technical: {
    primaryPattern: string;
    patterns: string[];
    rationale: string;
    confidence: number;
    source: PatternDetection["source"];
  };
}

const OVERSIGHT_NOTES: Record<Language, Record<PatternDetection["human_oversight"], string>> = {
  vi: {
    full: "Cơ chế kiểm soát: Hệ thống yêu cầu phê duyệt trước mọi thao tác thực thi, giúp giảm đáng kể rủi ro tự động hóa.",
    partial: "Cơ chế kiểm soát: Hệ thống yêu cầu phê duyệt đối với các thao tác quan trọng. Cần quy định rõ danh mục tác vụ bắt buộc phê duyệt.",
    none: "Cơ chế kiểm soát: Hệ thống thực thi tự động không qua phê duyệt thủ công. Nên bổ sung bước xác nhận đối với các thao tác nhạy cảm.",
  },
  en: {
    full: "Governance: All state-changing actions require explicit human approval, significantly reducing autonomous execution risk.",
    partial: "Governance: High-impact operations require human approval. Ensure approval thresholds are strictly defined.",
    none: "Governance: Actions execute without manual approval checkpoints. Consider adding confirmation gates for sensitive operations.",
  },
};

const COLLABORATION_SUMMARY_EN: Record<Collaboration, string> = {
  alone: "The system uses a single standalone AI agent to handle the workflow",
  pipeline: "The system processes requests through a sequential multi-agent pipeline",
  parallel: "The system executes multiple AI agents in parallel and aggregates their outputs",
  manager: "The system uses a central coordinator agent to delegate tasks to specialist sub-agents",
  team_chat: "The system uses peer AI agents that collaborate and hand off tasks directly",
  unsure: "The system integrates AI components to support operational workflows",
};

const AUTONOMY_SUMMARY_EN: Record<Autonomy, string> = {
  answer_only: "returning informational responses without executing external actions.",
  approval_required: "requiring explicit human approval before executing any action.",
  partial_auto: "executing routine tasks automatically while requiring approval for high-impact actions.",
  full_auto: "executing actions autonomously without manual review checkpoints.",
};

function buildPlainSummaryEn(answers: QuestionnaireAnswers): string {
  return `${COLLABORATION_SUMMARY_EN[answers.collaboration]}, ${AUTONOMY_SUMMARY_EN[answers.autonomy]}`;
}

function buildContextualAiAnalysis(
  detection: PatternDetection,
  answers: QuestionnaireAnswers,
  activeControls: string[],
  language: Language,
): AiAnalysisSummary {
  const isEn = language === "en";
  const activeSet = new Set(activeControls);
  const sysName = answers.system_name || (isEn ? "Target AI System" : "Hệ thống mục tiêu");
  const primaryInfo = localizePatternInfo(
    PATTERN_DISPLAY_INFO[detection.primary_pattern],
    language,
  );
  const scenarioSample =
    answers.scenarios && answers.scenarios.length > 0
      ? answers.scenarios[0]
      : answers.purpose_details || (isEn ? "core operational workflow" : "luồng nghiệp vụ chính");

  const scoreAiTemplate = (
    id: string,
    title: string,
    explanation: string,
    techName: string,
    baseL: Level,
    baseI: Level,
    ctxDeltaL: number,
    ctxDeltaI: number,
    owasp: string[],
    nist: string[],
    controlIds: string[],
    recommendations: string[],
    triggeredBy: string[],
  ): ReportedRisk => {
    const contextLikelihood = clamp(baseL + ctxDeltaL);
    const impact = clamp(baseI + ctxDeltaI);
    const appliedIds = controlIds.filter((cid) => activeSet.has(cid));
    const missingIds = controlIds.filter((cid) => !activeSet.has(cid));
    const discountWeight = Math.min(
      0.8,
      appliedIds.reduce((sum, cid) => sum + (TECHNICAL_CONTROLS[cid]?.weight ?? 0), 0),
    );
    const likelihood = clamp(Math.round(contextLikelihood * (1 - discountWeight)));
    const score = likelihood * impact;
    const severity = severityFor(score);
    const notes: string[] = [];
    if (discountWeight > 0) {
      notes.push(
        isEn
          ? `Applied ${appliedIds.length} controls (${appliedIds.join(", ")}): ${(discountWeight * 100).toFixed(0)}% discount → L = ${likelihood}.`
          : `Áp dụng ${appliedIds.length} kiểm soát (${appliedIds.join(", ")}): giảm ${(discountWeight * 100).toFixed(0)}% → L = ${likelihood}.`,
      );
    }
    return {
      id,
      title,
      explanation,
      likelihood,
      impact,
      score,
      severity,
      severityLabel: getSeverityLabel(severity, language),
      recommendations,
      adjustments: notes,
      origin: "ai_inferred_pattern",
      technical: {
        name: techName,
        owasp,
        nist,
        references: [...owasp, ...nist.map((n) => `NIST AI RMF ${n}`)],
        triggeredBy,
        baseLikelihood: baseL,
        contextLikelihood,
        baseImpact: baseI,
        baseScore: baseL * baseI,
        mitigationControlIds: controlIds,
        appliedControlIds: appliedIds,
        missingControlIds: missingIds,
        discountWeight,
      },
    };
  };

  const pubDelta = answers.audience === "public" ? 1 : 0;
  const sensDelta = answers.sensitive_data.length > 0 ? 1 : 0;
  const autoDelta =
    detection.human_oversight === "none" ? 1 : detection.human_oversight === "full" ? -1 : 0;

  const ai01 = scoreAiTemplate(
    "AI-01",
    isEn
      ? "Scenario & Workflow Context Manipulation"
      : "Thao túng ngữ cảnh theo kịch bản vận hành",
    isEn
      ? `In the context of ${sysName} (${scenarioSample}), adversarial or malformed inputs across multi-turn interactions can redirect task objectives and bypass workflow constraints.`
      : `Trong kịch bản vận hành của ${sysName} (${scenarioSample}), dữ liệu đầu vào bất thường qua nhiều lượt tương tác có thể làm lệch mục tiêu xử lý và vượt qua ràng buộc nghiệp vụ.`,
    "Contextual workflow & scenario objective hijacking",
    3,
    4,
    pubDelta,
    sensDelta,
    ["OWASP LLM01:2025 Prompt Injection", "OWASP Agentic AI: Goal Manipulation"],
    ["MAP 5.1", "MEASURE 2.7", "MANAGE 2.2"],
    ["CTRL_SYS_PROMPT_SEP", "CTRL_GUARDRAILS"],
    isEn
      ? [
          "Isolate untrusted scenario inputs from system instructions using structured delimiters.",
          "Validate state transitions against explicit business rules at each workflow step.",
        ]
      : [
          "Tách biệt dữ liệu đầu vào trong kịch bản khỏi chỉ thị hệ thống bằng cấu trúc phân cách rõ ràng.",
          "Kiểm tra tính hợp lệ của trạng thái nghiệp vụ tại từng bước chuyển tiếp trong quy trình.",
        ],
    ["AI Scenario Analyzer", `pattern:${detection.primary_pattern}`],
  );

  const resourceList =
    answers.resources.length > 0 ? answers.resources.join(", ") : isEn ? "internal context" : "ngữ cảnh nội bộ";

  const ai02 = scoreAiTemplate(
    "AI-02",
    isEn
      ? "Cross-Boundary Data & Tool Chaining Risk"
      : "Rủi ro chuỗi liên kết dữ liệu và công cụ liên thành phần",
    isEn
      ? `Combining ${primaryInfo.friendlyName} with connected resources (${resourceList}) creates chained attack paths where untrusted retrieved content can trigger unintended tool calls or expose sensitive records.`
      : `Sự kết hợp giữa mô hình ${primaryInfo.friendlyName.toLowerCase()} và tài nguyên tích hợp (${resourceList}) tạo ra đường dẫn liên hoàn, cho phép dữ liệu truy xuất không tin cậy kích hoạt công cụ hoặc làm lộ bản ghi nhạy cảm.`,
    "Cross-component indirect injection & tool-chaining exfiltration",
    3,
    4,
    answers.resources.includes("web_search") || answers.resources.includes("external_tools") ? 1 : 0,
    sensDelta,
    ["OWASP LLM02:2025 Sensitive Information Disclosure", "OWASP LLM06:2025 Excessive Agency"],
    ["MAP 2.3", "MEASURE 2.10", "MANAGE 2.4"],
    ["CTRL_TOOL_ALLOWLIST", "CTRL_DLP_REDACTION", "CTRL_RAG_ACL"],
    isEn
      ? [
          "Enforce strict parameter validation and least-privilege scopes between retrieval and tool execution.",
          "Apply PII/sensitive field redaction before passing retrieved records to downstream tools or agents.",
        ]
      : [
          "Áp dụng kiểm tra tham số chặt chẽ và giới hạn đặc quyền tối thiểu giữa bước tra cứu và bước gọi công cụ.",
          "Che dấu trường dữ liệu nhạy cảm trước khi chuyển bản ghi sang công cụ hoặc tác nhân kế tiếp.",
        ],
    ["AI Cross-Node Analyzer", ...answers.resources.map((r) => `resource:${r}`)],
  );

  const ai03 = scoreAiTemplate(
    "AI-03",
    isEn
      ? "Autonomous Decision Drift & Governance Gap"
      : "Rủi ro lệch hướng quyết định tự trị và lỗ hổng giám sát",
    isEn
      ? `With human oversight set to ${detection.human_oversight} across ${detection.is_multi_agent ? "a multi-agent topology" : "an agentic execution loop"}, cascading reasoning errors or unverified actions can mutate system state without auditability.`
      : `Với mức độ giám sát con người là ${detection.human_oversight} trên ${detection.is_multi_agent ? "cấu trúc đa tác nhân" : "vòng lặp suy luận tác nhân"}, sai lệch tích lũy hoặc thao tác chưa xác thực có thể làm thay đổi trạng thái hệ thống ngoài ý muốn.`,
    "Autonomous state mutation & multi-step governance drift",
    3,
    3,
    autoDelta,
    detection.is_multi_agent ? 1 : 0,
    ["OWASP LLM06:2025 Excessive Agency", "OWASP LLM10:2025 Unbounded Consumption"],
    ["GOVERN 1.4", "MEASURE 2.8", "MANAGE 4.1"],
    ["CTRL_DETERMINISTIC_ROUTER", "CTRL_SCOPED_DELEGATION", "CTRL_IMMUTABLE_TRACE_LOG"],
    isEn
      ? [
          "Enforce deterministic policy checkpoints before state-changing operations take effect.",
          "Maintain immutable telemetry logs across all reasoning iterations and agent handoffs.",
        ]
      : [
          "Thiết lập cổng kiểm tra chính sách cố định trước mọi thao tác làm thay đổi dữ liệu hoặc trạng thái.",
          "Lưu nhật ký bất biến cho toàn bộ các bước suy luận và chuyển giao tác vụ giữa các tác nhân.",
        ],
    ["AI Governance Analyzer", `oversight:${detection.human_oversight}`],
  );

  const aiRisks = [ai01, ai02, ai03].sort((a, b) => b.score - a.score || b.impact - a.impact);

  const executiveSummary = isEn
    ? `${sysName} operates under the ${primaryInfo.friendlyName} (${primaryInfo.googleCloudName}) architecture with ${detection.human_oversight} human oversight and ${answers.audience} network exposure. AI analysis identified ${aiRisks.length} contextual risk vectors across scenario execution, cross-component data flow, and autonomous governance.`
    : `${sysName} vận hành theo kiến trúc ${primaryInfo.friendlyName} (${primaryInfo.googleCloudName}) với cơ chế giám sát ${detection.human_oversight} và phạm vi truy cập ${answers.audience === "public" ? "công khai" : "nội bộ"}. Phân tích AI ghi nhận ${aiRisks.length} nhóm rủi ro ngữ cảnh trọng tâm liên quan đến kịch bản nghiệp vụ, luồng dữ liệu liên thành phần và kiểm soát tự trị.`;

  const scenarioObservations: string[] =
    !isEn && detection.ai_insights && detection.ai_insights.length > 0
      ? detection.ai_insights
      : isEn
        ? [
            answers.scenarios && answers.scenarios.length > 0
              ? `Evaluated ${answers.scenarios.length} operational scenario(s) (primary: ${answers.scenarios[0].slice(0, 90)}); untrusted inputs must be validated at each state transition.`
              : `System workflow (${(answers.purpose_details || answers.purpose).slice(0, 90)}) requires strict boundary separation between user prompts and system directives.`,
            detection.is_multi_agent
              ? `Multi-agent coordination (${detection.patterns.join(", ")}) introduces inter-agent trust boundaries requiring schema validation and scoped delegation tokens.`
              : `Agent execution pattern (${detection.patterns.join(", ")}) requires explicit tool allowlists and step-budget enforcement to prevent unintended actions.`,
            answers.sensitive_data.length > 0
              ? `Processing sensitive data (${answers.sensitive_data.join(", ")}) with ${answers.audience} access elevates impact severity and requires DLP redaction and caller-level ACLs.`
              : `Maintain continuous telemetry logging and periodic adversarial testing across all connected resources (${resourceList}).`,
          ]
        : [
            answers.scenarios && answers.scenarios.length > 0
              ? `Đã phân tích ${answers.scenarios.length} kịch bản vận hành (trọng tâm: ${answers.scenarios[0].slice(0, 90)}); cần kiểm tra tính hợp lệ của dữ liệu tại từng bước chuyển trạng thái.`
              : `Luồng xử lý của hệ thống (${(answers.purpose_details || answers.purpose).slice(0, 90)}) cần tách biệt rõ ranh giới giữa dữ liệu người dùng và chỉ thị gốc.`,
            detection.is_multi_agent
              ? `Kiến trúc đa tác nhân (${detection.patterns.join(", ")}) làm phát sinh ranh giới tin cậy nội bộ, đòi hỏi xác thực định dạng thông điệp và phân quyền theo phạm vi hẹp.`
              : `Mô hình thực thi (${detection.patterns.join(", ")}) cần giới hạn danh sách công cụ được phép gọi và áp đặt hạn mức số bước suy luận tối đa.`,
            answers.sensitive_data.length > 0
              ? `Hệ thống có xử lý dữ liệu nhạy cảm (${answers.sensitive_data.join(", ")}) trên môi trường ${answers.audience === "public" ? "công khai" : "nội bộ"}, cần che dấu PII và phân quyền truy xuất theo định danh.`
              : `Cần duy trì nhật ký kiểm toán bất biến và kiểm thử định kỳ trên toàn bộ các tài nguyên kết nối (${resourceList}).`,
          ];

  const rationale =
    detection.rationale ||
    (isEn
      ? `Mapped collaboration=${answers.collaboration} and autonomy=${answers.autonomy} to ${detection.primary_pattern} (${detection.patterns.join(", ")}) with oversight=${detection.human_oversight}.`
      : `Ánh xạ cơ chế phối hợp (${answers.collaboration}) và mức độ tự chủ (${answers.autonomy}) sang mẫu kiến trúc ${detection.primary_pattern} (${detection.patterns.join(", ")}) với mức giám sát ${detection.human_oversight}.`);

  return {
    engineLabel:
      detection.source === "llm"
        ? isEn
          ? "Gemini LLM + Contextual Analyzer"
          : "Gemini LLM + Phân tích ngữ cảnh"
        : isEn
          ? "AI Contextual & Scenario Analyzer"
          : "Phân tích ngữ cảnh & kịch bản AI",
    confidence: detection.source === "llm" ? detection.confidence : 0.88,
    executiveSummary,
    rationale,
    scenarioObservations,
    aiRisks,
  };
}

export function buildRiskReport(
  detection: PatternDetection,
  answers: QuestionnaireAnswers,
  activeControls: string[] = [],
  language: Language = "vi",
): RiskReport {
  const isEn = language === "en";
  const llmAddedSet = new Set<AgenticPattern>(detection.llm_added_patterns ?? []);
  const collected = new Map<
    string,
    { template: RiskTemplate; triggeredBy: Set<string>; hasSystemTrigger: boolean }
  >();
  const add = (templates: RiskTemplate[], source: string, isSystemTrigger: boolean): void => {
    for (const template of templates) {
      const entry = collected.get(template.id) ?? {
        template,
        triggeredBy: new Set<string>(),
        hasSystemTrigger: false,
      };
      entry.triggeredBy.add(source);
      if (isSystemTrigger) {
        entry.hasSystemTrigger = true;
      }
      collected.set(template.id, entry);
    }
  };

  for (const pattern of detection.patterns) {
    const isAiOnlyPattern = detection.source === "llm" && llmAddedSet.has(pattern);
    add(PATTERN_RISKS[pattern], PATTERN_TECH_NAMES[pattern], !isAiOnlyPattern);
  }
  for (const resource of answers.resources) {
    add(RESOURCE_RISKS[resource], `resource:${resource}`, true);
  }
  add(BASELINE_RISKS, "baseline", true);

  const activeSet = new Set(activeControls);

  const risks: ReportedRisk[] = [...collected.values()].map(
    ({ template, triggeredBy, hasSystemTrigger }) => {
      const adjustments = adjustmentsFor(template, detection, answers, language);
      const contextLikelihood = clamp(
        template.likelihood + adjustments.reduce((sum, item) => sum + (item.likelihood ?? 0), 0),
      );
      const impact = clamp(
        template.impact + adjustments.reduce((sum, item) => sum + (item.impact ?? 0), 0),
      );

      const applicableIds = template.technical.mitigationControlIds;
      const appliedIds = applicableIds.filter((id) => activeSet.has(id));
      const missingIds = applicableIds.filter((id) => !activeSet.has(id));
      const rawDiscount = appliedIds.reduce(
        (sum, id) => sum + (TECHNICAL_CONTROLS[id]?.weight ?? 0),
        0,
      );
      const discountWeight = Math.min(0.8, rawDiscount);
      const likelihood = clamp(Math.round(contextLikelihood * (1 - discountWeight)));
      const score = likelihood * impact;
      const severity = severityFor(score);

      const noteList = adjustments.map((item) => item.note);
      if (discountWeight > 0) {
        noteList.push(
          isEn
            ? `Applied ${appliedIds.length} technical controls (${appliedIds.join(", ")}): ${(discountWeight * 100).toFixed(0)}% discount → L = ${likelihood}.`
            : `Áp dụng ${appliedIds.length} kiểm soát kỹ thuật (${appliedIds.join(", ")}): giảm ${(discountWeight * 100).toFixed(0)}% → L = ${likelihood}.`,
        );
      }

      return {
        id: template.id,
        title: isEn ? template.titleEn : template.title,
        explanation: isEn ? template.explanationEn : template.explanation,
        likelihood,
        impact,
        score,
        severity,
        severityLabel: getSeverityLabel(severity, language),
        recommendations: isEn ? template.recommendationsEn : template.recommendations,
        adjustments: noteList,
        origin: hasSystemTrigger ? "system_rule" : "ai_inferred_pattern",
        technical: {
          name: template.technical.name,
          owasp: template.technical.owasp,
          nist: template.technical.nist,
          references: template.technical.references,
          triggeredBy: [...triggeredBy],
          baseLikelihood: template.likelihood,
          contextLikelihood,
          baseImpact: template.impact,
          baseScore: template.likelihood * template.impact,
          mitigationControlIds: applicableIds,
          appliedControlIds: appliedIds,
          missingControlIds: missingIds,
          discountWeight,
        },
      };
    },
  );

  const aiAnalysis = buildContextualAiAnalysis(detection, answers, activeControls, language);
  risks.push(...aiAnalysis.aiRisks);

  risks.sort((a, b) => b.score - a.score || b.impact - a.impact);

  const overallScore = risks.length > 0 ? risks[0].score : 1;
  const overallSeverity = severityFor(overallScore);
  const topActions = [
    ...new Set(
      risks
        .filter((risk) => risk.severity !== "Low")
        .map((risk) => risk.recommendations[0]),
    ),
  ].slice(0, 3);
  const countsBySeverity: Record<Severity, number> = { Low: 0, Medium: 0, High: 0, Critical: 0 };
  for (const risk of risks) countsBySeverity[risk.severity] += 1;

  const summaryText =
    isEn && detection.source === "rules"
      ? buildPlainSummaryEn(answers)
      : detection.plain_summary;

  return {
    answers,
    detection,
    primaryPatternInfo: localizePatternInfo(
      PATTERN_DISPLAY_INFO[detection.primary_pattern],
      language,
    ),
    detectedPatternsInfo: detection.patterns.map((pattern) =>
      localizePatternInfo(PATTERN_DISPLAY_INFO[pattern], language),
    ),
    summary: summaryText,
    overallScore,
    overallSeverity,
    overallSeverityLabel: getSeverityLabel(overallSeverity, language),
    oversightNote: OVERSIGHT_NOTES[language][detection.human_oversight],
    risks,
    aiAnalysis,
    topActions,
    countsBySeverity,
    technical: {
      primaryPattern: PATTERN_TECH_NAMES[detection.primary_pattern],
      patterns: detection.patterns.map((pattern) => PATTERN_TECH_NAMES[pattern]),
      rationale: aiAnalysis.rationale,
      confidence: detection.confidence,
      source: detection.source,
    },
  };
}
