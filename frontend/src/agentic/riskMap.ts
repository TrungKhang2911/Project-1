/**
 * Agentic pattern -> security risk mapping.
 *
 * The backend tells us WHICH agentic design patterns an application uses
 * (see backend/app/core/pattern_detector.py). This module decides WHAT that
 * means for security and phrases it for non-technical readers.
 *
 * Scoring follows the project's existing 5x5 model:
 *   score = likelihood (1-5) x impact (1-5)
 *   Low 1-5 | Medium 6-11 | High 12-19 | Critical 20-25
 * (same thresholds as backend/app/data/rule_store.json).
 *
 * Every user-facing string is plain Vietnamese. Technical names (OWASP IDs,
 * pattern names) live only in `technical` fields, which the UI shows in a
 * collapsed "for your engineering team" section.
 */
import type {
  AgenticPattern,
  PatternDetection,
  QuestionnaireAnswers,
  Resource,
} from "../types";

export type Severity = "Low" | "Medium" | "High" | "Critical";
type Level = 1 | 2 | 3 | 4 | 5;

/**
 * What kind of harm a risk causes. Modifiers target kinds:
 * - injection: someone manipulates the AI with crafted text
 * - action:    the AI performs a harmful real-world action (reduced by human approval)
 * - leak:      data reaches people who should not see it
 * - integrity: results become wrong or poisoned
 * - control:   people lose oversight of what the AI does
 * - cost:      runaway usage / availability
 */
export type RiskKind = "injection" | "action" | "leak" | "integrity" | "control" | "cost";

export interface RiskTemplate {
  id: string;
  kind: RiskKind;
  /** Short plain-language title shown to the user. */
  title: string;
  /** One or two plain-language sentences: what could go wrong and why. */
  explanation: string;
  likelihood: Level;
  impact: Level;
  /** Simple, actionable steps, most important first. */
  recommendations: string[];
  /** Raise likelihood by 1 when the app also reads any of these sources. */
  boostWhenResources?: Resource[];
  /** For engineers only. */
  technical: { name: string; references: string[] };
}

/* ------------------------------------------------------------------ */
/* Risk catalogue                                                      */
/* ------------------------------------------------------------------ */

const RISKS = {
  PROMPT_INJECTION: {
    id: "PROMPT_INJECTION",
    kind: "injection",
    title: "Bị lừa bằng lời nói",
    explanation:
      "Người dùng có thể viết những câu \"lừa\" khéo léo để AI quên các quy tắc bạn đặt ra, ví dụ nói những điều bị cấm hoặc tiết lộ hướng dẫn nội bộ.",
    likelihood: 4,
    impact: 3,
    recommendations: [
      "Kiểm tra câu trả lời của AI trước khi hiển thị cho người dùng.",
      "Thử \"tấn công\" ứng dụng bằng các câu lừa phổ biến trước khi ra mắt.",
      "Không đưa mật khẩu hay thông tin bí mật vào phần hướng dẫn của AI.",
    ],
    technical: {
      name: "Direct prompt injection",
      references: ["OWASP LLM01:2025 Prompt Injection", "OWASP LLM07:2025 System Prompt Leakage"],
    },
  },
  TOOL_HIJACK: {
    id: "TOOL_HIJACK",
    kind: "action",
    title: "Bị lừa để tự ý dùng công cụ",
    explanation:
      "AI của bạn tự quyết định khi nào gửi email, tra cứu hay thao tác dữ liệu. Nếu kẻ xấu lừa được nó bằng một câu lệnh khéo léo, AI có thể làm những việc bạn không hề cho phép.",
    likelihood: 4,
    impact: 5,
    recommendations: [
      "Chỉ cấp cho AI những công cụ thật sự cần thiết.",
      "Bắt buộc có người duyệt trước các hành động quan trọng như chuyển tiền, xoá dữ liệu, gửi email ra ngoài.",
      "Đặt hạn mức cho từng hành động (số tiền, số email mỗi ngày).",
    ],
    boostWhenResources: ["web_search", "internal_docs"],
    technical: {
      name: "Prompt injection leading to unauthorized tool use (ReAct loop)",
      references: ["OWASP LLM01:2025 Prompt Injection", "OWASP LLM06:2025 Excessive Agency"],
    },
  },
  RUNAWAY_LOOP: {
    id: "RUNAWAY_LOOP",
    kind: "cost",
    title: "Chạy vòng vòng không dừng",
    explanation:
      "AI tự thử, xem kết quả rồi thử lại. Gặp tình huống lạ, nó có thể lặp mãi, làm tốn chi phí và khiến hệ thống chậm hoặc ngừng hoạt động.",
    likelihood: 3,
    impact: 3,
    recommendations: [
      "Giới hạn số bước tối đa AI được làm cho mỗi yêu cầu.",
      "Đặt ngân sách chi phí hằng ngày và cảnh báo khi vượt.",
    ],
    technical: {
      name: "Unbounded agent loop / resource exhaustion",
      references: ["OWASP LLM10:2025 Unbounded Consumption"],
    },
  },
  CASCADING_POISONING: {
    id: "CASCADING_POISONING",
    kind: "integrity",
    title: "Lỗi dây chuyền",
    explanation:
      "Các AI làm việc nối tiếp nhau. Nếu bước đầu tiên đọc phải một tài liệu hay trang web có nội dung độc hại, các bước sau sẽ tin theo và kết quả cuối cùng bị \"nhiễm độc\" mà không ai hay biết.",
    likelihood: 3,
    impact: 4,
    recommendations: [
      "Kiểm tra và làm sạch kết quả ở giữa mỗi bước trước khi chuyển tiếp.",
      "Chỉ cho bước đầu tiên đọc những nguồn tài liệu đáng tin cậy.",
      "Lưu lại kết quả của từng bước để dễ truy vết khi có sự cố.",
    ],
    boostWhenResources: ["internal_docs", "web_search"],
    technical: {
      name: "Cascading poisoning across sequential agents",
      references: ["OWASP LLM01:2025 Prompt Injection (indirect)", "OWASP LLM04:2025 Data and Model Poisoning"],
    },
  },
  CROSS_TASK_LEAK: {
    id: "CROSS_TASK_LEAK",
    kind: "leak",
    title: "Lộ thông tin giữa các phần việc",
    explanation:
      "Nhiều AI xử lý cùng lúc các phần việc khác nhau. Nếu chúng dùng chung bộ nhớ hoặc dữ liệu, thông tin của phần này (ví dụ hồ sơ của khách hàng A) có thể lọt sang phần khác hoặc xuất hiện trong kết quả cuối.",
    likelihood: 3,
    impact: 4,
    recommendations: [
      "Tách riêng dữ liệu cho từng AI, chỉ đưa đúng phần nó cần.",
      "Kiểm tra bản tổng hợp cuối để loại bỏ thông tin không nên xuất hiện.",
    ],
    technical: {
      name: "Information leakage between parallel sub-tasks (shared context)",
      references: ["OWASP LLM02:2025 Sensitive Information Disclosure"],
    },
  },
  MERGE_CORRUPTION: {
    id: "MERGE_CORRUPTION",
    kind: "integrity",
    title: "Kết quả tổng hợp bị sai lệch",
    explanation:
      "Khi gộp kết quả từ nhiều AI, chỉ cần một AI trả lời sai hoặc bị lừa là bản tổng hợp cuối có thể sai theo.",
    likelihood: 3,
    impact: 2,
    recommendations: ["So sánh chéo kết quả giữa các AI và cảnh báo khi chúng mâu thuẫn nhau."],
    technical: {
      name: "Aggregation integrity in parallel fan-in",
      references: ["OWASP LLM09:2025 Misinformation"],
    },
  },
  CROSS_AGENT_CONTAMINATION: {
    id: "CROSS_AGENT_CONTAMINATION",
    kind: "injection",
    title: "Rủi ro lây nhiễm chéo",
    explanation:
      "Ứng dụng của bạn có nhiều AI chia sẻ công việc. Nếu kẻ xấu lừa được một AI, lỗi này có thể lan sang các AI khác và làm hỏng toàn bộ quy trình.",
    likelihood: 3,
    impact: 4,
    recommendations: [
      "Nên giới hạn quyền của từng AI.",
      "Coi tin nhắn giữa các AI là thông tin chưa được kiểm chứng, phải kiểm tra trước khi làm theo.",
      "Chuẩn bị cách tạm dừng nhanh một AI khi phát hiện nó hoạt động bất thường.",
    ],
    technical: {
      name: "Inter-agent prompt injection propagation",
      references: ["OWASP LLM01:2025 Prompt Injection", "OWASP Agentic AI: Agent Communication Poisoning"],
    },
  },
  PRIVILEGE_ESCALATION: {
    id: "PRIVILEGE_ESCALATION",
    kind: "action",
    title: "AI vượt quyền",
    explanation:
      "Có AI được giao nhiệm vụ chuyển việc cho AI khác. Kẻ xấu có thể lừa nó chuyển yêu cầu sang một AI có nhiều quyền hơn, nhờ đó làm được những việc lẽ ra bị cấm.",
    likelihood: 3,
    impact: 5,
    recommendations: [
      "Nên giới hạn quyền của từng AI ở mức tối thiểu cần thiết.",
      "Mỗi AI phải tự kiểm tra quyền, không chỉ tin vào AI giao việc.",
      "Không cho AI giao việc tự cấp thêm quyền cho AI khác.",
    ],
    technical: {
      name: "Privilege escalation via delegation (confused deputy)",
      references: ["OWASP LLM06:2025 Excessive Agency", "OWASP Agentic AI: Privilege Compromise"],
    },
  },
  ROUTING_BYPASS: {
    id: "ROUTING_BYPASS",
    kind: "injection",
    title: "Lách qua khâu kiểm duyệt",
    explanation:
      "AI \"trưởng nhóm\" quyết định mỗi yêu cầu sẽ đi đâu. Một câu lệnh khéo léo có thể khiến nó bỏ qua bước kiểm tra an toàn và chuyển thẳng yêu cầu tới nơi không nên tới.",
    likelihood: 3,
    impact: 4,
    recommendations: [
      "Đặt bước kiểm tra an toàn cố định mà AI không thể bỏ qua.",
      "Chỉ cho AI giao việc chọn trong danh sách đường đi đã được duyệt sẵn.",
    ],
    technical: {
      name: "Routing manipulation / guardrail bypass in coordinator",
      references: ["OWASP LLM01:2025 Prompt Injection", "OWASP LLM06:2025 Excessive Agency"],
    },
  },
  ACCOUNTABILITY_GAP: {
    id: "ACCOUNTABILITY_GAP",
    kind: "control",
    title: "Khó biết AI nào đã làm gì",
    explanation:
      "Các AI tự bàn bạc với nhau mà không có ai điều phối. Khi xảy ra sự cố, rất khó biết AI nào đã đưa ra quyết định sai.",
    likelihood: 3,
    impact: 3,
    recommendations: [
      "Ghi lại toàn bộ trao đổi giữa các AI.",
      "Giới hạn số vòng trao đổi và đặt điểm dừng rõ ràng.",
    ],
    technical: {
      name: "Non-deterministic emergent behaviour / weak auditability in swarm",
      references: ["NIST AI RMF GOVERN 1.4", "OWASP Agentic AI: Repudiation & Untraceability"],
    },
  },
  APPROVAL_FATIGUE: {
    id: "APPROVAL_FATIGUE",
    kind: "control",
    title: "Duyệt cho có",
    explanation:
      "Việc có người bấm \"Đồng ý\" giúp giảm rủi ro rất nhiều. Tuy nhiên nếu phải duyệt quá nhiều, người duyệt dễ bấm theo thói quen mà không đọc kỹ.",
    likelihood: 3,
    impact: 2,
    recommendations: [
      "Chỉ yêu cầu duyệt với những hành động quan trọng.",
      "Hiển thị rõ AI sắp làm gì, gửi cho ai, bao nhiêu tiền trước khi bấm \"Đồng ý\".",
    ],
    technical: {
      name: "Human-in-the-loop approval fatigue",
      references: ["OWASP LLM09:2025 Misinformation (overreliance)", "OWASP Agentic AI: Overwhelming Human-in-the-Loop"],
    },
  },
  MISINFORMATION: {
    id: "MISINFORMATION",
    kind: "integrity",
    title: "Trả lời sai nhưng nghe rất thuyết phục",
    explanation:
      "AI đôi khi \"bịa\" thông tin nhưng nói rất tự tin. Người dùng có thể tin và làm theo mà không kiểm tra lại.",
    likelihood: 3,
    impact: 3,
    recommendations: [
      "Ghi rõ cho người dùng biết đây là câu trả lời do AI tạo ra.",
      "Yêu cầu AI dẫn nguồn và kiểm tra lại với các thông tin quan trọng.",
    ],
    technical: {
      name: "Hallucination / overreliance",
      references: ["OWASP LLM09:2025 Misinformation"],
    },
  },
  POISONED_DOCS: {
    id: "POISONED_DOCS",
    kind: "injection",
    title: "Tài liệu bị cài \"bẫy\"",
    explanation:
      "AI đọc tài liệu của công ty để trả lời. Nếu ai đó chèn nội dung độc hại vào một tài liệu, AI có thể làm theo nội dung đó thay vì làm theo bạn.",
    likelihood: 3,
    impact: 4,
    recommendations: [
      "Chỉ cho người có trách nhiệm thêm hoặc sửa tài liệu mà AI đọc.",
      "Rà soát tài liệu mới trước khi đưa vào cho AI sử dụng.",
    ],
    technical: {
      name: "Indirect prompt injection / poisoning via retrieval corpus",
      references: [
        "OWASP LLM01:2025 Prompt Injection (indirect)",
        "OWASP LLM04:2025 Data and Model Poisoning",
        "OWASP LLM08:2025 Vector and Embedding Weaknesses",
      ],
    },
  },
  DOC_ACCESS_LEAK: {
    id: "DOC_ACCESS_LEAK",
    kind: "leak",
    title: "Lộ tài liệu cho người không có quyền",
    explanation:
      "AI có thể trả lời bằng nội dung lấy từ tài liệu mà người hỏi lẽ ra không được xem, ví dụ bảng lương hay hợp đồng.",
    likelihood: 3,
    impact: 4,
    recommendations: [
      "AI chỉ được tra cứu những tài liệu mà chính người hỏi có quyền xem.",
      "Tách riêng tài liệu mật khỏi kho tài liệu AI sử dụng.",
    ],
    technical: {
      name: "Missing per-user authorization on retrieval",
      references: ["OWASP LLM02:2025 Sensitive Information Disclosure", "OWASP LLM08:2025 Vector and Embedding Weaknesses"],
    },
  },
  MALICIOUS_WEB: {
    id: "MALICIOUS_WEB",
    kind: "injection",
    title: "Trang web độc hại điều khiển AI",
    explanation:
      "Khi AI đọc nội dung trên Internet, kẻ xấu có thể giấu những dòng chữ \"ra lệnh\" cho AI ngay trong trang web đó.",
    likelihood: 4,
    impact: 3,
    recommendations: [
      "Coi nội dung từ Internet là chưa đáng tin, không cho AI hành động chỉ dựa trên đó.",
      "Giới hạn danh sách trang web AI được phép đọc nếu có thể.",
    ],
    technical: {
      name: "Indirect prompt injection via web content",
      references: ["OWASP LLM01:2025 Prompt Injection (indirect)"],
    },
  },
  EXCESSIVE_AGENCY: {
    id: "EXCESSIVE_AGENCY",
    kind: "action",
    title: "AI có quá nhiều quyền",
    explanation:
      "AI được kết nối với email, lịch, thanh toán... Nếu nó có nhiều quyền hơn mức cần, chỉ một sai sót nhỏ cũng có thể gây thiệt hại thật.",
    likelihood: 3,
    impact: 5,
    recommendations: [
      "Chỉ cấp quyền tối thiểu (ví dụ: chỉ được xem lịch, không được xoá).",
      "Dùng tài khoản riêng cho AI, không dùng tài khoản quản trị.",
      "Đặt hạn mức cho các thao tác liên quan đến tiền.",
    ],
    technical: {
      name: "Excessive functionality / permissions on connected tools",
      references: ["OWASP LLM06:2025 Excessive Agency"],
    },
  },
  CUSTOMER_DATA_LEAK: {
    id: "CUSTOMER_DATA_LEAK",
    kind: "leak",
    title: "Lộ hoặc sửa sai dữ liệu khách hàng",
    explanation:
      "AI đọc hoặc ghi dữ liệu khách hàng và hệ thống công ty. Kẻ xấu có thể dụ AI tiết lộ thông tin của người khác hoặc sửa dữ liệu sai.",
    likelihood: 3,
    impact: 4,
    recommendations: [
      "Che bớt thông tin nhạy cảm (số điện thoại, số thẻ) trước khi đưa cho AI.",
      "Ưu tiên cho AI chỉ được đọc, hạn chế quyền ghi hoặc xoá.",
      "Ghi lại nhật ký mỗi lần AI truy cập dữ liệu.",
    ],
    technical: {
      name: "Sensitive data exposure through data-connected agent",
      references: ["OWASP LLM02:2025 Sensitive Information Disclosure", "OWASP LLM06:2025 Excessive Agency"],
    },
  },
} satisfies Record<string, RiskTemplate>;

/* ------------------------------------------------------------------ */
/* Mappings                                                            */
/* ------------------------------------------------------------------ */

/** Risks introduced by each agentic design pattern. */
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
  // Human-in-the-loop mainly LOWERS other risks (see oversightAdjustment).
  HUMAN_IN_THE_LOOP: [RISKS.APPROVAL_FATIGUE],
};

/** Risks introduced by the data sources and tools the AI can reach. */
export const RESOURCE_RISKS: Record<Resource, RiskTemplate[]> = {
  internal_docs: [RISKS.POISONED_DOCS, RISKS.DOC_ACCESS_LEAK],
  web_search: [RISKS.MALICIOUS_WEB],
  external_tools: [RISKS.EXCESSIVE_AGENCY],
  company_data: [RISKS.CUSTOMER_DATA_LEAK],
};

/** Risks every AI application has, regardless of architecture. */
export const BASELINE_RISKS: RiskTemplate[] = [RISKS.MISINFORMATION];

/** Pattern names for the engineering-team section only. */
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

/**
 * Plain-language Vietnamese descriptions of Google Cloud Agentic AI patterns
 * so users and stakeholders see how their AI system is structured.
 */
export interface PatternDisplayInfo {
  code: AgenticPattern;
  friendlyName: string;
  googleCloudName: string;
  description: string;
}

export const PATTERN_DISPLAY_INFO: Record<AgenticPattern, PatternDisplayInfo> = {
  SINGLE_AGENT: {
    code: "SINGLE_AGENT",
    friendlyName: "Một AI độc lập trả lời",
    googleCloudName: "Single-agent system",
    description:
      "Một mô hình AI duy nhất tiếp nhận câu hỏi, tra cứu thông tin cố định (nếu có) và trả lời trực tiếp cho người dùng.",
  },
  REACT: {
    code: "REACT",
    friendlyName: "Một AI tự suy luận và gọi công cụ",
    googleCloudName: "Single-agent with ReAct (Reason + Act loop)",
    description:
      "AI tự suy nghĩ bước tiếp theo, chủ động gọi công cụ bên ngoài hoặc thao tác dữ liệu, quan sát kết quả rồi lặp lại cho đến khi hoàn thành.",
  },
  SEQUENTIAL: {
    code: "SEQUENTIAL",
    friendlyName: "Nhiều AI nối tiếp theo dây chuyền",
    googleCloudName: "Multi-agent Sequential pattern",
    description:
      "Các AI thực hiện công việc theo thứ tự cố định: kết quả đầu ra của AI trước là dữ liệu đầu vào trực tiếp cho AI kế tiếp.",
  },
  PARALLEL: {
    code: "PARALLEL",
    friendlyName: "Nhiều AI xử lý song song rồi gộp kết quả",
    googleCloudName: "Multi-agent Parallel pattern",
    description:
      "Nhiều AI cùng lúc giải quyết các phần việc độc lập, sau đó một bước tổng hợp sẽ ghép kết quả lại thành câu trả lời cuối.",
  },
  COORDINATOR: {
    code: "COORDINATOR",
    friendlyName: "AI điều phối trung tâm giao việc động",
    googleCloudName: "Multi-agent Coordinator / Router pattern",
    description:
      "Một AI 'trưởng nhóm' phân tích từng yêu cầu để tự quyết định chia việc và chuyển cho các AI chuyên trách phù hợp.",
  },
  HIERARCHICAL: {
    code: "HIERARCHICAL",
    friendlyName: "Nhiều cấp AI phân rã công việc",
    googleCloudName: "Multi-agent Hierarchical task decomposition",
    description:
      "Cấu trúc nhiều tầng: AI cấp trên chia nhỏ mục tiêu lớn cho các AI cấp dưới, và các AI cấp dưới tiếp tục chia việc cho tầng sâu hơn.",
  },
  SWARM: {
    code: "SWARM",
    friendlyName: "Mạng lưới các AI tự trao đổi ngang hàng",
    googleCloudName: "Multi-agent Swarm / Collaborative network",
    description:
      "Các AI ngang hàng tự chuyển tiếp thông tin và thảo luận trực tiếp với nhau để đi đến kết quả mà không có một AI chỉ huy duy nhất.",
  },
  HUMAN_IN_THE_LOOP: {
    code: "HUMAN_IN_THE_LOOP",
    friendlyName: "Có bước chờ con người phê duyệt",
    googleCloudName: "Human-in-the-loop (HITL) checkpoint",
    description:
      "Hệ thống tạm dừng tại các bước quan trọng để chờ người có thẩm quyền xem xét và bấm 'Đồng ý' trước khi thực thi.",
  },
};

/* ------------------------------------------------------------------ */
/* Scoring                                                             */
/* ------------------------------------------------------------------ */

export const SEVERITY_LABELS: Record<Severity, string> = {
  Low: "Thấp",
  Medium: "Trung bình",
  High: "Cao",
  Critical: "Nghiêm trọng",
};

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
  /** Plain-language reason, shown under the risk. */
  note: string;
}

/**
 * Human-in-the-loop modifier for risks where the AI performs actions.
 * Approval does not stop the AI from being tricked; it stops the harmful
 * action from taking effect, so it lowers likelihood of harm.
 */
function oversightAdjustment(
  detection: PatternDetection,
  answers: QuestionnaireAnswers,
): Adjustment | null {
  switch (detection.human_oversight) {
    case "full":
      return { likelihood: -2, note: "Đã giảm mức độ vì mọi hành động đều phải chờ người bấm \"Đồng ý\"." };
    case "partial":
      return { likelihood: -1, note: "Đã giảm một phần vì việc quan trọng vẫn được hỏi ý kiến trước." };
    case "none":
      if (answers.autonomy === "answer_only") {
        return { likelihood: -2, note: "Đã giảm mức độ vì AI chỉ gợi ý, không tự thực hiện hành động." };
      }
      if (answers.autonomy === "full_auto") {
        return { likelihood: 1, note: "Tăng mức độ vì AI tự hành động mà không hỏi ai." };
      }
      // Backend found the AI acts on its own in practice, despite the selected answer.
      return { note: "Lưu ý: theo mô tả của bạn, AI có lúc tự hành động mà không chờ duyệt." };
  }
}

function adjustmentsFor(
  risk: RiskTemplate,
  detection: PatternDetection,
  answers: QuestionnaireAnswers,
): Adjustment[] {
  const adjustments: Adjustment[] = [];
  if (risk.kind === "action") {
    const oversight = oversightAdjustment(detection, answers);
    if (oversight) adjustments.push(oversight);
    if (answers.sensitive_data.includes("financial")) {
      adjustments.push({ impact: 1, note: "Tăng mức độ vì ứng dụng có liên quan đến tiền bạc." });
    }
  }
  if ((risk.kind === "injection" || risk.kind === "leak") && answers.audience === "public") {
    adjustments.push({ likelihood: 1, note: "Tăng mức độ vì ai cũng có thể dùng ứng dụng này." });
  }
  if (risk.kind === "leak" && answers.sensitive_data.length > 0) {
    adjustments.push({ impact: 1, note: "Tăng mức độ vì ứng dụng xử lý dữ liệu nhạy cảm." });
  }
  if (risk.boostWhenResources?.some((resource) => answers.resources.includes(resource))) {
    adjustments.push({
      likelihood: 1,
      note: "Tăng mức độ vì AI đọc nội dung từ tài liệu hoặc Internet, nơi có thể bị cài nội dung xấu.",
    });
  }
  return adjustments;
}

/* ------------------------------------------------------------------ */
/* Report                                                              */
/* ------------------------------------------------------------------ */

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
  /** Plain-language reasons the score moved up or down. */
  adjustments: string[];
  technical: {
    name: string;
    references: string[];
    triggeredBy: string[];
    baseScore: number;
  };
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
  /** Up to three distinct first-priority actions from the highest risks. */
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

const OVERSIGHT_NOTES: Record<PatternDetection["human_oversight"], string> = {
  full: "Tốt: ứng dụng luôn chờ bạn đồng ý trước khi hành động, nên các rủi ro do AI tự làm đã được giảm đáng kể.",
  partial: "Ứng dụng hỏi ý kiến bạn trước những việc quan trọng. Hãy chắc chắn rằng \"việc quan trọng\" được định nghĩa rõ ràng.",
  none: "Ứng dụng không có bước chờ người duyệt. Nếu AI có thể tự hành động, hãy cân nhắc thêm bước bấm \"Đồng ý\".",
};

export function buildRiskReport(
  detection: PatternDetection,
  answers: QuestionnaireAnswers,
): RiskReport {
  // Collect templates and remember which pattern/resource introduced each one.
  const collected = new Map<string, { template: RiskTemplate; triggeredBy: Set<string> }>();
  const add = (templates: RiskTemplate[], source: string): void => {
    for (const template of templates) {
      const entry = collected.get(template.id) ?? { template, triggeredBy: new Set<string>() };
      entry.triggeredBy.add(source);
      collected.set(template.id, entry);
    }
  };

  for (const pattern of detection.patterns) {
    add(PATTERN_RISKS[pattern], PATTERN_TECH_NAMES[pattern]);
  }
  for (const resource of answers.resources) {
    add(RESOURCE_RISKS[resource], `resource:${resource}`);
  }
  add(BASELINE_RISKS, "baseline");

  const risks: ReportedRisk[] = [...collected.values()].map(({ template, triggeredBy }) => {
    const adjustments = adjustmentsFor(template, detection, answers);
    const likelihood = clamp(
      template.likelihood + adjustments.reduce((sum, item) => sum + (item.likelihood ?? 0), 0),
    );
    const impact = clamp(
      template.impact + adjustments.reduce((sum, item) => sum + (item.impact ?? 0), 0),
    );
    const score = likelihood * impact;
    const severity = severityFor(score);
    return {
      id: template.id,
      title: template.title,
      explanation: template.explanation,
      likelihood,
      impact,
      score,
      severity,
      severityLabel: SEVERITY_LABELS[severity],
      recommendations: template.recommendations,
      adjustments: adjustments.map((item) => item.note),
      technical: {
        name: template.technical.name,
        references: template.technical.references,
        triggeredBy: [...triggeredBy],
        baseScore: template.likelihood * template.impact,
      },
    };
  });

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

  return {
    answers,
    detection,
    primaryPatternInfo: PATTERN_DISPLAY_INFO[detection.primary_pattern],
    detectedPatternsInfo: detection.patterns.map((pattern) => PATTERN_DISPLAY_INFO[pattern]),
    summary: detection.plain_summary,
    overallScore,
    overallSeverity,
    overallSeverityLabel: SEVERITY_LABELS[overallSeverity],
    oversightNote: OVERSIGHT_NOTES[detection.human_oversight],
    risks,
    topActions,
    countsBySeverity,
    technical: {
      primaryPattern: PATTERN_TECH_NAMES[detection.primary_pattern],
      patterns: detection.patterns.map((pattern) => PATTERN_TECH_NAMES[pattern]),
      rationale: detection.rationale,
      confidence: detection.confidence,
      source: detection.source,
    },
  };
}

