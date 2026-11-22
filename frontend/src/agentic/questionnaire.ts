/**
 * Plain-language questionnaire (bilingual VI / EN). Option values match the
 * backend enums in backend/app/schemas/agentic_schema.py; labels never use
 * technical jargon in Normal Mode.
 */
import type {
  Audience,
  Autonomy,
  Collaboration,
  Language,
  Purpose,
  QuestionnaireAnswers,
  Resource,
  SensitiveData,
} from "../types";

export interface ChoiceOption<T extends string> {
  value: T;
  icon: string;
  label: string;
  hint?: string;
}

interface BaseStep {
  id: string;
  title: string;
  helper: string;
}

export interface SingleChoiceStep<K extends keyof QuestionnaireAnswers, T extends string>
  extends BaseStep {
  kind: "single";
  field: K;
  options: ChoiceOption<T>[];
}

export interface MultiChoiceStep<K extends keyof QuestionnaireAnswers, T extends string>
  extends BaseStep {
  kind: "multi";
  field: K;
  options: ChoiceOption<T>[];
  /** Label for the "none of these" choice, which clears the selection. */
  noneLabel: string;
}

export type WizardStep =
  | SingleChoiceStep<"purpose", Purpose>
  | SingleChoiceStep<"collaboration", Collaboration>
  | SingleChoiceStep<"autonomy", Autonomy>
  | SingleChoiceStep<"audience", Audience>
  | MultiChoiceStep<"resources", Resource>
  | MultiChoiceStep<"sensitive_data", SensitiveData>;

export const SYSTEM_NAME_MAX = 120;
export const PURPOSE_DETAILS_MAX = 500;
export const SCENARIO_MAX = 300;
export const MAX_SCENARIOS = 5;

export interface ScenarioPreset {
  label: string;
  text: string;
}

export const SCENARIO_PRESETS: Record<Purpose, ScenarioPreset[]> = {
  customer_support: [
    {
      label: "Đổi trả đơn hàng",
      text: "Khách hàng gửi mã đơn qua kênh chat, hệ thống tra cứu trạng thái và tạo phiếu đổi trả hoặc hoàn tiền.",
    },
    {
      label: "Tra cứu chính sách",
      text: "Khách hàng hỏi chính sách bảo hành, hệ thống truy xuất kho tài liệu nội bộ để phản hồi.",
    },
  ],
  content: [
    {
      label: "Tóm tắt tài liệu nội bộ",
      text: "Nhân sự tải hợp đồng hoặc báo cáo nội bộ lên để hệ thống tóm tắt các điều khoản chính.",
    },
    {
      label: "Soạn và gửi email",
      text: "Hệ thống tổng hợp thông tin từ Internet, soạn nội dung tiếp thị và gửi email đến danh sách khách hàng.",
    },
  ],
  data_analysis: [
    {
      label: "Tổng hợp doanh thu và nhân sự",
      text: "Hệ thống truy xuất dữ liệu bán hàng và bảng lương để lập báo cáo tổng hợp cho cấp quản lý.",
    },
    {
      label: "Phân tích đa tác nhân",
      text: "Một tác nhân truy vấn số liệu từ cơ sở dữ liệu, tác nhân khác đối chiếu và lập báo cáo phân tích.",
    },
  ],
  task_automation: [
    {
      label: "Đặt lịch và gửi thư xác nhận",
      text: "Hệ thống đọc email đến, sắp xếp lịch họp trên hệ thống nội bộ và gửi thư xác nhận cho đối tác.",
    },
    {
      label: "Điều phối phê duyệt mua sắm",
      text: "Tác nhân điều phối tiếp nhận yêu cầu mua sắm, phân công tác nhân kiểm tra ngân sách và tác nhân tạo lệnh thanh toán.",
    },
  ],
  coding: [
    {
      label: "Kiểm thử và cập nhật mã nguồn",
      text: "Hệ thống đọc kho mã nguồn nội bộ, thực thi kiểm thử tự động và tạo yêu cầu cập nhật mã.",
    },
  ],
  other: [
    {
      label: "Xử lý quy trình nghiệp vụ",
      text: "Người dùng gửi yêu cầu, hệ thống tra cứu dữ liệu liên quan và thực thi các bước xử lý tiếp theo.",
    },
  ],
};

export const WIZARD_STEPS: WizardStep[] = [
  {
    id: "purpose",
    kind: "single",
    field: "purpose",
    title: "Nhiệm vụ chính của hệ thống AI là gì?",
    helper: "Chọn nhóm chức năng phù hợp nhất với hệ thống.",
    options: [
      { value: "customer_support", icon: "01", label: "Hỗ trợ khách hàng và giải đáp thắc mắc" },
      { value: "content", icon: "02", label: "Soạn thảo, dịch thuật hoặc tóm tắt nội dung" },
      { value: "data_analysis", icon: "03", label: "Phân tích dữ liệu và lập báo cáo" },
      {
        value: "task_automation",
        icon: "04",
        label: "Tự động hóa tác vụ vận hành",
        hint: "Gửi email, đặt lịch, xử lý đơn hàng",
      },
      { value: "coding", icon: "05", label: "Hỗ trợ lập trình và kỹ thuật" },
      { value: "other", icon: "06", label: "Nghiệp vụ khác" },
    ],
  },
  {
    id: "collaboration",
    kind: "single",
    field: "collaboration",
    title: "Cấu trúc phối hợp giữa các tác nhân AI?",
    helper: "Chọn mô hình xử lý sát nhất với thiết kế của hệ thống.",
    options: [
      { value: "alone", icon: "●", label: "Một AI độc lập", hint: "Một mô hình xử lý toàn bộ quy trình" },
      {
        value: "pipeline",
        icon: "→",
        label: "Xử lý tuần tự theo chuỗi",
        hint: "Đầu ra của bước trước là đầu vào của bước kế tiếp",
      },
      {
        value: "parallel",
        icon: "⇉",
        label: "Xử lý song song và tổng hợp",
        hint: "Nhiều AI xử lý đồng thời các phần việc độc lập rồi hợp nhất kết quả",
      },
      {
        value: "manager",
        icon: "◈",
        label: "AI điều phối trung tâm",
        hint: "Một AI phân tích yêu cầu và phân công cho các AI chuyên biệt",
      },
      {
        value: "team_chat",
        icon: "◎",
        label: "Phối hợp ngang hàng",
        hint: "Các AI trực tiếp trao đổi và chuyển tiếp thông tin để thống nhất kết quả",
      },
      { value: "unsure", icon: "?", label: "Chưa xác định" },
    ],
  },
  {
    id: "autonomy",
    kind: "single",
    field: "autonomy",
    title: "Cơ chế kiểm soát khi AI thực thi tác vụ?",
    helper: "Áp dụng cho các thao tác có tác động thực tế như gửi thư, giao dịch hoặc chỉnh sửa dữ liệu.",
    options: [
      {
        value: "answer_only",
        icon: "○",
        label: "Chỉ phản hồi thông tin",
        hint: "Không tự thực thi thao tác lên hệ thống khác",
      },
      {
        value: "approval_required",
        icon: "✓",
        label: "Luôn yêu cầu phê duyệt",
        hint: "Mọi tác vụ đều cần người có thẩm quyền xác nhận trước khi chạy",
      },
      {
        value: "partial_auto",
        icon: "◐",
        label: "Tự động có điều kiện",
        hint: "Tự xử lý tác vụ thông thường, yêu cầu phê duyệt với tác vụ quan trọng",
      },
      {
        value: "full_auto",
        icon: "⚡",
        label: "Tự động hoàn toàn",
        hint: "Thực thi trực tiếp không qua bước phê duyệt thủ công",
      },
    ],
  },
  {
    id: "resources",
    kind: "multi",
    field: "resources",
    title: "Hệ thống kết nối với những nguồn tài nguyên nào?",
    helper: "Chọn tất cả nguồn dữ liệu và công cụ mà hệ thống được phép truy cập.",
    noneLabel: "Không kết nối tài nguyên bên ngoài",
    options: [
      {
        value: "internal_docs",
        icon: "▤",
        label: "Kho tài liệu nội bộ",
        hint: "Quy trình, chính sách, hợp đồng, cơ sở tri thức",
      },
      { value: "web_search", icon: "⊕", label: "Truy vấn Internet" },
      {
        value: "external_tools",
        icon: "⌘",
        label: "Công cụ và dịch vụ bên ngoài",
        hint: "Email, lịch làm việc, cổng thanh toán, API bên thứ ba",
      },
      {
        value: "company_data",
        icon: "▥",
        label: "Cơ sở dữ liệu nghiệp vụ",
        hint: "Hồ sơ khách hàng, đơn hàng, kho vận, ERP/CRM",
      },
    ],
  },
  {
    id: "audience",
    kind: "single",
    field: "audience",
    title: "Đối tượng sử dụng hệ thống?",
    helper: "Xác định phạm vi truy cập để đánh giá mức độ phơi nhiễm trước rủi ro bên ngoài.",
    options: [
      { value: "internal", icon: "▣", label: "Nhân sự nội bộ" },
      { value: "public", icon: "◎", label: "Khách hàng hoặc người dùng bên ngoài" },
    ],
  },
  {
    id: "sensitive_data",
    kind: "multi",
    field: "sensitive_data",
    title: "Hệ thống có xử lý dữ liệu nhạy cảm không?",
    helper: "Chọn các phân loại dữ liệu xuất hiện trong quy trình xử lý.",
    noneLabel: "Không xử lý dữ liệu nhạy cảm",
    options: [
      {
        value: "personal",
        icon: "◈",
        label: "Dữ liệu cá nhân",
        hint: "Họ tên, số điện thoại, địa chỉ, thông tin định danh",
      },
      {
        value: "financial",
        icon: "◇",
        label: "Dữ liệu tài chính",
        hint: "Tài khoản ngân hàng, thẻ thanh toán, lịch sử giao dịch",
      },
      {
        value: "confidential",
        icon: "▪",
        label: "Thông tin mật của tổ chức",
        hint: "Chiến lược giá, mã nguồn, hợp đồng nội bộ",
      },
    ],
  },
];

export const WIZARD_STEPS_EN: WizardStep[] = [
  {
    id: "purpose",
    kind: "single",
    field: "purpose",
    title: "Primary function of the AI system",
    helper: "Select the core operational function.",
    options: [
      { value: "customer_support", icon: "01", label: "Customer support & inquiry handling" },
      { value: "content", icon: "02", label: "Content drafting, translation, or summarization" },
      { value: "data_analysis", icon: "03", label: "Data analysis & reporting" },
      {
        value: "task_automation",
        icon: "04",
        label: "Automated workflow execution",
        hint: "Sending emails, scheduling, order processing",
      },
      { value: "coding", icon: "05", label: "Software engineering & code assistance" },
      { value: "other", icon: "06", label: "Other operational workflow" },
    ],
  },
  {
    id: "collaboration",
    kind: "single",
    field: "collaboration",
    title: "Agent collaboration structure",
    helper: "Select the orchestration model that matches your system design.",
    options: [
      { value: "alone", icon: "●", label: "Single standalone agent", hint: "One model handles the entire workflow" },
      {
        value: "pipeline",
        icon: "→",
        label: "Sequential pipeline",
        hint: "Output from one step feeds directly into the next step",
      },
      {
        value: "parallel",
        icon: "⇉",
        label: "Parallel execution & aggregation",
        hint: "Multiple agents process sub-tasks concurrently before merging results",
      },
      {
        value: "manager",
        icon: "◈",
        label: "Central coordinator",
        hint: "A routing agent decomposes requests and delegates to specialist sub-agents",
      },
      {
        value: "team_chat",
        icon: "◎",
        label: "Peer-to-peer swarm",
        hint: "Peer agents communicate directly and hand off tasks without a central controller",
      },
      { value: "unsure", icon: "?", label: "Not yet determined" },
    ],
  },
  {
    id: "autonomy",
    kind: "single",
    field: "autonomy",
    title: "Action execution & human oversight",
    helper: "Applies to state-changing operations such as sending emails, payments, or database writes.",
    options: [
      {
        value: "answer_only",
        icon: "○",
        label: "Read-only / informational responses",
        hint: "Does not execute actions on external systems",
      },
      {
        value: "approval_required",
        icon: "✓",
        label: "Mandatory human approval",
        hint: "All actions require explicit human confirmation before execution",
      },
      {
        value: "partial_auto",
        icon: "◐",
        label: "Conditional autonomy",
        hint: "Executes routine tasks automatically; requires approval for high-impact actions",
      },
      {
        value: "full_auto",
        icon: "⚡",
        label: "Fully autonomous execution",
        hint: "Executes actions directly without manual review checkpoints",
      },
    ],
  },
  {
    id: "resources",
    kind: "multi",
    field: "resources",
    title: "Connected data sources & external tools",
    helper: "Select all resources accessible to the system.",
    noneLabel: "No external data sources or tools",
    options: [
      {
        value: "internal_docs",
        icon: "▤",
        label: "Internal document repository",
        hint: "Policies, SOPs, contracts, internal knowledge base",
      },
      { value: "web_search", icon: "⊕", label: "Live web search" },
      {
        value: "external_tools",
        icon: "⌘",
        label: "External APIs & services",
        hint: "Email, calendar, payment gateways, third-party integrations",
      },
      {
        value: "company_data",
        icon: "▥",
        label: "Enterprise databases",
        hint: "Customer records, orders, inventory, ERP/CRM",
      },
    ],
  },
  {
    id: "audience",
    kind: "single",
    field: "audience",
    title: "System exposure & user base",
    helper: "Determines exposure to untrusted external inputs.",
    options: [
      { value: "internal", icon: "▣", label: "Internal staff only" },
      { value: "public", icon: "◎", label: "External customers or public users" },
    ],
  },
  {
    id: "sensitive_data",
    kind: "multi",
    field: "sensitive_data",
    title: "Sensitive data exposure",
    helper: "Select all data classifications processed by the system.",
    noneLabel: "No sensitive data processed",
    options: [
      {
        value: "personal",
        icon: "◈",
        label: "Personal Identifiable Information (PII)",
        hint: "Names, phone numbers, addresses, national IDs",
      },
      {
        value: "financial",
        icon: "◇",
        label: "Financial & payment records",
        hint: "Bank accounts, payment cards, billing, transactions",
      },
      {
        value: "confidential",
        icon: "▪",
        label: "Confidential business data",
        hint: "Pricing strategy, proprietary code, internal contracts",
      },
    ],
  },
];

export const SCENARIO_PRESETS_EN: Record<Purpose, ScenarioPreset[]> = {
  customer_support: [
    {
      label: "Order return & refund",
      text: "A customer submits an order ID via chat; the system checks order status and creates a return or refund ticket.",
    },
    {
      label: "Policy lookup",
      text: "A customer asks about warranty terms; the system retrieves answers from the internal knowledge base.",
    },
  ],
  content: [
    {
      label: "Contract summarization",
      text: "Staff upload internal contracts or reports for the system to summarize key clauses.",
    },
    {
      label: "Marketing email dispatch",
      text: "The system gathers web information, drafts marketing copy, and sends emails to customer lists.",
    },
  ],
  data_analysis: [
    {
      label: "Sales & payroll reporting",
      text: "The system reads sales and payroll records to generate executive summary reports.",
    },
    {
      label: "Multi-agent data review",
      text: "One agent queries database metrics while another cross-checks anomalies and compiles the report.",
    },
  ],
  task_automation: [
    {
      label: "Meeting scheduling & email",
      text: "The system reads incoming emails, books calendar slots, and sends confirmation messages to partners.",
    },
    {
      label: "Procurement routing",
      text: "A coordinator agent receives purchase requests and delegates budget verification and payment order creation to sub-agents.",
    },
  ],
  coding: [
    {
      label: "Automated test & patch",
      text: "The system reads internal repositories, executes test suites, and opens pull requests.",
    },
  ],
  other: [
    {
      label: "Workflow processing",
      text: "Users submit requests; the system queries relevant records and executes downstream workflow steps.",
    },
  ],
};

export function getScenarioPresets(language: Language): Record<Purpose, ScenarioPreset[]> {
  return language === "en" ? SCENARIO_PRESETS_EN : SCENARIO_PRESETS;
}

export function getWizardSteps(language: Language): WizardStep[] {
  return language === "en" ? WIZARD_STEPS_EN : WIZARD_STEPS;
}
