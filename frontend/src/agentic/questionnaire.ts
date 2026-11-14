/**
 * Plain-language questionnaire. Option values match the backend enums in
 * backend/app/schemas/agentic_schema.py; labels never use technical terms.
 */
import type {
  Audience,
  Autonomy,
  Collaboration,
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
      text: "Khách hàng gửi mã đơn qua khung chat, AI tra cứu trạng thái và tự tạo phiếu đổi trả hoặc hoàn tiền.",
    },
    {
      label: "Tư vấn từ tài liệu",
      text: "Khách hỏi chính sách bảo hành, AI tìm trong kho tài liệu nội bộ để trả lời trực tiếp.",
    },
  ],
  content: [
    {
      label: "Tóm tắt tài liệu mật",
      text: "Nhân viên tải hợp đồng hoặc báo cáo nội bộ lên để AI tóm tắt các điều khoản chính.",
    },
    {
      label: "Soạn và gửi email",
      text: "AI tự tìm thông tin trên Internet, viết bài/email tiếp thị rồi gửi cho danh sách khách hàng.",
    },
  ],
  data_analysis: [
    {
      label: "Phân tích doanh thu & lương",
      text: "AI đọc dữ liệu bán hàng và bảng lương công ty để lập báo cáo tổng hợp cho quản lý.",
    },
    {
      label: "Nhiều AI cùng phân tích",
      text: "Một AI thu thập số liệu từ cơ sở dữ liệu, một AI khác kiểm tra chéo và viết nhận xét.",
    },
  ],
  task_automation: [
    {
      label: "Đặt lịch & gửi email tự động",
      text: "AI đọc email đến, tự sắp lịch họp trên lịch công ty và gửi thư xác nhận cho đối tác.",
    },
    {
      label: "Duyệt chi / đặt hàng",
      text: "AI trưởng nhóm nhận yêu cầu mua sắm, giao cho AI kiểm tra ngân sách và AI tạo lệnh thanh toán.",
    },
  ],
  coding: [
    {
      label: "Tự chạy mã và sửa lỗi",
      text: "AI đọc mã nguồn của công ty, tự chạy thử nghiệm và tự tạo yêu cầu cập nhật mã.",
    },
  ],
  other: [
    {
      label: "Xử lý yêu cầu theo quy trình",
      text: "Người dùng gửi yêu cầu, AI tra cứu thông tin cần thiết và thực hiện các bước xử lý tiếp theo.",
    },
  ],
};

export const WIZARD_STEPS: WizardStep[] = [
  {
    id: "purpose",
    kind: "single",
    field: "purpose",
    title: "Ứng dụng AI của bạn làm nhiệm vụ chính là gì?",
    helper: "Chọn việc gần giống nhất. Bạn có thể mô tả thêm ở bên dưới.",
    options: [
      { value: "customer_support", icon: "01", label: "Trả lời câu hỏi, chăm sóc khách hàng" },
      { value: "content", icon: "02", label: "Viết, dịch hoặc tóm tắt nội dung" },
      { value: "data_analysis", icon: "03", label: "Phân tích số liệu, làm báo cáo" },
      {
        value: "task_automation",
        icon: "04",
        label: "Tự động làm việc thay tôi",
        hint: "Ví dụ: gửi email, đặt lịch, đặt hàng",
      },
      { value: "coding", icon: "05", label: "Hỗ trợ lập trình, kỹ thuật" },
      { value: "other", icon: "06", label: "Việc khác" },
    ],
  },
  {
    id: "collaboration",
    kind: "single",
    field: "collaboration",
    title: "Nó có làm việc một mình không, hay có nhiều AI khác cùng chia việc?",
    helper: "Hãy hình dung ứng dụng như một nhóm nhân viên. Chọn cách làm việc giống nhất.",
    options: [
      { value: "alone", icon: "●", label: "Một mình", hint: "Một AI lo hết mọi việc" },
      {
        value: "pipeline",
        icon: "→",
        label: "Lần lượt như dây chuyền",
        hint: "AI này làm xong thì chuyển cho AI kia làm tiếp",
      },
      {
        value: "parallel",
        icon: "⇉",
        label: "Cùng lúc rồi gộp lại",
        hint: "Mỗi AI làm một phần cùng lúc, sau đó ghép kết quả",
      },
      {
        value: "manager",
        icon: "◈",
        label: "Có một AI \"trưởng nhóm\"",
        hint: "AI trưởng nhóm xem yêu cầu rồi giao việc cho các AI khác",
      },
      {
        value: "team_chat",
        icon: "◎",
        label: "Các AI tự bàn bạc với nhau",
        hint: "Không ai chỉ huy, các AI trao đổi qua lại để ra kết quả",
      },
      { value: "unsure", icon: "?", label: "Tôi không chắc" },
    ],
  },
  {
    id: "autonomy",
    kind: "single",
    field: "autonomy",
    title: "AI có tự động thực hiện hành động, hay nó phải đợi bạn bấm \"Đồng ý\"?",
    helper: "Hành động là những việc có tác động thật: gửi email, mua hàng, sửa dữ liệu…",
    options: [
      {
        value: "answer_only",
        icon: "○",
        label: "Chỉ trả lời hoặc gợi ý",
        hint: "AI không tự làm gì, người dùng tự quyết",
      },
      {
        value: "approval_required",
        icon: "✓",
        label: "Luôn đợi tôi bấm \"Đồng ý\"",
        hint: "AI chuẩn bị sẵn, nhưng chỉ làm khi có người duyệt",
      },
      {
        value: "partial_auto",
        icon: "◐",
        label: "Việc nhỏ tự làm, việc lớn thì hỏi",
        hint: "Ví dụ: tự trả lời email thường, hỏi trước khi chuyển tiền",
      },
      {
        value: "full_auto",
        icon: "⚡",
        label: "Tự làm hết, không cần hỏi",
      },
    ],
  },
  {
    id: "resources",
    kind: "multi",
    field: "resources",
    title: "Nó có cần tra cứu tài liệu của công ty hoặc gọi công cụ bên ngoài không?",
    helper: "Chọn tất cả những gì AI được phép dùng.",
    noneLabel: "Không, chỉ dùng kiến thức có sẵn",
    options: [
      {
        value: "internal_docs",
        icon: "▤",
        label: "Tra cứu tài liệu nội bộ",
        hint: "Quy trình, chính sách, hợp đồng, tài liệu hướng dẫn…",
      },
      { value: "web_search", icon: "⊕", label: "Tìm kiếm trên Internet" },
      {
        value: "external_tools",
        icon: "⌘",
        label: "Dùng dịch vụ bên ngoài",
        hint: "Email, lịch, thanh toán, mạng xã hội…",
      },
      {
        value: "company_data",
        icon: "▥",
        label: "Đọc hoặc sửa dữ liệu của công ty",
        hint: "Danh sách khách hàng, đơn hàng, kho hàng…",
      },
    ],
  },
  {
    id: "audience",
    kind: "single",
    field: "audience",
    title: "Ai sẽ sử dụng ứng dụng này?",
    helper: "Điều này giúp ước lượng khả năng có người cố tình lợi dụng AI.",
    options: [
      { value: "internal", icon: "▣", label: "Chỉ nhân viên trong công ty" },
      { value: "public", icon: "◎", label: "Khách hàng hoặc bất kỳ ai trên Internet" },
    ],
  },
  {
    id: "sensitive_data",
    kind: "multi",
    field: "sensitive_data",
    title: "AI có tiếp xúc với thông tin nhạy cảm không?",
    helper: "Chọn tất cả những gì phù hợp.",
    noneLabel: "Không có thông tin nhạy cảm",
    options: [
      {
        value: "personal",
        icon: "◈",
        label: "Thông tin cá nhân",
        hint: "Họ tên, số điện thoại, địa chỉ, CCCD…",
      },
      {
        value: "financial",
        icon: "◇",
        label: "Tiền bạc, tài chính",
        hint: "Số tài khoản, thẻ, giao dịch, thanh toán…",
      },
      {
        value: "confidential",
        icon: "▪",
        label: "Bí mật kinh doanh",
        hint: "Giá vốn, chiến lược, hợp đồng mật…",
      },
    ],
  },
];

