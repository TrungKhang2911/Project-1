import type { Language, UserPreferences } from "../types";

export const PREFS_STORAGE_KEY = "ai_risk_assessment_preferences_v1";

export const DEFAULT_PREFERENCES: UserPreferences = {
  theme: "light",
  language: "vi",
  mode: "normal",
};

export function loadPreferences(): UserPreferences {
  try {
    const raw = window.localStorage.getItem(PREFS_STORAGE_KEY);
    if (!raw) return DEFAULT_PREFERENCES;
    const parsed = JSON.parse(raw) as Partial<UserPreferences>;
    return {
      theme: parsed.theme === "dark" ? "dark" : "light",
      language: parsed.language === "en" ? "en" : "vi",
      mode: parsed.mode === "dev" ? "dev" : "normal",
    };
  } catch {
    return DEFAULT_PREFERENCES;
  }
}

export function savePreferences(prefs: UserPreferences): void {
  try {
    window.localStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    // Ignore storage quota errors
  }
}

export interface UIStrings {
  eyebrowNormal: string;
  eyebrowDev: string;
  titleNormal: string;
  titleDev: string;
  subtitleNormal: string;
  subtitleDev: string;
  settingsLabel: string;
  modeNormal: string;
  modeDev: string;
  themeLight: string;
  themeDark: string;
  langVi: string;
  langEn: string;
  stepCounter: (current: number, total: number) => string;
  reviewTitle: string;
  reviewHeading: string;
  backBtn: string;
  nextBtn: string;
  submitBtn: string;
  submittingBtn: string;
  editBtn: string;
  deleteBtn: string;
  targetBoxTitle: string;
  systemNameLabel: string;
  systemNamePlaceholder: string;
  systemDescLabel: string;
  systemDescPlaceholder: string;
  scenariosLabel: (count: number, max: number) => string;
  scenariosHelper: string;
  quickPresetLabel: string;
  scenarioInputPlaceholder: string;
  addScenarioBtn: string;
  scenarioItemPrefix: (index: number) => string;
  reportHeading: (name: string) => string;
  savedTag: (id: string) => string;
  saveBtn: string;
  savedBtn: string;
  savingBtn: string;
  exportMd: string;
  exportCsv: string;
  exportJson: string;
  newAssessmentBtn: string;
  overallRiskLabel: string;
  patternBoxEyebrow: string;
  combinedPatternsLabel: string;
  systemSummaryTitle: string;
  detailedDescLabel: string;
  recordedScenariosLabel: string;
  topActionsTitle: string;
  riskDetailsTitle: string;
  whatToDoLabel: string;
  techDetailsSummary: string;
  historyHeading: (count: number) => string;
  historySub: string;
  viewRecordBtn: string;
  unnamedSystem: string;
}

export const UI_STRINGS: Record<Language, UIStrings> = {
  vi: {
    eyebrowNormal: "Đánh giá an toàn hệ thống AI",
    eyebrowDev: "Kỹ thuật bảo mật AI · Phân tích định lượng",
    titleNormal: "Đánh giá rủi ro ứng dụng AI",
    titleDev: "Phân tích kiến trúc Agentic AI và ánh xạ rủi ro",
    subtitleNormal:
      "Xác định mô hình kiến trúc AI, nhận diện rủi ro bảo mật và đề xuất biện pháp kiểm soát dựa trên kịch bản vận hành thực tế.",
    subtitleDev:
      "Cấu hình mẫu kiến trúc Agentic AI, các biện pháp kiểm soát kỹ thuật và thành phần hệ thống để tính điểm rủi ro theo chuẩn OWASP và NIST.",
    settingsLabel: "Tùy chỉnh",
    modeNormal: "Cơ bản",
    modeDev: "Kỹ thuật",
    themeLight: "Sáng",
    themeDark: "Tối",
    langVi: "VI",
    langEn: "EN",
    stepCounter: (c, t) => `Bước ${c} / ${t}`,
    reviewTitle: "Xác nhận thông tin",
    reviewHeading: "Kiểm tra thông tin trước khi phân tích",
    backBtn: "← Quay lại",
    nextBtn: "Tiếp tục →",
    submitBtn: "Phân tích rủi ro →",
    submittingBtn: "Đang xử lý…",
    editBtn: "Sửa",
    deleteBtn: "Xóa",
    targetBoxTitle: "Thông tin hệ thống và kịch bản vận hành",
    systemNameLabel: "Tên hệ thống",
    systemNamePlaceholder: "Ví dụ: Hệ thống hỗ trợ xử lý đơn hàng tự động",
    systemDescLabel: "Mô tả quy trình hoạt động",
    systemDescPlaceholder:
      "Ví dụ: Hệ thống tiếp nhận yêu cầu từ khách hàng, tra cứu dữ liệu đơn hàng và kho vận, sau đó soạn phản hồi hoặc tạo phiếu hoàn tiền.",
    scenariosLabel: (count, max) => `Kịch bản vận hành (${count}/${max})`,
    scenariosHelper:
      "Mô tả ngắn gọn dữ liệu đầu vào, các bước xử lý của AI và thao tác đầu ra.",
    quickPresetLabel: "Mẫu kịch bản:",
    scenarioInputPlaceholder: "Nhập kịch bản vận hành…",
    addScenarioBtn: "Thêm",
    scenarioItemPrefix: (idx) => `Kịch bản ${idx}`,
    reportHeading: (name) => `Báo cáo đánh giá: ${name}`,
    savedTag: (id) => `Mã hồ sơ: #${id}`,
    saveBtn: "Lưu báo cáo",
    savedBtn: "✓ Đã lưu",
    savingBtn: "Đang lưu…",
    exportMd: "↓ Markdown",
    exportCsv: "↓ CSV",
    exportJson: "↓ JSON",
    newAssessmentBtn: "Đánh giá mới",
    overallRiskLabel: "Mức rủi ro tổng thể",
    patternBoxEyebrow: "Kiến trúc Agentic AI",
    combinedPatternsLabel: "Mẫu kiến trúc kết hợp:",
    systemSummaryTitle: "Tổng quan hệ thống",
    detailedDescLabel: "Mô tả hoạt động:",
    recordedScenariosLabel: "Kịch bản vận hành:",
    topActionsTitle: "Khuyến nghị ưu tiên",
    riskDetailsTitle: "Danh mục rủi ro chi tiết",
    whatToDoLabel: "Biện pháp xử lý:",
    techDetailsSummary: "Phụ lục kỹ thuật (OWASP / NIST / Pattern Mapping)",
    historyHeading: (count) => `Hồ sơ đã lưu (${count})`,
    historySub: "Chọn bản ghi để xem chi tiết hoặc xuất báo cáo",
    viewRecordBtn: "Xem",
    unnamedSystem: "Hệ thống AI",
  },
  en: {
    eyebrowNormal: "AI System Security Assessment",
    eyebrowDev: "AI Security Engineering · Quantitative Analysis",
    titleNormal: "AI Application Risk Assessment",
    titleDev: "Agentic AI Architecture & Risk Mapping",
    subtitleNormal:
      "Identify AI architecture patterns, evaluate security risks, and review actionable controls based on operational scenarios.",
    subtitleDev:
      "Configure Agentic AI design patterns, technical controls, and system nodes for quantitative risk scoring mapped to OWASP and NIST.",
    settingsLabel: "Preferences",
    modeNormal: "Standard",
    modeDev: "Technical",
    themeLight: "Light",
    themeDark: "Dark",
    langVi: "VI",
    langEn: "EN",
    stepCounter: (c, t) => `Step ${c} / ${t}`,
    reviewTitle: "Review",
    reviewHeading: "Review system configuration before analysis",
    backBtn: "← Back",
    nextBtn: "Continue →",
    submitBtn: "Run assessment →",
    submittingBtn: "Analyzing…",
    editBtn: "Edit",
    deleteBtn: "Remove",
    targetBoxTitle: "System Details & Operational Scenarios",
    systemNameLabel: "System name",
    systemNamePlaceholder: "e.g., Automated Order Support System",
    systemDescLabel: "Operational workflow description",
    systemDescPlaceholder:
      "e.g., Receives customer inquiries, queries order and inventory databases, and drafts responses or creates refund tickets.",
    scenariosLabel: (count, max) => `Operational scenarios (${count}/${max})`,
    scenariosHelper:
      "Briefly describe input data, agent processing steps, and external actions.",
    quickPresetLabel: "Presets:",
    scenarioInputPlaceholder: "Enter an operational scenario…",
    addScenarioBtn: "Add",
    scenarioItemPrefix: (idx) => `Scenario ${idx}`,
    reportHeading: (name) => `Assessment Report: ${name}`,
    savedTag: (id) => `Record ID: #${id}`,
    saveBtn: "Save",
    savedBtn: "✓ Saved",
    savingBtn: "Saving…",
    exportMd: "↓ Markdown",
    exportCsv: "↓ CSV",
    exportJson: "↓ JSON",
    newAssessmentBtn: "New assessment",
    overallRiskLabel: "Overall Risk Level",
    patternBoxEyebrow: "Agentic AI Architecture",
    combinedPatternsLabel: "Combined patterns:",
    systemSummaryTitle: "System Overview",
    detailedDescLabel: "Workflow description:",
    recordedScenariosLabel: "Operational scenarios:",
    topActionsTitle: "Priority Mitigations",
    riskDetailsTitle: "Detailed Risk Breakdown",
    whatToDoLabel: "Recommended controls:",
    techDetailsSummary: "Technical Appendix (OWASP / NIST / Pattern Mapping)",
    historyHeading: (count) => `Saved Assessments (${count})`,
    historySub: "Select a record to inspect or export",
    viewRecordBtn: "Open",
    unnamedSystem: "AI System",
  },
};

