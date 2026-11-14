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
    eyebrowNormal: "Kiểm tra an toàn hệ thống AI",
    eyebrowDev: "AI Security Engineering · Academic & Technical Mode",
    titleNormal: "Ứng dụng AI của bạn có an toàn không?",
    titleDev: "Phân tích Kiến trúc Agentic AI & Ánh xạ Rủi ro Học thuật",
    subtitleNormal:
      "Mô tả hệ thống và kịch bản sử dụng bằng ngôn ngữ đời thường. Hệ thống sẽ tự động nhận diện mô hình tích hợp AI (theo chuẩn Google Cloud Agentic Patterns), chỉ ra rủi ro và lưu lại kết quả để xuất báo cáo.",
    subtitleDev:
      "Chế độ Kỹ thuật / Học thuật (Dev Mode): Khai báo trực tiếp mẫu kiến trúc Agentic AI, cấu hình phạm vi OWASP LLM Top 10 / NIST AI RMF 1.0, thiết lập trọng số giảm thiểu (Mitigation Discount W_total) hoặc cấu hình từng Node kiến trúc để nhận báo cáo định lượng chuyên sâu.",
    settingsLabel: "Tùy biến",
    modeNormal: "Normal Mode",
    modeDev: "Dev Mode",
    themeLight: "Sáng",
    themeDark: "Tối",
    langVi: "VI",
    langEn: "EN",
    stepCounter: (c, t) => `Bước ${c} / ${t}`,
    reviewTitle: "Bước cuối · Xem lại thông tin",
    reviewHeading: "Kiểm tra lại thông tin hệ thống trước khi phân tích",
    backBtn: "← Quay lại",
    nextBtn: "Tiếp tục →",
    submitBtn: "Xem đánh giá rủi ro →",
    submittingBtn: "Đang phân tích…",
    editBtn: "Sửa",
    deleteBtn: "Xoá",
    targetBoxTitle: "Thông tin chi tiết về hệ thống & kịch bản hoạt động (khuyến khích)",
    systemNameLabel: "Tên ứng dụng / hệ thống AI (đích đánh giá)",
    systemNamePlaceholder: "Ví dụ: Trợ lý CSKH tự động đơn hàng Shopee/Website",
    systemDescLabel: "Mô tả chi tiết hệ thống AI của bạn hoạt động như thế nào?",
    systemDescPlaceholder:
      "Ví dụ: Hệ thống tiếp nhận tin nhắn của khách, một AI tra cứu kho và đơn hàng, sau đó AI khác soạn phản hồi hoặc tạo phiếu hoàn tiền.",
    scenariosLabel: (count, max) => `Các kịch bản tình huống thực tế của hệ thống (${count}/${max})`,
    scenariosHelper:
      "Nêu các tình huống cụ thể (ai gửi gì vào, AI xử lý bước nào, tác động ra sao) để AI phân tích chính xác mô hình và rủi ro.",
    quickPresetLabel: "Gợi ý nhanh:",
    scenarioInputPlaceholder: "Nhập một kịch bản sử dụng rồi bấm 'Thêm kịch bản'…",
    addScenarioBtn: "Thêm kịch bản",
    scenarioItemPrefix: (idx) => `Kịch bản ${idx}`,
    reportHeading: (name) => `Kết quả đánh giá: ${name}`,
    savedTag: (id) => `Mã hồ sơ đã lưu: #${id}`,
    saveBtn: "Lưu kết quả",
    savedBtn: "✓ Đã lưu",
    savingBtn: "Đang lưu…",
    exportMd: "↓ Xuất Markdown",
    exportCsv: "↓ Xuất CSV",
    exportJson: "↓ Xuất JSON",
    newAssessmentBtn: "Đánh giá mới",
    overallRiskLabel: "Mức rủi ro chung",
    patternBoxEyebrow: "Mô hình mẫu tích hợp AI được ghi nhận (Google Cloud Agentic Pattern)",
    combinedPatternsLabel: "Các mẫu hình kết hợp trong hệ thống:",
    systemSummaryTitle: "Mô tả hệ thống & kịch bản vận hành (Đích đánh giá)",
    detailedDescLabel: "Mô tả chi tiết:",
    recordedScenariosLabel: "Các kịch bản vận hành đã ghi nhận:",
    topActionsTitle: "Việc nên làm ngay",
    riskDetailsTitle: "Chi tiết từng rủi ro",
    whatToDoLabel: "Bạn nên làm gì?",
    techDetailsSummary: "Thông tin dành cho đội kỹ thuật (OWASP / NIST / Pattern Mapping)",
    historyHeading: (count) => `Lịch sử các lần đánh giá đã lưu (${count})`,
    historySub: "Chọn một bản ghi để xem lại hoặc kết xuất báo cáo (Markdown / CSV / JSON)",
    viewRecordBtn: "Xem lại",
    unnamedSystem: "Ứng dụng AI của bạn",
  },
  en: {
    eyebrowNormal: "AI System Safety Check",
    eyebrowDev: "AI Security Engineering · Academic & Technical Mode",
    titleNormal: "Is your AI application safe?",
    titleDev: "Agentic AI Architecture & Academic Risk Mapping",
    subtitleNormal:
      "Describe your system and real-world scenarios in plain language. We automatically map it to Google Cloud Agentic AI design patterns, highlight security risks, and store your report for export.",
    subtitleDev:
      "Developer / Academic Mode: Explicitly configure Google Cloud Agentic AI design patterns, OWASP LLM Top 10 / NIST AI RMF 1.0 taxonomies, mitigation discount weights (W_total), or component nodes for quantitative risk analysis.",
    settingsLabel: "Preferences",
    modeNormal: "Normal Mode",
    modeDev: "Dev Mode",
    themeLight: "Light",
    themeDark: "Dark",
    langVi: "VI",
    langEn: "EN",
    stepCounter: (c, t) => `Step ${c} / ${t}`,
    reviewTitle: "Final Step · Review answers",
    reviewHeading: "Review your system information before analysis",
    backBtn: "← Back",
    nextBtn: "Continue →",
    submitBtn: "View risk assessment →",
    submittingBtn: "Analyzing…",
    editBtn: "Edit",
    deleteBtn: "Remove",
    targetBoxTitle: "Target System Details & Operational Scenarios (Recommended)",
    systemNameLabel: "AI System / Application Name (Target under evaluation)",
    systemNamePlaceholder: "e.g., Automated Order Support Assistant",
    systemDescLabel: "How does your AI system operate in detail?",
    systemDescPlaceholder:
      "e.g., The system receives customer chats; one agent queries order/inventory databases and another agent drafts replies or issues refund tickets.",
    scenariosLabel: (count, max) => `Concrete Operational Scenarios (${count}/${max})`,
    scenariosHelper:
      "Describe real use-case scenarios (inputs, agent processing steps, external actions) for accurate pattern and risk inference.",
    quickPresetLabel: "Quick presets:",
    scenarioInputPlaceholder: "Enter an operational scenario and click 'Add scenario'…",
    addScenarioBtn: "Add scenario",
    scenarioItemPrefix: (idx) => `Scenario ${idx}`,
    reportHeading: (name) => `Assessment Report: ${name}`,
    savedTag: (id) => `Saved Record ID: #${id}`,
    saveBtn: "Save report",
    savedBtn: "✓ Saved",
    savingBtn: "Saving…",
    exportMd: "↓ Export Markdown",
    exportCsv: "↓ Export CSV",
    exportJson: "↓ Export JSON",
    newAssessmentBtn: "New assessment",
    overallRiskLabel: "Overall Risk Level",
    patternBoxEyebrow: "Detected AI Integration Pattern (Google Cloud Agentic Pattern)",
    combinedPatternsLabel: "Combined patterns in this architecture:",
    systemSummaryTitle: "Target System Description & Operational Scenarios",
    detailedDescLabel: "Detailed description:",
    recordedScenariosLabel: "Recorded operational scenarios:",
    topActionsTitle: "Priority Actions",
    riskDetailsTitle: "Detailed Risk Breakdown",
    whatToDoLabel: "Recommended Actions:",
    techDetailsSummary: "Engineering & Academic Appendix (OWASP / NIST / Pattern Mapping)",
    historyHeading: (count) => `Saved Assessment History (${count})`,
    historySub: "Select a saved record to inspect or export (Markdown / CSV / JSON)",
    viewRecordBtn: "Inspect",
    unnamedSystem: "Your AI Application",
  },
};

