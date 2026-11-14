export interface ArchitectureNode {
  node_type: string;
  is_public: boolean;
  controls: string[];
  custom_description?: string;
}

export interface AssessmentRequest {
  architecture: ArchitectureNode[];
}

export interface ControlOption {
  control_id: string;
  description: string;
}

export interface ComponentOption {
  node_type: string;
  display_name: string;
  controls: ControlOption[];
}

export interface ComponentsResponse {
  components: ComponentOption[];
}

export interface EvaluatedRiskResult {
  source_component: string;
  risk_id: string;
  risk_name: string;
  nist_categories: string[];
  attack_scenario: string;
  inherent_score: number;
  residual_likelihood: number;
  residual_impact: number;
  residual_score: number;
  severity_level: "Low" | "Medium" | "High" | "Critical";
  recommended_action: string;
  missing_mitigations: string[];
}

export type RiskMatrix = number[][];

export interface AssessmentResponse {
  results: EvaluatedRiskResult[];
  overall_risk_score: number;
  overall_severity: "Low" | "Medium" | "High" | "Critical";
  risk_matrix_summary: RiskMatrix;
}

/* ------------------------------------------------------------------ */
/* Plain-language questionnaire (mirrors backend agentic_schema.py)    */
/* ------------------------------------------------------------------ */

export type Purpose =
  | "customer_support"
  | "content"
  | "data_analysis"
  | "task_automation"
  | "coding"
  | "other";
export type Collaboration =
  | "alone"
  | "pipeline"
  | "parallel"
  | "manager"
  | "team_chat"
  | "unsure";
export type Autonomy =
  | "answer_only"
  | "approval_required"
  | "partial_auto"
  | "full_auto";
export type Resource =
  | "internal_docs"
  | "web_search"
  | "external_tools"
  | "company_data";
export type Audience = "internal" | "public";
export type SensitiveData = "personal" | "financial" | "confidential";

export interface QuestionnaireAnswers {
  system_name?: string;
  purpose: Purpose;
  purpose_details?: string;
  scenarios?: string[];
  collaboration: Collaboration;
  autonomy: Autonomy;
  resources: Resource[];
  audience: Audience;
  sensitive_data: SensitiveData[];
}

export type AgenticPattern =
  | "SINGLE_AGENT"
  | "REACT"
  | "SEQUENTIAL"
  | "PARALLEL"
  | "COORDINATOR"
  | "HIERARCHICAL"
  | "SWARM"
  | "HUMAN_IN_THE_LOOP";

export type HumanOversight = "none" | "partial" | "full";

export interface PatternDetection {
  primary_pattern: AgenticPattern;
  patterns: AgenticPattern[];
  human_oversight: HumanOversight;
  is_multi_agent: boolean;
  confidence: number;
  rationale: string;
  plain_summary: string;
  source: "llm" | "rules";
}

export interface ClassificationResponse {
  detection: PatternDetection;
}

export interface SavedRiskItem {
  id: string;
  title: string;
  explanation: string;
  likelihood: number;
  impact: number;
  score: number;
  severity: "Low" | "Medium" | "High" | "Critical";
  severityLabel: string;
  recommendations: string[];
  adjustments: string[];
}

export interface SavedAssessmentCreate {
  answers: QuestionnaireAnswers;
  detection: PatternDetection;
  overall_score: number;
  overall_severity: "Low" | "Medium" | "High" | "Critical";
  overall_severity_label: string;
  oversight_note: string;
  top_actions: string[];
  risks: SavedRiskItem[];
}

export interface SavedAssessmentRecord extends SavedAssessmentCreate {
  assessment_id: string;
  created_at: string;
}

export interface SavedAssessmentsListResponse {
  records: SavedAssessmentRecord[];
}
