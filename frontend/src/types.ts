export interface ArchitectureNode {
  node_type: string;
  is_public: boolean;
  controls: string[];
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
