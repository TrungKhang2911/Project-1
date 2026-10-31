import { useState } from "react";

import { ArchitectureInput } from "./components/ArchitectureInput";
import { RiskDashboard } from "./components/RiskDashboard";
import type { AssessmentRequest, AssessmentResponse } from "./types";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "") ?? "http://localhost:8000";

export function App(): JSX.Element {
  const [assessment, setAssessment] = useState<AssessmentResponse | null>(null);

  async function submitAssessment(request: AssessmentRequest): Promise<void> {
    const response = await fetch(`${API_BASE_URL}/api/v1/assess`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const errorBody: unknown = await response.json().catch(() => null);
      const detail =
        typeof errorBody === "object" &&
        errorBody !== null &&
        "detail" in errorBody &&
        typeof errorBody.detail === "string"
          ? errorBody.detail
          : `Assessment request failed (${response.status}).`;
      throw new Error(detail);
    }

    const result: AssessmentResponse = await response.json();
    setAssessment(result);
  }

  return (
    <main className="app-shell">
      <header className="app-header">
        <p className="app-header__eyebrow">AI Security Engineering</p>
        <h1>AI System Risk Assessment</h1>
        <p>Evaluate architecture risks using a versioned, deterministic knowledge base.</p>
      </header>
      <div className="app-layout">
        <ArchitectureInput apiBaseUrl={API_BASE_URL} onAssess={submitAssessment} />
        <RiskDashboard assessment={assessment} />
      </div>
    </main>
  );
}
