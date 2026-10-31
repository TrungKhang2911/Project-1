import type { AssessmentResponse, EvaluatedRiskResult } from "../types";

interface RiskDashboardProps {
  assessment: AssessmentResponse | null;
}

const SEVERITY_COLORS: Record<string, string> = {
  Low: "#2e7d32",
  Medium: "#edb600",
  High: "#ed6c02",
  Critical: "#c62828",
};

function getSeverity(score: number): "Low" | "Medium" | "High" | "Critical" {
  if (score <= 5) return "Low";
  if (score <= 11) return "Medium";
  if (score <= 19) return "High";
  return "Critical";
}

function RiskMatrix({ matrix }: { matrix: number[][] }): JSX.Element {
  return (
    <table className="risk-matrix">
      <caption>Risk matrix (Likelihood × Impact)</caption>
      <thead>
        <tr>
          <th scope="col">Likelihood / Impact</th>
          {[1, 2, 3, 4, 5].map((impact) => (
            <th scope="col" key={impact}>
              {impact}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {[5, 4, 3, 2, 1].map((likelihood) => (
          <tr key={likelihood}>
            <th scope="row">{likelihood}</th>
            {[1, 2, 3, 4, 5].map((impact) => {
              const score = likelihood * impact;
              const severity = getSeverity(score);
              const count = matrix[likelihood - 1]?.[impact - 1] ?? 0;
              return (
                <td
                  key={impact}
                  style={{
                    backgroundColor: SEVERITY_COLORS[severity],
                    color: severity === "Medium" ? "#1f1f1f" : "#ffffff",
                  }}
                  aria-label={`${count} risks at likelihood ${likelihood}, impact ${impact}, ${severity}`}
                >
                  {count}
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RiskDetails({ risk }: { risk: EvaluatedRiskResult }): JSX.Element {
  return (
    <article className="risk-card">
      <header>
        <h3>
          {risk.risk_id}: {risk.risk_name}
        </h3>
        <span
          className="risk-card__severity"
          style={{ backgroundColor: SEVERITY_COLORS[risk.severity_level] }}
        >
          {risk.severity_level} · {risk.residual_score}/25
        </span>
      </header>
      <p>
        <strong>Component:</strong> {risk.source_component}
      </p>
      <p>
        <strong>Inherent score:</strong> {risk.inherent_score}/25
      </p>
      <p>{risk.attack_scenario}</p>
      <p>
        <strong>NIST mappings:</strong> {risk.nist_categories.join(", ")}
      </p>
      <p>
        <strong>Recommended action:</strong> {risk.recommended_action}
      </p>
      {risk.missing_mitigations.length > 0 ? (
        <div>
          <strong>Missing mitigations</strong>
          <ul>
            {risk.missing_mitigations.map((mitigation) => (
              <li key={mitigation}>{mitigation}</li>
            ))}
          </ul>
        </div>
      ) : (
        <p>All defined mitigations for this risk are applied.</p>
      )}
    </article>
  );
}

export function RiskDashboard({ assessment }: RiskDashboardProps): JSX.Element {
  if (assessment === null) {
    return <section aria-live="polite">Submit an architecture to view its risk assessment.</section>;
  }

  return (
    <section className="risk-dashboard" aria-live="polite">
      <h2>Risk assessment</h2>
      <div
        className="risk-dashboard__summary"
        style={{ borderColor: SEVERITY_COLORS[assessment.overall_severity] }}
      >
        <p>
          Overall risk score: <strong>{assessment.overall_risk_score}/25</strong>
        </p>
        <p>
          Overall severity:{" "}
          <strong style={{ color: SEVERITY_COLORS[assessment.overall_severity] }}>
            {assessment.overall_severity}
          </strong>
        </p>
        <small>Overall score is the highest residual score among evaluated risks.</small>
      </div>

      <RiskMatrix matrix={assessment.risk_matrix_summary} />

      <div className="risk-dashboard__results">
        {assessment.results.map((risk, index) => (
          <RiskDetails
            key={`${risk.source_component}-${risk.risk_id}-${index}`}
            risk={risk}
          />
        ))}
      </div>
    </section>
  );
}
