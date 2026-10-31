import { useEffect, useState } from "react";

import type {
  ArchitectureNode,
  AssessmentRequest,
  ComponentOption,
  ComponentsResponse,
} from "../types";

interface ArchitectureInputProps {
  apiBaseUrl?: string;
  onAssess: (request: AssessmentRequest) => Promise<void>;
}

interface EditableNode extends ArchitectureNode {
  localId: number;
}

const DEFAULT_API_BASE_URL = "http://localhost:8000";

export function ArchitectureInput({
  apiBaseUrl = DEFAULT_API_BASE_URL,
  onAssess,
}: ArchitectureInputProps): JSX.Element {
  const [components, setComponents] = useState<ComponentOption[]>([]);
  const [nodes, setNodes] = useState<EditableNode[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [nextId, setNextId] = useState<number>(1);

  useEffect(() => {
    const controller = new AbortController();

    async function loadComponents(): Promise<void> {
      try {
        setLoading(true);
        const response = await fetch(
          `${apiBaseUrl.replace(/\/$/, "")}/api/v1/components`,
          { signal: controller.signal },
        );
        if (!response.ok) {
          throw new Error(`Unable to load component options (${response.status}).`);
        }
        const payload = (await response.json()) as ComponentsResponse;
        if (!Array.isArray(payload.components) || payload.components.length === 0) {
          throw new Error("The API returned no component options.");
        }
        setComponents(payload.components);
        setNodes((current) =>
          current.length > 0
            ? current
            : [
                {
                  localId: 1,
                  node_type: payload.components[0].node_type,
                  is_public: true,
                  controls: [],
                },
              ],
        );
        setNextId((current) => Math.max(current, 2));
        setError(null);
      } catch (loadError: unknown) {
        if (loadError instanceof DOMException && loadError.name === "AbortError") {
          return;
        }
        setError(
          loadError instanceof Error
            ? loadError.message
            : "An unexpected error occurred while loading components.",
        );
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      }
    }

    void loadComponents();
    return () => controller.abort();
  }, [apiBaseUrl]);

  function addNode(): void {
    if (components.length === 0) {
      return;
    }
    setNodes((current) => [
      ...current,
      {
        localId: nextId,
        node_type: components[0].node_type,
        is_public: true,
        controls: [],
      },
    ]);
    setNextId((current) => current + 1);
  }

  function updateNode(
    localId: number,
    update: (node: EditableNode) => EditableNode,
  ): void {
    setNodes((current) =>
      current.map((node) => (node.localId === localId ? update(node) : node)),
    );
  }

  async function submitAssessment(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (nodes.length === 0) {
      setError("Add at least one architecture node before assessing.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await onAssess({
        architecture: nodes.map(({ localId: _localId, ...node }) => node),
      });
    } catch (assessmentError: unknown) {
      setError(
        assessmentError instanceof Error
          ? assessmentError.message
          : "Assessment failed unexpectedly.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return <p role="status">Loading architecture options…</p>;
  }

  return (
    <form className="architecture-input" onSubmit={(event) => void submitAssessment(event)}>
      <header className="architecture-input__header">
        <div>
          <h2>System architecture</h2>
          <p>Configure each component and its applicable security controls.</p>
        </div>
        <button type="button" onClick={addNode} disabled={components.length === 0}>
          Add node
        </button>
      </header>

      {error !== null && <p role="alert">{error}</p>}

      {nodes.map((node, index) => {
        const selectedComponent = components.find(
          (component) => component.node_type === node.node_type,
        );
        return (
          <fieldset className="architecture-node" key={node.localId}>
            <legend>Node {index + 1}</legend>
            <label>
              Component
              <select
                value={node.node_type}
                onChange={(event) =>
                  updateNode(node.localId, (current) => ({
                    ...current,
                    node_type: event.target.value,
                    controls: [],
                  }))
                }
              >
                {components.map((component) => (
                  <option key={component.node_type} value={component.node_type}>
                    {component.display_name}
                  </option>
                ))}
              </select>
            </label>

            <label className="architecture-node__public">
              <input
                type="checkbox"
                checked={node.is_public}
                onChange={(event) =>
                  updateNode(node.localId, (current) => ({
                    ...current,
                    is_public: event.target.checked,
                  }))
                }
              />
              Publicly accessible
            </label>

            <fieldset>
              <legend>Security controls</legend>
              {selectedComponent?.controls.map((control) => (
                <label key={control.control_id} className="architecture-control">
                  <input
                    type="checkbox"
                    checked={node.controls.includes(control.control_id)}
                    onChange={(event) =>
                      updateNode(node.localId, (current) => ({
                        ...current,
                        controls: event.target.checked
                          ? [...current.controls, control.control_id]
                          : current.controls.filter(
                              (controlId) => controlId !== control.control_id,
                            ),
                      }))
                    }
                  />
                  <span>
                    <strong>{control.control_id}</strong>
                    <small>{control.description}</small>
                  </span>
                </label>
              ))}
              {selectedComponent?.controls.length === 0 && (
                <p>No controls are defined for this component.</p>
              )}
            </fieldset>

            <button
              type="button"
              onClick={() =>
                setNodes((current) =>
                  current.filter((candidate) => candidate.localId !== node.localId),
                )
              }
              aria-label={`Remove node ${index + 1}`}
            >
              Remove node
            </button>
          </fieldset>
        );
      })}

      <button type="submit" disabled={submitting || nodes.length === 0}>
        {submitting ? "Assessing…" : "Assess risks"}
      </button>
    </form>
  );
}
