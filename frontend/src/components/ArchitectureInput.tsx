import { useEffect, useState } from "react";

import type {
  ArchitectureNode,
  AssessmentRequest,
  ComponentOption,
  ComponentsResponse,
  Language,
} from "../types";

interface ArchitectureInputProps {
  apiBaseUrl?: string;
  language?: Language;
  onAssess: (request: AssessmentRequest) => Promise<void>;
}

interface EditableNode extends ArchitectureNode {
  localId: number;
}

const DEFAULT_API_BASE_URL = "http://localhost:8000";

export function ArchitectureInput({
  apiBaseUrl = DEFAULT_API_BASE_URL,
  language = "vi",
  onAssess,
}: ArchitectureInputProps): JSX.Element {
  const isEn = language === "en";
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
          throw new Error(
            isEn
              ? `Unable to load component options (${response.status}).`
              : `Không thể tải danh sách thành phần (${response.status}).`,
          );
        }
        const payload = (await response.json()) as ComponentsResponse;
        if (!Array.isArray(payload.components) || payload.components.length === 0) {
          throw new Error(
            isEn
              ? "The API returned no component options."
              : "Máy chủ không trả về danh sách thành phần.",
          );
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
            : isEn
              ? "Unable to load architecture components."
              : "Không thể tải danh sách thành phần hệ thống.",
        );
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      }
    }

    void loadComponents();
    return () => controller.abort();
  }, [apiBaseUrl, isEn]);

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
      setError(
        isEn
          ? "Add at least one architecture node before assessing."
          : "Cần thêm ít nhất một thành phần trước khi đánh giá.",
      );
      return;
    }
    if (
      nodes.some(
        (node) =>
          node.node_type === "Other" && !node.custom_description?.trim(),
      )
    ) {
      setError(
        isEn
          ? "Describe each custom component before assessing."
          : "Vui lòng nhập mô tả cho thành phần tùy chỉnh.",
      );
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await onAssess({
        architecture: nodes.map(
          ({ localId: _localId, custom_description, ...node }) => ({
            ...node,
            ...(node.node_type === "Other"
              ? { custom_description: custom_description?.trim() ?? "" }
              : {}),
          }),
        ),
      });
    } catch (assessmentError: unknown) {
      setError(
        assessmentError instanceof Error
          ? assessmentError.message
          : isEn
            ? "Assessment failed unexpectedly."
            : "Quá trình đánh giá gặp sự cố.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return (
      <p role="status">
        {isEn ? "Loading architecture components…" : "Đang tải danh sách thành phần…"}
      </p>
    );
  }

  return (
    <form className="architecture-input" onSubmit={(event) => void submitAssessment(event)}>
      <header className="architecture-input__header">
        <div>
          <h2>{isEn ? "System Architecture" : "Thành phần kiến trúc"}</h2>
          <p>
            {isEn
              ? "Configure each component node and its deployed security controls."
              : "Cấu hình từng thành phần hệ thống và các kiểm soát bảo mật tương ứng."}
          </p>
        </div>
        <button type="button" onClick={addNode} disabled={components.length === 0}>
          {isEn ? "+ Add Node" : "+ Thêm thành phần"}
        </button>
      </header>

      {error !== null && <p role="alert">{error}</p>}

      {nodes.map((node, index) => {
        const selectedComponent = components.find(
          (component) => component.node_type === node.node_type,
        );
        return (
          <fieldset className="architecture-node" key={node.localId}>
            <legend>{isEn ? `Node ${index + 1}` : `Thành phần ${index + 1}`}</legend>
            <label>
              {isEn ? "Component Type" : "Loại thành phần"}
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
                <option value="Other">
                  {isEn ? "Other (Custom Component)" : "Khác (Thành phần tùy chỉnh)"}
                </option>
              </select>
            </label>

            {node.node_type === "Other" && (
              <label>
                {isEn ? "Component Description" : "Mô tả thành phần"}
                <textarea
                  value={node.custom_description ?? ""}
                  onChange={(event) =>
                    updateNode(node.localId, (current) => ({
                      ...current,
                      custom_description: event.target.value,
                      controls: [],
                    }))
                  }
                  placeholder={
                    isEn
                      ? "e.g., Internal Redis session cache"
                      : "Ví dụ: Bộ nhớ đệm phiên truy cập Redis nội bộ"
                  }
                  rows={4}
                  required
                />
              </label>
            )}

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
              {isEn ? "Publicly accessible" : "Cho phép truy cập từ mạng công cộng"}
            </label>

            {node.node_type !== "Other" && (
              <fieldset>
                <legend>{isEn ? "Security Controls" : "Kiểm soát bảo mật"}</legend>
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
                  <p>
                    {isEn
                      ? "No predefined controls for this component."
                      : "Chưa có kiểm soát định nghĩa sẵn cho thành phần này."}
                  </p>
                )}
              </fieldset>
            )}

            <button
              type="button"
              onClick={() =>
                setNodes((current) =>
                  current.filter((candidate) => candidate.localId !== node.localId),
                )
              }
              aria-label={isEn ? `Remove node ${index + 1}` : `Xóa thành phần ${index + 1}`}
            >
              {isEn ? "Remove node" : "Xóa thành phần"}
            </button>
          </fieldset>
        );
      })}

      <button type="submit" disabled={submitting || nodes.length === 0}>
        {submitting
          ? isEn
            ? "Assessing…"
            : "Đang đánh giá…"
          : isEn
            ? "Assess Risks"
            : "Đánh giá rủi ro"}
      </button>
    </form>
  );
}
