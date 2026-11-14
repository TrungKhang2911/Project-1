import { useEffect, useRef, useState } from "react";

import {
  MAX_SCENARIOS,
  PURPOSE_DETAILS_MAX,
  SCENARIO_MAX,
  SCENARIO_PRESETS,
  SYSTEM_NAME_MAX,
  WIZARD_STEPS,
  type ChoiceOption,
  type WizardStep,
} from "../agentic/questionnaire";
import type { Purpose, QuestionnaireAnswers } from "../types";

interface AssessmentWizardProps {
  onSubmit: (answers: QuestionnaireAnswers) => Promise<void>;
}

type MultiField = "resources" | "sensitive_data";
type SingleStep = Extract<WizardStep, { kind: "single" }>;
type MultiStep = Extract<WizardStep, { kind: "multi" }>;

type Draft = Partial<Omit<QuestionnaireAnswers, MultiField | "purpose_details" | "system_name" | "scenarios">> &
  Pick<QuestionnaireAnswers, MultiField> & {
    system_name: string;
    purpose_details: string;
    scenarios: string[];
  };

const EMPTY_DRAFT: Draft = {
  system_name: "",
  resources: [],
  sensitive_data: [],
  purpose_details: "",
  scenarios: [],
};
const REVIEW_STEP = WIZARD_STEPS.length;

function isAnswered(step: WizardStep, draft: Draft, noneChosen: Record<MultiField, boolean>): boolean {
  if (step.kind === "multi") {
    return draft[step.field].length > 0 || noneChosen[step.field];
  }
  return draft[step.field] !== undefined;
}

function toAnswers(draft: Draft): QuestionnaireAnswers | null {
  const { purpose, collaboration, autonomy, audience } = draft;
  if (!purpose || !collaboration || !autonomy || !audience) return null;
  const systemName = draft.system_name.trim();
  const details = draft.purpose_details.trim();
  const scenarios = draft.scenarios.map((item) => item.trim()).filter(Boolean);
  return {
    purpose,
    collaboration,
    autonomy,
    audience,
    resources: draft.resources,
    sensitive_data: draft.sensitive_data,
    ...(systemName ? { system_name: systemName } : {}),
    ...(details ? { purpose_details: details } : {}),
    ...(scenarios.length > 0 ? { scenarios } : {}),
  };
}

function ChoiceCard({
  type,
  name,
  option,
  checked,
  index,
  onChange,
}: {
  type: "radio" | "checkbox";
  name: string;
  option: Pick<ChoiceOption<string>, "icon" | "label" | "hint">;
  checked: boolean;
  index: number;
  onChange: () => void;
}): JSX.Element {
  return (
    <label
      className={`choice-card${checked ? " choice-card--selected" : ""}`}
      style={{ animationDelay: `${index * 45}ms` }}
    >
      <input type={type} name={name} checked={checked} onChange={onChange} />
      <span className="choice-card__icon" aria-hidden="true">
        {option.icon}
      </span>
      <span className="choice-card__text">
        <span className="choice-card__label">{option.label}</span>
        {option.hint && <span className="choice-card__hint">{option.hint}</span>}
      </span>
      <span className="choice-card__check" aria-hidden="true">
        {checked ? "✓" : ""}
      </span>
    </label>
  );
}

export function AssessmentWizard({ onSubmit }: AssessmentWizardProps): JSX.Element {
  const [stepIndex, setStepIndex] = useState(0);
  const [draft, setDraft] = useState<Draft>(EMPTY_DRAFT);
  const [scenarioInput, setScenarioInput] = useState("");
  const [noneChosen, setNoneChosen] = useState<Record<MultiField, boolean>>({
    resources: false,
    sensitive_data: false,
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const previousStep = useRef(stepIndex);

  // Move focus to the new question so keyboard and screen-reader users follow along
  // (but not on first render, to avoid hijacking focus on page load).
  useEffect(() => {
    if (previousStep.current !== stepIndex) headingRef.current?.focus();
    previousStep.current = stepIndex;
  }, [stepIndex]);

  const step: WizardStep | undefined = WIZARD_STEPS[stepIndex];
  const canContinue = step === undefined || isAnswered(step, draft, noneChosen);

  function chooseSingle(current: SingleStep, value: string): void {
    setDraft((previous) => ({ ...previous, [current.field]: value }));
  }

  function toggleMulti(current: MultiStep, value: string): void {
    const field = current.field;
    setNoneChosen((previous) => ({ ...previous, [field]: false }));
    setDraft((previous) => {
      const selected: string[] = previous[field];
      const next = selected.includes(value)
        ? selected.filter((item) => item !== value)
        : [...selected, value];
      return { ...previous, [field]: next };
    });
  }

  function chooseNone(current: MultiStep): void {
    setNoneChosen((previous) => ({ ...previous, [current.field]: true }));
    setDraft((previous) => ({ ...previous, [current.field]: [] }));
  }

  function addScenario(text: string): void {
    const cleaned = text.trim();
    if (!cleaned || draft.scenarios.length >= MAX_SCENARIOS) return;
    if (draft.scenarios.includes(cleaned)) return;
    setDraft((previous) => ({
      ...previous,
      scenarios: [...previous.scenarios, cleaned.slice(0, SCENARIO_MAX)],
    }));
    setScenarioInput("");
  }

  function removeScenario(index: number): void {
    setDraft((previous) => ({
      ...previous,
      scenarios: previous.scenarios.filter((_, idx) => idx !== index),
    }));
  }

  async function submit(): Promise<void> {
    const answers = toAnswers(draft);
    if (answers === null) {
      setError("Vui lòng trả lời đầy đủ các câu hỏi trước khi xem kết quả.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await onSubmit(answers);
    } catch (submitError: unknown) {
      setError(
        submitError instanceof Error
          ? submitError.message
          : "Không thể đánh giá lúc này. Vui lòng thử lại.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  function renderPurposeTargetDetails(): JSX.Element {
    const currentPurpose: Purpose = draft.purpose ?? "customer_support";
    const presets = SCENARIO_PRESETS[currentPurpose];

    return (
      <div className="wizard__target-box">
        <h3>Thông tin chi tiết về hệ thống &amp; kịch bản hoạt động (khuyến khích)</h3>

        <label className="wizard__details">
          <span>Tên ứng dụng / hệ thống AI (đích đánh giá)</span>
          <input
            type="text"
            className="wizard__text-input"
            value={draft.system_name}
            maxLength={SYSTEM_NAME_MAX}
            placeholder="Ví dụ: Trợ lý CSKH tự động đơn hàng Shopee/Website"
            onChange={(event) =>
              setDraft((previous) => ({ ...previous, system_name: event.target.value }))
            }
          />
        </label>

        <label className="wizard__details">
          <span>Mô tả chi tiết hệ thống AI của bạn hoạt động như thế nào?</span>
          <textarea
            value={draft.purpose_details}
            maxLength={PURPOSE_DETAILS_MAX}
            rows={3}
            placeholder="Ví dụ: Hệ thống tiếp nhận tin nhắn của khách, một AI tra cứu kho và đơn hàng, sau đó AI khác soạn phản hồi hoặc tạo phiếu hoàn tiền."
            onChange={(event) =>
              setDraft((previous) => ({ ...previous, purpose_details: event.target.value }))
            }
          />
          <small>
            {draft.purpose_details.length}/{PURPOSE_DETAILS_MAX} ký tự
          </small>
        </label>

        <div className="wizard__scenarios">
          <span>
            Các kịch bản tình huống thực tế của hệ thống ({draft.scenarios.length}/{MAX_SCENARIOS})
          </span>
          <p className="wizard__helper">
            Nêu các tình huống cụ thể (ai gửi gì vào, AI xử lý bước nào, tác động ra sao) để AI phân tích chính xác mô hình và rủi ro.
          </p>

          <div className="wizard__preset-chips">
            <small>Gợi ý nhanh:</small>
            {presets.map((preset) => (
              <button
                key={preset.label}
                type="button"
                className="chip-button"
                disabled={draft.scenarios.length >= MAX_SCENARIOS || draft.scenarios.includes(preset.text)}
                onClick={() => addScenario(preset.text)}
              >
                + {preset.label}
              </button>
            ))}
          </div>

          <div className="wizard__scenario-adder">
            <input
              type="text"
              className="wizard__text-input"
              value={scenarioInput}
              maxLength={SCENARIO_MAX}
              placeholder="Nhập một kịch bản sử dụng rồi bấm 'Thêm kịch bản'…"
              onChange={(event) => setScenarioInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  addScenario(scenarioInput);
                }
              }}
            />
            <button
              type="button"
              className="button-secondary"
              disabled={!scenarioInput.trim() || draft.scenarios.length >= MAX_SCENARIOS}
              onClick={() => addScenario(scenarioInput)}
            >
              Thêm kịch bản
            </button>
          </div>

          {draft.scenarios.length > 0 && (
            <ul className="wizard__scenario-list">
              {draft.scenarios.map((scenario, idx) => (
                <li key={scenario}>
                  <span>
                    <strong>Kịch bản {idx + 1}:</strong> {scenario}
                  </span>
                  <button
                    type="button"
                    className="link-button"
                    onClick={() => removeScenario(idx)}
                    aria-label={`Xoá kịch bản ${idx + 1}`}
                  >
                    Xoá
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    );
  }

  function renderStep(current: WizardStep): JSX.Element {
    if (current.kind === "single") {
      return (
        <>
          <div className="choice-grid">
            {current.options.map((option, idx) => (
              <ChoiceCard
                key={option.value}
                type="radio"
                name={current.field}
                option={option}
                index={idx}
                checked={draft[current.field] === option.value}
                onChange={() => chooseSingle(current, option.value)}
              />
            ))}
          </div>
          {current.field === "purpose" && renderPurposeTargetDetails()}
        </>
      );
    }

    const selected: string[] = draft[current.field];
    return (
      <div className="choice-grid">
        {current.options.map((option, idx) => (
          <ChoiceCard
            key={option.value}
            type="checkbox"
            name={current.field}
            option={option}
            index={idx}
            checked={selected.includes(option.value)}
            onChange={() => toggleMulti(current, option.value)}
          />
        ))}
        <ChoiceCard
          type="checkbox"
          name={current.field}
          option={{ icon: "—", label: current.noneLabel }}
          index={current.options.length}
          checked={noneChosen[current.field]}
          onChange={() => chooseNone(current)}
        />
      </div>
    );
  }

  function answerLabel(current: WizardStep): string {
    if (current.kind === "multi") {
      const selected: string[] = draft[current.field];
      if (selected.length === 0) return current.noneLabel;
      return current.options
        .filter((option) => selected.includes(option.value))
        .map((option) => option.label)
        .join(", ");
    }
    const value = draft[current.field];
    return current.options.find((option) => option.value === value)?.label ?? "Chưa trả lời";
  }

  const progress = Math.round((Math.min(stepIndex, REVIEW_STEP) / REVIEW_STEP) * 100);

  return (
    <section className="wizard" aria-labelledby="wizard-heading">
      <div className="wizard__progress">
        <div className="wizard__progress-header">
          <span>
            {step ? `Bước ${stepIndex + 1} / ${WIZARD_STEPS.length}` : "Bước cuối · Xem lại thông tin"}
          </span>
          <div className="wizard__steps-dots" aria-hidden="true">
            {WIZARD_STEPS.map((item, idx) => {
              const done = idx < stepIndex;
              const current = idx === stepIndex;
              return (
                <span
                  key={item.id}
                  className={`step-dot${done ? " step-dot--done" : ""}${current ? " step-dot--current" : ""}`}
                />
              );
            })}
          </div>
        </div>
        <div
          className="wizard__bar"
          role="progressbar"
          aria-valuenow={progress}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Tiến độ"
        >
          <div style={{ width: `${progress}%` }} />
        </div>
      </div>

      {step ? (
        <fieldset className="wizard__step animate-step" key={step.id}>
          <legend className="visually-hidden">{step.title}</legend>
          <h2 id="wizard-heading" ref={headingRef} tabIndex={-1}>
            {step.title}
          </h2>
          <p className="wizard__helper">{step.helper}</p>
          {renderStep(step)}
        </fieldset>
      ) : (
        <div className="wizard__step animate-step" key="review">
          <h2 id="wizard-heading" ref={headingRef} tabIndex={-1}>
            Kiểm tra lại thông tin hệ thống trước khi phân tích
          </h2>
          <dl className="wizard__review">
            {draft.system_name.trim() && (
              <div>
                <dt>Tên hệ thống AI (đích đánh giá)</dt>
                <dd>{draft.system_name.trim()}</dd>
              </div>
            )}
            {WIZARD_STEPS.map((item, index) => (
              <div key={item.id}>
                <dt>{item.title}</dt>
                <dd>
                  {answerLabel(item)}
                  {item.field === "purpose" && draft.purpose_details.trim() && (
                    <em> — {draft.purpose_details.trim()}</em>
                  )}
                  <button type="button" className="link-button" onClick={() => setStepIndex(index)}>
                    Sửa
                  </button>
                </dd>
                {item.field === "purpose" && draft.scenarios.length > 0 && (
                  <ul className="wizard__review-scenarios">
                    {draft.scenarios.map((scenario, idx) => (
                      <li key={scenario}>
                        Kịch bản {idx + 1}: {scenario}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </dl>
        </div>
      )}

      {error !== null && (
        <p className="wizard__error" role="alert">
          {error}
        </p>
      )}

      <div className="wizard__nav">
        <button
          type="button"
          className="button-secondary"
          onClick={() => setStepIndex((index) => Math.max(0, index - 1))}
          disabled={stepIndex === 0 || submitting}
        >
          Quay lại
        </button>
        {step ? (
          <button
            type="button"
            onClick={() => setStepIndex((index) => index + 1)}
            disabled={!canContinue}
          >
            Tiếp tục →
          </button>
        ) : (
          <button type="button" onClick={() => void submit()} disabled={submitting}>
            {submitting ? (
              <span className="button-loading">
                <span className="spinner-dot" aria-hidden="true" />
                Đang phân tích…
              </span>
            ) : (
              "Xem đánh giá rủi ro →"
            )}
          </button>
        )}
      </div>
    </section>
  );
}
