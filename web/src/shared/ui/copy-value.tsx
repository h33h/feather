'use client';
import { useId, useRef, useState } from 'react';
import { TaskButton } from './components';
/** Public identifiers/URLs only; clipboard writes happen on an explicit gesture. */
export function CopyValue({
  label,
  value,
  buttonLabel,
}: {
  label: string;
  value: string;
  buttonLabel?: string;
}) {
  const id = useId(),
    input = useRef<HTMLInputElement>(null);
  const [feedback, setFeedback] = useState<{ value: string; message: string } | null>(null);
  async function copy() {
    if (!value) return;
    const copiedValue = value;
    try {
      if (!navigator.clipboard?.writeText) throw Error('CLIPBOARD_UNAVAILABLE');
      await navigator.clipboard.writeText(copiedValue);
      setFeedback({ value: copiedValue, message: 'Скопировано' });
    } catch {
      input.current?.focus();
      input.current?.select();
      setFeedback({
        value: copiedValue,
        message: 'Не удалось скопировать автоматически. Скопируйте выделенный текст вручную.',
      });
    }
  }
  return (
    <div className="copy-value">
      <label htmlFor={id}>{label}</label>
      <div className="copy-value-controls">
        <input
          id={id}
          ref={input}
          value={value}
          readOnly
          autoComplete="off"
          onFocus={(event) => event.currentTarget.select()}
        />
        <TaskButton
          secondary
          aria-label={buttonLabel ?? 'Скопировать ' + label}
          disabled={!value}
          onClick={() => void copy()}
        >
          Копировать
        </TaskButton>
      </div>
      <p className="copy-value-feedback" role="status" aria-live="polite">
        {feedback?.value === value ? feedback.message : ''}
      </p>
    </div>
  );
}
