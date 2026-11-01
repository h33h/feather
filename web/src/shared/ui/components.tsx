import type { ButtonHTMLAttributes, LabelHTMLAttributes, ReactNode } from 'react';

import './primitives.css';

export function TaskButton({
  secondary = false,
  destructive = false,
  variant = 'solid',
  loading = false,
  children,
  className = '',
  type = 'button',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  secondary?: boolean;
  destructive?: boolean;
  variant?: 'solid' | 'text';
  loading?: boolean;
}) {
  return (
    <button
      {...props}
      type={type}
      disabled={props.disabled || loading}
      aria-busy={loading || props['aria-busy']}
      aria-label={
        props['aria-label'] ?? (loading && typeof children === 'string' ? children : undefined)
      }
      className={
        'task-button ui-button' +
        (secondary ? ' quiet' : '') +
        (destructive ? ' task-danger' : '') +
        (variant === 'text' ? ' text-button' : '') +
        (className ? ' ' + className : '')
      }
    >
      {loading ? (
        <>
          <span className="button-loading-label" aria-hidden="true">
            {children}
          </span>
          <span className="button-spinner" aria-hidden="true" />
        </>
      ) : (
        children
      )}
    </button>
  );
}

export function DesignAsset({ name }: { name: 'login-KeyIcon' | 'modal-close' }) {
  return (
    <span
      aria-hidden="true"
      className="design-asset design-icon"
      style={{ width: 20, height: 20, maskImage: `url('/figma/${name}.svg')` }}
    />
  );
}

/** A labelled 44 px icon action. Keep domain behavior in the caller. */
export function IconButton({
  label,
  tone,
  round = false,
  className = '',
  children,
  type = 'button',
  ...props
}: Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'aria-label'> & {
  label: string;
  tone: 'subtle' | 'ghost';
  round?: boolean;
}) {
  return (
    <button
      {...props}
      type={type}
      aria-label={label}
      data-tone={tone}
      className={
        'icon-button ui-icon-button' +
        (round ? ' ui-icon-round' : '') +
        (className ? ' ' + className : '')
      }
    >
      {children}
    </button>
  );
}

/** Use native input/select and keep error IDs/validation in the feature. */
export function Field({
  label,
  children,
  className = '',
  ...props
}: LabelHTMLAttributes<HTMLLabelElement> & { label: ReactNode }) {
  return (
    <label {...props} className={'task-field ui-field' + (className ? ' ' + className : '')}>
      {label}
      {children}
    </label>
  );
}
