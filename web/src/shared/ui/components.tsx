import Image from 'next/image';
import Link from 'next/link';
import type { ButtonHTMLAttributes, HTMLAttributes, LabelHTMLAttributes, ReactNode } from 'react';

import './primitives.css';

export function TaskButton({
  secondary = false,
  destructive = false,
  variant = 'solid',
  loading = false,
  disabledSurface = 'none',
  children,
  className = '',
  type = 'button',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  secondary?: boolean;
  destructive?: boolean;
  variant?: 'solid' | 'text';
  loading?: boolean;
  disabledSurface?: 'none' | 'selected' | 'muted';
}) {
  return (
    <button
      {...props}
      type={type}
      data-disabled-surface={disabledSurface}
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

export function TaskLink({
  href,
  children,
  secondary = false,
}: {
  href: string;
  children: ReactNode;
  secondary?: boolean;
}) {
  return (
    <Link href={href} className={'task-link' + (secondary ? ' secondary' : '')}>
      {children}
    </Link>
  );
}

// Preserve each exported SVG's native dimensions; desktop and mobile icons are separate assets.
export function DesignAsset({
  name,
  width = 20,
  height = width,
  className = '',
}: {
  name: string;
  width?: number;
  height?: number;
  className?: string;
}) {
  if (
    (/Icon|Ellipse|(?:-check|-close)$/.test(name) && !name.startsWith('login-')) ||
    name === 'login-KeyIcon'
  )
    return (
      <span
        aria-hidden="true"
        className={'design-asset design-icon ' + className}
        style={{ width, height, maskImage: `url('/figma/${name}.svg')` }}
      />
    );
  return (
    <Image
      unoptimized
      src={'/figma/' + name + '.svg'}
      alt=""
      width={width}
      height={height}
      className={'design-asset ' + className}
    />
  );
}

export function PageHeading({
  title,
  back,
  backLabel,
  onBack,
  action,
  fixed = false,
}: {
  title: string;
  back?: string;
  backLabel?: string;
  onBack?: () => void;
  action?: ReactNode;
  fixed?: boolean;
}) {
  return (
    <div
      className={
        'page-heading' + (onBack ? ' has-back' : '') + (fixed ? ' fixed-mobile-title' : '')
      }
    >
      {onBack && (
        <button className="store-back" aria-label={backLabel} onClick={onBack}>
          <span aria-hidden="true">‹</span> {back}
        </button>
      )}
      <div className="page-title">
        <h1 tabIndex={-1}>{title}</h1>
        {action}
      </div>
    </div>
  );
}

/** A labelled 44 px icon action. Keep domain behavior in the caller. */
export function IconButton({
  label,
  tone = 'secondary',
  round = false,
  className = '',
  children,
  type = 'button',
  ...props
}: Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'aria-label'> & {
  label: string;
  tone?: 'secondary' | 'subtle' | 'ghost' | 'danger';
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
        (tone === 'secondary' ? ' quiet' : '') +
        (round ? ' ui-icon-round' : '') +
        (className ? ' ' + className : '')
      }
    >
      {children}
    </button>
  );
}

export function Chevron({
  direction = 'right',
  size = 20,
  className = '',
}: {
  direction?: 'right' | 'down';
  size?: number;
  className?: string;
}) {
  return (
    <DesignAsset
      name="settings-IconChevronRight"
      width={size}
      className={
        'ui-chevron' + (direction === 'down' ? ' is-down' : '') + (className ? ' ' + className : '')
      }
    />
  );
}

export function StatusChip({
  tone = 'accent',
  className = '',
  ...props
}: HTMLAttributes<HTMLSpanElement> & { tone?: 'neutral' | 'accent' | 'success' | 'error' }) {
  return (
    <span
      {...props}
      data-tone={tone}
      className={'ui-status-chip' + (className ? ' ' + className : '')}
    />
  );
}

/** Navigation only: never place another interactive control inside the row. */
export function ActionRow({
  title,
  description,
  leading,
  meta,
  className = '',
  ...props
}: Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'title' | 'children'> & {
  title: ReactNode;
  description?: ReactNode;
  leading?: ReactNode;
  meta?: ReactNode;
}) {
  return (
    <button
      {...props}
      type="button"
      className={'ui-action-row' + (className ? ' ' + className : '')}
    >
      {leading}
      <span className="ui-row-content">
        <strong>{title}</strong>
        {description && <span className="ui-row-description">{description}</span>}
      </span>
      {meta}
      <Chevron />
    </button>
  );
}

export function FactsList({
  items,
  stacked = false,
  className = '',
}: {
  items: { label: string; value: ReactNode }[];
  stacked?: boolean;
  className?: string;
}) {
  const available = items.filter(
    (item) => item.value !== null && item.value !== undefined && item.value !== '',
  );
  if (!available.length) return null;
  return (
    <dl
      className={'ui-facts' + (stacked ? ' is-stacked' : '') + (className ? ' ' + className : '')}
    >
      {available.map((item) => (
        <div key={item.label}>
          <dt>{item.label}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
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
