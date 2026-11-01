'use client';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { TaskButton } from '../../shared/ui';

export function InstallerScreen({
  title,
  description,
  children,
  actions,
  centered = false,
  welcome = false,
}: {
  title?: string;
  description?: string;
  children?: ReactNode;
  actions?: ReactNode;
  centered?: boolean;
  welcome?: boolean;
}) {
  const heading = useRef<HTMLHeadingElement>(null),
    main = useRef<HTMLElement>(null);
  useEffect(() => {
    const target = heading.current ?? main.current?.querySelector('h1');
    target?.setAttribute('tabindex', '-1');
    target?.focus({ preventScroll: true });
  }, [title]);
  return (
    <div className={'installer-screen' + (welcome ? ' installer-welcome-screen' : '')}>
      <main ref={main} className={'installer-main' + (centered ? ' installer-centered' : '')}>
        <div className="installer-body">
          {title && (
            <div className="installer-intro">
              <h1 ref={heading} tabIndex={-1}>
                {title}
              </h1>
              {description && <p>{description}</p>}
            </div>
          )}
          {children}
        </div>
      </main>
      {actions && <footer className="installer-footer">{actions}</footer>}
    </div>
  );
}

export function InstallerIcon({ name }: { name: 'back' | 'chevron' | 'copy' | 'check' }) {
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {name === 'back' ? (
        <path d="m14 5-7 7 7 7M7 12h14" />
      ) : name === 'chevron' ? (
        <path d="m6 9 6 6 6-6" />
      ) : name === 'check' ? (
        <path d="m5 12 4 4L19 6" />
      ) : (
        <>
          <rect x="8" y="8" width="12" height="13" rx="2" />
          <path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3" />
        </>
      )}
    </svg>
  );
}

export function InstallerCopyLink({ value, label }: { value: string; label: string }) {
  const [feedback, setFeedback] = useState<{ value: string; failed: boolean } | null>(null);
  return (
    <>
      <TaskButton
        variant="text"
        onClick={() => {
          if (!navigator.clipboard?.writeText) {
            setFeedback({ value, failed: true });
            return;
          }
          void navigator.clipboard
            .writeText(value)
            .then(() => setFeedback({ value, failed: false }))
            .catch(() => setFeedback({ value, failed: true }));
        }}
      >
        {label}
      </TaskButton>
      {feedback?.value === value &&
        (feedback.failed ? (
          <p className="installer-caption" role="status">
            Не удалось скопировать. Откройте или скопируйте <a href={value}>ссылку вручную</a>.
          </p>
        ) : (
          <p className="installer-caption" role="status">
            Ссылка скопирована.
          </p>
        ))}
    </>
  );
}
