'use client';
import { useEffect, useRef, useState } from 'react';
import { ThemeToggle } from '../../shared/ui/theme-control';
import { InstallerIcon } from './screen';

export function InstallerProfile({ id, logout }: { id: string; logout: () => Promise<void> }) {
  const [open, setOpen] = useState(false),
    [copied, setCopied] = useState(false),
    [error, setError] = useState('');
  const root = useRef<HTMLDivElement>(null),
    trigger = useRef<HTMLButtonElement>(null),
    identifier = useRef<HTMLSpanElement>(null);
  const live = useRef(true);
  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);
  useEffect(() => {
    if (!open) return;
    const outside = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false);
        trigger.current?.focus();
      }
    };
    document.addEventListener('pointerdown', outside);
    document.addEventListener('keydown', escape);
    return () => {
      document.removeEventListener('pointerdown', outside);
      document.removeEventListener('keydown', escape);
    };
  }, [open]);
  async function copy() {
    setError('');
    try {
      if (!navigator.clipboard?.writeText) throw Error('CLIPBOARD_UNAVAILABLE');
      await navigator.clipboard.writeText(id);
      if (live.current) setCopied(true);
    } catch {
      if (!live.current) return;
      const selection = window.getSelection(),
        range = document.createRange();
      if (selection && identifier.current) {
        range.selectNodeContents(identifier.current);
        selection.removeAllRanges();
        selection.addRange(range);
      }
      setError('Не удалось скопировать. Скопируйте выделенный текст вручную.');
    }
  }
  return (
    <div
      className="installer-profile"
      ref={root}
      onBlur={(event) => {
        if (event.relatedTarget && !event.currentTarget.contains(event.relatedTarget))
          setOpen(false);
      }}
    >
      <button
        className="installer-profile-trigger"
        type="button"
        ref={trigger}
        aria-expanded={open}
        onClick={() => {
          setOpen(!open);
          setCopied(false);
          setError('');
        }}
      >
        <span>{id}</span>
        <InstallerIcon name="chevron" />
      </button>
      {open && (
        <div className="installer-profile-menu">
          <div className="installer-profile-id-row">
            <span data-profile-id ref={identifier}>
              {id}
            </span>
            <button
              type="button"
              className="installer-icon-button"
              aria-label="Скопировать ID профиля"
              onClick={() => void copy()}
            >
              <InstallerIcon name={copied ? 'check' : 'copy'} />
            </button>
          </div>
          {error && (
            <p role="alert" className="installer-caption">
              {error}
            </p>
          )}
          <ThemeToggle />
          <button
            type="button"
            className="installer-text-button"
            onClick={() =>
              void logout().catch(() => {
                if (live.current) setError('Не удалось выйти. Повторите попытку.');
              })
            }
          >
            Выйти
          </button>
        </div>
      )}
    </div>
  );
}
