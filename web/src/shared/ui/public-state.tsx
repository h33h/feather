import Link from 'next/link';
import type { PublicStateCopy } from './public-document';
import './public.css';

export function PublicState({ title, message, actionLabel }: PublicStateCopy) {
  return (
    <div className="store public-shell">
      <header className="public-header">
        <Link className="public-brand" href="/" aria-label="iSign — на главную">
          iSign
        </Link>
      </header>
      <main className="public-main">
        <div className="public-content">
          <h1 className="public-title">{title}</h1>
          <p className="public-message">{message}</p>
        </div>
        <div className="public-actions">
          <Link className="public-action" href="/">
            {actionLabel}
          </Link>
        </div>
      </main>
    </div>
  );
}
