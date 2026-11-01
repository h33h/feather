'use client';
import Link from 'next/link';
import type { AuthSession } from '../api/contracts';
import { DesignAsset } from './components';
import { ThemeSelect } from './theme-control';
import './shell.css';
export function Glyph({ path }: { path: string }) {
  return (
    <svg
      width="22"
      height="22"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={path} />
    </svg>
  );
}
export function StoreHeader({
  session,
  onProfile,
  back,
}: {
  session: AuthSession | null;
  onProfile?: () => void;
  back?: { label: string; ariaLabel: string; onClick: () => void };
}) {
  return (
    <header
      className={
        'store-header' + (!session ? ' guest-header' : '') + (back ? ' has-mobile-back' : '')
      }
    >
      <div className="store-header-inner">
        <Link href="/" className="store-brand" aria-label="iSign — главная">
          iSign
        </Link>
        {back && (
          <button className="mobile-page-back" aria-label={back.ariaLabel} onClick={back.onClick}>
            <Glyph path="M15 5l-7 7 7 7" />
            <span>{back.label}</span>
          </button>
        )}
        <div className="store-header-actions">
          <ThemeSelect />
          {session && onProfile && (
            <div className="store-account">
              <button className="profile-button" aria-label="Профиль и вход" onClick={onProfile}>
                <DesignAsset name="catalog-IconUser" width={24} />
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
