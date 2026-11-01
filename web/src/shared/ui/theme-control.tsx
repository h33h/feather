'use client';

import { createContext, useContext, useSyncExternalStore, type ReactNode } from 'react';
import { initializeTheme, themeConfig, type ThemePreference } from './theme';
import './theme.css';

const options: { value: ThemePreference; label: string }[] = [
  { value: 'system', label: 'Системная' },
  { value: 'light', label: 'Светлая' },
  { value: 'dark', label: 'Тёмная' },
];
function currentPreference(): ThemePreference {
  const value = document.documentElement.dataset.themePreference;
  return value === 'light' || value === 'dark' ? value : 'system';
}
function subscribe(onChange: () => void) {
  window.addEventListener(themeConfig.changeEvent, onChange);
  return () => window.removeEventListener(themeConfig.changeEvent, onChange);
}
function choose(value: ThemePreference) {
  initializeTheme(themeConfig, value);
  try {
    localStorage.setItem(themeConfig.storageKey, value);
  } catch {
    // The preference still works for this visit when storage is unavailable.
  }
  window.dispatchEvent(new Event(themeConfig.changeEvent));
}
const ThemeContext = createContext({ preference: 'system' as ThemePreference, choose });

export function ThemeProvider({ children }: { children: ReactNode }) {
  const preference = useSyncExternalStore(subscribe, currentPreference, () => 'system' as const);
  return <ThemeContext value={{ preference, choose }}>{children}</ThemeContext>;
}

function ThemeIcon({ mode }: { mode: ThemePreference }) {
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
      {mode === 'system' ? (
        <>
          <rect x="3" y="4" width="18" height="13" rx="2" />
          <path d="M8 21h8m-4-4v4" />
        </>
      ) : mode === 'light' ? (
        <>
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5" />
        </>
      ) : (
        <path d="M20.5 13A8.5 8.5 0 0 1 11 3.5 8.5 8.5 0 1 0 20.5 13Z" />
      )}
    </svg>
  );
}

export function ThemeSelect() {
  const { preference, choose } = useContext(ThemeContext);
  return (
    <label
      className="theme-select"
      title={
        'Тема: ' +
        options.find((option) => option.value === preference)!.label.toLocaleLowerCase('ru')
      }
    >
      <ThemeIcon mode={preference} />
      <span className="visually-hidden">Цветовая тема</span>
      <select
        value={preference}
        onChange={(event) => choose(event.target.value as ThemePreference)}
      >
        {options.map(({ value, label }) => (
          <option key={value} value={value}>
            {label}
          </option>
        ))}
      </select>
    </label>
  );
}
