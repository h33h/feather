'use client';
import { createContext, useContext, useSyncExternalStore, type ReactNode } from 'react';
import { initializeTheme, themeConfig, type ThemePreference } from './theme';
import './theme.css';
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
    /* Still works for this visit. */
  }
  window.dispatchEvent(new Event(themeConfig.changeEvent));
}
const ThemeContext = createContext({ preference: 'system' as ThemePreference, choose });
export function ThemeProvider({ children }: { children: ReactNode }) {
  const preference = useSyncExternalStore(subscribe, currentPreference, () => 'system' as const);
  return <ThemeContext value={{ preference, choose }}>{children}</ThemeContext>;
}
export function ThemeToggle() {
  const { choose } = useContext(ThemeContext);
  const dark = useSyncExternalStore(
    subscribe,
    () => document.documentElement.dataset.theme === 'dark',
    () => false,
  );
  return (
    <label className="theme-toggle">
      <span>Тёмная тема</span>
      <span className="theme-switch-control">
        <input
          type="checkbox"
          role="switch"
          aria-label="Тёмная тема"
          checked={dark}
          onChange={(event) => choose(event.target.checked ? 'dark' : 'light')}
        />
        <span className="theme-switch-track" aria-hidden="true" />
      </span>
    </label>
  );
}
