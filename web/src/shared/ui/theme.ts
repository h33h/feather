import { darkTokens, designTokens } from './tokens';

export type ThemePreference = 'system' | 'light' | 'dark';

export const themeConfig = {
  storageKey: 'isign-theme',
  changeEvent: 'isign:theme-change',
  light: designTokens['color-surface'],
  dark: darkTokens['color-surface'],
};

// Keep this function self-contained: it also runs in <head> before hydration.
export function initializeTheme(
  config: typeof themeConfig,
  chosen?: ThemePreference,
): ThemePreference {
  let preference: ThemePreference = chosen ?? 'system';
  if (chosen === undefined) {
    try {
      const saved = localStorage.getItem(config.storageKey);
      if (saved === 'light' || saved === 'dark') preference = saved;
    } catch {
      // A blocked storage API must not prevent the page from opening.
    }
  }
  const resolved =
    preference === 'system'
      ? matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light'
      : preference;
  const root = document.documentElement;
  root.dataset.theme = resolved;
  root.dataset.themePreference = preference;
  root.style.colorScheme = resolved;
  const meta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
  if (meta) meta.content = config[resolved];
  return preference;
}

// Standalone installation and offline pages share the same live behavior as the app.
function bootstrapTheme(config: typeof themeConfig, apply: typeof initializeTheme) {
  apply(config);
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (document.documentElement.dataset.themePreference === 'system') {
      apply(config, 'system');
      window.dispatchEvent(new Event(config.changeEvent));
    }
  });
  window.addEventListener('storage', (event) => {
    if (event.key === null || event.key === config.storageKey) {
      apply(config);
      window.dispatchEvent(new Event(config.changeEvent));
    }
  });
}

export const themeScript = `(${bootstrapTheme.toString()})(${JSON.stringify(themeConfig)}, ${initializeTheme.toString()});`;
