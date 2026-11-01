import { designTokenCss, responsiveTokenCss } from './tokens';
import { themeScript } from './theme';

export type PublicStateCopy = { title: string; message: string; actionLabel: string };

// This stylesheet also generates public.css for shared public states.
export const publicSurfaceCss = `
body:has(.public-shell) { margin: 0; background: var(--color-surface); }
.store.public-shell {
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  min-height: 100dvh;
  padding: 0 env(safe-area-inset-right) 0 env(safe-area-inset-left);
  background: var(--color-surface);
  color: var(--color-text);
  color-scheme: var(--theme-color-scheme);
  font: 400 var(--text-body)/var(--line-body) -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}
.public-shell *, .public-shell *::before, .public-shell *::after { box-sizing: border-box; }
.public-shell ::selection { background: var(--color-selection); color: var(--color-selection-text); }
.store.public-shell .public-header {
  display: flex;
  flex: none;
  align-items: center;
  justify-content: center;
  height: calc(72px + env(safe-area-inset-top));
  margin: 0;
  padding: calc(14px + env(safe-area-inset-top)) var(--space-screen) 14px;
  border: 0;
}
.store.public-shell .public-brand {
  display: inline-flex;
  align-items: center;
  min-height: var(--control-target);
  color: var(--color-action);
  font-size: 24px;
  line-height: 30px;
  font-weight: var(--font-strong);
  text-decoration: none;
}
.store.public-shell .public-main {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-width: 0;
  width: min(704px, 100%);
  max-width: none;
  margin: 0 auto;
  padding: var(--space-screen) var(--space-screen) calc(var(--space-page-bottom) + env(safe-area-inset-bottom));
}
.store.public-shell .public-content {
  display: flex;
  flex-direction: column;
  flex: 1;
  align-items: center;
  justify-content: center;
  gap: var(--space-section);
  padding-block: var(--space-section);
  text-align: center;
}
.store.public-shell .public-title {
  margin: 0;
  color: var(--color-text);
  font-size: var(--text-title);
  line-height: var(--line-title);
  font-weight: var(--font-strong);
  letter-spacing: 0;
  overflow-wrap: anywhere;
  text-wrap: balance;
}
.store.public-shell .public-message,
.store.public-shell .public-note {
  max-width: 72ch;
  margin: 0;
  color: var(--color-text-secondary);
  font-size: var(--text-body);
  line-height: var(--line-body);
  overflow-wrap: anywhere;
}
.store.public-shell .public-actions {
  display: grid;
  flex: none;
  gap: var(--space-field);
  width: 100%;
  padding-top: var(--space-section);
}
.store.public-shell .public-actions form { margin: 0; }
.store.public-shell .public-note {
  font-size: var(--text-label);
  line-height: var(--line-label);
  text-align: center;
}
.store.public-shell .public-action {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  min-height: var(--control-height);
  margin: 0;
  padding: var(--space-control) var(--space-field);
  border: 0;
  border-radius: var(--control-radius);
  background: var(--color-action-fill);
  color: var(--color-on-action);
  font: var(--font-medium) var(--text-label)/var(--line-label) -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  text-align: center;
  text-decoration: none;
  overflow-wrap: anywhere;
  cursor: pointer;
}
.store.public-shell .public-action:hover { background: var(--color-action-fill-hover); }
.store.public-shell .public-action.secondary {
  background: var(--color-selected);
  color: var(--color-action);
}
.store.public-shell .public-action.secondary:hover { background: var(--color-secondary-hover); }
.public-shell :is(a, button):focus-visible { outline: 3px solid var(--color-action); outline-offset: 3px; }
@media (max-width: 700px) {
  .store.public-shell .public-header {
    height: calc(64px + env(safe-area-inset-top));
    padding-block: calc(10px + env(safe-area-inset-top)) 10px;
  }
}
`;

const escape = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (character) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!,
  );

/** Static copy only; capability tokens and provider diagnostics must not enter these pages. */
export function publicDocument({
  title,
  message,
  actionLabel,
  installation = false,
  documentTitle = 'iSign — ' + title,
}: PublicStateCopy & { installation?: boolean; documentTitle?: string }) {
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><meta name="theme-color" content="#ffffff"><meta name="robots" content="noindex"><title>${escape(documentTitle)}</title><script>${themeScript}</script><style>
${designTokenCss(':root, .store')}${responsiveTokenCss}${publicSurfaceCss}
</style></head><body><div class="store public-shell"><header class="public-header"><a class="public-brand" href="/" aria-label="iSign — на главную">iSign</a></header><main class="public-main"><div class="public-content"><h1 class="public-title">${escape(title)}</h1><p class="public-message">${escape(message)}</p></div><div class="public-actions">${
    installation
      ? '<p class="public-note">После продолжения Safari предложит подтвердить установку.</p><form method="post"><button class="public-action" type="submit">Продолжить установку</button></form><a class="public-action secondary" href="/">Вернуться в iSign</a>'
      : '<a class="public-action" href="/">' + escape(actionLabel) + '</a>'
  }</div></main></div></body></html>`;
}
