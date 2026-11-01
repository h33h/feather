'use client';
import { useCallback, useEffect, useState } from 'react';

export type InstallerView =
  | 'welcome'
  | 'invite'
  | 'account'
  | 'account-status'
  | 'device'
  | 'profile'
  | 'device-qr'
  | 'confirm'
  | 'install'
  | 'install-qr'
  | 'after'
  | 'settings';
type Entry = { scope: string; view: InstallerView; back?: InstallerView };
const historyKey = 'isignInstaller';

/** History carries screen names only. Sessions, grants and active links are never restored from it. */
export function useInstallerNavigation(
  scope: string,
  initial: InstallerView,
  allowed: InstallerView[],
) {
  const [entry, setEntry] = useState<Entry | null>(null);
  const choices = allowed.join(',');
  const view = entry?.scope === scope && allowed.includes(entry.view) ? entry.view : initial;
  useEffect(() => {
    const accept = () => {
      const candidate = window.history.state?.[historyKey] as Entry | undefined;
      const next: Entry =
        candidate?.scope === scope && choices.split(',').includes(candidate.view)
          ? candidate
          : { scope, view: initial };
      window.history.replaceState(
        { ...window.history.state, [historyKey]: next },
        '',
        '#' + next.view,
      );
      setEntry(next);
    };
    accept();
    window.addEventListener('popstate', accept);
    return () => window.removeEventListener('popstate', accept);
  }, [scope, initial, choices]);
  const navigate = useCallback(
    (target: InstallerView, replace = false) => {
      if (!choices.split(',').includes(target)) return;
      const next: Entry = { scope, view: target, ...(replace ? {} : { back: view }) };
      window.history[replace ? 'replaceState' : 'pushState'](
        { ...window.history.state, [historyKey]: next },
        '',
        '#' + target,
      );
      setEntry(next);
    },
    [scope, view, choices],
  );
  const back = () => {
    if (entry?.scope === scope && entry.back && allowed.includes(entry.back)) window.history.back();
    else navigate(initial, true);
  };
  return {
    view,
    navigate,
    back,
    canBack: !!(entry?.scope === scope && entry.back && allowed.includes(entry.back)),
  };
}
