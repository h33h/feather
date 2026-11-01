'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { type Api, type AuthSession } from './contracts';
import { messages } from './errors';
import { passkeyLogin } from './passkey-client';
import { loadSession } from './session-loader';
import { readResponse } from './response';
const responseSchema = z
  .object({
    csrf: z.string().optional(),
    profileXml: z.string().optional(),
    expiresAt: z.number().optional(),
    installUrl: z.string().optional(),
    handoffUrl: z.string().optional(),
    qrSvg: z.string().optional(),
  })
  .catchall(z.unknown());

/** Generic authenticated requests, fresh authentication and action feedback. */
export function useSession({
  onReset,
  onMutation,
  onRefresh,
}: {
  onReset?: () => void;
  onMutation?: (path: string) => void;
  onRefresh?: () => Promise<void>;
} = {}) {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [sessionError, setSessionError] = useState('');
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [notice, setNotice] = useState('');
  const generation = useRef(0),
    csrf = useRef(''),
    busyRef = useRef(false),
    actionVersion = useRef(0);
  const authenticatedSession = useRef<AuthSession | null>(null);
  const sessionRequest = useRef<Promise<AuthSession | null> | null>(null);
  const callbacks = useRef({ onReset, onMutation, onRefresh });
  useEffect(() => {
    callbacks.current = { onReset, onMutation, onRefresh };
  }, [onReset, onMutation, onRefresh]);
  const reset = useCallback(() => {
    generation.current++;
    actionVersion.current++;
    busyRef.current = false;
    setBusy(false);
    setError('');
    setNotice('');
    csrf.current = '';
    authenticatedSession.current = null;
    sessionRequest.current = null;
    setSession(null);
    setSessionError('');
    callbacks.current.onReset?.();
  }, []);
  const api: Api = useCallback(
    async (path, data, options) => {
      const requestEpoch = generation.current;
      const send: Api = async (endpoint, payload, opts) => {
        const epoch = generation.current;
        const method = opts?.method ?? (payload === undefined ? 'GET' : 'POST');
        const response = await fetch('/api/' + endpoint, {
          method,
          headers:
            method === 'GET'
              ? {}
              : { 'content-type': 'application/json', 'x-isign-csrf': csrf.current },
          body: payload === undefined ? undefined : JSON.stringify(payload),
          cache: 'no-store',
        });
        const value = await readResponse(response, responseSchema);
        if (!response.ok) {
          if (response.status === 401 && epoch === generation.current) reset();
          const code = typeof value.code === 'string' ? value.code : '';
          throw Object.assign(
            new Error(messages[code] ?? 'Действие не выполнено. Повторите попытку.'),
            { code },
          );
        }
        if (epoch === generation.current) {
          if (typeof value.csrf === 'string') csrf.current = value.csrf;
          if (method !== 'GET') callbacks.current.onMutation?.(endpoint);
        }
        return value;
      };
      try {
        return await send(path, data, options);
      } catch (problem) {
        if (requestEpoch !== generation.current) throw problem;
        if (
          (problem as { code?: string }).code !== 'FRESH_AUTH_REQUIRED' ||
          path.startsWith('auth/')
        )
          throw problem;
        setNotice('Подтвердите действие с passkey.');
        try {
          await passkeyLogin(send, true);
        } finally {
          setNotice('');
        }
        return send(path, data, options);
      }
    },
    [reset],
  );
  const reloadSession = useCallback(
    (force = false) =>
      loadSession(
        api,
        {
          generation,
          request: sessionRequest,
          accept: (value) => {
            if (
              authenticatedSession.current &&
              authenticatedSession.current.profile.id !== value.profile.id
            )
              reset();
            authenticatedSession.current = value;
            setSession(value);
            setSessionError('');
          },
        },
        force,
      ),
    [api, reset],
  );
  const isAuthenticated = useCallback(() => authenticatedSession.current !== null, []);
  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const initialize = async () => {
      try {
        await reloadSession();
      } catch (problem) {
        if (alive && (problem as { code?: string }).code !== 'UNAUTHENTICATED') {
          setSessionError(
            problem instanceof Error ? problem.message : 'Не удалось загрузить сессию.',
          );
          timer = setTimeout(initialize, 5000);
        }
      } finally {
        if (alive) setLoading(false);
      }
    };
    void initialize();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [reloadSession]);
  useEffect(() => {
    if (!session) return;
    const focus = () => {
      void reloadSession(true)
        .then(() => callbacks.current.onRefresh?.())
        .catch(() => {});
    };
    window.addEventListener('focus', focus);
    return () => window.removeEventListener('focus', focus);
  }, [session, reloadSession]);
  const action = useCallback(
    async (fn: () => Promise<void>) => {
      if (busyRef.current) return;
      busyRef.current = true;
      const version = ++actionVersion.current,
        epoch = generation.current;
      setBusy(true);
      setError('');
      setNotice('');
      try {
        await fn();
        if (epoch !== generation.current) return;
        await reloadSession(true);
        if (epoch !== generation.current) return;
        await callbacks.current.onRefresh?.();
      } catch (problem) {
        if (epoch !== generation.current) return;
        setError(problem instanceof Error ? problem.message : 'Действие не выполнено.');
        void callbacks.current.onRefresh?.().catch(() => {});
      } finally {
        if (version === actionVersion.current) {
          busyRef.current = false;
          setBusy(false);
        }
      }
    },
    [reloadSession],
  );
  const logout = async () => {
    await api('auth/logout', {});
    reset();
    setNotice('');
  };
  return {
    session,
    loading,
    sessionError,
    busy,
    error,
    notice,
    setError,
    setNotice,
    api,
    action,
    logout,
    reloadSession,
    generation,
    isAuthenticated,
    retry: () => action(async () => {}),
  };
}
