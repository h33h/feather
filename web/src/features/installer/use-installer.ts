'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  appleSchema,
  devicesSchema,
  type AppleData,
  type DeviceData,
} from '../../shared/api/contracts';
import { installerErrorMessage } from '../../shared/api/errors';
import { useSession } from '../../shared/api/use-session';
import {
  installationErrors,
  installationSchema,
  releaseSchema,
  receiptSchema,
  type ClientInstallation,
} from './model';
const emptyApple: AppleData = { connection: null, shares: [], uploadAllowed: false };
const emptyDevices: DeviceData = { devices: [], collectedDevices: [] };
function saved(owner: string): { operationId?: string; key?: string; deviceId?: string } {
  try {
    const value = receiptSchema.safeParse(
      JSON.parse(sessionStorage.getItem('isign-client-install:' + owner) ?? '{}'),
    );
    return value.success ? value.data : {};
  } catch {
    return {};
  }
}
function forget(owner: string) {
  try {
    sessionStorage.removeItem('isign-client-install:' + owner);
  } catch {}
}
function remember(owner: string, value: { operationId?: string; key: string; deviceId: string }) {
  try {
    sessionStorage.setItem('isign-client-install:' + owner, JSON.stringify(value));
  } catch {
    /* Recovery is optional when browser storage is unavailable. */
  }
}
export function useInstaller() {
  const [data, setData] = useState<{ owner: string; apple: AppleData; devices: DeviceData } | null>(
    null,
  );
  const [release, setRelease] = useState<ReturnType<typeof releaseSchema.parse> | null>(null);
  const [resourceError, setResourceError] = useState('');
  const [selected, setSelected] = useState<{ owner: string; id: string } | null>(null);
  const [operation, setOperation] = useState<{
    owner: string;
    deviceId: string;
    value: ClientInstallation;
  } | null>(null);
  const [restart, setRestart] = useState<{ owner: string; deviceId: string } | null>(null);
  const refreshRef = useRef<() => Promise<void>>(async () => {});
  const reset = useCallback(() => {
    setData(null);
    setSelected(null);
    setOperation(null);
    setRestart(null);
    setResourceError('');
  }, []);
  const auth = useSession({
    onReset: reset,
    onRefresh: useCallback(() => refreshRef.current(), []),
  });
  const { api, generation, isAuthenticated } = auth;
  const owner = auth.session?.profile.id;
  const refresh = useCallback(async () => {
    if (!owner || !isAuthenticated()) return;
    const epoch = generation.current;
    const [apple, devices] = await Promise.all([api('apple'), api('devices')]);
    const value = { owner, apple: appleSchema.parse(apple), devices: devicesSchema.parse(devices) };
    if (epoch === generation.current) {
      setData(value);
      setResourceError('');
    }
  }, [owner, api, generation, isAuthenticated]);
  useEffect(() => {
    refreshRef.current = refresh;
  }, [refresh]);
  const loadRelease = useCallback(async () => {
    try {
      setRelease(releaseSchema.parse(await api('client/release')));
    } catch {
      setRelease({ name: 'iSign Client', available: false, reason: 'RELEASE_STATUS_UNAVAILABLE' });
    }
  }, [api]);
  useEffect(() => {
    let alive = true;
    void api('client/release')
      .then((value) => {
        if (alive) setRelease(releaseSchema.parse(value));
      })
      .catch(() => {
        if (alive)
          setRelease({
            name: 'iSign Client',
            available: false,
            reason: 'RELEASE_STATUS_UNAVAILABLE',
          });
      });
    return () => {
      alive = false;
    };
  }, [api]);
  useEffect(() => {
    if (!owner) return;
    let alive = true;
    const load = () => {
      if (document.visibilityState === 'visible')
        void refresh().catch(() => {
          if (alive)
            setResourceError('Не удалось обновить аккаунт и устройства. Повторите попытку.');
        });
    };
    load();
    const timer = setInterval(load, 10000);
    const focus = () => load();
    window.addEventListener('focus', focus);
    return () => {
      alive = false;
      clearInterval(timer);
      window.removeEventListener('focus', focus);
    };
  }, [owner, refresh]);
  const apple = data && data.owner === owner ? data.apple : emptyApple;
  const devices = data && data.owner === owner ? data.devices : emptyDevices;
  const readyDevices = devices.devices.filter((device) => device.status === 'ready');
  const chosen =
    selected && selected.owner === owner
      ? readyDevices.find((device) => device.id === selected.id)
      : undefined;
  const deviceId =
    chosen?.id ?? readyDevices.find((device) => device.selected)?.id ?? readyDevices[0]?.id ?? '';
  const currentOperation =
    operation && operation.owner === owner && operation.deviceId === deviceId
      ? operation.value
      : null;
  useEffect(() => {
    if (!owner || !deviceId) return;
    const stored = saved(owner);
    if (!stored.operationId || stored.deviceId !== deviceId) return;
    const epoch = generation.current;
    let alive = true;
    void api('client/install/' + encodeURIComponent(stored.operationId))
      .then((value) => {
        if (alive && epoch === generation.current)
          setOperation({ owner, deviceId, value: installationSchema.parse(value) });
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [owner, deviceId, api, generation]);
  const operationId = currentOperation?.operationId;
  const operationState = currentOperation?.state;
  const active = !!currentOperation && !['failed', 'cancelled'].includes(currentOperation.state);
  useEffect(() => {
    if (!owner || !operationId || !active) return;
    const epoch = generation.current;
    let alive = true;
    const poll = async () => {
      if (!alive || document.visibilityState !== 'visible') return;
      try {
        const value = installationSchema.parse(
          await api('client/install/' + encodeURIComponent(operationId)),
        );
        if (alive && epoch === generation.current) {
          setOperation({ owner, deviceId, value });
          setResourceError('');
        }
      } catch (problem) {
        if (alive && epoch === generation.current) {
          const code = (problem as { code?: string }).code ?? '';
          setResourceError(
            installationErrors[code] ??
              'Не удалось проверить подготовку. Повторим запрос при восстановлении связи.',
          );
          if (
            ['NOT_FOUND', 'CLIENT_INSTALLATION_UNAVAILABLE', 'APPLE_ACCESS_UNAVAILABLE'].includes(
              code,
            )
          ) {
            setOperation(null);
            forget(owner);
            setRestart({ owner, deviceId });
          }
        }
      }
    };
    void poll();
    const timer = setInterval(() => void poll(), operationState === 'ready' ? 15000 : 3000);
    const focus = () => void poll();
    window.addEventListener('focus', focus);
    document.addEventListener('visibilitychange', focus);
    return () => {
      alive = false;
      clearInterval(timer);
      window.removeEventListener('focus', focus);
      document.removeEventListener('visibilitychange', focus);
    };
  }, [owner, deviceId, operationId, operationState, active, api, generation]);
  async function refreshOperation() {
    if (!owner || !operationId) return;
    const epoch = generation.current;
    try {
      const value = installationSchema.parse(
        await api('client/install/' + encodeURIComponent(operationId)),
      );
      if (epoch === generation.current) setOperation({ owner, deviceId, value });
    } catch (problem) {
      if (
        epoch === generation.current &&
        ['NOT_FOUND', 'CLIENT_INSTALLATION_UNAVAILABLE'].includes(
          (problem as { code?: string }).code ?? '',
        )
      ) {
        setOperation(null);
        forget(owner);
        setRestart({ owner, deviceId });
      }
    }
  }
  async function start(retry = false) {
    if (!owner || !deviceId) return;
    const epoch = generation.current,
      previous = saved(owner);
    const key =
      !retry && previous.deviceId === deviceId && previous.key ? previous.key : crypto.randomUUID();
    remember(owner, { key, deviceId });
    await auth.action(async () => {
      try {
        const value = installationSchema.parse(await api('client/install', { deviceId, key }));
        if (epoch !== generation.current) return;
        remember(owner, { operationId: value.operationId, key, deviceId });
        setRestart(null);
        setOperation({ owner, deviceId, value });
      } catch (problem) {
        if (
          epoch === generation.current &&
          (problem as { code?: string }).code === 'IDEMPOTENCY_BINDING_MISMATCH'
        ) {
          forget(owner);
          setRestart({ owner, deviceId });
        }
        throw problem;
      }
    });
  }
  async function logout() {
    if (owner) {
      try {
        sessionStorage.removeItem('isign-client-install:' + owner);
      } catch {}
    }
    await auth.logout();
  }
  const code = currentOperation?.reason ?? '';
  return {
    ...auth,
    logout,
    apple,
    devices,
    readyDevices,
    deviceId,
    selectDevice: (id: string) => {
      if (owner) setSelected({ owner, id });
    },
    release,
    loadRelease,
    resourceError,
    resourcesLoaded: !!owner && data?.owner === owner,
    refresh,
    operation: currentOperation,
    refreshOperation,
    restartRequired: !!restart && restart.owner === owner && restart.deviceId === deviceId,
    start,
    operationReason: code ? (installationErrors[code] ?? installerErrorMessage(code)) : '',
  };
}
