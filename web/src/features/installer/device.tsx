'use client';
import { useEffect, useRef, useState } from 'react';
import { Field, TaskButton } from '../../shared/ui';
import type { Action, Api, DeviceData } from '../../shared/api/contracts';
import { DeviceProfile } from './device-profile';
import { InstallerScreen } from './screen';
import type { InstallerView } from './navigation';

function PendingDevice({
  device,
  identity,
  api,
  action,
  busy,
  picker,
  onAdd,
}: {
  device: DeviceData['devices'][number];
  identity?: DeviceData['collectedDevices'][number];
  api: Api;
  action: Action;
  busy: boolean;
  picker: React.ReactNode;
  onAdd: () => void;
}) {
  const [os, setOs] = useState(''),
    [udid, setUdid] = useState(identity?.udid ?? '');
  const live = useRef(true);
  const identityId = identity?.id,
    maskedUdid = identity?.udid;
  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);
  useEffect(() => {
    if (!identityId || !maskedUdid?.startsWith('••')) return;
    let alive = true;
    const reveal = () =>
      void api('devices/collected/' + encodeURIComponent(identityId) + '/udid')
        .then((value) => {
          if (alive && typeof value.udid === 'string') setUdid(value.udid);
        })
        .catch(() => {});
    reveal();
    window.addEventListener('focus', reveal);
    return () => {
      alive = false;
      window.removeEventListener('focus', reveal);
    };
  }, [identityId, maskedUdid, api]);
  const waiting = ['registering', 'apple_processing'].includes(device.status);
  const registerable = ['collected', 'not_registered'].includes(device.status);
  const statuses: Record<string, string> = {
    certificate_required:
      'Для проверки устройства нужен сертификат. Завершите подготовку аккаунта и повторите проверку.',
    ineligible:
      'Apple пока не разрешает установку на это устройство. Проверьте его состояние в Apple Developer.',
    disabled:
      'Устройство отключено в Apple Developer. Включите его или обратитесь к владельцу доступа.',
    connection_changed: 'Аккаунт изменился. Проверьте подключение и повторите проверку устройства.',
  };
  return (
    <InstallerScreen
      title={device.name}
      description={device.os_version ? 'iOS ' + device.os_version : undefined}
      actions={
        <>
          {registerable ? (
            <TaskButton
              disabled={busy || (!device.os_version && !os.trim())}
              loading={busy}
              aria-label={'Зарегистрировать устройство: ' + device.name}
              onClick={() =>
                void action(async () => {
                  if (!device.os_version)
                    await api('devices/' + encodeURIComponent(device.id) + '/os', {
                      version: os.trim(),
                    });
                  if (!live.current) return;
                  await api('devices/' + encodeURIComponent(device.id) + '/register', {
                    slotConsent: true,
                  });
                })
              }
            >
              Зарегистрировать
            </TaskButton>
          ) : (
            <TaskButton
              disabled={busy}
              loading={busy}
              aria-label={'Проверить устройство: ' + device.name}
              onClick={() =>
                void action(async () => {
                  await api('devices/' + encodeURIComponent(device.id) + '/poll', {});
                })
              }
            >
              Проверить статус
            </TaskButton>
          )}
          <TaskButton variant="text" disabled={busy} onClick={onAdd}>
            Добавить другое устройство
          </TaskButton>
        </>
      }
    >
      {picker}
      <dl className="installer-identifier">
        <dt>UDID</dt>
        <dd>{udid || 'Идентификатор пока недоступен'}</dd>
      </dl>
      {!device.os_version && registerable && (
        <Field label={'Версия iOS для ' + device.name}>
          <input
            inputMode="decimal"
            placeholder="18.0"
            value={os}
            onChange={(event) => setOs(event.target.value)}
          />
        </Field>
      )}
      {waiting ? (
        <p className="installer-status" role="status">
          Ожидаем Apple
        </p>
      ) : (
        !registerable && (
          <p className="installer-status" role="status">
            {statuses[device.status] ??
              'Устройство пока недоступно для установки. Повторите проверку.'}
          </p>
        )
      )}
    </InstallerScreen>
  );
}

export function InstallerDevice({
  devices,
  deviceId,
  select,
  api,
  action,
  busy,
  view,
  navigate,
  refresh,
}: {
  devices: DeviceData;
  deviceId: string;
  select: (id: string) => void;
  api: Api;
  action: Action;
  busy: boolean;
  view: InstallerView;
  navigate: (view: InstallerView, replace?: boolean) => void;
  refresh: () => Promise<void>;
}) {
  const [chosen, setChosen] = useState(''),
    [adding, setAdding] = useState(false);
  const device =
    devices.devices.find((item) => item.id === chosen) ??
    devices.devices.find((item) => item.id === deviceId) ??
    devices.devices[0];
  const previousStatus = useRef(device?.status),
    previousView = useRef(view);
  useEffect(() => {
    if (view === 'device' && previousView.current !== 'device') setAdding(false);
    previousView.current = view;
    if (
      device?.status === 'ready' &&
      previousStatus.current &&
      previousStatus.current !== 'ready'
    ) {
      select(device.id);
      navigate('install', true);
    }
    previousStatus.current = device?.status;
  }, [view, device, select, navigate]);
  const collection =
    view === 'profile' || view === 'device-qr' || adding || !devices.devices.length;
  if (collection && (!devices.collectedDevices.length || adding || view !== 'device'))
    return (
      <DeviceProfile
        api={api}
        action={action}
        busy={busy}
        view={view}
        navigate={navigate}
        devices={devices}
        refresh={refresh}
        onCancel={
          devices.devices.length || devices.collectedDevices.length
            ? () => {
                setAdding(false);
                navigate('device', true);
              }
            : undefined
        }
        onCollected={(id) => {
          setChosen(id);
          setAdding(false);
          if (devices.devices.find((device) => device.id === id)?.status === 'ready') {
            select(id);
            navigate('install', true);
          } else navigate('confirm', true);
        }}
      />
    );
  const picker =
    devices.devices.length > 1 ? (
      <Field label="Устройство для установки">
        <select
          value={device?.id ?? ''}
          onChange={(event) => {
            setChosen(event.target.value);
            if (devices.devices.find((item) => item.id === event.target.value)?.status === 'ready')
              select(event.target.value);
          }}
        >
          {devices.devices.map((item) => (
            <option key={item.id} value={item.id}>
              {item.name}
              {item.os_version ? ' · iOS ' + item.os_version : ''}
            </option>
          ))}
        </select>
      </Field>
    ) : null;
  if (device && device.status !== 'ready') {
    const identity = devices.collectedDevices.find((item) =>
      item.bindings.some((binding) => binding.deviceId === device.id),
    );
    return (
      <PendingDevice
        key={JSON.stringify([
          device.id,
          device.team_id,
          identity?.bindings.map((binding) => [binding.connectionId, binding.generation]),
        ])}
        device={device}
        identity={identity}
        api={api}
        action={action}
        busy={busy}
        picker={picker}
        onAdd={() => setAdding(true)}
      />
    );
  }
  return (
    <InstallerScreen
      title={device ? 'Ваш iPhone' : 'Подключаем устройство'}
      actions={
        <>
          {device && (
            <TaskButton
              onClick={() => {
                select(device.id);
                navigate('install');
              }}
            >
              Продолжить
            </TaskButton>
          )}
          <TaskButton
            variant={device ? 'text' : 'solid'}
            disabled={busy}
            onClick={() => setAdding(true)}
          >
            Добавить другое устройство
          </TaskButton>
          {!device && (
            <TaskButton variant="text" disabled={busy} onClick={() => void action(refresh)}>
              Проверить статус
            </TaskButton>
          )}
        </>
      }
    >
      {picker ??
        (device && (
          <div>
            <strong>{device.name}</strong>
            <p className="installer-caption">
              {device.os_version ? 'iOS ' + device.os_version : ''}
            </p>
          </div>
        ))}
      {!device && (
        <p className="installer-status" role="status">
          Идентификатор получен. Подготавливаем привязку устройства к аккаунту.
        </p>
      )}
    </InstallerScreen>
  );
}
