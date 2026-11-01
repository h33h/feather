'use client';
import { useEffect, useRef, useState } from 'react';
import { Field, TaskButton } from '../../shared/ui';
import type { Action, Api, DeviceData } from '../../shared/api/contracts';
import { DeviceProfile } from './device-profile';

function PendingDevice({
  device,
  team,
  api,
  action,
  busy,
}: {
  device: DeviceData['devices'][number];
  team: string;
  api: Api;
  action: Action;
  busy: boolean;
}) {
  const [consent, setConsent] = useState(false),
    [os, setOs] = useState('');
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const statuses: Record<string, string> = {
    registering: 'Регистрация устройства отправлена в Apple. Проверьте её состояние.',
    apple_processing: 'Apple обрабатывает регистрацию устройства. Повторите проверку позже.',
    pending: 'Apple обрабатывает регистрацию устройства. Повторите проверку позже.',
    processing: 'Apple обрабатывает регистрацию устройства. Повторите проверку позже.',
    certificate_required:
      'Для проверки устройства нужен действующий сертификат команды. Проверьте подготовку Apple-аккаунта и повторите проверку устройства.',
    ineligible:
      'Apple пока не разрешает использовать это устройство для установки. Проверьте его состояние в Apple Developer и повторите проверку.',
    disabled:
      'Устройство отключено в Apple Developer. Включите его в своей команде или обратитесь к владельцу доступа, затем повторите проверку.',
    connection_changed:
      'Привязка к Apple-команде изменилась. Проверьте подключённый аккаунт и повторите проверку устройства.',
  };
  return (
    <div className="installer-device">
      <strong>{device.name}</strong>
      {['collected', 'not_registered'].includes(device.status) ? (
        <>
          {!device.os_version && (
            <Field label={'Версия iOS для ' + device.name}>
              <input
                placeholder="18.0"
                inputMode="decimal"
                value={os}
                onChange={(event) => setOs(event.target.value)}
              />
            </Field>
          )}
          <label className="installer-consent">
            <input
              type="checkbox"
              checked={consent}
              onChange={(event) => setConsent(event.target.checked)}
            />
            Разрешаю зарегистрировать {device.name} в Apple-команде {team}
          </label>
          <p className="installer-caption">
            Регистрация займёт слот устройства в этой Apple Developer команде.
          </p>
          <TaskButton
            aria-label={'Зарегистрировать устройство: ' + device.name}
            disabled={busy || !consent || (!device.os_version && !os.trim())}
            onClick={() =>
              void action(async () => {
                if (!device.os_version)
                  await api('devices/' + device.id + '/os', { version: os.trim() });
                if (!mounted.current) return;
                await api('devices/' + device.id + '/register', { slotConsent: true });
                if (mounted.current) setConsent(false);
              })
            }
          >
            Зарегистрировать {device.name}
          </TaskButton>
        </>
      ) : (
        <>
          <p role="status">
            {statuses[device.status] ??
              'Устройство пока недоступно для установки. Проверьте его статус в Apple.'}
          </p>
          <TaskButton
            secondary
            aria-label={'Проверить устройство: ' + device.name}
            disabled={busy}
            onClick={() =>
              void action(async () => {
                await api('devices/' + device.id + '/poll', {});
              })
            }
          >
            Проверить {device.name}
          </TaskButton>
        </>
      )}
    </div>
  );
}

export function InstallerDevice({
  devices,
  deviceId,
  select,
  api,
  action,
  busy,
}: {
  devices: DeviceData;
  deviceId: string;
  select: (id: string) => void;
  api: Api;
  action: Action;
  busy: boolean;
}) {
  const ready = devices.devices.filter((device) => device.status === 'ready');
  const pending = devices.devices.filter((device) => device.status !== 'ready');
  return (
    <>
      {ready.length > 0 && (
        <Field label="Устройство для установки">
          <select value={deviceId} onChange={(event) => select(event.target.value)}>
            {ready.map((device) => (
              <option key={device.id} value={device.id}>
                {device.name}
                {device.os_version ? ' · iOS ' + device.os_version : ''}
              </option>
            ))}
          </select>
        </Field>
      )}
      {pending.map((device) => {
        const bindings = devices.collectedDevices.flatMap((identity) =>
          identity.bindings.filter((binding) => binding.deviceId === device.id),
        );
        return (
          <PendingDevice
            key={JSON.stringify([
              device.id,
              device.team_id,
              bindings.map((binding) => [binding.connectionId, binding.teamId, binding.generation]),
            ])}
            device={device}
            team={device.team_id ?? bindings[0]?.teamId ?? 'подключённого аккаунта'}
            api={api}
            action={action}
            busy={busy}
          />
        );
      })}
      {devices.collectedDevices.some((identity) => !identity.bindings.length) && (
        <p role="status">
          Идентификатор получен. Подготавливаем привязку устройства к Apple-команде.
        </p>
      )}
      {devices.devices.length > 0 || devices.collectedDevices.length > 0 ? (
        <details>
          <summary>Добавить другое устройство</summary>
          <DeviceProfile api={api} action={action} busy={busy} enrollment />
        </details>
      ) : (
        <DeviceProfile api={api} action={action} busy={busy} enrollment />
      )}
    </>
  );
}
