'use client';
import { useEffect, useRef, useState } from 'react';
import Image from 'next/image';
import { z } from 'zod';
import type { Action, Api, DeviceData } from '../../shared/api/contracts';
import { TaskButton } from '../../shared/ui';
import { useBrowserContext } from '../../shared/ui/browser-context';
import { InstallerCopyLink, InstallerScreen } from './screen';
import type { InstallerView } from './navigation';

const profileSchema = z.object({
  profileXml: z.string(),
  profileUrl: z.string(),
  qrSvg: z.string(),
  expiresAt: z.number().finite(),
});
type Profile = z.infer<typeof profileSchema> & { before: string[] };
export function DeviceProfile({
  api,
  action,
  busy,
  view,
  navigate,
  devices,
  refresh,
  onCollected,
  onCancel,
}: {
  api: Api;
  action: Action;
  busy: boolean;
  view: InstallerView;
  navigate: (view: InstallerView, replace?: boolean) => void;
  devices: DeviceData;
  refresh: () => Promise<void>;
  onCollected: (id: string) => void;
  onCancel?: () => void;
}) {
  const [profile, setProfile] = useState<Profile | null>(null),
    [now, setNow] = useState(Date.now),
    [checked, setChecked] = useState(false);
  const { isIOS } = useBrowserContext();
  const live = useRef(true),
    sequence = useRef(0),
    previousView = useRef(view);
  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);
  useEffect(() => {
    if (view === 'device' && previousView.current !== 'device') {
      sequence.current++;
      setProfile(null);
      setChecked(false);
    }
    previousView.current = view;
    if ((view === 'profile' || view === 'device-qr') && !profile) navigate('device', true);
  }, [view, profile, navigate]);
  useEffect(() => {
    if (!profile) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [profile]);
  useEffect(() => {
    if (!profile || view === 'device' || profile.expiresAt <= now) return;
    const identity = devices.collectedDevices.find(
      (item) => !profile.before.includes(item.id + ':' + item.verifiedAt) && item.bindings.length,
    );
    if (identity) onCollected(identity.bindings[0].deviceId);
  }, [devices, profile, now, view, onCollected]);
  async function issue(qr: boolean) {
    const request = ++sequence.current;
    const before = devices.collectedDevices.map((item) => item.id + ':' + item.verifiedAt);
    await action(async () => {
      const result = profileSchema.parse(await api('devices/challenge', {}));
      if (!live.current || sequence.current !== request) return;
      const url = new URL(result.profileUrl);
      if (
        url.origin !== location.origin ||
        !url.pathname.startsWith('/device-profile/') ||
        url.username ||
        url.password ||
        result.expiresAt <= Date.now()
      )
        throw new Error('Ссылка профиля истекла или не прошла проверку. Получите новую.');
      setProfile({ ...result, before });
      setNow(Date.now());
      setChecked(false);
      if (!qr) {
        const link = document.createElement('a');
        link.href = url.href;
        link.download = 'isign-device.mobileconfig';
        link.click();
      }
      navigate(qr ? 'device-qr' : 'profile');
    });
  }
  const expired = !!profile && profile.expiresAt <= now;
  if (view === 'device-qr' && profile)
    return (
      <InstallerScreen
        title="Продолжите на iPhone"
        description="Откройте QR камерой iPhone и перейдите в Safari."
        centered
        actions={
          <>
            {expired ? (
              <TaskButton disabled={busy} onClick={() => void issue(true)}>
                Обновить ссылку
              </TaskButton>
            ) : (
              <InstallerCopyLink label="Скопировать ссылку" value={profile.profileUrl} />
            )}
            <TaskButton variant="text" disabled={busy} onClick={() => void action(refresh)}>
              Проверить статус
            </TaskButton>
          </>
        }
      >
        {expired ? (
          <p className="installer-status" role="status">
            Срок ссылки профиля истёк. Получите новую ссылку.
          </p>
        ) : (
          <>
            <Image
              unoptimized
              width={192}
              height={192}
              alt="QR профиля для iPhone"
              src={'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(profile.qrSvg)}
            />
            <p className="installer-caption" role="status">
              Устройство появится после установки профиля.
            </p>
          </>
        )}
      </InstallerScreen>
    );
  if (view === 'profile' && profile)
    return (
      <InstallerScreen
        title="Установите профиль"
        description="Продолжите в настройках iPhone."
        actions={
          <>
            {expired ? (
              <TaskButton disabled={busy} onClick={() => void issue(false)}>
                Скачать новый профиль
              </TaskButton>
            ) : (
              <TaskButton
                disabled={busy}
                onClick={() =>
                  void action(async () => {
                    await refresh();
                    if (live.current) setChecked(true);
                  })
                }
              >
                Проверить статус
              </TaskButton>
            )}
            {!expired && (
              <TaskButton variant="text" disabled={busy} onClick={() => void issue(false)}>
                Скачать профиль повторно
              </TaskButton>
            )}
          </>
        }
      >
        <ol className="installer-instructions">
          <li>Настройки → Профиль загружен → Установить.</li>
          <li>Вернитесь в Safari. Страница продолжит автоматически.</li>
        </ol>
        <p className="installer-status" role="status">
          {expired
            ? 'Срок профиля истёк. Скачайте новый профиль.'
            : checked
              ? 'Идентификатор пока не получен. Установите профиль в настройках iPhone.'
              : 'Ожидаем идентификатор устройства…'}
        </p>
      </InstallerScreen>
    );
  return (
    <InstallerScreen
      title="Добавьте iPhone"
      description={
        isIOS
          ? 'Профиль передаст идентификатор этого iPhone в iSign.'
          : 'Продолжите на iPhone, на который установите клиент.'
      }
      actions={
        <>
          <TaskButton disabled={busy} loading={busy} onClick={() => void issue(!isIOS)}>
            {isIOS ? 'Скачать профиль' : 'Продолжить на iPhone'}
          </TaskButton>
          {onCancel && (
            <TaskButton variant="text" onClick={onCancel}>
              Вернуться к устройствам
            </TaskButton>
          )}
        </>
      }
    />
  );
}
