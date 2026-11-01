'use client';
import { useEffect, useRef, useState } from 'react';
import Image from 'next/image';
import type { Action, Api } from '../../shared/api/contracts';
import { TaskButton } from '../../shared/ui';
import { Modal } from '../../shared/ui/modal';
import { useBrowserContext } from '../../shared/ui/browser-context';
import { CopyValue } from '../../shared/ui/copy-value';
export function DeviceProfile({
  api,
  action,
  busy,
  enrollment,
  storeLayout = false,
}: {
  api: Api;
  action: Action;
  busy: boolean;
  enrollment: boolean;
  storeLayout?: boolean;
}) {
  const [expiresAt, setExpiresAt] = useState<number | null>(null),
    [phone, setPhone] = useState<{ url: string; svg: string; expiresAt: number } | null>(null),
    [sheet, setSheet] = useState<'profile' | 'qr' | null>(null);
  const { origin, isIOS: onDevice } = useBrowserContext();
  const returnFocus = useRef<HTMLElement | null>(null),
    mounted = useRef(true);
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  useEffect(() => {
    if (!expiresAt && !phone) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [expiresAt, phone]);
  const request = () => api('devices/challenge', {});
  async function download() {
    await action(async () => {
      const result = await request();
      if (!mounted.current) return;
      if (typeof result.profileXml !== 'string')
        throw new Error('Профиль не получен. Попробуйте позже.');
      let url: string;
      if (typeof result.profileUrl === 'string') {
        const target = new URL(result.profileUrl);
        if (target.origin !== location.origin)
          throw new Error('Ссылка профиля не прошла проверку.');
        url = target.href;
      } else {
        url = URL.createObjectURL(
          new Blob([result.profileXml], { type: 'application/x-apple-aspen-config' }),
        );
        setTimeout(() => URL.revokeObjectURL(url), 60000);
      }
      const link = document.createElement('a');
      if (
        typeof result.expiresAt !== 'number' ||
        !Number.isFinite(result.expiresAt) ||
        result.expiresAt <= Date.now()
      )
        throw new Error('Срок ссылки профиля истёк. Получите новый профиль.');
      link.href = url;
      link.download = 'isign-device.mobileconfig';
      link.click();
      setExpiresAt(Number(result.expiresAt));
      setSheet('profile');
      setNow(Date.now());
    });
  }
  async function transfer() {
    await action(async () => {
      const value = await request();
      if (!mounted.current) return;
      if (typeof value.profileUrl !== 'string' || typeof value.qrSvg !== 'string')
        throw new Error('Ссылка для iPhone не получена.');
      const url = new URL(value.profileUrl);
      if (url.origin !== location.origin) throw new Error('Ссылка профиля не прошла проверку.');
      if (
        typeof value.expiresAt !== 'number' ||
        !Number.isFinite(value.expiresAt) ||
        value.expiresAt <= Date.now()
      )
        throw new Error('Срок ссылки профиля истёк. Получите новую ссылку.');
      setPhone({ url: url.href, svg: value.qrSvg, expiresAt: Number(value.expiresAt) });
      setSheet('qr');
      setNow(Date.now());
    });
  }
  const downloadLabel = storeLayout ? 'Скачать профиль' : 'Скачать профиль для UDID';
  return (
    <div className="device-profile">
      <div className="installer-help">
        <p>
          Профиль передаст UDID, модель и версию системы этого iPhone на сервер iSign{' '}
          <strong>{origin || 'этого сайта'}</strong> и вернёт вас в Safari.
        </p>
        <p className="installer-caption">
          Он не управляет устройством и не подключает MDM. Регистрация устройства в Apple —
          отдельное действие с вашим согласием на использование слота команды.
        </p>
      </div>
      <div className="device-instructions">
        <ol className="profile-steps" data-downloaded={!!expiresAt}>
          <li>
            <strong>Скачайте профиль</strong>
            <p>Откройте iSign в Safari на iPhone и разрешите загрузку.</p>
          </li>
          <li>
            <strong>Установите профиль</strong>
            <p>Настройки → Профиль загружен → Установить.</p>
          </li>
          <li>
            <strong>Вернитесь в iSign</strong>
            <p>Идентификатор устройства появится автоматически.</p>
          </li>
        </ol>
      </div>
      <div className="device-profile-actions">
        <TaskButton
          disabled={busy}
          onClick={(event) => {
            returnFocus.current = event.currentTarget;
            void (onDevice ? download() : transfer());
          }}
        >
          {onDevice ? downloadLabel : 'Продолжить на iPhone'}
        </TaskButton>
        <div className="device-alternative">
          <TaskButton
            variant="text"
            disabled={busy}
            onClick={(event) => {
              returnFocus.current = event.currentTarget;
              void (onDevice ? transfer() : download());
            }}
          >
            {onDevice ? 'Продолжить на iPhone' : downloadLabel}
          </TaskButton>
        </div>
      </div>
      {sheet && (
        <Modal
          title={sheet === 'qr' ? 'Продолжить на iPhone' : 'Установка профиля'}
          className="device-profile-sheet"
          onClose={() => setSheet(null)}
          returnFocusRef={returnFocus}
        >
          {sheet === 'qr' &&
            phone &&
            (phone.expiresAt > now ? (
              <div className="profile-transfer">
                <p>
                  Сканируйте QR камерой iPhone и откройте профиль в Safari до{' '}
                  {new Date(phone.expiresAt).toLocaleTimeString('ru-RU')}.
                </p>
                <Image
                  unoptimized
                  width={192}
                  height={192}
                  alt="QR профиля для iPhone"
                  src={'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(phone.svg)}
                />
                <CopyValue
                  label="Ссылка для iPhone"
                  value={phone.url}
                  buttonLabel="Скопировать ссылку для iPhone"
                />
                <TaskButton secondary onClick={() => setSheet(null)}>
                  Закрыть QR профиля
                </TaskButton>
              </div>
            ) : (
              <div role="status">
                <p>Срок ссылки профиля истёк. Получите новую ссылку.</p>
                <TaskButton disabled={busy} onClick={() => void transfer()}>
                  Получить новую ссылку
                </TaskButton>
              </div>
            ))}
          {sheet === 'profile' && expiresAt && (
            <div role="status">
              {expiresAt <= now ? (
                <>
                  <p>Срок профиля истёк. Скачайте новый профиль.</p>
                  <TaskButton disabled={busy} onClick={() => void download()}>
                    Скачать новый профиль
                  </TaskButton>
                </>
              ) : (
                <p>
                  Откройте скачанный профиль в настройках iPhone до{' '}
                  {new Date(expiresAt).toLocaleTimeString('ru-RU')}.{' '}
                  {enrollment
                    ? 'После возврата UDID появится автоматически.'
                    : 'Автоматическое получение UDID временно недоступно. Повторите позже.'}
                </p>
              )}
            </div>
          )}
        </Modal>
      )}
    </div>
  );
}
