'use client';
import Image from 'next/image';
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { TaskButton } from '../../shared/ui';
import { useBrowserContext } from '../../shared/ui/browser-context';
import type { Action, Api } from '../../shared/api/contracts';
import { installerErrorMessage } from '../../shared/api/errors';
import { operationLabels, type ClientInstallation } from './model';
import { InstallerCopyLink, InstallerScreen } from './screen';
import type { InstallerView } from './navigation';
const ticketSchema = z.object({
  installUrl: z.string(),
  handoffUrl: z.string(),
  qrSvg: z.string(),
  expiresAt: z.number().finite(),
});

export function InstallerInstallation({
  operation,
  reason,
  api,
  action,
  start,
  busy,
  eligible,
  runnerAvailable,
  releaseAvailable,
  releaseLoading,
  releaseReason,
  refreshAvailability,
  refreshOperation,
  restartRequired,
  deviceName,
  view,
  navigate,
}: {
  operation: ClientInstallation | null;
  reason: string;
  api: Api;
  action: Action;
  start: (retry?: boolean) => Promise<void>;
  busy: boolean;
  eligible: boolean;
  runnerAvailable: boolean;
  releaseAvailable: boolean;
  releaseLoading: boolean;
  releaseReason?: string;
  refreshAvailability: () => Promise<void>;
  refreshOperation: () => Promise<void>;
  restartRequired: boolean;
  deviceName: string;
  view: InstallerView;
  navigate: (view: InstallerView, replace?: boolean) => void;
}) {
  const { isIOS } = useBrowserContext();
  const live = useRef(true),
    requested = useRef(false),
    ticketEpoch = useRef(0);
  const [ticket, setTicket] = useState<z.infer<typeof ticketSchema> | null>(null),
    [now, setNow] = useState(Date.now),
    [pendingTicket, setPendingTicket] = useState<{ view: InstallerView; request: number } | null>(
      null,
    );
  const ticketPending = pendingTicket?.view === view;
  const [checking, setChecking] = useState(false),
    [checked, setChecked] = useState(false);
  useLayoutEffect(() => {
    ticketEpoch.current++;
    requested.current = false;
  }, [view]);
  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);
  useEffect(() => {
    if (!ticket) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [ticket]);
  const ready = operation?.state === 'ready';
  const canPrepare = eligible && releaseAvailable && runnerAvailable;
  const failed =
    restartRequired || (!!operation && ['failed', 'cancelled'].includes(operation.state));
  const getTicket = useCallback(
    async (qr: boolean) => {
      if (!operation || !eligible || busy) return;
      const request = ++ticketEpoch.current;
      requested.current = true;
      setPendingTicket({ view, request });
      try {
        await action(async () => {
          let value: z.infer<typeof ticketSchema>;
          try {
            value = ticketSchema.parse(
              await api(
                'client/install/' + encodeURIComponent(operation.operationId) + '/ticket',
                {},
              ),
            );
          } catch (problem) {
            if (!live.current || request !== ticketEpoch.current) return;
            await refreshOperation();
            throw problem;
          }
          if (!live.current || request !== ticketEpoch.current) return;
          const handoff = new URL(value.handoffUrl),
            install = new URL(value.installUrl),
            manifest = new URL(install.searchParams.get('url') ?? '');
          if (
            handoff.origin !== location.origin ||
            manifest.origin !== location.origin ||
            !handoff.pathname.startsWith('/handoff/') ||
            !manifest.pathname.startsWith('/install/') ||
            handoff.username ||
            handoff.password ||
            manifest.username ||
            manifest.password ||
            install.protocol !== 'itms-services:' ||
            install.searchParams.get('action') !== 'download-manifest' ||
            value.expiresAt <= Date.now()
          )
            throw Error('Ссылка установки не прошла проверку. Получите новую ссылку.');
          setNow(Date.now());
          setTicket(value);
          navigate(qr ? 'install-qr' : 'after');
          if (!qr) window.location.assign(value.installUrl);
        });
      } finally {
        if (live.current)
          setPendingTicket((current) => (current?.request === request ? null : current));
      }
    },
    [operation, eligible, busy, api, action, refreshOperation, navigate, view],
  );
  useEffect(() => {
    if (view === 'install-qr' && ready && !busy && !ticket && !requested.current)
      void getTicket(true);
  }, [view, ready, busy, ticket, getTicket]);
  async function checkAvailability() {
    setChecking(true);
    setChecked(false);
    try {
      await refreshAvailability();
      if (live.current) setChecked(true);
    } finally {
      if (live.current) setChecking(false);
    }
  }
  if (view === 'after' && ready)
    return (
      <InstallerScreen
        title="После установки"
        description="Сначала подтвердите установку в Safari."
        actions={
          <>
            <a className="installer-primary-link" href="isign-feather://open">
              Открыть iSign Client
            </a>
            <TaskButton variant="text" disabled={busy} onClick={() => void getTicket(false)}>
              Установить повторно
            </TaskButton>
          </>
        }
      >
        <ol className="installer-instructions">
          <li>Откройте iSign Client.</li>
          <li>Войдите с тем же passkey.</li>
        </ol>
      </InstallerScreen>
    );
  if (view === 'install-qr' && ready) {
    const expired = !!ticket && ticket.expiresAt <= now;
    return (
      <InstallerScreen
        centered
        title="Продолжите на iPhone"
        description={'Откройте QR камерой ' + deviceName + '. Войдите с тем же passkey.'}
        actions={
          <>
            {!ticket || expired ? (
              <TaskButton
                loading={ticketPending}
                disabled={busy}
                onClick={() => void getTicket(true)}
              >
                {expired ? 'Обновить ссылку' : 'Получить ссылку'}
              </TaskButton>
            ) : (
              <InstallerCopyLink label="Скопировать ссылку" value={ticket.handoffUrl} />
            )}
            <TaskButton variant="text" onClick={() => navigate('install')}>
              Вернуться
            </TaskButton>
          </>
        }
      >
        {ticket && !expired ? (
          <>
            <Image
              unoptimized
              width={192}
              height={192}
              src={'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(ticket.qrSvg)}
              alt="QR установки iSign Client"
            />
            <p className="installer-caption">
              Ссылка действует до {new Date(ticket.expiresAt).toLocaleTimeString('ru-RU')}.
            </p>
            <a className="installer-text-link" href={ticket.handoffUrl}>
              Открыть страницу установки
            </a>
          </>
        ) : (
          <p role="status" className="installer-status">
            {expired
              ? 'Срок ссылки истёк. Обновите ссылку установки.'
              : ticketPending
                ? 'Получаем ссылку установки…'
                : 'Получите ссылку для выбранного устройства.'}
          </p>
        )}
      </InstallerScreen>
    );
  }
  return (
    <InstallerScreen
      centered
      actions={
        <>
          {ready ? (
            <TaskButton
              loading={ticketPending}
              disabled={busy || !eligible}
              onClick={() => void getTicket(!isIOS)}
            >
              Установить
            </TaskButton>
          ) : (
            <TaskButton
              loading={busy}
              disabled={!canPrepare || (!!operation && !failed)}
              onClick={() => void start(!!failed)}
            >
              {failed ? 'Подготовить заново' : 'Подготовить установку'}
            </TaskButton>
          )}
          <TaskButton variant="text" onClick={() => navigate('settings')}>
            Параметры установки
          </TaskButton>
        </>
      }
    >
      <div className="installer-client">
        <Image
          src="/icons/client.png"
          alt="Иконка iSign Client"
          width={104}
          height={104}
          priority
        />
        <div className="installer-intro">
          <h1>iSign Client</h1>
          <p>Для {deviceName}</p>
        </div>
      </div>
      {operation && !ready && (
        <div role="status" aria-live="polite" className="installer-status">
          <p>{operationLabels[operation.state] ?? 'Проверяем подготовку клиента'}</p>
          {reason && <p>{reason}</p>}
        </div>
      )}
      {!ready && (
        <>
          {releaseLoading && (
            <p role="status" className="installer-caption">
              Проверяем доступность сборки…
            </p>
          )}
          {!releaseLoading && !releaseAvailable && (
            <p className="installer-status" role="status">
              {!releaseReason || releaseReason === 'CLIENT_RELEASE_NOT_CONFIGURED'
                ? 'Версия клиента ещё не опубликована.'
                : installerErrorMessage(releaseReason, 'Сборка клиента временно недоступна.')}
            </p>
          )}
          {!runnerAvailable && (
            <p className="installer-status" role="status">
              Сервер сейчас не подготавливает новые установки. Проверьте доступность позже.
            </p>
          )}
          {(!releaseAvailable || !runnerAvailable) && (
            <TaskButton
              variant="text"
              loading={checking}
              disabled={busy}
              onClick={() => void checkAvailability()}
            >
              Проверить доступность
            </TaskButton>
          )}
          {checked && (
            <p role="status" className="installer-caption">
              {canPrepare
                ? 'Сборка и сервис подписи доступны. Можно продолжить.'
                : 'Проверка завершена. Установка пока недоступна.'}
            </p>
          )}
        </>
      )}
    </InstallerScreen>
  );
}
