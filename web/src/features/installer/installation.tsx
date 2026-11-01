'use client';
import Image from 'next/image';
import { useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { TaskButton } from '../../shared/ui';
import { CopyValue } from '../../shared/ui/copy-value';
import { useBrowserContext } from '../../shared/ui/browser-context';
import type { Action, Api } from '../../shared/api/contracts';
import { installerErrorMessage } from '../../shared/api/errors';
import { operationLabels, type ClientInstallation } from './model';
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
}) {
  const { isIOS } = useBrowserContext();
  const live = useRef(true),
    transferHeading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);
  const [ticket, setTicket] = useState<z.infer<typeof ticketSchema> | null>(null),
    [showQR, setShowQR] = useState(false),
    [now, setNow] = useState(Date.now);
  const [ticketPending, setTicketPending] = useState(false);
  const [checking, setChecking] = useState(false),
    [checked, setChecked] = useState(false);
  useEffect(() => {
    if (!ticket) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [ticket]);
  useEffect(() => {
    if (showQR && ticket) transferHeading.current?.focus({ preventScroll: true });
  }, [showQR, ticket]);
  const ready = operation?.state === 'ready';
  const canPrepare = eligible && releaseAvailable && runnerAvailable;
  const failed =
    restartRequired || (!!operation && ['failed', 'cancelled'].includes(operation.state));
  async function getTicket(qr: boolean) {
    if (!operation || !eligible) return;
    setTicketPending(true);
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
          await refreshOperation();
          throw problem;
        }
        if (!live.current) return;
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
        setShowQR(qr);
        if (!qr) window.location.assign(value.installUrl);
      });
    } finally {
      if (live.current) setTicketPending(false);
    }
  }
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
  return (
    <>
      {operation && !ready && (
        <div role="status" aria-live="polite" className="installer-progress">
          <strong>{operationLabels[operation.state] ?? 'Проверяем подготовку клиента'}</strong>
          {!failed && <p>Состояние обновляется автоматически. Можно оставить страницу открытой.</p>}
          {reason && <p>{reason}</p>}
        </div>
      )}
      {ready ? (
        <>
          <p className="installer-caption installer-before-action">
            {isIOS
              ? 'Safari предложит установить клиент. Он подписан только для выбранного устройства.'
              : 'Откройте установку в Safari на выбранном iPhone или iPad. Сканируйте QR камерой этого устройства.'}
          </p>
          <div className="installer-actions">
            <TaskButton
              loading={ticketPending}
              disabled={busy || !eligible}
              onClick={() => void getTicket(!isIOS)}
            >
              {isIOS ? 'Установить на устройство' : 'Показать QR установки'}
            </TaskButton>
            {isIOS && (
              <TaskButton
                variant="text"
                disabled={busy || !eligible}
                onClick={() => void getTicket(true)}
              >
                Показать QR установки
              </TaskButton>
            )}
          </div>
        </>
      ) : (
        <>
          <TaskButton
            loading={busy}
            disabled={!canPrepare || (!!operation && !failed)}
            onClick={() => void start(!!failed)}
          >
            {failed ? 'Подготовить заново' : 'Подготовить установку'}
          </TaskButton>
          <div className="installer-availability">
            {releaseLoading ? (
              <p role="status" className="installer-caption">
                Проверяем доступность сборки…
              </p>
            ) : (
              !releaseAvailable && (
                <>
                  <p className="installer-muted">
                    {!releaseReason || releaseReason === 'CLIENT_RELEASE_NOT_CONFIGURED'
                      ? 'Версия клиента ещё не опубликована.'
                      : installerErrorMessage(releaseReason, 'Сборка клиента временно недоступна.')}
                  </p>
                  <p className="installer-caption">
                    Администратор сервиса должен опубликовать проверенную сборку. Обратитесь к тому,
                    кто предоставил ссылку на этот сервис.
                  </p>
                </>
              )
            )}
            {!runnerAvailable && (
              <p role="status" className="installer-caption">
                Сервер сейчас не подготавливает новые установки. Обратитесь к администратору сервиса
                или проверьте готовность ещё раз.
              </p>
            )}
            {(!releaseAvailable || !runnerAvailable) && (
              <TaskButton
                secondary
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
                  : 'Проверка завершена. Установка пока недоступна по указанным причинам.'}
              </p>
            )}
          </div>
        </>
      )}
      {eligible &&
        ready &&
        ticket &&
        showQR &&
        (ticket.expiresAt > now ? (
          <section className="installer-qr" aria-labelledby="installer-transfer-heading">
            <h3 id="installer-transfer-heading" ref={transferHeading} tabIndex={-1}>
              Продолжите на iPhone или iPad
            </h3>
            <Image
              unoptimized
              width={192}
              height={192}
              src={'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(ticket.qrSvg)}
              alt="QR установки iSign Client"
            />
            <CopyValue
              label="Ссылка установки"
              value={ticket.handoffUrl}
              buttonLabel="Скопировать ссылку установки"
            />
            <a href={ticket.handoffUrl}>Открыть страницу установки</a>
            <p className="installer-caption">
              Ссылка действует до {new Date(ticket.expiresAt).toLocaleTimeString('ru-RU')}.
            </p>
          </section>
        ) : (
          <p role="status">Срок ссылки истёк. Получите новую ссылку установки.</p>
        ))}
      {ready && (
        <section className="installer-after-install" aria-labelledby="installer-after-heading">
          <div className="installer-after-title">
            <Image src="/icons/client.png" alt="Иконка iSign Client" width={36} height={36} />
            <h3 id="installer-after-heading">После установки</h3>
          </div>
          <ol>
            <li>Откройте iSign Client с этой иконкой.</li>
            <li>В Настройки → iSign войдите с тем же passkey, которым пользовались на сайте.</li>
          </ol>
          {isIOS && (
            <a className="task-link" href="isign-feather://open">
              Открыть iSign Client
            </a>
          )}
          <p className="installer-caption">
            Сайт выдаёт ссылку установки, но не получает подтверждение от iOS, что приложение
            установилось.
          </p>
        </section>
      )}
    </>
  );
}
