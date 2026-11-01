'use client';
import { useEffect, useId, useRef, useState } from 'react';
import { Field, Modal, TaskButton } from '../../shared/ui';
import { installerErrorMessage } from '../../shared/api/errors';
import type { Action, Api, AppleData } from '../../shared/api/contracts';
import { InstallerScreen } from './screen';

export function InstallerAccount({
  apple,
  api,
  action,
  busy,
  onContinue,
}: {
  apple: AppleData;
  api: Api;
  action: Action;
  busy: boolean;
  onContinue: () => void;
}) {
  const [issuer, setIssuer] = useState(''),
    [keyId, setKeyId] = useState('');
  const [file, setFile] = useState<File | null>(null),
    [fileError, setFileError] = useState(''),
    [connectError, setConnectError] = useState('');
  const [touched, setTouched] = useState({ issuer: false, key: false });
  const [disconnectOpen, setDisconnectOpen] = useState(false),
    [disconnecting, setDisconnecting] = useState(false),
    [disconnectError, setDisconnectError] = useState('');
  const fileInput = useRef<HTMLInputElement>(null),
    disconnectOpener = useRef<HTMLButtonElement | null>(null),
    mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const id = useId(),
    formId = 'account-' + id,
    issuerErrorId = 'issuer-error-' + id,
    keyErrorId = 'key-error-' + id,
    fileErrorId = 'p8-error-' + id;
  const issuerInvalid = !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(issuer.trim());
  const keyInvalid = !/^[A-Z0-9]{10}$/.test(keyId.trim().toUpperCase());
  const issuerError = touched.issuer && issuerInvalid,
    keyError = touched.key && keyInvalid;
  const connection = apple.connection;
  const needsPreparation =
    (connection?.state === 'ready' && !connection.identityReady) ||
    (connection?.state === 'action_required' &&
      ['TEAM_PROOF_REQUIRED', 'CERTIFICATE_REQUIRED'].includes(connection.last_error ?? ''));
  const ready = connection?.state === 'ready' && connection.identityReady;
  async function connect() {
    if (busy) return;
    setTouched({ issuer: true, key: true });
    if (!file || issuerInvalid || keyInvalid) return;
    if (file.size > 16384) {
      setFileError('Выберите приватный ключ .p8 размером до 16 KiB.');
      return;
    }
    const selected = file;
    setFileError('');
    setConnectError('');
    await action(async () => {
      let p8 = '';
      try {
        p8 = await selected.text();
        if (!mounted.current) return;
        await api('apple/connect', {
          issuerId: issuer.trim(),
          keyId: keyId.trim(),
          filename: selected.name,
          keyType: 'team',
          p8,
        });
      } catch (problem) {
        if (!mounted.current) return;
        const code = (problem as { code?: string }).code;
        if (!['TEAM_PROOF_REQUIRED', 'CERTIFICATE_REQUIRED'].includes(code ?? '')) {
          if (code === 'INVALID_P8' || code === 'TEAM_KEY_REQUIRED')
            setFileError(installerErrorMessage(code));
          else
            setConnectError(
              installerErrorMessage(
                code,
                'Не удалось подключить аккаунт. Проверьте данные и повторите попытку.',
              ),
            );
        }
      } finally {
        p8 = '';
        if (mounted.current) {
          setFile(null);
          if (fileInput.current) fileInput.current.value = '';
        }
      }
    });
  }
  async function disconnect() {
    if (busy || disconnecting || !connection) return;
    setDisconnecting(true);
    setDisconnectError('');
    await action(async () => {
      try {
        await api('apple/disconnect', {});
        if (mounted.current) setDisconnectOpen(false);
      } catch (problem) {
        if (mounted.current)
          setDisconnectError(
            installerErrorMessage(
              (problem as { code?: string }).code,
              'Не удалось отключить доступ. Повторите попытку.',
            ),
          );
      } finally {
        if (mounted.current) setDisconnecting(false);
      }
    });
  }
  const disconnectLabel = connection?.shared ? 'Отказаться от доступа' : 'Отключить свою команду';
  if (connection)
    return (
      <>
        <InstallerScreen
          title="Подключённый аккаунт"
          description={connection.shared ? 'Предоставленный доступ' : 'Команда Apple Developer'}
          actions={
            <>
              {ready ? (
                <TaskButton onClick={onContinue}>Продолжить</TaskButton>
              ) : needsPreparation && !connection.shared ? (
                <TaskButton
                  disabled={busy}
                  loading={busy}
                  onClick={() =>
                    void action(async () => {
                      await api('apple/bootstrap', {});
                    })
                  }
                >
                  Подготовить аккаунт
                </TaskButton>
              ) : null}
              {!ready && (
                <TaskButton
                  variant="text"
                  disabled={busy}
                  onClick={() =>
                    void action(async () => {
                      await api('apple');
                    })
                  }
                >
                  Проверить доступ
                </TaskButton>
              )}
              <TaskButton
                variant="text"
                destructive
                disabled={busy}
                onClick={(event) => {
                  disconnectOpener.current = event.currentTarget;
                  setDisconnectError('');
                  setDisconnectOpen(true);
                }}
              >
                {disconnectLabel}
              </TaskButton>
            </>
          }
        >
          <dl className="installer-identifier">
            <dt>Команда</dt>
            <dd>{connection.team_id ?? 'Проверяется'}</dd>
          </dl>
          {!ready && (
            <p className="installer-status installer-account-state" role="status">
              {needsPreparation
                ? connection.shared
                  ? 'Владелец команды должен завершить подготовку аккаунта. Затем проверьте доступ.'
                  : 'Подготовьте сертификат для установки клиента.'
                : installerErrorMessage(
                    connection.last_error,
                    connection.state === 'validating'
                      ? 'Проверяем аккаунт…'
                      : 'Проверьте доступ. Если ошибка остаётся, обратитесь к владельцу аккаунта.',
                  )}
            </p>
          )}
        </InstallerScreen>
        {disconnectOpen && (
          <Modal
            title={disconnectLabel + '?'}
            width={480}
            returnFocusRef={disconnectOpener}
            closeDisabled={disconnecting}
            onClose={() => {
              if (!disconnecting) setDisconnectOpen(false);
            }}
          >
            <div className="installer-disconnect">
              <p>
                Команда <strong>{connection.team_id ?? 'Apple Developer'}</strong>
              </p>
              {connection.shared ? (
                <>
                  <p>
                    Будет отозван только ваш доступ к этой команде. Текущая подготовка и ссылки
                    установки вашего профиля с этим доступом станут недоступны.
                  </p>
                  <p>
                    Подключение владельца, доступы других пользователей и ключи команды сохранятся.
                  </p>
                </>
              ) : (
                <>
                  <p>
                    Команда будет отключена от всех профилей iSign. Привязки профилей к команде
                    будут удалены, а все выданные доступы — отозваны.
                  </p>
                  <p>
                    Текущая подготовка будет отменена, выданные ссылки установки перестанут
                    работать. Ключи и другие секреты команды на сервере будут помечены для удаления.
                  </p>
                  <p>
                    Ключ API и сертификаты в Apple автоматически не отзываются. При необходимости
                    отзовите их в App Store Connect и Apple Developer.
                  </p>
                </>
              )}
              {disconnecting && <p role="status">Отключаем доступ… Дождитесь завершения.</p>}
              {disconnectError && (
                <p className="installer-error" role="alert">
                  {disconnectError}
                </p>
              )}
              <div className="installer-actions">
                <TaskButton
                  secondary
                  disabled={disconnecting}
                  onClick={() => setDisconnectOpen(false)}
                >
                  Отмена
                </TaskButton>
                <TaskButton
                  destructive
                  loading={disconnecting}
                  disabled={busy}
                  onClick={() => void disconnect()}
                >
                  {disconnectLabel}
                </TaskButton>
              </div>
            </div>
          </Modal>
        )}
      </>
    );
  return (
    <InstallerScreen
      title="Подключите аккаунт"
      actions={
        <TaskButton
          type="submit"
          form={formId}
          disabled={busy || !file || !issuer.trim() || !keyId.trim()}
          loading={busy}
        >
          Подключить
        </TaskButton>
      }
    >
      <form
        id={formId}
        className="installer-form"
        onSubmit={(event) => {
          event.preventDefault();
          void connect();
        }}
      >
        <div>
          <Field label="Issuer ID">
            <input
              value={issuer}
              onChange={(event) => setIssuer(event.target.value)}
              onBlur={() => setTouched((value) => ({ ...value, issuer: true }))}
              required
              autoComplete="off"
              spellCheck={false}
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              aria-invalid={issuerError || undefined}
              aria-describedby={issuerError ? issuerErrorId : undefined}
            />
          </Field>
          {issuerError && (
            <p id={issuerErrorId} className="installer-field-error">
              Issuer ID состоит из 36 символов: букв a–f, цифр и дефисов.
            </p>
          )}
        </div>
        <div>
          <Field label="Key ID">
            <input
              value={keyId}
              onChange={(event) => setKeyId(event.target.value)}
              onBlur={() => setTouched((value) => ({ ...value, key: true }))}
              required
              autoComplete="off"
              spellCheck={false}
              placeholder="ABC123DEF4"
              aria-invalid={keyError || undefined}
              aria-describedby={keyError ? keyErrorId : undefined}
            />
          </Field>
          {keyError && (
            <p id={keyErrorId} className="installer-field-error">
              Key ID состоит из 10 букв и цифр.
            </p>
          )}
        </div>
        <Field label="Ключ .p8" className="installer-file-field">
          <input
            ref={fileInput}
            aria-label="Ключ .p8"
            aria-describedby={fileError ? fileErrorId : undefined}
            aria-invalid={!!fileError || undefined}
            className="installer-file-input"
            type="file"
            accept=".p8"
            required
            onChange={(event) => {
              setFile(event.target.files?.[0] ?? null);
              setFileError('');
              setConnectError('');
            }}
          />
          <span className="installer-file-face" aria-hidden="true">
            {file?.name ?? 'Выбрать файл .p8'}
          </span>
        </Field>
        {fileError && (
          <p id={fileErrorId} className="installer-error" role="alert">
            {fileError}
          </p>
        )}
        {connectError && (
          <p className="installer-error" role="alert">
            {connectError}
          </p>
        )}
      </form>
      <details className="installer-help">
        <summary>Где взять ключ?</summary>
        <p>
          В App Store Connect откройте Users and Access → Integrations → App Store Connect API →
          Team Keys. Скопируйте Issuer ID, Key ID и скачайте .p8. Нужен ключ команды Apple Developer
          Program.
        </p>
        <p>
          <a
            href="https://developer.apple.com/help/app-store-connect/get-started/app-store-connect-api"
            target="_blank"
            rel="noreferrer"
          >
            Создание Team API Key — Apple
          </a>
        </p>
      </details>
    </InstallerScreen>
  );
}
