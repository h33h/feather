'use client';
import { useEffect, useId, useRef, useState } from 'react';
import { Field, Modal, TaskButton } from '../../shared/ui';
import { CopyValue } from '../../shared/ui/copy-value';
import { useBrowserContext } from '../../shared/ui/browser-context';
import { installerErrorMessage } from '../../shared/api/errors';
import { appleSchema, type Action, type Api, type AppleData } from '../../shared/api/contracts';

type InstallerAccountProps = {
  apple: AppleData;
  profileId: string;
  api: Api;
  action: Action;
  busy: boolean;
};

export function InstallerAccount(props: InstallerAccountProps) {
  const connection = props.apple.connection;
  return (
    <InstallerAccountBinding
      key={JSON.stringify([
        props.profileId,
        connection?.id,
        connection?.team_id,
        connection?.shared,
      ])}
      {...props}
    />
  );
}

function InstallerAccountBinding({ apple, profileId, api, action, busy }: InstallerAccountProps) {
  const [mode, setMode] = useState<'own' | 'shared'>('own');
  const [issuer, setIssuer] = useState(''),
    [keyId, setKeyId] = useState(''),
    [file, setFile] = useState<File | null>(null),
    [fileError, setFileError] = useState(''),
    [connectError, setConnectError] = useState('');
  const [touched, setTouched] = useState({ issuer: false, key: false });
  const [check, setCheck] = useState<'idle' | 'pending' | 'absent' | 'found' | 'failed'>('idle');
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
  const id = useId();
  const issuerHelp = 'issuer-help-' + id,
    issuerErrorId = 'issuer-error-' + id,
    keyHelp = 'key-help-' + id,
    keyErrorId = 'key-error-' + id,
    fileHelp = 'p8-help-' + id,
    fileErrorId = 'p8-error-' + id;
  const { origin } = useBrowserContext();
  // Match parseTeamKey's normalization and identifier rules; Apple validates permissions.
  const issuerInvalid = !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(issuer.trim());
  const keyInvalid = !/^[A-Z0-9]{10}$/.test(keyId.trim().toUpperCase());
  const issuerError = touched.issuer && issuerInvalid;
  const keyError = touched.key && keyInvalid;
  const connection = apple.connection;
  const needsPreparation =
    (connection?.state === 'ready' && connection.identityReady === false) ||
    (connection?.state === 'action_required' &&
      ['TEAM_PROOF_REQUIRED', 'CERTIFICATE_REQUIRED'].includes(connection.last_error ?? ''));

  async function checkAccess() {
    if (busy) return;
    setCheck('pending');
    await action(async () => {
      try {
        const current = appleSchema.parse(await api('apple'));
        if (mounted.current) setCheck(current.connection ? 'found' : 'absent');
      } catch {
        if (mounted.current) setCheck('failed');
      }
    });
  }
  const checkFeedback = (
    <>
      {check === 'pending' && <p role="status">Проверяем доступ…</p>}
      {check === 'absent' && (
        <p role="status">
          Доступ пока не предоставлен. Попросите владельца проверить ID профиля и выдать доступ,
          затем повторите проверку.
        </p>
      )}
      {check === 'found' && <p role="status">Подключение команды найдено. Проверка завершена.</p>}
      {check === 'failed' && (
        <p className="installer-error" role="alert">
          Не удалось проверить доступ. Повторите попытку после восстановления связи.
        </p>
      )}
    </>
  );

  function clearFile() {
    if (!mounted.current) return;
    setFile(null);
    if (fileInput.current) fileInput.current.value = '';
  }
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
        // A read may outlive logout or a new team binding. Never submit that
        // private key through a session belonging to the next account view.
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
          if (code === 'INVALID_ISSUER_ID') setTouched((value) => ({ ...value, issuer: true }));
          if (code === 'INVALID_KEY_ID') setTouched((value) => ({ ...value, key: true }));
          if (code === 'INVALID_P8' || code === 'TEAM_KEY_REQUIRED')
            setFileError(installerErrorMessage(code));
          else
            setConnectError(
              installerErrorMessage(
                code,
                'Не удалось подключить команду. Проверьте доступ и повторите попытку.',
              ),
            );
        }
      } finally {
        p8 = '';
        clearFile();
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
        if (!mounted.current) return;
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
  const disconnectButton = (
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
  );
  const disconnectDialog = disconnectOpen && connection && (
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
              Будет отозван только ваш доступ к этой команде. Текущая подготовка и ссылки установки
              вашего профиля с этим доступом станут недоступны.
            </p>
            <p>Подключение владельца, доступы других пользователей и ключи команды сохранятся.</p>
          </>
        ) : (
          <>
            <p>
              Команда будет отключена от всех профилей iSign. Привязки профилей к команде будут
              удалены, а все выданные доступы — отозваны.
            </p>
            <p>
              Текущая подготовка будет отменена, выданные ссылки установки перестанут работать.
              Ключи и другие секреты команды на сервере будут помечены для удаления.
            </p>
            <p>
              Ключ API и сертификаты в Apple автоматически не отзываются. При необходимости отзовите
              их в App Store Connect и Apple Developer.
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
          <TaskButton secondary disabled={disconnecting} onClick={() => setDisconnectOpen(false)}>
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
  );

  if (connection?.state === 'ready' && !needsPreparation)
    return (
      <div className="installer-account-ready">
        <div>
          <strong>
            {connection.shared ? 'Предоставленный доступ' : 'Своя команда Apple Developer'}
          </strong>
          <p>Команда {connection.team_id}</p>
        </div>
        {disconnectButton}
        {disconnectDialog}
      </div>
    );
  if (connection)
    return (
      <div className="installer-account-state">
        <p className="installer-summary">
          {connection.shared ? 'Предоставленный доступ' : 'Своя команда Apple Developer'}
        </p>
        <p>
          Команда <strong>{connection.team_id ?? 'проверяется'}</strong>
        </p>
        {needsPreparation ? (
          <>
            <p className="installer-muted">
              Подготовьте сертификат для первоначальной установки клиента.
            </p>
            {connection.shared ? (
              <p>Владелец команды должен завершить подготовку команды. Затем проверьте доступ.</p>
            ) : (
              <TaskButton
                disabled={busy}
                onClick={() =>
                  void action(async () => {
                    await api('apple/bootstrap', {});
                  })
                }
              >
                Подготовить аккаунт
              </TaskButton>
            )}
          </>
        ) : (
          <p role="status">
            {installerErrorMessage(
              connection.last_error,
              connection.state === 'validating'
                ? 'Проверяем подключение команды. Подождите и проверьте доступ снова.'
                : 'Команда пока недоступна. Проверьте доступ; если ошибка остаётся, обратитесь к владельцу команды или администратору сервера.',
            )}
          </p>
        )}
        <div className="installer-actions">
          <TaskButton variant="text" disabled={busy} onClick={() => void checkAccess()}>
            Проверить доступ
          </TaskButton>
          {disconnectButton}
        </div>
        {checkFeedback}
        {disconnectDialog}
      </div>
    );
  return (
    <>
      <div className="installer-choice" role="group" aria-label="Способ подключения команды">
        <button
          type="button"
          aria-pressed={mode === 'own'}
          disabled={busy}
          onClick={() => {
            setMode('own');
            setCheck('idle');
          }}
        >
          Своя команда
        </button>
        <button
          type="button"
          aria-pressed={mode === 'shared'}
          disabled={busy}
          onClick={() => {
            setMode('shared');
            setCheck('idle');
            clearFile();
          }}
        >
          Доступ от владельца
        </button>
      </div>
      {mode === 'own' ? (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void connect();
          }}
        >
          <p className="installer-muted">
            Нужна команда Apple Developer Program и её Team API Key из App Store Connect. Обычного
            Apple Account для этого недостаточно. Если команды нет, выберите «Доступ от владельца».
          </p>
          <details className="installer-account-help">
            <summary>Где взять Issuer ID, Key ID и P8?</summary>
            <ol>
              <li>
                В App Store Connect откройте Users and Access → Integrations → App Store Connect API
                → Team Keys. Если доступ к API ещё не включён, запросить его должен Account Holder.
              </li>
              <li>
                Team API Key может создать Account Holder или Admin. Права ключа должны разрешать
                нужные операции с сертификатами, устройствами и профилями. Individual API Key здесь
                не подходит.
              </li>
              <li>
                Скопируйте Issuer ID вверху страницы и Key ID из строки нужного ключа. В этой же
                строке нажмите Download API Key, чтобы скачать файл .p8. Apple разрешает скачать
                приватный ключ только один раз — сохраните свою копию.
              </li>
            </ol>
            <p>
              <a
                href="https://developer.apple.com/help/app-store-connect/get-started/app-store-connect-api"
                target="_blank"
                rel="noreferrer"
              >
                Создание Team API Key — Apple
              </a>
            </p>
            <p>
              <a
                href="https://developer.apple.com/documentation/appstoreconnectapi/generating-tokens-for-api-requests"
                target="_blank"
                rel="noreferrer"
              >
                Issuer ID и Key ID — Apple
              </a>
            </p>
          </details>
          <div className="installer-fields">
            <div>
              <Field label="Issuer ID">
                <input
                  value={issuer}
                  onChange={(event) => setIssuer(event.target.value)}
                  onBlur={() => setTouched((value) => ({ ...value, issuer: true }))}
                  required
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="12345678-1234-1234-1234-123456789abc"
                  aria-invalid={issuerError || undefined}
                  aria-describedby={issuerHelp + (issuerError ? ' ' + issuerErrorId : '')}
                />
              </Field>
              <p id={issuerHelp} className="installer-caption">
                ID издателя вверху страницы Team Keys.
              </p>
              {issuerError && (
                <p id={issuerErrorId} className="installer-field-error">
                  Issuer ID состоит из 36 символов: букв a–f, цифр и дефисов, как в примере.
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
                  aria-describedby={keyHelp + (keyError ? ' ' + keyErrorId : '')}
                />
              </Field>
              <p id={keyHelp} className="installer-caption">
                ID из строки выбранного Team API Key.
              </p>
              {keyError && (
                <p id={keyErrorId} className="installer-field-error">
                  Key ID состоит из 10 букв и цифр. Скопируйте его из строки ключа.
                </p>
              )}
            </div>
          </div>
          <Field label="P8-ключ" className="installer-file-field">
            <input
              ref={fileInput}
              aria-label="P8-ключ"
              aria-describedby={fileHelp + (fileError ? ' ' + fileErrorId : '')}
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
              <span>Выбрать ключ</span>
              <span>{file?.name ?? 'Файл .p8'}</span>
            </span>
          </Field>
          <p id={fileHelp} className="installer-caption">
            Приватный файл выбранного Team API Key, до 16 KiB.
          </p>
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
          <p className="installer-caption installer-key-trust">
            Приватный ключ будет отправлен на сервер iSign{' '}
            <strong>{origin || 'этого сайта'}</strong> для запросов к Apple при подготовке подписи и
            регистрации устройств. Передавайте ключ только серверу, которому доверяете.
          </p>
          <TaskButton type="submit" disabled={busy || !file || !issuer.trim() || !keyId.trim()}>
            Подключить аккаунт
          </TaskButton>
          <p className="installer-caption">
            Сервер хранит ключ в зашифрованном виде и может использовать для этих действий. После
            отправки выбор файла будет очищен; исходный файл останется на вашем устройстве.
            Отключение команды в iSign помечает серверные секреты для удаления. Отозвать сам ключ
            можно в App Store Connect → Team Keys.
          </p>
        </form>
      ) : (
        <div>
          <p>
            Передайте владельцу команды Apple Developer ID своего профиля. Он сможет предоставить
            доступ из iSign Client.
          </p>
          <CopyValue
            label="ID профиля iSign"
            value={profileId}
            buttonLabel="Скопировать ID профиля"
          />
          <p className="installer-caption">После предоставления доступа команда появится здесь.</p>
          <TaskButton disabled={busy} onClick={() => void checkAccess()}>
            Проверить доступ
          </TaskButton>
          {checkFeedback}
        </div>
      )}
    </>
  );
}
