'use client';
import Image from 'next/image';
import Link from 'next/link';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { PersonalLogin } from '../auth/controls';
import { ThemeSelect } from '../../shared/ui/theme-control';
import { TaskButton } from '../../shared/ui';
import { InstallerAccount } from './account';
import { InstallerDevice } from './device';
import { InstallerInstallation } from './installation';
import { useInstaller } from './use-installer';
import './installer.css';

function CompletedStep({
  title,
  value,
  children,
}: {
  title: string;
  value: string;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="installer-completed">
      <button
        type="button"
        className="installer-completed-toggle"
        aria-expanded={open}
        aria-label={'Изменить: ' + title + ', ' + value}
        onClick={() => setOpen((previous) => !previous)}
      >
        <span className="installer-completed-check" aria-hidden="true">
          ✓
        </span>
        <span className="installer-completed-content">
          <span>{title}</span>
          <strong>{value}</strong>
        </span>
        <span className="installer-edit">{open ? 'Свернуть' : 'Изменить'}</span>
      </button>
      {open && <div className="installer-completed-editor">{children}</div>}
    </div>
  );
}

export default function Installer() {
  const state = useInstaller();
  const accountReady =
    state.apple.connection?.state === 'ready' && state.apple.connection.identityReady !== false;
  const loggedIn = !!state.session;
  const step = !accountReady ? 1 : !state.deviceId ? 2 : 3;
  const phase = !loggedIn ? 'auth' : step === 1 ? 'account' : step === 2 ? 'device' : 'install';
  const heading = useRef<HTMLHeadingElement>(null),
    previousPhase = useRef(phase);
  useEffect(() => {
    if (heading.current && previousPhase.current !== phase) {
      heading.current.focus();
      previousPhase.current = phase;
    }
  }, [phase, state.resourcesLoaded]);
  const shownVersion = state.operation ? state.operation.version : state.release?.version;
  const device = state.readyDevices.find((item) => item.id === state.deviceId);
  const accountPanel = state.session && (
    <InstallerAccount
      key={state.session.profile.id}
      apple={state.apple}
      profileId={state.session.profile.publicProfileId ?? ''}
      api={state.api}
      action={state.action}
      busy={state.busy}
    />
  );
  const devicePanel = (
    <InstallerDevice
      key={[
        state.session?.profile.id,
        state.apple.connection?.id,
        state.apple.connection?.team_id,
      ].join(':')}
      devices={state.devices}
      deviceId={state.deviceId}
      select={state.selectDevice}
      api={state.api}
      action={state.action}
      busy={state.busy}
    />
  );
  const connection = state.apple.connection;
  const bindingGeneration = Math.max(
    0,
    ...state.devices.collectedDevices
      .flatMap((identity) => identity.bindings)
      .filter(
        (binding) =>
          binding.deviceId === state.deviceId &&
          binding.connectionId === connection?.id &&
          binding.teamId === connection?.team_id,
      )
      .map((binding) => binding.generation),
  );
  const grantScope = connection?.shared
    ? state.apple.shares
        .filter((share) => share.connectionId === connection.id)
        .map((share) => [share.id, share.generation, share.state].join('.'))
        .sort()
        .join('|')
    : 'owner';
  const deliveryScope = [
    state.session?.profile.id,
    connection?.id,
    connection?.team_id,
    grantScope,
    bindingGeneration,
    state.deviceId,
    state.operation?.operationId ?? 'new',
    state.operation?.state === 'ready' ? 'delivery' : 'preparation',
  ].join(':');
  const titles = {
    auth: 'Войдите для установки',
    account: 'Команда Apple Developer',
    device: 'Добавьте iPhone',
    install:
      state.operation?.state === 'ready' ? 'Клиент готов к установке' : 'Установка на iPhone',
  };
  return (
    <div className="store installer" data-ui="installer">
      <header className="installer-header">
        <Link href="/" className="installer-brand">
          iSign
        </Link>
        <div className="installer-header-actions">
          <ThemeSelect />
          {state.session && (
            <>
              <span className="installer-user">{state.session.profile.loginName}</span>
              <button
                type="button"
                className="installer-text-button"
                onClick={() => void state.logout().catch((error) => state.setError(error.message))}
              >
                Выйти
              </button>
            </>
          )}
        </div>
      </header>
      <main className="installer-main">
        <span className="visually-hidden" role="status" aria-live="polite">
          {state.operation?.state === 'ready' ? 'Клиент готов к установке' : ''}
        </span>
        <div className="installer-product">
          <Image
            src="/icons/client.png"
            alt="Иконка iSign Client"
            width={56}
            height={56}
            priority
          />
          <div>
            <h1>iSign Client</h1>
            <p>{shownVersion ? 'Версия ' + shownVersion + ' · ' : ''}iOS 16 и новее</p>
          </div>
        </div>
        {loggedIn && (
          <ol className="installer-steps" aria-label="Шаги установки">
            {['Команда', 'Устройство', 'Установка'].map((label, index) => (
              <li
                key={label}
                aria-current={step === index + 1 ? 'step' : undefined}
                data-complete={step > index + 1}
              >
                <span aria-hidden="true">{step > index + 1 ? '✓' : index + 1}</span>
                {label}
              </li>
            ))}
          </ol>
        )}
        {state.sessionError && (
          <p role="alert" className="installer-error">
            {state.sessionError}
          </p>
        )}
        {state.error && (
          <p role="alert" className="installer-error">
            {state.error}
          </p>
        )}
        {state.notice && (
          <p role="status" className="installer-note">
            {state.notice}
          </p>
        )}
        {state.loading ? (
          <p className="installer-wait" role="status">
            Проверяем вход…
          </p>
        ) : !loggedIn ? (
          <section className="installer-current" aria-labelledby="installer-heading">
            <h2 id="installer-heading" ref={heading} tabIndex={-1}>
              {titles.auth}
            </h2>
            <p className="installer-description">
              Используйте passkey своего профиля. Для первого входа понадобится приглашение.
            </p>
            <div className="installer-panel">
              <PersonalLogin
                api={state.api}
                action={state.action}
                busy={state.busy}
                actionError={state.error}
                clearActionError={() => state.setError('')}
              />
            </div>
            <p className="installer-footnote">Дальше — Apple-аккаунт и устройство для установки.</p>
          </section>
        ) : (
          <>
            {state.resourceError && (
              <div className="installer-error" role="alert">
                <p>{state.resourceError}</p>
                <TaskButton secondary onClick={() => void state.action(state.refresh)}>
                  Обновить данные
                </TaskButton>
              </div>
            )}
            {!state.resourcesLoaded ? (
              <p className="installer-wait" role="status">
                Получаем аккаунт и устройства…
              </p>
            ) : (
              <>
                {accountReady && (
                  <div className="installer-completed-list">
                    <CompletedStep
                      title={
                        state.apple.connection?.shared
                          ? 'Предоставленный доступ'
                          : 'Команда Apple Developer'
                      }
                      value={state.apple.connection?.team_id ?? 'Команда подключена'}
                    >
                      {accountPanel}
                    </CompletedStep>
                    {device && (
                      <CompletedStep
                        title="Устройство"
                        value={
                          device.name + (device.os_version ? ' · iOS ' + device.os_version : '')
                        }
                      >
                        {devicePanel}
                      </CompletedStep>
                    )}
                  </div>
                )}
                <section
                  className="installer-current"
                  aria-labelledby="installer-heading"
                  data-phase={phase}
                >
                  <h2 id="installer-heading" ref={heading} tabIndex={-1}>
                    {titles[phase]}
                  </h2>
                  {phase === 'account' && (
                    <>
                      <div className="installer-panel">{accountPanel}</div>
                    </>
                  )}
                  {phase === 'device' && (
                    <>
                      <p className="installer-description">
                        Подтвердите устройство, для которого будет подписан клиент.
                      </p>
                      <div className="installer-panel">{devicePanel}</div>
                    </>
                  )}
                  {phase === 'install' && (
                    <>
                      {!state.operation && (
                        <p className="installer-description">
                          Подготовим приложение для выбранного iPhone. Затем Safari предложит
                          установить его.
                        </p>
                      )}
                      <div className="installer-panel installer-install-panel">
                        <InstallerInstallation
                          key={deliveryScope}
                          operation={state.operation}
                          refreshOperation={state.refreshOperation}
                          restartRequired={state.restartRequired}
                          reason={state.operationReason}
                          api={state.api}
                          action={state.action}
                          start={state.start}
                          busy={state.busy}
                          eligible={accountReady && !!state.deviceId}
                          runnerAvailable={state.session!.capabilities?.runner === true}
                          releaseAvailable={!!state.release?.available}
                          releaseLoading={!state.release}
                          releaseReason={state.release?.reason}
                          refreshAvailability={() =>
                            state.action(async () => {
                              await state.loadRelease();
                            })
                          }
                        />
                      </div>
                    </>
                  )}
                </section>
              </>
            )}
          </>
        )}
        {state.release?.reason === 'RELEASE_STATUS_UNAVAILABLE' && (
          <div className="installer-note">
            <p>Не удалось проверить версию клиента.</p>
            <TaskButton secondary onClick={() => void state.loadRelease()}>
              Проверить версию
            </TaskButton>
          </div>
        )}
      </main>
    </div>
  );
}
