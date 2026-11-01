'use client';
import { useEffect } from 'react';
import { PersonalLogin } from '../auth/controls';
import { TaskButton } from '../../shared/ui';
import { InstallerAccount } from './account';
import { InstallerDevice } from './device';
import { InstallerInstallation } from './installation';
import { InstallerProfile } from './profile-menu';
import { InstallerIcon, InstallerScreen } from './screen';
import { useInstaller } from './use-installer';
import { useInstallerNavigation, type InstallerView } from './navigation';
import './installer.css';

export default function Installer() {
  const state = useInstaller(),
    connection = state.apple.connection;
  const accountReady = connection?.state === 'ready' && connection.identityReady;
  const grantScope = connection?.shared
    ? state.apple.shares
        .filter((share) => share.connectionId === connection.id)
        .map((share) => [share.id, share.generation, share.state].join('.'))
        .sort()
        .join('|')
    : 'owner';
  const scope = JSON.stringify([
    state.session?.profile.id ?? 'guest',
    connection?.id,
    connection?.team_id,
    connection?.shared,
    grantScope,
  ]);
  const initial: InstallerView = !state.session
    ? 'welcome'
    : !accountReady
      ? 'account'
      : !state.deviceId
        ? 'device'
        : 'install';
  const allowed: InstallerView[] = !state.session
    ? ['welcome', 'invite']
    : !accountReady
      ? ['account', 'account-status']
      : [
          'account',
          'account-status',
          'device',
          'profile',
          'device-qr',
          'confirm',
          ...(state.deviceId
            ? (['install', 'install-qr', 'after', 'settings'] as InstallerView[])
            : []),
        ];
  const navigation = useInstallerNavigation(scope, initial, allowed),
    { view, navigate } = navigation;
  useEffect(() => {
    if (view === 'account' && accountReady) navigate(state.deviceId ? 'install' : 'device', true);
  }, [view, accountReady, state.deviceId, navigate]);
  useEffect(() => {
    if (['install-qr', 'after'].includes(view) && state.operation?.state !== 'ready')
      navigate('install', true);
  }, [view, state.operation?.state, navigate]);
  const device = state.readyDevices.find((item) => item.id === state.deviceId);
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
  const deliveryScope = JSON.stringify([
    scope,
    bindingGeneration,
    state.deviceId,
    state.operation?.operationId ?? 'new',
    state.operation?.state === 'ready' ? 'delivery' : 'preparation',
  ]);
  function back() {
    if (navigation.canBack) navigation.back();
    else
      navigate(
        view === 'invite'
          ? 'welcome'
          : ['profile', 'device-qr', 'confirm', 'install'].includes(view)
            ? 'device'
            : view === 'device'
              ? 'account-status'
              : initial,
      );
  }
  const authenticated = !!state.session;
  const showHeader = !state.loading && (authenticated || view === 'invite');
  let screen;
  if (state.loading)
    screen = (
      <InstallerScreen centered>
        <p className="installer-caption" role="status">
          Проверяем вход…
        </p>
      </InstallerScreen>
    );
  else if (!state.session)
    screen = (
      <PersonalLogin
        key={view}
        api={state.api}
        action={state.action}
        busy={state.busy}
        inviteMode={view === 'invite'}
        navigate={(invite) => navigate(invite ? 'invite' : 'welcome')}
        actionError={state.error}
        clearActionError={() => state.setError('')}
      />
    );
  else if (!state.resourcesLoaded)
    screen = (
      <InstallerScreen centered>
        <p className="installer-caption" role="status">
          Получаем аккаунт и устройства…
        </p>
      </InstallerScreen>
    );
  else if (view === 'account' || view === 'account-status')
    screen = (
      <InstallerAccount
        key={scope}
        apple={state.apple}
        api={state.api}
        action={state.action}
        busy={state.busy}
        onContinue={() => navigate(state.deviceId ? 'install' : 'device')}
      />
    );
  else if (['device', 'profile', 'device-qr', 'confirm'].includes(view))
    screen = (
      <InstallerDevice
        key={scope}
        devices={state.devices}
        deviceId={state.deviceId}
        select={state.selectDevice}
        api={state.api}
        action={state.action}
        busy={state.busy}
        view={view}
        navigate={navigate}
        refresh={state.refresh}
      />
    );
  else if (view === 'settings')
    screen = (
      <InstallerScreen
        title="Параметры установки"
        actions={
          <>
            <TaskButton
              disabled={!state.operation || state.operation.state !== 'ready'}
              onClick={() => navigate('install-qr')}
            >
              Установка через QR
            </TaskButton>
            <TaskButton variant="text" onClick={() => navigate('install')}>
              Вернуться
            </TaskButton>
          </>
        }
      >
        <div className="installer-settings">
          <div>
            <span>Устройство</span>
            <strong>
              {device?.name}
              {device?.os_version ? ' · iOS ' + device.os_version : ''}
            </strong>
            <button
              type="button"
              className="installer-text-button"
              aria-label="Изменить устройство"
              onClick={() => navigate('device')}
            >
              Изменить
            </button>
          </div>
          <div>
            <span>Команда</span>
            <strong>{connection?.team_id}</strong>
            <button
              type="button"
              className="installer-text-button"
              aria-label="Посмотреть аккаунт"
              onClick={() => navigate('account-status')}
            >
              Посмотреть
            </button>
          </div>
          <p className="installer-caption">
            {state.operation?.version || state.release?.version
              ? 'Версия ' + (state.operation?.version ?? state.release?.version) + ' · '
              : ''}
            iOS 16 и новее
          </p>
          {state.operation?.state !== 'ready' && (
            <p className="installer-caption">
              Сначала подготовьте клиент для выбранного устройства.
            </p>
          )}
        </div>
      </InstallerScreen>
    );
  else
    screen = (
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
        eligible={!!accountReady && !!state.deviceId}
        runnerAvailable={state.session.capabilities.runner}
        releaseAvailable={!!state.release?.available}
        releaseLoading={!state.release}
        releaseReason={state.release?.reason}
        refreshAvailability={() => state.action(state.loadRelease)}
        deviceName={device?.name ?? 'iPhone'}
        view={view}
        navigate={navigate}
      />
    );
  return (
    <div className="store installer" data-view={view}>
      {showHeader && (
        <header className="installer-header">
          {(view !== 'account' || navigation.canBack) && (
            <button type="button" className="installer-back installer-text-button" onClick={back}>
              <InstallerIcon name="back" />
              Назад
            </button>
          )}
          {state.session && (
            <InstallerProfile
              key={state.session.profile.id}
              id={state.session.profile.publicProfileId}
              logout={state.logout}
            />
          )}
        </header>
      )}
      {(state.sessionError ||
        (authenticated && state.error) ||
        state.resourceError ||
        state.notice) && (
        <div className="installer-feedback">
          {(state.sessionError || (authenticated && state.error)) && (
            <p className="installer-error" role="alert">
              {state.sessionError || state.error}
            </p>
          )}
          {state.resourceError && (
            <div role="alert">
              <p>{state.resourceError}</p>
              <TaskButton variant="text" onClick={() => void state.action(state.refresh)}>
                Обновить данные
              </TaskButton>
            </div>
          )}
          {state.notice && <p role="status">{state.notice}</p>}
        </div>
      )}
      {screen}
    </div>
  );
}
