'use client';
import './controls.css';
import { Field } from '../../shared/ui';
import { passkeyLogin } from '../../shared/api/passkey-client';
import { useState } from 'react';
import { DesignAsset, TaskButton } from '../../shared/ui';
import { Toast } from '../../shared/ui/toast';
import {
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
} from '@simplewebauthn/browser';
import type { Api, Action } from '../../shared/api/contracts';
export function PersonalLogin({
  api,
  action,
  busy,
  actionError = '',
  clearActionError,
}: {
  api: Api;
  action: Action;
  busy: boolean;
  actionError?: string;
  clearActionError?: () => void;
}) {
  const [invite, setInvite] = useState(''),
    [first, setFirst] = useState(false),
    [inviteInvalid, setInviteInvalid] = useState(false),
    [error, setError] = useState('');
  const failure = error || actionError;
  function clearError() {
    setError('');
    setInviteInvalid(false);
    clearActionError?.();
  }
  function login() {
    setError('');
    void action(async () => {
      try {
        await passkeyLogin(api);
      } catch (problem) {
        setError('Повторите вход с passkey своего профиля.');
        throw problem;
      }
    });
  }
  return (
    <div className={'login-controls' + (first ? ' invite-login' : '')}>
      {first ? (
        <form
          className="task-form"
          onSubmit={(event) => {
            event.preventDefault();
            setError('');
            setInviteInvalid(false);
            void action(async () => {
              try {
                const issued = await api('auth/passkey/register-options', {
                  invite: invite.trim(),
                });
                const response = await startRegistration({
                  optionsJSON: issued.options as PublicKeyCredentialCreationOptionsJSON,
                });
                await api('auth/passkey/register', { requestId: issued.requestId, response });
                setInvite('');
              } catch (problem) {
                const invalid = /INVITE/.test((problem as { code?: string }).code ?? '');
                setInviteInvalid(invalid);
                setError(
                  invalid
                    ? 'Код истёк или уже использован.'
                    : problem instanceof Error
                      ? problem.message
                      : 'Не удалось создать passkey. Повторите попытку.',
                );
                throw problem;
              }
            });
          }}
        >
          <Field label="Код приглашения">
            <input
              required
              autoComplete="off"
              spellCheck={false}
              value={invite}
              maxLength={43}
              aria-invalid={inviteInvalid}
              aria-describedby={inviteInvalid && error ? 'login-error' : undefined}
              onChange={(event) => {
                setInvite(event.target.value);
                clearError();
              }}
            />
          </Field>
          {inviteInvalid && error && (
            <p className="inline-error" id="login-error" role="alert">
              {failure}
            </p>
          )}
          <div className="login-actions">
            <TaskButton
              type="button"
              variant="text"
              className="login-switch"
              disabled={busy}
              onClick={() => {
                setFirst(false);
                setError('');
                clearActionError?.();
              }}
            >
              Уже есть passkey? Войти
            </TaskButton>
            <TaskButton
              type="submit"
              className="passkey-login"
              disabled={busy}
              loading={busy}
              aria-label="Создать passkey"
            >
              <DesignAsset name="login-KeyIcon" />
              Создать passkey
            </TaskButton>
          </div>
        </form>
      ) : (
        <>
          <div className="login-actions">
            <TaskButton
              className="passkey-login"
              disabled={busy}
              onClick={login}
              loading={busy}
              aria-label="Войти с passkey"
            >
              <DesignAsset name="login-KeyIcon" />
              Войти с passkey
            </TaskButton>
            <TaskButton
              variant="text"
              className="login-switch"
              disabled={busy}
              onClick={() => {
                setFirst(true);
                setError('');
                clearActionError?.();
              }}
            >
              Первый вход
            </TaskButton>
          </div>
        </>
      )}
      {!inviteInvalid && failure && <Toast message={failure} onClose={clearError} />}
    </div>
  );
}
