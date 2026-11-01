'use client';
import Image from 'next/image';
import { useState } from 'react';
import {
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
} from '@simplewebauthn/browser';
import { Field, TaskButton } from '../../shared/ui';
import { passkeyLogin } from '../../shared/api/passkey-client';
import type { Api, Action } from '../../shared/api/contracts';
import { InstallerScreen } from '../installer/screen';

export function PersonalLogin({
  api,
  action,
  busy,
  inviteMode,
  navigate,
  actionError,
  clearActionError,
}: {
  api: Api;
  action: Action;
  busy: boolean;
  inviteMode: boolean;
  navigate: (invite: boolean) => void;
  actionError: string;
  clearActionError: () => void;
}) {
  const [invite, setInvite] = useState(''),
    [invalid, setInvalid] = useState(false);
  async function register() {
    setInvalid(false);
    await action(async () => {
      try {
        const issued = await api('auth/passkey/register-options', { invite: invite.trim() });
        const response = await startRegistration({
          optionsJSON: issued.options as PublicKeyCredentialCreationOptionsJSON,
        });
        await api('auth/passkey/register', { requestId: issued.requestId, response });
        setInvite('');
      } catch (error) {
        setInvalid(/INVITE/.test((error as { code?: string }).code ?? ''));
        throw error;
      }
    });
  }
  return inviteMode ? (
    <InstallerScreen
      title="Первый вход"
      actions={
        <>
          <TaskButton type="submit" form="installer-invite" disabled={busy} loading={busy}>
            Создать passkey
          </TaskButton>
          <TaskButton
            variant="text"
            disabled={busy}
            onClick={() => {
              clearActionError();
              navigate(false);
            }}
          >
            Уже есть профиль? Войти
          </TaskButton>
        </>
      }
    >
      <form
        id="installer-invite"
        onSubmit={(event) => {
          event.preventDefault();
          void register();
        }}
      >
        <Field label="Код приглашения">
          <input
            required
            autoComplete="off"
            spellCheck={false}
            maxLength={43}
            value={invite}
            aria-invalid={invalid}
            aria-describedby={invalid ? 'invite-error' : undefined}
            onChange={(event) => {
              setInvite(event.target.value);
              setInvalid(false);
              clearActionError();
            }}
          />
        </Field>
        {actionError && (
          <p role="alert" id="invite-error" className="installer-error">
            {invalid ? 'Код истёк или уже использован.' : actionError}
          </p>
        )}
      </form>
    </InstallerScreen>
  ) : (
    <InstallerScreen
      centered
      welcome
      actions={
        <>
          <TaskButton
            disabled={busy}
            loading={busy}
            onClick={() =>
              void action(async () => {
                await passkeyLogin(api);
              })
            }
          >
            Войти с passkey
          </TaskButton>
          <TaskButton
            variant="text"
            disabled={busy}
            onClick={() => {
              clearActionError();
              navigate(true);
            }}
          >
            Есть приглашение
          </TaskButton>
        </>
      }
    >
      <div className="installer-welcome">
        <Image src="/brand/isign-mark.svg" width={144} height={144} alt="Знак iSign" priority />
        <h1>iSign</h1>
      </div>
      {actionError && (
        <p className="installer-error" role="alert">
          {actionError}
        </p>
      )}
    </InstallerScreen>
  );
}
