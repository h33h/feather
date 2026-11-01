'use client';
import { useState } from 'react';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
function csrf() {
  return (
    document.cookie
      .split('; ')
      .find((value) => value.startsWith('isign-csrf='))
      ?.slice('isign-csrf='.length) ?? ''
  );
}
async function post(path: string, data: unknown) {
  const response = await fetch('/api/' + path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'x-isign-csrf': csrf() },
    body: JSON.stringify(data),
  });
  const result = await response.json();
  if (!response.ok) throw Error(result.code ?? 'Authentication failed');
  return result;
}
/** Browser owns the WebAuthn ceremony and cookie. Only a one-use code returns to iSign Client. */
export default function NativeAuthorize() {
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [invite, setInvite] = useState('');
  async function authorize(register = false) {
    setBusy(true);
    setError('');
    try {
      const transactionId = new URL(window.location.href).searchParams.get('transactionId');
      if (!transactionId)
        throw Error(
          'This sign-in link is missing its transaction. Start sign-in again in iSign Client.',
        );
      if (register) {
        const issued = await post('auth/passkey/register-options', { invite: invite.trim() });
        const response = await startRegistration({ optionsJSON: issued.options });
        await post('auth/passkey/register', { requestId: issued.requestId, response });
      } else {
        const issued = await post('auth/passkey/login-options', {});
        const response = await startAuthentication({ optionsJSON: issued.options });
        await post('auth/passkey/login', { requestId: issued.requestId, response });
      }
      const result = await post('auth/native/complete', { transactionId });
      const callback = new URL(result.callbackUrl);
      if (
        callback.protocol !== 'isign-feather:' ||
        callback.host !== 'auth' ||
        callback.pathname !== '/callback'
      )
        throw Error('Invalid application callback');
      window.location.assign(callback.toString());
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : 'Sign-in failed. Try again from iSign Client.',
      );
      setBusy(false);
    }
  }
  return (
    <main style={{ maxWidth: 480, margin: '10vh auto', padding: 24 }}>
      <h1>Sign in to iSign Client</h1>
      <p>Confirm your iSign account with a passkey to return to iSign Client.</p>
      <button disabled={busy} onClick={() => void authorize()}>
        {busy ? 'Waiting for your passkey…' : 'Continue with passkey'}
      </button>
      <details>
        <summary>Register with an invitation</summary>
        <label>
          Invitation token
          <input
            value={invite}
            onChange={(event) => setInvite(event.target.value)}
            autoComplete="off"
            disabled={busy}
          />
        </label>
        <button disabled={busy || !invite.trim()} onClick={() => void authorize(true)}>
          Create passkey and continue
        </button>
      </details>
      {error && (
        <p role="alert">
          {error}. If this link has expired or sign-in was interrupted, start sign-in again in iSign
          Client.
        </p>
      )}
    </main>
  );
}
