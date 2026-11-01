import {
  startAuthentication,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';
import type { Api } from './contracts';
export async function passkeyLogin(api: Api, fresh = false) {
  const issued = await api('auth/passkey/' + (fresh ? 'fresh-options' : 'login-options'), {});
  const response = await startAuthentication({
    optionsJSON: issued.options as PublicKeyCredentialRequestOptionsJSON,
  });
  return api('auth/passkey/' + (fresh ? 'fresh' : 'login'), {
    requestId: issued.requestId,
    response,
  });
}
