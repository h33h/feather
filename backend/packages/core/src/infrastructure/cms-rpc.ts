import { createHmac, timingSafeEqual } from 'node:crypto';
import { Failure, token } from '../shared/index';
import { canonicalReport } from '../shared/canonical-json';
import type { CmsVerifier, VerifiedDevicePayload } from '../devices/onboarding';
import { providerRequest, boundedResponseText, type HttpTransport } from './config';
/** The configured policy and CA pin are deployment trust decisions, never browser inputs. */
export function deviceCmsRpc(options: {
  origin: string;
  authToken: string;
  audience: string;
  proofKey: Buffer;
  policyId: string;
  caSha256: string;
  transport: HttpTransport;
}): CmsVerifier {
  const u = new URL(options.origin);
  if (
    u.protocol !== 'https:' ||
    u.pathname !== '/' ||
    u.username ||
    u.password ||
    u.search ||
    u.hash ||
    options.authToken.length < 32 ||
    options.proofKey.length < 32 ||
    !/^[a-f0-9]{64}$/.test(options.caSha256) ||
    !/^[A-Za-z0-9:_-]{1,100}$/.test(options.policyId)
  )
    throw new Failure('CMS_CONFIGURATION_INVALID', 503);
  return async (bytes) => {
    if (!bytes.length || bytes.length > 65536) throw new Failure('INVALID_DEVICE_CALLBACK');
    const binding = { nonce: token() };
    const input = {
      binding,
      audience: options.audience,
      payload: {
        cmsBase64: bytes.toString('base64'),
        policyId: options.policyId,
        caSha256: options.caSha256,
      },
    };
    return providerRequest(
      options.transport,
      new URL('/v1/control/device-cms', u),
      {
        method: 'POST',
        headers: {
          Authorization: 'Bearer ' + options.authToken,
          'x-runner-audience': options.audience,
          'Content-Type': 'application/json',
        },
        body: canonicalReport(input),
      },
      async (r) => {
        if (r.status !== 200) throw new Failure('CMS_VERIFIER_UNAVAILABLE', 503);
        const envelope = JSON.parse(await boundedResponseText(r, 8192)) as {
          report: {
            operation: string;
            binding: unknown;
            audience: string;
            value: {
              payload: VerifiedDevicePayload & {
                deviceCertificate: unknown;
              };
              policyId: string;
              caSha256: string;
            };
          };
          attestation: string;
        };
        if (
          !envelope.report ||
          !/^[a-f0-9]{64}$/.test(envelope.attestation) ||
          !timingSafeEqual(
            createHmac('sha256', options.proofKey)
              .update(canonicalReport(envelope.report))
              .digest(),
            Buffer.from(envelope.attestation, 'hex'),
          ) ||
          envelope.report.operation !== 'device-cms' ||
          envelope.report.audience !== options.audience ||
          canonicalReport(envelope.report.binding) !== canonicalReport(binding) ||
          envelope.report.value.policyId !== options.policyId ||
          envelope.report.value.caSha256 !== options.caSha256
        )
          throw new Failure('CMS_VERIFIER_PROOF_INVALID', 403);
        const p = envelope.report.value.payload;
        const certificate = p.deviceCertificate;
        if (
          p.signatureVerified !== true ||
          p.issuerTrusted !== true ||
          typeof certificate !== 'string' ||
          !/^[a-f0-9]{64}$/.test(certificate)
        )
          throw new Failure('INVALID_DEVICE_CALLBACK');
        return { ...p, deviceCertificate: true };
      },
      30000,
    );
  };
}
