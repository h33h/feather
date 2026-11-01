import { it, expect } from 'vitest';
import { createHmac } from 'node:crypto';
import { deviceCmsRpc } from '../packages/core/src/infrastructure/cms-rpc';
import { canonicalReport } from '../packages/core/src/shared/canonical-json';
it('accepts only authenticated device CMS evidence bound to nonce and configured CA policy', async () => {
  const proofKey = Buffer.alloc(32, 7);
  let change = false;
  const verify = deviceCmsRpc({
    origin: 'https://broker.example.invalid',
    authToken: 'fixture'.repeat(8),
    audience: 'fixture',
    proofKey,
    policyId: 'apple-fixture',
    caSha256: 'a'.repeat(64),
    transport: async (_url, init) => {
      const input = JSON.parse(String(init.body));
      const report = {
        binding: change ? { nonce: 'wrong' } : input.binding,
        operation: 'device-cms',
        audience: 'fixture',
        value: {
          policyId: 'apple-fixture',
          caSha256: 'a'.repeat(64),
          payload: {
            challenge: 'fixture',
            udid: 'A'.repeat(40),
            product: 'iPhone16,1',
            version: '18.0',
            signatureVerified: true,
            issuerTrusted: true,
            deviceCertificate: 'b'.repeat(64),
          },
        },
      };
      return Response.json({
        report,
        attestation: createHmac('sha256', proofKey).update(canonicalReport(report)).digest('hex'),
      });
    },
  });
  expect(await verify(Buffer.from('synthetic CMS'))).toMatchObject({
    deviceCertificate: true,
    signatureVerified: true,
  });
  change = true;
  await expect(verify(Buffer.from('synthetic CMS'))).rejects.toThrow('PROVIDER_UNAVAILABLE');
});
