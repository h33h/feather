import { createHash, X509Certificate } from 'node:crypto';
import { Failure } from '../shared/index';
import type { AppleRequestPort } from './request-port';
import { certificateTeamId } from './onboarding';
import { normalizeUdid, type DeviceApi, type DeviceResource } from '../devices/onboarding';
import type { ControlResource } from '../devices/eligibility';
type Resource = ControlResource & {
  type: string;
};
function resources(value: unknown): Resource[] {
  const root = value as {
    data?: unknown;
  };
  const list = Array.isArray(root?.data) ? root.data : [root?.data];
  if (
    list.some((x) => !x || typeof x.id !== 'string' || typeof x.type !== 'string' || !x.attributes)
  )
    throw new Failure('APPLE_RESPONSE_INVALID', 502);
  return list as Resource[];
}
export class AppleProvisioningApi implements DeviceApi {
  constructor(
    private client: AppleRequestPort,
    private now: () => number,
    private eligibility?: (
      resourceId: string,
      udid: string,
    ) => Promise<Pick<DeviceResource, 'eligible' | 'processing' | 'ineligible'>>,
  ) {}
  private async deviceEligibility(
    resourceId: string,
    udid: string,
  ): Promise<
    | Pick<DeviceResource, 'eligible' | 'processing' | 'ineligible' | 'certificateRequired'>
    | undefined
  > {
    try {
      return await this.eligibility?.(resourceId, udid);
    } catch (error) {
      if (error instanceof Failure && error.code === 'CERTIFICATE_REQUIRED')
        return { certificateRequired: true };
      throw error;
    }
  }
  private async list(path: string) {
    const rows: Resource[] = [];
    let next: string | undefined = path;
    const seen = new Set<string>();
    while (next) {
      if (seen.has(next) || seen.size >= 100) throw new Failure('APPLE_PAGINATION_INVALID', 502);
      seen.add(next);
      const page = (await this.client.request('GET', next)) as {
        links?: {
          next?: string;
        };
      };
      rows.push(...resources(page));
      next = page.links?.next ?? undefined;
      if (next) {
        const url = new URL(next, 'https://api.appstoreconnect.apple.com');
        if (
          url.origin !== 'https://api.appstoreconnect.apple.com' ||
          url.pathname !== new URL(path, 'https://api.appstoreconnect.apple.com').pathname
        )
          throw new Failure('APPLE_PAGINATION_INVALID', 502);
        next = url.pathname + url.search;
      }
    }
    return rows;
  }
  async find(udid: string) {
    const rows = (
      await this.list('/v1/devices?filter[udid]=' + encodeURIComponent(normalizeUdid(udid)))
    ).filter(
      (r) =>
        typeof r.attributes.udid === 'string' &&
        normalizeUdid(r.attributes.udid) === normalizeUdid(udid),
    );
    return Promise.all(
      rows.map(async (r) => ({
        id: r.id,
        status: String(r.attributes.status),
        ...(r.attributes.status === 'ENABLED'
          ? await this.deviceEligibility(r.id, normalizeUdid(udid))
          : undefined),
      })),
    );
  }
  async register(udid: string, name: string) {
    if (!name.trim() || name.length > 100) throw new Failure('INVALID_DEVICE_NAME');
    const row = resources(
      await this.client.request('POST', '/v1/devices', {
        data: { type: 'devices', attributes: { name, platform: 'IOS', udid: normalizeUdid(udid) } },
      }),
    )[0];
    if (
      row.type !== 'devices' ||
      typeof row.attributes.udid !== 'string' ||
      normalizeUdid(row.attributes.udid) !== normalizeUdid(udid) ||
      row.attributes.platform !== 'IOS'
    )
      throw new Failure('APPLE_DEVICE_RESPONSE_MISMATCH', 409);
    return {
      id: row.id,
      status: String(row.attributes.status),
      ...(row.attributes.status === 'ENABLED'
        ? await this.deviceEligibility(row.id, normalizeUdid(udid))
        : undefined),
    };
  }
  async rawDevice(udid: string, resourceId: string) {
    const rows = (
      await this.list('/v1/devices?filter[udid]=' + encodeURIComponent(normalizeUdid(udid)))
    ).filter(
      (r) =>
        r.id === resourceId &&
        typeof r.attributes.udid === 'string' &&
        normalizeUdid(r.attributes.udid) === normalizeUdid(udid),
    );
    if (rows.length > 1) throw new Failure('RESOURCE_RECONCILIATION_AMBIGUOUS', 409);
    return rows[0] ? { id: rows[0].id, status: String(rows[0].attributes.status) } : null;
  }
  async findBundles(identifier: string) {
    return (
      await this.list('/v1/bundleIds?filter[identifier]=' + encodeURIComponent(identifier))
    ).filter((r) => r.attributes.identifier === identifier);
  }
  async findProfiles(bundleResourceId: string, name: string) {
    return (
      await this.list('/v1/profiles?filter[name]=' + encodeURIComponent(name) + '&include=bundleId')
    ).filter((r) => {
      const relation = r.relationships?.bundleId?.data;
      return (
        r.attributes.name === name &&
        !Array.isArray(relation) &&
        relation?.type === 'bundleIds' &&
        relation.id === bundleResourceId
      );
    });
  }
  async findCertificates(spkiSha256: string) {
    if (!/^[a-f0-9]{64}$/.test(spkiSha256)) throw new Failure('INVALID_PUBLIC_KEY_DIGEST');
    const rows = await this.list('/v1/certificates?filter[certificateType]=IOS_DISTRIBUTION');
    const matches: {
      id: string;
      certificate: string;
    }[] = [];
    for (const row of rows) {
      if (typeof row.attributes.certificateContent !== 'string') continue;
      try {
        const cert = new X509Certificate(Buffer.from(row.attributes.certificateContent, 'base64'));
        const digest = createHash('sha256')
          .update(cert.publicKey.export({ type: 'spki', format: 'der' }))
          .digest('hex');
        if (digest !== spkiSha256) continue;
        certificateTeamId(cert.toString(), this.now());
        matches.push({ id: row.id, certificate: cert.toString() });
      } catch {
        /* Only current public certificates with the persisted key and a genuine Team OU reconcile. */
      }
    }
    return matches;
  }
  async validateTeam() {
    await this.client.request('GET', '/v1/devices?limit=1');
    await this.client.request('GET', '/v1/bundleIds?limit=1');
    await this.client.request('GET', '/v1/profiles?limit=1');
    return this.teamProof();
  }
  async teamProof() {
    const rows = await this.list('/v1/certificates?filter[certificateType]=IOS_DISTRIBUTION');
    const teams = new Set<string>();
    for (const row of rows) {
      const encoded = row.attributes.certificateContent;
      if (typeof encoded !== 'string') continue;
      try {
        teams.add(
          certificateTeamId(
            Buffer.from(encoded, 'base64').toString('utf8').includes('BEGIN CERTIFICATE')
              ? Buffer.from(encoded, 'base64').toString('utf8')
              : new X509Certificate(Buffer.from(encoded, 'base64')).toString(),
            this.now(),
          ),
        );
      } catch {
        /* Expired or unsuitable public certificates are not proof. */
      }
    }
    if (teams.size !== 1) throw new Failure('TEAM_PROOF_REQUIRED', 409);
    return { teamId: [...teams][0], source: 'apple-api-certificate' as const, verified: true };
  }
  async bundle(identifier: string, name: string) {
    if (
      identifier !== '*' &&
      !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(identifier) &&
      !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.\*$/.test(identifier)
    )
      throw new Failure('INVALID_BUNDLE_ID');
    const matches = (
      await this.list('/v1/bundleIds?filter[identifier]=' + encodeURIComponent(identifier))
    ).filter((x) => x.attributes.identifier === identifier);
    if (matches.length > 1) throw new Failure('RESOURCE_RECONCILIATION_AMBIGUOUS', 409);
    if (matches[0]) return matches[0];
    return resources(
      await this.client.request('POST', '/v1/bundleIds', {
        data: { type: 'bundleIds', attributes: { identifier, name, platform: 'IOS' } },
      }),
    )[0];
  }
  async certificate(csr: string, expectedSpkiSha256: string) {
    if (
      csr.length > 16384 ||
      !/^-----BEGIN CERTIFICATE REQUEST-----\n/.test(csr) ||
      !/^[a-f0-9]{64}$/.test(expectedSpkiSha256)
    )
      throw new Failure('INVALID_CSR');
    const row = resources(
      await this.client.request('POST', '/v1/certificates', {
        data: {
          type: 'certificates',
          attributes: { certificateType: 'IOS_DISTRIBUTION', csrContent: csr },
        },
      }),
    )[0];
    const cert = new X509Certificate(
      Buffer.from(String(row.attributes.certificateContent), 'base64'),
    );
    const digest = createHash('sha256')
      .update(cert.publicKey.export({ type: 'spki', format: 'der' }))
      .digest('hex');
    if (digest !== expectedSpkiSha256 || Date.parse(cert.validTo) <= this.now())
      throw new Failure('CERTIFICATE_IDENTITY_MISMATCH');
    return {
      resource: row,
      certificate: cert.toString(),
      expiresAt: Date.parse(cert.validTo),
      teamId: certificateTeamId(cert.toString(), this.now()),
    };
  }
  async revokeCertificate(resourceId: string) {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(resourceId))
      throw new Failure('INVALID_CERTIFICATE_RESOURCE');
    await this.client.request('DELETE', '/v1/certificates/' + encodeURIComponent(resourceId));
  }
  async profile(input: {
    name: string;
    bundleId: string;
    certificateIds: string[];
    deviceIds: string[];
  }) {
    if (!input.name || !input.bundleId || !input.certificateIds.length || !input.deviceIds.length)
      throw new Failure('INVALID_PROFILE_REQUEST');
    const relation = (type: string, ids: string[]) => ({ data: ids.map((id) => ({ type, id })) });
    return resources(
      await this.client.request('POST', '/v1/profiles', {
        data: {
          type: 'profiles',
          attributes: { name: input.name, profileType: 'IOS_APP_ADHOC' },
          relationships: {
            bundleId: { data: { type: 'bundleIds', id: input.bundleId } },
            certificates: relation('certificates', input.certificateIds),
            devices: relation('devices', input.deviceIds),
          },
        },
      }),
    )[0];
  }
}
