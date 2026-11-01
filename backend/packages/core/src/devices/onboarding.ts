import { assertAppleAccess, type AppleAccess } from '../apple/access';
import type { Database } from '../shared/database';
import { Failure, hash, id } from '../shared/index';
export const normalizeUdid = (value: string) => {
  const udid = value.trim().toUpperCase();
  if (!/^(?:[0-9A-F]{40}|[0-9A-F]{8}-[0-9A-F]{16})$/.test(udid)) throw new Failure('INVALID_UDID');
  return udid;
};
export type VerifiedDevicePayload = {
  challenge: string;
  udid: string;
  product?: string;
  version?: string;
  signatureVerified: boolean;
  issuerTrusted: boolean;
  deviceCertificate: boolean;
};
export type CmsVerifier = (body: Buffer) => Promise<VerifiedDevicePayload>;
export const denyCms: CmsVerifier = async () => {
  throw new Failure('CMS_VERIFIER_UNAVAILABLE', 503);
};
export type DeviceResource = {
  id: string;
  status: string;
  eligible?: boolean;
  processing?: boolean;
  ineligible?: boolean;
  certificateRequired?: boolean;
};
export interface DeviceApi {
  find(udid: string): Promise<DeviceResource[]>;
  register(udid: string, name: string): Promise<DeviceResource>;
  rawDevice?(
    udid: string,
    resourceId: string,
  ): Promise<{
    id: string;
    status: string;
  } | null>;
}
const status = (resource: DeviceResource) => {
  if (resource.status === 'DISABLED') return 'disabled';
  if (resource.ineligible === true) return 'ineligible';
  if (resource.certificateRequired === true) return 'certificate_required';
  if (resource.processing === true) return 'apple_processing';
  switch (resource.status) {
    case 'ENABLED':
      return resource.eligible === true ? 'ready' : 'apple_processing';
    case 'PROCESSING':
      return 'apple_processing';
    case 'INELIGIBLE':
      return 'ineligible';
    case 'DISABLED':
      return 'disabled';
    default:
      throw new Failure('APPLE_DEVICE_STATUS_UNKNOWN', 409);
  }
};
export type DeviceApiFactory = (binding: AppleAccess) => Promise<DeviceApi>;
export class DeviceOnboarding {
  constructor(
    private db: Database,
    private api: DeviceApi | DeviceApiFactory,
    private now: () => number,
  ) {}
  private freshDevices = new Map<
    string,
    {
      until: number;
    }
  >();
  async checkRegistered(owner: string, device: string, force = true) {
    const key = owner + ':' + device;
    const row = await this.db.query<{
      udid: string;
      apple_resource_id: string;
      connection_id: string;
      connection_owner_id: string;
      connection_generation: number;
      access_grant_id: string | null;
      access_grant_generation: number | null;
    }>(
      "SELECT * FROM signing_devices WHERE id=$1 AND owner_id=$2 AND status='ready' AND enrollment_verified_at IS NOT NULL",
      [device, owner],
    );
    const d = row.rows[0];
    if (!d?.udid || !d.apple_resource_id) throw new Failure('DEVICE_NOT_READY', 409);
    const binding = {
      ownerId: owner,
      connectionId: d.connection_id,
      generation: d.connection_generation,
      connectionOwnerId: d.connection_owner_id,
      accessGrantId: d.access_grant_id,
      accessGrantGeneration: d.access_grant_generation,
    };
    await assertAppleAccess(this.db, binding);
    if (!force && (this.freshDevices.get(key)?.until ?? 0) > this.now()) return;
    const api = typeof this.api === 'function' ? await this.api(binding) : this.api;
    if (!api.rawDevice) throw new Failure('APPLE_DEVICE_READ_UNAVAILABLE', 503);
    const remote = await api.rawDevice(d.udid, d.apple_resource_id);
    await assertAppleAccess(this.db, binding);
    if (!remote || remote.id !== d.apple_resource_id || remote.status !== 'ENABLED') {
      this.freshDevices.delete(key);
      await this.db.query(
        'UPDATE devices SET status=$3,selected=false WHERE id=$1 AND owner_id=$2',
        [device, owner, remote?.status === 'DISABLED' ? 'disabled' : 'ineligible'],
      );
      throw new Failure('DEVICE_NOT_READY', 409);
    }
    this.freshDevices.set(key, { until: this.now() + 15000 });
    if (this.freshDevices.size > 1000)
      this.freshDevices.delete(this.freshDevices.keys().next().value!);
  }
  private validName(input: string) {
    const name = input.trim();
    if (!name || name.length > 100 || /[\x00-\x1f\x7f]/.test(name))
      throw new Failure('INVALID_DEVICE_NAME');
    return name;
  }
  async reportOs(owner: string, device: string, version: string) {
    if (!/^\d{1,2}\.\d{1,2}(?:\.\d{1,2})?$/.test(version) || Number(version.split('.')[0]) < 12)
      throw new Failure('INVALID_DEVICE_OS');
    const updated = await this.db.query(
      "UPDATE devices SET os_version=$3,os_version_source='user_report' WHERE id=$1 AND owner_id=$2 AND enrollment_verified_at IS NOT NULL AND status!='locally_removed' AND NOT EXISTS(SELECT 1 FROM jobs WHERE device_id=$1 AND owner_id=$2 AND state IN('queued','analyzing','provisioning','signing','verifying')) RETURNING id",
      [device, owner, version],
    );
    if (!updated.rows.length) throw new Failure('DEVICE_OS_UPDATE_UNAVAILABLE', 409);
    return { id: device, osVersion: version, source: 'user_report' };
  }
  async rename(owner: string, device: string, name: string) {
    const result = await this.db.query(
      "UPDATE devices SET name=$3 WHERE id=$1 AND owner_id=$2 AND status!='locally_removed' AND EXISTS(SELECT 1 FROM users WHERE id=$2 AND deleted_at IS NULL) RETURNING id",
      [device, owner, this.validName(name)],
    );
    if (!result.rows.length) throw new Failure('DEVICE_NOT_FOUND', 404);
    return { id: device, name: name.trim() };
  }
  async poll(
    owner: string,
    device: string,
    lease?: {
      checkId: string;
      token: string;
    },
  ) {
    const row = await this.db.query<{
      udid: string;
      connection_id: string;
      connection_generation: number;
      connection_owner_id: string;
      access_grant_id: string | null;
      access_grant_generation: number | null;
    }>(
      "SELECT d.* FROM devices d JOIN apple_connections c ON c.id=d.connection_id AND c.owner_id=d.owner_id JOIN users u ON u.id=d.owner_id WHERE d.id=$1 AND d.owner_id=$2 AND c.state='ready' AND c.generation=d.connection_generation AND d.connection_owner_id=c.connection_owner_id AND d.access_grant_id IS NOT DISTINCT FROM c.access_grant_id AND d.access_grant_generation IS NOT DISTINCT FROM c.access_grant_generation AND u.deleted_at IS NULL AND d.status!='locally_removed' AND d.enrollment_verified_at IS NOT NULL",
      [device, owner],
    );
    const d = row.rows[0];
    if (!d?.udid) throw new Failure('DEVICE_NOT_FOUND', 404);
    const api =
      typeof this.api === 'function'
        ? await this.api({
            ownerId: owner,
            connectionId: d.connection_id,
            generation: d.connection_generation,
            connectionOwnerId: d.connection_owner_id,
            accessGrantId: d.access_grant_id,
            accessGrantGeneration: d.access_grant_generation,
          })
        : this.api;
    const matches = await api.find(d.udid);
    if (matches.length > 1) throw new Failure('RESOURCE_RECONCILIATION_AMBIGUOUS', 409);
    if (!matches.length)
      throw new Failure(lease ? 'APPLE_DEVICE_NOT_FOUND' : 'RESOURCE_RECONCILIATION_REQUIRED', 409);
    await this.db.query(
      "UPDATE device_registration_operations SET state=CASE WHEN state='revoked' THEN state ELSE 'complete' END,resource_id=$4 WHERE connection_id=$1 AND generation=$2 AND udid_hash=$3 AND state IN('submitted','unknown','revoked')",
      [d.connection_id, d.connection_generation, hash(d.udid), matches[0].id],
    );
    const next = status(matches[0]);
    const updated = await this.db.query(
      "UPDATE devices SET status=$3,apple_resource_id=$4 WHERE id=$1 AND owner_id=$2 AND connection_generation=$5 AND status!='locally_removed' AND EXISTS(SELECT 1 FROM users WHERE id=$2 AND deleted_at IS NULL) AND EXISTS(SELECT 1 FROM apple_connections c WHERE id=$6 AND owner_id=$2 AND generation=$5 AND state='ready' AND devices.connection_owner_id=c.connection_owner_id AND devices.access_grant_id IS NOT DISTINCT FROM c.access_grant_id AND devices.access_grant_generation IS NOT DISTINCT FROM c.access_grant_generation)" +
        (lease
          ? ' AND EXISTS(SELECT 1 FROM device_collection_checks k WHERE k.id=$7 AND k.lease_token=$8 AND k.lease_until>$9 AND k.device_id=devices.id AND k.owner_id=devices.owner_id AND k.generation=devices.connection_generation AND k.connection_owner_id=devices.connection_owner_id AND k.access_grant_id IS NOT DISTINCT FROM devices.access_grant_id AND k.access_grant_generation IS NOT DISTINCT FROM devices.access_grant_generation)'
          : '') +
        ' RETURNING id',
      [
        device,
        owner,
        next,
        matches[0].id,
        d.connection_generation,
        d.connection_id,
        ...(lease ? [lease.checkId, lease.token, this.now()] : []),
      ],
    );
    if (!updated.rows.length) throw new Failure('CONNECTION_CHANGED', 409);
    return { id: device, status: next, udid: '••••' + d.udid.slice(-4) };
  }
  async register(owner: string, device: string, slotConsent: boolean) {
    const row = await this.db.query<{
      udid: string;
      name: string;
      connection_id: string;
      connection_generation: number;
      connection_owner_id: string;
      access_grant_id: string | null;
      access_grant_generation: number | null;
      status: string;
    }>(
      "SELECT d.* FROM devices d JOIN apple_connections c ON c.id=d.connection_id AND c.owner_id=d.owner_id WHERE d.id=$1 AND d.owner_id=$2 AND c.state='ready' AND c.generation=d.connection_generation AND d.connection_owner_id=c.connection_owner_id AND d.access_grant_id IS NOT DISTINCT FROM c.access_grant_id AND d.access_grant_generation IS NOT DISTINCT FROM c.access_grant_generation AND d.status!='locally_removed' AND d.enrollment_verified_at IS NOT NULL AND EXISTS(SELECT 1 FROM users WHERE id=$2 AND deleted_at IS NULL)",
      [device, owner],
    );
    const d = row.rows[0];
    if (!d?.udid) throw new Failure('DEVICE_NOT_FOUND', 404);
    const api =
      typeof this.api === 'function'
        ? await this.api({
            ownerId: owner,
            connectionId: d.connection_id,
            generation: d.connection_generation,
            connectionOwnerId: d.connection_owner_id,
            accessGrantId: d.access_grant_id,
            accessGrantGeneration: d.access_grant_generation,
          })
        : this.api;
    let matches = await api.find(d.udid);
    if (matches.length > 1) throw new Failure('RESOURCE_RECONCILIATION_AMBIGUOUS', 409);
    if (!matches.length) {
      if (!slotConsent) throw new Failure('DEVICE_SLOT_CONSENT_REQUIRED', 409);
      if (['registering', 'apple_processing', 'certificate_required'].includes(d.status))
        throw new Failure('RESOURCE_RECONCILIATION_REQUIRED', 409);
      const operationId = id();
      const operation = await this.db.query<{
        id: string;
      }>(
        "INSERT INTO device_registration_operations(id,connection_id,connection_owner_id,generation,udid_hash,principal_id,device_id,access_grant_id,access_grant_generation,state,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'submitted',$10) ON CONFLICT(connection_id,generation,udid_hash) DO NOTHING RETURNING id",
        [
          operationId,
          d.connection_id,
          d.connection_owner_id,
          d.connection_generation,
          hash(d.udid),
          owner,
          device,
          d.access_grant_id,
          d.access_grant_generation,
          this.now(),
        ],
      );
      if (!operation.rows.length) throw new Failure('RESOURCE_RECONCILIATION_REQUIRED', 409);
      const claimed = await this.db.query(
        "UPDATE devices SET status='registering' WHERE id=$1 AND owner_id=$2 AND status='collected' AND connection_generation=$3 AND EXISTS(SELECT 1 FROM apple_connections c WHERE id=$4 AND owner_id=$2 AND generation=$3 AND state='ready' AND devices.connection_owner_id=c.connection_owner_id AND devices.access_grant_id IS NOT DISTINCT FROM c.access_grant_id AND devices.access_grant_generation IS NOT DISTINCT FROM c.access_grant_generation) RETURNING id",
        [device, owner, d.connection_generation, d.connection_id],
      );
      if (!claimed.rows.length) throw new Failure('DEVICE_NOT_ELIGIBLE', 409);
      try {
        await assertAppleAccess(this.db, {
          ownerId: owner,
          connectionId: d.connection_id,
          generation: d.connection_generation,
          connectionOwnerId: d.connection_owner_id,
          accessGrantId: d.access_grant_id,
          accessGrantGeneration: d.access_grant_generation,
        });
        matches = [await api.register(d.udid, d.name)];
        await this.db.query(
          "UPDATE device_registration_operations SET resource_id=$2,state=CASE WHEN state='revoked' THEN state ELSE 'complete' END WHERE id=$1",
          [operationId, matches[0].id],
        );
      } catch (error) {
        await this.db.query(
          "UPDATE device_registration_operations SET state='unknown' WHERE id=$1 AND state='submitted'",
          [operationId],
        );
        throw error;
      }
    }
    await this.db.query(
      "UPDATE device_registration_operations SET state=CASE WHEN state='revoked' THEN state ELSE 'complete' END,resource_id=$4 WHERE connection_id=$1 AND generation=$2 AND udid_hash=$3 AND state IN('submitted','unknown','revoked')",
      [d.connection_id, d.connection_generation, hash(d.udid), matches[0].id],
    );
    const next = status(matches[0]);
    const updated = await this.db.query(
      "UPDATE devices SET status=$3,apple_resource_id=$4 WHERE id=$1 AND owner_id=$2 AND connection_generation=$5 AND status!='locally_removed' AND EXISTS(SELECT 1 FROM users WHERE id=$2 AND deleted_at IS NULL) AND EXISTS(SELECT 1 FROM apple_connections c WHERE id=$6 AND owner_id=$2 AND generation=$5 AND state='ready' AND devices.connection_owner_id=c.connection_owner_id AND devices.access_grant_id IS NOT DISTINCT FROM c.access_grant_id AND devices.access_grant_generation IS NOT DISTINCT FROM c.access_grant_generation) RETURNING id",
      [device, owner, next, matches[0].id, d.connection_generation, d.connection_id],
    );
    if (!updated.rows.length) throw new Failure('CONNECTION_CHANGED', 409);
    return { id: device, status: next, udid: '••••' + d.udid.slice(-4) };
  }
}
const xml = (value: string) =>
  value.replace(
    /[<>&"']/g,
    (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' })[c]!,
  );
/** Server configuration controls origin; callback path and capabilities cannot be supplied by the browser. */
export function profileServiceXml(
  origin: string,
  challenge: string,
  payloadIdentifier = 'com.isign.device-enrollment',
) {
  const url = new URL(origin);
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash ||
    !/^[A-Za-z0-9_-]{43}$/.test(challenge) ||
    !/^[A-Za-z0-9.-]{1,128}$/.test(payloadIdentifier)
  )
    throw new Failure('INVALID_PROFILE_SERVICE_CONFIGURATION');
  url.pathname = '/api/devices/callback';
  url.searchParams.set('challenge', challenge);
  return `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>PayloadVersion</key><integer>1</integer><key>PayloadUUID</key><string>${id()}</string><key>PayloadIdentifier</key><string>${xml(payloadIdentifier)}</string><key>PayloadDisplayName</key><string>iSign: идентификатор iPhone</string><key>PayloadDescription</key><string>Передаёт UDID, модель и версию системы этого iPhone и возвращает в Safari. Не управляет устройством и не регистрирует его в Apple.</string><key>PayloadType</key><string>Profile Service</string><key>PayloadContent</key><dict><key>URL</key><string>${xml(url.href)}</string><key>DeviceAttributes</key><array><string>UDID</string><string>PRODUCT</string><string>VERSION</string></array><key>Challenge</key><string>${xml(challenge)}</string></dict></dict></plist>`;
}
