import type { NativeSessions } from '../auth/native-sessions';
import type { AdminUsers } from '../auth/admin';
import type { AppleSharing } from '../apple/access';
import type { ConnectionLifecycle } from '../apple/connection-lifecycle';
import type { DeviceCollection } from '../devices/collection';
import type { DeviceOnboarding } from '../devices/onboarding';
import type { DeviceActions } from '../devices/actions';
import type { CatalogRegistry } from '../catalog/registry';
import type { FeatherCatalog } from '../catalog/feather-feed';
import type { FeatherSigningAssets } from '../feather/signing-assets';
import type { FeatherProfileRequest } from '../feather/profile-service';
import type { RuntimeQueries } from './queries';
import type { ConnectApple } from './connect-apple';
import type { RequestLifecycle } from './request-lifecycle';
import { Failure } from '../shared';

export type NativeQuery =
  | { kind: 'apple' | 'devices' | 'sources' | 'signing.identity' | 'admin.users' }
  | { kind: 'device.udid' | 'source.feed' | 'signing.profiles'; id: string };
export type NativeCommand =
  | {
      kind: 'apple.connect';
      input: { filename: string; issuerId: string; keyId: string; keyType?: 'team'; p8: string };
    }
  | {
      kind:
        | 'apple.disconnect'
        | 'apple.bootstrap'
        | 'device.challenge'
        | 'account.delete'
        | 'signing.bundle'
        | 'signing.revoke';
    }
  | { kind: 'apple.share'; profileId: string }
  | {
      kind:
        | 'apple.revokeShare'
        | 'device.poll'
        | 'device.select'
        | 'device.remove'
        | 'device.removeCollected'
        | 'source.refresh'
        | 'source.disable'
        | 'source.remove'
        | 'admin.reinvite'
        | 'admin.block'
        | 'admin.unblock'
        | 'admin.remove';
      id: string;
    }
  | { kind: 'device.register'; id: string; slotConsent: boolean }
  | { kind: 'device.os'; id: string; version: string }
  | { kind: 'device.rename' | 'source.rename'; id: string; name: string }
  | { kind: 'source.add'; name: string; url: string; trustPublisher: true }
  | { kind: 'source.download'; sourceId: string; releaseId: string; snapshot: string }
  | { kind: 'signing.ensure'; retry?: boolean }
  | { kind: 'signing.profiles'; request: FeatherProfileRequest; retry?: boolean }
  | { kind: 'admin.invite'; name: string };

export type NativeApplicationPorts = {
  auth: Pick<NativeSessions, 'authorize' | 'requireFresh'>;
  queries: Pick<RuntimeQueries, 'apple' | 'devices'>;
  sharing: Pick<AppleSharing, 'list' | 'share' | 'revoke'>;
  collections: Pick<DeviceCollection, 'list' | 'reveal' | 'challengeNative'>;
  devices: Pick<DeviceOnboarding, 'register' | 'poll' | 'reportOs' | 'rename'>;
  actions: Pick<DeviceActions, 'selectDevice' | 'removeDevice' | 'removeIdentity'>;
  catalogs: Pick<CatalogRegistry, 'add' | 'refresh' | 'disable' | 'remove' | 'rename'>;
  catalog: Pick<FeatherCatalog, 'list' | 'feed' | 'download'>;
  assets: Pick<
    FeatherSigningAssets,
    'ensure' | 'status' | 'bundle' | 'profiles' | 'profileStatus' | 'revoke'
  >;
  admin: Pick<AdminUsers, 'list' | 'invite' | 'reinvite' | 'setBlocked' | 'remove'>;
  connectApple: ConnectApple['run'];
  disconnectApple: ConnectionLifecycle['disconnectFor'];
  deleteAccount: RequestLifecycle['deleteAccountFor'];
  bootstrap?: (owner: string) => Promise<unknown>;
};
const freshCommands = new Set<NativeCommand['kind']>([
  'apple.connect',
  'apple.disconnect',
  'apple.bootstrap',
  'apple.share',
  'apple.revokeShare',
  'device.register',
  'account.delete',
  'signing.bundle',
  'signing.revoke',
]);
/** Native authentication is independent of the cookie/CSRF transport adapter. */
export class NativeApplication {
  constructor(private ports: NativeApplicationPorts) {}
  private async principal(raw: string, kind: string, fresh = false) {
    const p = await (fresh ? this.ports.auth.requireFresh(raw) : this.ports.auth.authorize(raw));
    if (kind.startsWith('admin.') && p.role !== 'admin') throw new Failure('ADMIN_REQUIRED', 403);
    return p;
  }
  async view(raw: string, query: NativeQuery): Promise<unknown> {
    const p = await this.principal(raw, query.kind);
    const result = await this.read(p.ownerId, query);
    await this.principal(raw, query.kind);
    return result;
  }
  private async read(owner: string, query: NativeQuery): Promise<unknown> {
    switch (query.kind) {
      case 'apple':
        return {
          ...(await this.ports.queries.apple(owner)),
          shares: await this.ports.sharing.list(owner),
        };
      case 'devices':
        return {
          devices: await this.ports.queries.devices(owner),
          collectedDevices: await this.ports.collections.list(owner),
        };
      case 'device.udid':
        return this.ports.collections.reveal(owner, query.id);
      case 'sources':
        return this.ports.catalog.list(owner);
      case 'source.feed':
        return this.ports.catalog.feed(owner, query.id);
      case 'signing.identity':
        return this.ports.assets.status(owner);
      case 'signing.profiles': {
        const result = await this.ports.assets.profileStatus(owner, query.id);
        return result;
      }
      case 'admin.users':
        return { users: await this.ports.admin.list(owner) };
    }
  }
  async command(raw: string, command: NativeCommand): Promise<unknown> {
    const fresh =
      freshCommands.has(command.kind) ||
      command.kind.startsWith('admin.') ||
      ('retry' in command && command.retry === true);
    const p = await this.principal(raw, command.kind, fresh);
    const owner = p.ownerId;
    switch (command.kind) {
      case 'apple.connect': {
        const bytes = Buffer.from(command.input.p8);
        try {
          return await this.ports.connectApple(owner, { ...command.input, p8: bytes });
        } finally {
          bytes.fill(0);
        }
      }
      case 'apple.disconnect':
        await this.ports.disconnectApple(owner);
        break;
      case 'apple.bootstrap': {
        if (!this.ports.bootstrap) throw new Failure('BOOTSTRAP_BROKER_UNAVAILABLE', 503);
        return this.ports.bootstrap(owner);
      }
      case 'apple.share':
        return this.ports.sharing.share(owner, command.profileId);
      case 'apple.revokeShare':
        return this.ports.sharing.revoke(owner, command.id);
      case 'device.challenge':
        return this.ports.collections.challengeNative(owner, p.sessionId);
      case 'device.register':
        return this.ports.devices.register(owner, command.id, command.slotConsent);
      case 'device.poll':
        return this.ports.devices.poll(owner, command.id);
      case 'device.os':
        return this.ports.devices.reportOs(owner, command.id, command.version);
      case 'device.rename':
        return this.ports.devices.rename(owner, command.id, command.name);
      case 'device.select':
        await this.ports.actions.selectDevice(owner, command.id);
        break;
      case 'device.remove':
        await this.ports.actions.removeDevice(owner, command.id);
        break;
      case 'device.removeCollected':
        await this.ports.actions.removeIdentity(owner, command.id);
        break;
      case 'source.add': {
        const result = await this.ports.catalogs.add(
          owner,
          command.name,
          command.url,
          [],
          command.trustPublisher,
        );
        try {
          await this.ports.catalogs.refresh(owner, result.id, true);
        } catch (error) {
          if (error instanceof Failure) return { ...result, refreshError: error.code };
          throw error;
        }
        return result;
      }
      case 'source.refresh':
        return this.ports.catalogs.refresh(owner, command.id, true);
      case 'source.disable':
        await this.ports.catalogs.disable(owner, command.id);
        break;
      case 'source.remove':
        await this.ports.catalogs.remove(owner, command.id);
        break;
      case 'source.rename':
        await this.ports.catalogs.rename(owner, command.id, command.name);
        break;
      case 'source.download': {
        const result = await this.ports.catalog.download(owner, command);
        await this.principal(raw, command.kind);
        return result;
      }
      case 'signing.ensure':
        return this.ports.assets.ensure(owner, { retry: command.retry });
      case 'signing.revoke':
        return this.ports.assets.revoke(owner);
      case 'signing.bundle': {
        const result = await this.ports.assets.bundle(owner);
        await this.principal(raw, command.kind, true);
        return result;
      }
      case 'signing.profiles': {
        const result = await this.ports.assets.profiles(owner, command.request, {
          retry: command.retry,
        });
        await this.principal(raw, command.kind, fresh);
        return result;
      }
      case 'admin.invite': {
        const result = await this.ports.admin.invite(owner, command.name);
        await this.principal(raw, command.kind, true);
        return result;
      }
      case 'admin.reinvite': {
        const result = await this.ports.admin.reinvite(owner, command.id);
        await this.principal(raw, command.kind, true);
        return result;
      }
      case 'admin.block':
        await this.ports.admin.setBlocked(owner, command.id, true);
        break;
      case 'admin.unblock':
        await this.ports.admin.setBlocked(owner, command.id, false);
        break;
      case 'admin.remove':
        await this.ports.admin.remove(owner, command.id);
        break;
      case 'account.delete':
        await this.ports.deleteAccount(owner);
        break;
    }
    return { ok: true };
  }
}
