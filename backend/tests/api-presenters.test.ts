import { describe, expect, it } from 'vitest';
import * as presenters from '../server/http/presenters';
const secret = { secret_ref: 'secret', owner_id: 'owner', lease_token: 'lease' };
const session = {
  authenticated: true,
  csrf: 'csrf',
  profile: { id: 'u', loginName: 'user', role: 'admin', ...secret },
  capabilities: { runner: true, ...secret },
  ...secret,
};
const fixtures = {
  presentSession: session,
  presentReleases: {
    releases: [
      {
        id: 'r',
        sourceId: 's',
        snapshot: 'snap',
        name: 'App',
        displayVersion: '1',
        version: '1',
        description: '',
        url: 'https://secret.test/app.ipa',
        digest: 'secret',
        ...secret,
      },
    ],
    ...secret,
  },
  presentLibrary: {
    jobs: [
      {
        id: 'j',
        upload_id: 'u',
        state: 'signing',
        reason: null,
        display_snapshot: { name: 'App', ...secret },
        warnings: [{ code: 'WARN', componentPath: 'App', ...secret }],
        ...secret,
      },
    ],
    artifacts: [
      {
        id: 'a',
        job_id: 'j',
        eligible: true,
        verified: true,
        expires_at: 10,
        valid_until: 10,
        ...secret,
      },
    ],
    ...secret,
  },
  presentApple: {
    connection: { id: 'c', state: 'ready', shared: false, ...secret },
    uploadAllowed: true,
    shares: [
      {
        id: 's',
        generation: 1,
        state: 'ready',
        connectionId: 'c',
        teamId: 't',
        direction: 'incoming',
        profileId: 'p',
        ...secret,
      },
    ],
    ...secret,
  },
  presentDevices: {
    devices: [
      { id: 'd', name: 'iPhone', status: 'ready', os_version: '18', selected: true, ...secret },
    ],
    collectedDevices: [
      {
        id: 'c',
        name: 'iPhone',
        udid: 'masked',
        product: null,
        osVersion: null,
        createdAt: 1,
        verifiedAt: 1,
        status: 'ready',
        bindings: [
          {
            deviceId: 'd',
            connectionId: 'c',
            teamId: 't',
            generation: 1,
            status: 'ready',
            shared: false,
            ...secret,
          },
        ],
        ...secret,
      },
    ],
    ...secret,
  },
  presentSources: {
    sources: [
      {
        id: 's',
        name: 'Catalog',
        state: 'ready',
        kind: 'iapps',
        last_error: null,
        refresh_lease_until: 20,
        refresh_token: 'internal',
        ...secret,
      },
    ],
    ...secret,
  },
  presentHistory: {
    items: [
      {
        id: 'j',
        name: 'App',
        version: null,
        finishedAt: 1,
        state: 'failed',
        error: null,
        warnings: [{ code: 'WARN', componentPath: 'App', ...secret }],
        ...secret,
      },
    ],
    nextCursor: null,
    ...secret,
  },
};
describe('HTTP DTO presenters', () => {
  for (const [name, fixture] of Object.entries(fixtures)) {
    it(`${name} projects only public fields at every depth`, () => {
      const presenter = presenters[name as keyof typeof fixtures];
      expect(typeof presenter).toBe('function');
      const output = JSON.stringify(presenter(fixture));
      for (const key of [...Object.keys(secret), 'refresh_token', 'https://secret.test', 'digest'])
        expect(output).not.toContain(key);
      expect(JSON.stringify(fixture)).toContain('secret_ref');
    });
    it(`${name} rejects malformed data`, () => {
      const presenter = presenters[name as keyof typeof fixtures];
      expect(typeof presenter).toBe('function');
      expect(() => presenter({})).toThrow();
    });
  }
  it('retains existing public wire names and refresh progress', () => {
    expect(presenters.presentSources(fixtures.presentSources).sources[0].refresh_lease_until).toBe(
      20,
    );
    expect(presenters.presentLibrary(fixtures.presentLibrary).jobs[0].upload_id).toBe('u');
    expect(presenters.presentSession(session).profile.loginName).toBe('user');
  });
  it('rejects malformed nested data rather than asserting DTO types', () => {
    expect(() =>
      presenters.presentSession({ ...session, profile: { ...session.profile, role: 'root' } }),
    ).toThrow();
    expect(() =>
      presenters.presentLibrary({
        ...fixtures.presentLibrary,
        jobs: [{ ...fixtures.presentLibrary.jobs[0], warnings: [{ code: 1 }] }],
      }),
    ).toThrow();
  });
});
it('preserves nullable database device fields instead of failing an existing device', () => {
  expect(
    presenters.presentDevices({
      devices: [
        {
          id: 'd',
          name: 'iPhone',
          status: 'pending',
          os_version: null,
          os_version_source: null,
          selected: false,
        },
      ],
      collectedDevices: [],
    }).devices[0].os_version,
  ).toBeNull();
});
