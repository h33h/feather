import { describe, expect, it } from 'vitest';
import * as presenters from '../server/http/presenters';
const secret = { secret_ref: 'secret', owner_id: 'owner', lease_token: 'lease' };
const session = {
  authenticated: true,
  csrf: 'csrf',
  profile: { id: 'u', loginName: 'user', role: 'admin', publicProfileId: 'profile', ...secret },
  capabilities: {
    runner: true,
    appleOnboarding: true,
    bootstrap: true,
    deviceEnrollment: true,
    ...secret,
  },
  ...secret,
};
const fixtures = {
  presentSession: session,
  presentApple: {
    connection: {
      id: 'c',
      state: 'ready',
      team_id: 'TEAM',
      last_error: null,
      identityReady: true,
      shared: false,
      ...secret,
    },
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
      {
        id: 'd',
        name: 'iPhone',
        status: 'ready',
        os_version: '18',
        team_id: 'TEAM',
        os_version_source: null,
        selected: true,
        ...secret,
      },
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
  it('retains existing public session wire names', () => {
    expect(presenters.presentSession(session).profile.loginName).toBe('user');
  });
  it('rejects malformed nested data rather than asserting DTO types', () => {
    expect(() =>
      presenters.presentSession({ ...session, profile: { ...session.profile, role: 'root' } }),
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
          team_id: null,
          os_version_source: null,
          selected: false,
        },
      ],
      collectedDevices: [],
    }).devices[0].os_version,
  ).toBeNull();
});
