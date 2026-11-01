import { expect, it } from 'vitest';
import { JobLifecycle } from '../packages/core/src/signing/job-lifecycle';
import { RuntimeQueries } from '../packages/core/src/application/queries';
import { SessionService } from '../packages/core/src/auth/sessions';
import { presentLibrary, presentSession } from '../server/http/presenters';
import { librarySchema } from '../packages/contracts/src/index';
import { query } from '../../web/src/shared/api/query';
import { createJobsFixture } from './job-fixtures';
import { loginFixture } from './helpers/login';
it.each(['upload', 'catalog'] as const)(
  'presents real %s submission snapshots while receiving',
  async (source) => {
    const db = await createJobsFixture();
    try {
      const lifecycle = new JobLifecycle(db, () => 1000);
      const { jobId } = await lifecycle.beginSubmission('o', {
        key: 'receive',
        deviceId: 'd',
        name: 'App.ipa',
        source,
      });
      await db.query(
        'UPDATE jobs SET display_snapshot=display_snapshot || \'{"secret_ref":"private"}\'::jsonb WHERE id=$1',
        [jobId],
      );
      const raw = await new RuntimeQueries(db, () => 1000).library('o');
      const output = presentLibrary(raw);
      expect(output.jobs[0]).toMatchObject({
        id: jobId,
        state: 'receiving',
        display_snapshot: { name: 'App.ipa', version: null, source, device: 'phone' },
      });
      expect(output.jobs[0].display_snapshot).not.toHaveProperty('secret_ref');
      await expect(query(async () => raw, 'library', librarySchema)).resolves.toEqual(output);
    } finally {
      await db.close();
    }
  },
);
it.each([null, '1.2'])(
  'presents real queued snapshots with version %s and null source',
  async (version) => {
    const db = await createJobsFixture();
    try {
      if (version)
        await db.query('UPDATE uploads SET metadata=$1 WHERE id=$2', [
          JSON.stringify({ title: 'App', version }),
          'u',
        ]);
      const { id } = await new JobLifecycle(db, () => 1000).enqueue('o', 'u', 'queue', 'd');
      const raw = await new RuntimeQueries(db, () => 1000).library('o');
      const output = presentLibrary(raw);
      expect(output.jobs[0]).toMatchObject({
        id,
        state: 'queued',
        display_snapshot: { version, source: null, device: 'phone' },
      });
      await expect(query(async () => raw, 'library', librarySchema)).resolves.toEqual(output);
    } finally {
      await db.close();
    }
  },
);
it('presents the real session producer public profile ID and rejects impossible database nulls', async () => {
  const db = await createJobsFixture();
  try {
    const login = await loginFixture(db, 'o@example.test', 1000);
    const session = await new SessionService(db, { now: () => 1000 }).session(login.token);
    const output = presentSession({
      csrf: login.csrf,
      profile: {
        id: session.ownerId,
        loginName: session.loginName,
        role: session.role,
        publicProfileId: session.publicProfileId,
      },
      capabilities: {},
    });
    expect(output.profile.publicProfileId).toMatch(/^profile_[a-f0-9]{32}$/);
    await expect(
      db.query('UPDATE users SET public_profile_id=NULL WHERE id=$1', [session.ownerId]),
    ).rejects.toThrow();
    expect(() =>
      presentSession({ ...output, profile: { ...output.profile, publicProfileId: null } }),
    ).toThrow();
  } finally {
    await db.close();
  }
});
