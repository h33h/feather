import { expect, it } from 'vitest';
import { SessionService } from '../packages/core/src/auth/sessions';
import { presentSession } from '../server/http/presenters';
import { createJobsFixture } from './job-fixtures';
import { loginFixture } from './helpers/login';
it('presents the real session producer public profile ID and rejects impossible database nulls', async () => {
  const db = await createJobsFixture();
  try {
    const login = await loginFixture(db, 'o@example.test', 1000);
    const session = await new SessionService(db, { now: () => 1000 }).session(login.token);
    const output = presentSession({
      authenticated: true,
      csrf: login.csrf,
      profile: {
        id: session.ownerId,
        loginName: session.loginName,
        role: session.role,
        publicProfileId: session.publicProfileId,
      },
      capabilities: {
        runner: true,
        appleOnboarding: true,
        bootstrap: true,
        deviceEnrollment: true,
      },
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
