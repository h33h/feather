import type { Database } from '../../packages/core/src/shared/database';
import { resolveAppleAccess } from '../../packages/core/src/apple/access';
import { hash, id } from '../../packages/core/src/shared';
export async function collectedDeviceFixture(
  db: Database,
  owner: string,
  connection: string,
  udid: string,
  now = 100,
) {
  const generation = (
    await db.query<{ generation: number }>('SELECT generation FROM connections WHERE id=$1', [
      connection,
    ])
  ).rows[0].generation;
  const access = await resolveAppleAccess(db, owner, connection, generation);
  const device = id();
  await db.query(
    "INSERT INTO devices(id,owner_id,connection_id,connection_owner_id,access_grant_id,access_grant_generation,name,status,udid,udid_hash,connection_generation,enrollment_verified_at,enrollment_cms_sha256) VALUES($1,$2,$3,$4,$5,$6,'iPhone','collected',$7,$8,$9,$10,'trusted-fixture')",
    [
      device,
      owner,
      connection,
      access.connectionOwnerId,
      access.accessGrantId,
      access.accessGrantGeneration,
      udid,
      hash(udid),
      generation,
      now,
    ],
  );
  return { id: device };
}
