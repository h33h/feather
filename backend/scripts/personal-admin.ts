import { initializeDatabase } from '../packages/core/src/infrastructure/database-init';
import { initializePersonalVault } from '../packages/core/src/infrastructure/personal-bootstrap';
import { loadPrivateEnvironment } from '../packages/core/src/infrastructure/private-environment';
import { loadProviderConfig } from '../packages/core/src/infrastructure/config';
import { ProviderError } from '../packages/core/src/shared/errors';
import { createPersonalPool } from '../packages/core/src/composition/personal-kernel';
import { ProductionDatabase } from '../packages/core/src/infrastructure/postgres';
import { PersonalAuth } from '../packages/core/src/auth/passkeys';
/** Operator bootstrap/emergency recovery only. Normal management uses the admin UI. */
async function main() {
  if (process.env.ISIGN_SERVER_ENV_FILE)
    await loadPrivateEnvironment(process.env.ISIGN_SERVER_ENV_FILE, process.env);
  const config = loadProviderConfig(process.env);
  if (config.mode !== 'personal') throw new ProviderError('PERSONAL_RUNTIME_REQUIRED');
  const command = process.argv[2],
    argument = process.argv[3];
  if (command !== 'init' && command !== 'recover-admin')
    throw new ProviderError('USAGE: init ADMIN_LOGIN | recover-admin ADMIN_ID');
  if (!argument) throw new ProviderError('ADMIN_ARGUMENT_REQUIRED');
  const db = new ProductionDatabase(createPersonalPool(config, process.env));
  try {
    const auth = new PersonalAuth(db, config.origin);
    if (command === 'init') {
      if (!/^[a-zA-Z0-9_-]{1,40}$/.test(argument)) throw new ProviderError('ADMIN_NAME_REQUIRED');
      await initializeDatabase(db);
      await initializePersonalVault(db, config);
      console.log(JSON.stringify(await auth.bootstrapAdmin(argument)));
    } else {
      if (
        !(
          await db.query(
            "SELECT id FROM users WHERE id=$1 AND role='admin' AND deleted_at IS NULL",
            [argument],
          )
        ).rows.length
      )
        throw new ProviderError('ADMIN_NOT_FOUND');
      await db.query('UPDATE users SET blocked_at=NULL WHERE id=$1', [argument]);
      console.log(JSON.stringify(await auth.operatorReinvite(argument)));
    }
  } finally {
    await db.close();
  }
}
main().catch((error) => {
  console.error(error instanceof ProviderError ? error.code : 'ADMIN_COMMAND_FAILED');
  process.exitCode = 1;
});
