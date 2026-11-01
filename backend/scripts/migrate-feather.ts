import { loadPrivateEnvironment } from '../packages/core/src/infrastructure/private-environment';
import { loadProviderConfig, ProviderError } from '../packages/core/src/infrastructure/config';
import { createPersonalPool } from '../packages/core/src/composition/personal-kernel';
import { ProductionDatabase } from '../packages/core/src/infrastructure/postgres';
import { migrateFeather } from '../packages/core/src/infrastructure/native-migrations';
import { Failure } from '../packages/core/src/shared';
async function main() {
  if (process.env.ISIGN_SERVER_ENV_FILE)
    await loadPrivateEnvironment(process.env.ISIGN_SERVER_ENV_FILE, process.env);
  const config = loadProviderConfig(process.env);
  const db = new ProductionDatabase(createPersonalPool(config, process.env));
  try {
    console.log(JSON.stringify(await migrateFeather(db)));
  } finally {
    await db.close();
  }
}
main().catch((error) => {
  console.error(
    error instanceof ProviderError || error instanceof Failure
      ? error.code
      : 'FEATHER_MIGRATION_FAILED',
  );
  process.exitCode = 1;
});
