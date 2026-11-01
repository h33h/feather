import type { QueryDatabase } from '../shared/database';
import { requireAdmin } from '../auth/admin';
import { assertUploadAccess, hasUploadAccess } from '../library/access';
export class RequestAuthorization {
  constructor(
    private db: QueryDatabase,
    private now: () => number,
  ) {}
  requireAdmin(session: { ownerId: string }) {
    return requireAdmin(this.db, session, this.now());
  }
  requireUpload(owner: string) {
    return assertUploadAccess(this.db, owner);
  }
  uploadAllowed(owner: string) {
    return hasUploadAccess(this.db, owner);
  }
}
