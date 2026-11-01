import type { QueryDatabase } from '../shared/database';
import { assertUploadAccess } from '../library/access';
export class RequestAuthorization {
  constructor(private db: QueryDatabase) {}
  requireUpload(owner: string) {
    return assertUploadAccess(this.db, owner);
  }
}
