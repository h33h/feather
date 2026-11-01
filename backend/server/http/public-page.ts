import { createHash } from 'node:crypto';
import { publicDocument } from '../../../web/src/shared/ui/public-document';
import { themeScript } from '../../../web/src/shared/ui/theme';

// Capability pages allow only this exact bootstrap, never arbitrary inline scripts.
export const publicThemeScriptPolicy =
  "script-src 'sha256-" + createHash('sha256').update(themeScript).digest('base64') + "'";

export function publicPage(title: string, message: string, installation = false) {
  return publicDocument({ title, message, actionLabel: 'Вернуться в iSign', installation });
}
