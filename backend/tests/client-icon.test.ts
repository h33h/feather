import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
it('shows the actual default iOS client icon in the installer', () => {
  const directory = new URL(
    '../../ios/ISignClient/Resources/Assets.xcassets/AppIcon.appiconset/',
    import.meta.url,
  );
  const metadata = JSON.parse(readFileSync(new URL('Contents.json', directory), 'utf8'));
  const main = metadata.images.find(
    (image: { filename?: string; platform?: string; appearances?: unknown }) =>
      image.platform === 'ios' && image.filename && !image.appearances,
  );
  expect(main).toBeDefined();
  const digest = (value: Buffer) => createHash('sha256').update(value).digest('hex');
  expect(digest(readFileSync(new URL('../../web/public/icons/client.png', import.meta.url)))).toBe(
    digest(readFileSync(new URL(main.filename, directory))),
  );
});
