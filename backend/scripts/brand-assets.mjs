import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// Next.js already supplies sharp; brand exports need no extra app dependency.
const requireFromNext = createRequire(import.meta.resolve('next/package.json'));
const sharp = requireFromNext('sharp');
const masterPath = 'web/public/brand/isign-mark.svg';
const master = await readFile(new URL('../../' + masterPath, import.meta.url), 'utf8');
if (!master.includes('fill="#155BEA"')) throw new Error('Unexpected brand master color');
const mark = (color = '#155BEA') => master.replace('fill="#155BEA"', `fill="${color}"`);
const outputs = new Map();
const add = (path, data) => outputs.set(path, Buffer.isBuffer(data) ? data : Buffer.from(data));
async function png(size, color, background) {
  let image = sharp(Buffer.from(mark(color)), { density: 144 }).resize(size, size);
  if (background) image = image.flatten({ background }).removeAlpha();
  return image.png({ compressionLevel: 9 }).toBuffer();
}

const white = '#FFFFFF';
const defaultIcon = await png(1024, '#155BEA', white);
const transparentMark = await png(1024, '#155BEA');
const whiteMark = await png(1024, white);
const darkMark = await png(1024, '#5B8EFF');
add('web/public/brand/isign-mark-white.svg', mark(white));
add('web/public/brand/isign-mark.png', transparentMark);
add('web/public/brand/isign-mark-white.png', whiteMark);
add('web/public/icons/client.png', defaultIcon);
add('web/public/icons/icon-192.png', await png(192, '#155BEA', white));
add('web/public/icons/icon-512.png', await png(512, '#155BEA', white));
add('web/public/icons/apple-touch-icon.png', await png(180, '#155BEA', white));
const favicon = master.replace(
  '<g fill="#155BEA">',
  '<rect width="1254" height="1254" fill="#FFFFFF"/>\n  <g fill="#155BEA">',
);
add('web/public/icons/isign.svg', favicon);

// PNG-backed ICO entries preserve the exact small-size exports in current browsers.
const sizes = [16, 32, 48];
const entries = await Promise.all(sizes.map((size) => png(size, '#155BEA', white)));
const header = Buffer.alloc(6 + 16 * sizes.length);
header.writeUInt16LE(1, 2);
header.writeUInt16LE(sizes.length, 4);
let offset = header.length;
for (let index = 0; index < sizes.length; index++) {
  const entry = 6 + 16 * index;
  header[entry] = sizes[index];
  header[entry + 1] = sizes[index];
  header.writeUInt16LE(1, entry + 4);
  header.writeUInt16LE(32, entry + 6);
  header.writeUInt32LE(entries[index].length, entry + 8);
  header.writeUInt32LE(offset, entry + 12);
  offset += entries[index].length;
}
add('web/public/icons/favicon.ico', Buffer.concat([header, ...entries]));
add('web/public/icons/favicon-16.png', entries[0]);
add('web/public/icons/favicon-32.png', entries[1]);

const native = 'ios/ISignClient/Resources/';
const appIcons = native + 'Assets.xcassets/AppIcon.appiconset/';
add(appIcons + 'isign.png', defaultIcon);
add(appIcons + 'isign-dark.png', darkMark);
add(appIcons + 'isign-tinted.png', whiteMark);
add(native + 'Assets.xcassets/Glyph.imageset/isign.png', whiteMark);
add(native + 'AppIcon.icon/Assets/isign.svg', master);

const check = process.argv.includes('--check');
let stale = false;
for (const [path, bytes] of outputs) {
  const destination = new URL('../../' + path, import.meta.url);
  if (check) {
    const current = await readFile(destination).catch((error) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (!current?.equals(bytes)) {
      console.error('Brand asset needs regeneration:', path);
      stale = true;
    }
  } else {
    await mkdir(dirname(fileURLToPath(destination)), { recursive: true });
    await writeFile(destination, bytes);
  }
}
if (stale) process.exitCode = 1;
else
  console.log(`${outputs.size} brand assets ${check ? 'verified' : 'exported'} from ${masterPath}`);
