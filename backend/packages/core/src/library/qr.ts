import QRCode from 'qrcode';
import { Failure } from '../shared/index';
export async function handoffQr(origin: string, cap: string) {
  const url = new URL(origin);
  if (
    url.protocol !== 'https:' ||
    url.pathname !== '/' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !/^[A-Za-z0-9_-]{43}$/.test(cap)
  )
    throw new Failure('HTTPS_INSTALL_ORIGIN_REQUIRED', 503);
  return QRCode.toString(url.origin + '/handoff/' + cap, {
    type: 'svg',
    errorCorrectionLevel: 'M',
    margin: 4,
    width: 256,
  });
}
