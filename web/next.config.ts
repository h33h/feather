import type { NextConfig } from 'next';
const config: NextConfig = {
  poweredByHeader: false,
  compress: true,
  distDir: process.env.ISIGN_NEXT_DIST_DIR ?? '.next',
  logging: { incomingRequests: false },
  devIndicators: false,
  outputFileTracingRoot: process.cwd(),
  turbopack: { root: process.cwd() },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        ],
      },
    ];
  },
};
export default config;
