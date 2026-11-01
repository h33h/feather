import type { Metadata, Viewport } from 'next';
import { RetireWebApp } from '../features/pwa/registration';
import { ThemeProvider } from '../shared/ui/theme-control';
import { themeScript } from '../shared/ui/theme';
import './globals.css';
export const metadata: Metadata = {
  title: 'Установка iSign Client',
  description: 'Подключите Apple-аккаунт, добавьте устройство и установите iSign Client',
  applicationName: 'iSign',
  icons: {
    icon: [
      { url: '/icons/favicon.ico', sizes: '16x16 32x32 48x48', type: 'image/x-icon' },
      { url: '/icons/isign.svg', sizes: 'any', type: 'image/svg+xml' },
    ],
    apple: [{ url: '/icons/apple-touch-icon.png', sizes: '180x180' }],
  },
};
export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  viewportFit: 'cover',
  themeColor: '#ffffff',
};
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ru" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>
        <ThemeProvider>{children}</ThemeProvider>
        <RetireWebApp />
      </body>
    </html>
  );
}
