import { z } from 'zod';
export const releaseSchema = z.object({
  name: z.literal('iSign Client'),
  available: z.boolean(),
  version: z.string().optional(),
  reason: z.string().optional(),
});
export const installationSchema = z.object({
  operationId: z.string(),
  jobId: z.string(),
  state: z.string(),
  reason: z.string().nullable().optional(),
  artifactId: z.string().optional(),
  updatedAt: z.number().optional(),
  version: z.string().optional(),
});
export type ClientInstallation = z.infer<typeof installationSchema>;
export const operationLabels: Record<string, string> = {
  receiving: 'Загружаем сборку клиента',
  queued: 'Ожидаем очередь на подпись',
  analyzing: 'Проверяем сборку клиента',
  provisioning: 'Готовим профиль для устройства',
  signing: 'Подписываем iSign Client',
  verifying: 'Проверяем подписанное приложение',
  ready: 'Клиент готов к установке',
  failed: 'Не удалось подготовить клиент',
  cancelled: 'Подготовка отменена',
};
export const terminal = (state: string) => ['ready', 'failed', 'cancelled'].includes(state);
export const installationErrors: Record<string, string> = {
  CLIENT_RELEASE_UNAVAILABLE: 'Версия клиента ещё не опубликована.',
  CLIENT_RELEASE_CHANGED: 'Сборка клиента обновилась. Начните подготовку заново.',
  CLIENT_RELEASE_DIGEST_MISMATCH: 'Сборка клиента не прошла проверку. Повторите позже.',
  CLIENT_INSTALLATION_UNAVAILABLE:
    'Эта установка больше недоступна. Проверьте доступ к аккаунту и устройство.',
  CLIENT_INSTALL_ARTIFACT_UNAVAILABLE: 'Срок установки истёк. Подготовьте клиент заново.',
  NOT_FOUND: 'Эта установка больше недоступна. Начните подготовку заново.',
};

export const receiptSchema = z.object({
  operationId: z.string().min(1).max(200).optional(),
  key: z
    .string()
    .regex(/^[A-Za-z0-9_-]{1,100}$/)
    .optional(),
  deviceId: z.string().min(1).max(100).optional(),
});
