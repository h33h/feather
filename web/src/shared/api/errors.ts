export const messages: Record<string, string> = {
  IDEMPOTENCY_BINDING_MISMATCH: 'Сборка или устройство изменились. Подготовьте клиент заново.',
  CLIENT_INSTALL_NOT_READY: 'Ссылка установки недоступна. Проверьте подготовку клиента.',
  CLIENT_INSTALL_ARTIFACT_UNAVAILABLE: 'Срок установки истёк. Подготовьте клиент заново.',
  CLIENT_RELEASE_NOT_CONFIGURED: 'Версия клиента ещё не опубликована.',
  CLIENT_RELEASE_INVALID: 'Сборка клиента временно недоступна.',
  CLIENT_RELEASE_CHECKSUM_MISMATCH: 'Сборка клиента не прошла проверку. Повторите позже.',
  CLIENT_RELEASE_UNAVAILABLE: 'Сборка клиента временно недоступна.',
  CLIENT_INSTALLER_MIGRATION_REQUIRED: 'Установка клиента временно недоступна.',
  CLIENT_INSTALLATION_UNAVAILABLE:
    'Эта установка больше недоступна. Проверьте аккаунт и устройство.',

  NATIVE_PIPELINE_REQUIRED: 'Сервис подписи временно недоступен. Повторите подготовку позже.',
  RELEASE_UNAVAILABLE: 'Версия клиента изменилась. Обновите данные и подготовьте клиент заново.',
  QUOTA_EXCEEDED:
    'Недостаточно места. Дождитесь удаления файлов по сроку хранения или обратитесь к администратору.',
  UNAUTHENTICATED: 'Сессия завершилась. Войдите снова.',
  UNAUTHORIZED: 'Сессия завершилась. Войдите снова.',
  CSRF: 'Обновите страницу и повторите действие.',
  DEVICE_NOT_ELIGIBLE:
    'Не удалось зарегистрировать устройство. Проверьте его состояние и подключение Apple.',
  DEVICE_ONBOARDING_UNAVAILABLE:
    'Регистрация iPhone временно недоступна. Уже добавленные устройства можно использовать.',
  CMS_VERIFIER_UNAVAILABLE:
    'Проверка профиля iPhone ещё не настроена. Регистрация временно недоступна.',
  APPLE_CONNECTION_REQUIRED:
    'Подключите свою команду Apple Developer или получите доступ от владельца.',
  CONNECTION_UNAVAILABLE:
    'Подключение команды недоступно. Откройте сведения о команде и проверьте доступ.',
  CONNECTION_CHANGED: 'Команда Apple изменилась. Обновите данные и проверьте её подключение.',
  APPLE_ACCESS_CHANGED:
    'Предоставленный доступ изменился. Откройте сведения о команде и проверьте доступ.',
  APPLE_ACCESS_UNAVAILABLE: 'Доступ Apple отозван или недоступен. Обратитесь к владельцу команды.',
  CERTIFICATE_CREATION_CONSENT_REQUIRED: 'В сведениях о команде запустите подготовку сертификата.',
  DEVICE_SELECTION_REQUIRED: 'Выберите готовый iPhone перед подготовкой.',
  ACTIVE_JOB_EXISTS: 'Подготовка уже идёт. Обновите данные, чтобы увидеть её состояние.',
  INVALID_REQUEST: 'Проверьте заполненные поля и выбранный файл.',
  INVALID_ISSUER_ID: 'Скопируйте Issuer ID со страницы Team Keys в App Store Connect.',
  INVALID_KEY_ID: 'Скопируйте Key ID из строки выбранного Team API Key в App Store Connect.',
  INVALID_P8:
    'Не удалось прочитать приватный ключ. Выберите исходный файл .p8 из App Store Connect размером до 16 KiB.',
  TEAM_KEY_REQUIRED: 'Выберите Team API Key в формате P8.',
  TEAM_PROOF_REQUIRED:
    'В сведениях о команде запустите подготовку сертификата для проверки команды.',
  TEAM_UNAVAILABLE: 'Команда Apple недоступна. Проверьте права Team API Key в App Store Connect.',
  SOURCE_EXPIRED: 'Срок хранения исходной сборки истёк. Подготовьте клиент заново.',
  AUTH_RATE_LIMITED: 'Слишком много попыток входа. Подождите и повторите.',
  PASSKEY_AUTH_FAILED: 'Вход не подтверждён. Повторите с passkey своего профиля.',
  MAPPING_CONSENT_REQUIRED: 'Подтвердите подготовку для выбранного iPhone.',
  HANDOFF_INVALID: 'Ссылка установки истекла. Получите новую ссылку установки.',
  ARTIFACT_NOT_FOUND: 'Подписанный файл больше недоступен. Подготовьте приложение снова.',
};
messages.APPLE_ACCESS_REQUIRED = messages.APPLE_CONNECTION_REQUIRED;
messages.DEVICE_REPLACEMENT_CONFIRMATION_REQUIRED =
  'Используйте действие «Заменить UDID», чтобы сменить устройство профиля.';
messages.DEVICE_IDENTITY_CHANGED =
  'Запрос устройства уже изменился. Скачайте новый профиль для замены.';
messages.CERTIFICATE_REQUIRED =
  'Для установки нужен сертификат подписи. В сведениях о команде запустите её подготовку.';

Object.assign(messages, {
  APPLE_AUTH_FAILED:
    'Apple не приняла ключ. Проверьте Issuer ID, Key ID и права Team API Key в App Store Connect.',
  APPLE_ACCESS_ACTION_REQUIRED:
    'Apple отклонила доступ. Владелец команды должен проверить ключ, его права и соглашения Apple Developer.',
  APPLE_RATE_LIMITED:
    'Apple ограничила частоту запросов. Подождите несколько минут и проверьте доступ снова.',
  APPLE_TEMPORARY_UNAVAILABLE: 'Apple временно недоступна. Подождите и повторите действие.',
  APPLE_OPERATION_REJECTED:
    'Apple отклонила действие. Проверьте доступ команды и повторите попытку; если ошибка остаётся, обратитесь к администратору сервера.',
  APPLE_ONBOARDING_UNAVAILABLE:
    'Подключение команды временно недоступно. Обратитесь к администратору сервера.',
  APPLE_CONNECTION_EXISTS: 'Команда уже подключена. Обновите данные и откройте сведения о команде.',
  APPLE_DISCONNECTED: 'Команда отключена. Подключите её снова или получите доступ от владельца.',
  APPLE_SHARE_DISCONNECTED: 'Предоставленный доступ отключён. Обратитесь к владельцу команды.',
  APPLE_CREDENTIAL_REQUIRED:
    'Ключ команды недоступен. Владелец должен проверить сведения о подключении команды.',
  BOOTSTRAP_BROKER_UNAVAILABLE:
    'Подготовка сертификата на сервере недоступна. Обратитесь к администратору сервера.',
  BOOTSTRAP_BUSY: 'Сертификат уже готовится. Подождите и проверьте доступ снова.',
  BOOTSTRAP_NOT_REQUIRED: 'Повторная подготовка сертификата не нужна. Обновите данные команды.',
  SECRET_UNAVAILABLE:
    'Сохранённый ключ команды недоступен. Владелец должен проверить подключение; если ошибка остаётся, обратитесь к администратору сервера.',
  MUTATION_OUTCOME_UNKNOWN:
    'Apple не подтвердила результат. Обновите данные перед повторной попыткой.',
  RESOURCE_RECONCILIATION_REQUIRED:
    'Нужно проверить результат предыдущего действия в Apple. Обратитесь к администратору сервера.',
  RESOURCE_RECONCILIATION_AMBIGUOUS:
    'Ресурсы команды в Apple требуют проверки. Обратитесь к администратору сервера.',
  CERTIFICATE_IDENTITY_MISMATCH:
    'Сертификат не соответствует ключу команды. Владелец должен проверить подключение; обратитесь к администратору сервера.',
  OWNED_CERTIFICATE_REQUIRED:
    'Нужен сертификат, подготовленный этим сервером. Владелец должен проверить подключение команды.',
  BUNDLE_IDENTIFIER_UNAVAILABLE:
    'Идентификатор клиента недоступен в Apple. Повторите подготовку; если ошибка остаётся, обратитесь к администратору сервера.',
  FRESH_AUTH_REQUIRED: 'Подтвердите действие с passkey своего профиля.',
});

messages.RUNNER_BUSY = 'Сервис подписи занят. Повторите подготовку немного позже.';
messages.RUNNER_TEMPORARY_UNAVAILABLE =
  'Сервис подписи временно недоступен. Повторите подготовку позже.';
messages.RUNNER_REQUEST_REJECTED =
  'Сервис подписи отклонил сборку клиента. Повторите подготовку; если ошибка остаётся, обратитесь к администратору сервера.';
messages.SOURCE_DIGEST_MISMATCH =
  'Сборка клиента изменилась или получена не полностью. Повторите подготовку.';
for (const code of ['SOURCE_LIMIT', 'INPUT_TOO_LARGE'])
  messages[code] =
    'Сборка клиента превышает допустимый размер. Обратитесь к администратору сервера.';
for (const code of [
  'ARCHIVE_LIMIT',
  'ARCHIVE_METADATA_LIMIT',
  'METADATA_LIMIT',
  'BINARY_LIMIT',
  'LINUX_SOURCE_CAPACITY_UNSUPPORTED',
])
  messages[code] =
    'Сборка клиента превышает лимиты обработки. Обратитесь к администратору сервера.';
for (const code of [
  'ARCHIVE_INVALID',
  'ZIP_PATH_REJECTED',
  'ZIP_ENTRY_REJECTED',
  'MACHO_BOUNDS',
  'FAT_BOUNDS',
  'FAT_ARCHITECTURE_DUPLICATE',
  'FAT_ARCHITECTURE_MISMATCH',
  'FAT_METADATA_MISMATCH',
  'SEGMENT_BOUNDS',
  'SECTION_BOUNDS',
  'SIGNATURE_BOUNDS',
])
  messages[code] =
    'Сборка клиента повреждена или некорректна. Повторите подготовку; если ошибка остаётся, обратитесь к администратору сервера.';
for (const code of [
  'MAIN_APP_REQUIRED',
  'METADATA_INVALID',
  'MIN_OS_MISMATCH',
  'EXTENSION_ID_MISMATCH',
])
  messages[code] = 'Данные в сборке клиента некорректны. Обратитесь к администратору сервера.';
for (const code of [
  'COMPONENT_GRAPH_REJECTED',
  'NESTED_APP_UNSUPPORTED',
  'UNMODELED_EXECUTABLE',
  'DYLIB_TYPE_REQUIRED',
])
  messages[code] =
    'Сборка клиента содержит неподдерживаемые компоненты. Обратитесь к администратору сервера.';
for (const code of [
  'MACHO_UNSUPPORTED',
  'ARCHITECTURE_UNSUPPORTED',
  'LINUX_FAT_SOURCE_UNSUPPORTED',
])
  messages[code] =
    'Сборка клиента не поддерживает архитектуру этого iPhone. Обратитесь к администратору сервера.';
for (const code of ['PLATFORM_INVALID', 'PLATFORM_UNSUPPORTED'])
  messages[code] =
    'Сборка клиента не предназначена для устройства iOS. Обратитесь к администратору сервера.';
messages.DRM_UNSUPPORTED =
  'Сборка клиента защищена DRM и не подходит для подписи. Обратитесь к администратору сервера.';
messages.ENTITLEMENTS_INVALID =
  'Права в сборке клиента повреждены или некорректны. Обратитесь к администратору сервера.';
messages.ENTITLEMENTS_MISMATCH =
  'Данные прав в сборке клиента не совпадают. Обратитесь к администратору сервера.';
messages.ENTITLEMENTS_VALUE_UNSUPPORTED =
  'Сборка клиента содержит неподдерживаемые права. Обратитесь к администратору сервера.';
messages.DER_ENTITLEMENTS_UNSUPPORTED =
  'Формат прав в сборке клиента не поддерживается. Обратитесь к администратору сервера.';

export function installerErrorMessage(
  code: string | null | undefined,
  fallback = 'Действие не выполнено. Обновите данные и повторите попытку.',
): string {
  return (code && Object.hasOwn(messages, code) && messages[code]) || fallback;
}
