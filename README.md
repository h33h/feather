# iSign

iSign — сервис для управления Apple Developer аккаунтами, устройствами и источниками приложений с iOS-клиентом **iSign Client**.

На сайте пользователь входит по passkey, подключает свою Apple Developer команду или получает общий доступ, добавляет устройство и устанавливает iSign Client. Backend подписывает для него только сборку клиента, опубликованную оператором. iSign Client загружает IPA, применяет настройки и твики, подписывает приложение на устройстве и устанавливает его или экспортирует готовый файл.

## Возможности

- Вход по passkey, приглашения и управление пользователями.
- Подключение Apple Developer команды через App Store Connect API key и общий доступ к ней.
- Сбор UDID через Profile Service и регистрация устройств в Apple.
- Управление источниками и каталогами AltStore, GBox и iApps.
- Автоматическое получение и обновление сертификатов и профилей подписи.
- Локальная подпись IPA с поддержкой расширений, entitlements и твиков.
- Установка приложений, экспорт IPA и подпись без сети с действующим кэшированным комплектом.

## Структура

| Путь                                                       | Содержимое                                             |
| ---------------------------------------------------------- | ------------------------------------------------------ |
| [`backend/server/`](backend/server/)                       | HTTP API, сборка сервисов и фоновые задачи             |
| [`backend/packages/`](backend/packages/)                   | Логика сервиса, PostgreSQL, Apple API и runner         |
| [`backend/deploy/personal/`](backend/deploy/personal/)     | Docker Compose, nginx и конфигурация развёртывания     |
| [`backend/tests/`](backend/tests/)                         | Тесты backend и веб-флоу                               |
| [`web/`](web/)                                             | Веб-установщик, статические ресурсы и маршруты Next.js |
| [`ios/ISignClient/`](ios/ISignClient/)                     | iOS-приложение                                         |
| [`ios/ISignClient.xcodeproj/`](ios/ISignClient.xcodeproj/) | Xcode-проект                                           |
| [`ios/Tests/`](ios/Tests/)                                 | Тесты клиента и signing bridge                         |
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml)     | CI для backend, runner и iOS                           |

Общие зависимости Node.js, lockfile и настройки TypeScript находятся в корне. Команды `pnpm` запускаются из корня репозитория. Next.js обслуживает веб-интерфейс и передаёт API-запросы обработчикам из `backend/server/`.

## Требования

Для backend нужны Node.js 22, pnpm 10.33.0, PostgreSQL 16, Python 3.12 и OpenSSL. Для сборки iOS нужны macOS и Xcode. Приложение поддерживает iOS 16 и новее.

## Подготовка

```sh
git clone --recurse-submodules git@github.com:h33h/feather.git
cd feather
pnpm install --frozen-lockfile
pnpm setup:runner
pnpm setup:catalog
```

Зависимости iOS `Zsign` и `IDeviceKitten` подключены как Git submodules. Для их загрузки в существующем checkout выполните `git submodule update --init --recursive`.

## Backend

Подготовьте PostgreSQL, runner и переменные окружения. Примеры настроек: [локальное окружение](backend/.env.example), [production](backend/.env.production.example), [публичные настройки сервиса](backend/deploy/personal/personal.env.example).

Задайте публичный адрес сервиса в `ISIGN_ORIGIN`, подключение к runner и пути к хранилищу и ключу шифрования. Для локальной разработки используйте `ISIGN_PERSONAL_DATABASE_TRANSPORT=loopback`; iOS-клиенту нужен доступный HTTPS-адрес сервиса.

Сохраните `DATABASE_URL`, `ISIGN_RUNNER_TOKEN` и `ISIGN_RUNNER_PROOF_KEY` в отдельном файле `server.env` с правами `0600`. Его формат указан в [примере](backend/deploy/personal/server.env.example). Публичные настройки загрузите в окружение процесса:

```sh
set -a
. /absolute/path/personal.env
set +a
export ISIGN_SERVER_ENV_FILE=/absolute/path/server.env
```

Для нового окружения одной командой создайте текущую схему БД, ключ хранилища и первого администратора. Инициализация требует пустую БД и права на создание таблиц и индексов:

```sh
pnpm personal:admin init admin
```

Используйте приглашение из вывода команды для регистрации passkey администратора и запустите сервер разработки:

```sh
pnpm dev
```

Установщик доступен по `http://localhost:3000`. Native API использует путь `/api/native/v1`. Native API обязателен; сервер проверяет полную текущую схему БД при запуске. Backend и клиент используют один текущий контракт и обновляются вместе. Для production используйте [Dockerfile](backend/deploy/personal/Dockerfile.web), [Compose](backend/deploy/personal/compose.yml) и [конфигурацию nginx](backend/deploy/personal/nginx.conf).

## Установщик

Сайт ведёт пользователя через три шага: Apple-аккаунт, устройство и установка клиента. Для общего доступа пользователь передаёт ID своего профиля владельцу команды; владелец предоставляет доступ из приложения. Для нового устройства сайт выдаёт профиль сбора UDID и запрашивает подтверждение регистрации в Apple.

Публикуйте исходную сборку клиента как файл, доступный backend. Укажите её абсолютный путь и SHA256 в публичном окружении сервиса:

```sh
ISIGN_CLIENT_IPA_PATH=/absolute/path/ISignClient.ipa
ISIGN_CLIENT_IPA_SHA256=REPLACE_WITH_64_HEX_DIGITS
ISIGN_CLIENT_VERSION=2.9.0
```

В Compose положите файл в каталог `client/` рядом с `compose.yml` и используйте путь `/run/isign/client/ISignClient.ipa`. Контрольная сумма и версия находятся в JSON, который создаёт команда упаковки ниже. Сайт показывает недоступность установки, пока сборка не опубликована и не прошла проверку.

Конфигурация Compose должна использовать команду `node --import tsx backend/scripts/personal-start.ts` и tmpfs для `/app/web/.next/cache`; деплой проверяет эти настройки перед запуском контейнера.

Backend получает IPA из этого файла, подписывает для выбранного устройства и выдаёт ссылку или QR установки. Повторный запрос сохраняет ту же операцию; подготовку можно продолжить после перезагрузки страницы. Управление источниками, библиотекой и пользователями находится в iSign Client.

## Сборка iSign Client

Откройте `ios/ISignClient.xcodeproj` или `ios/ISignClient.xcworkspace` в Xcode. Выберите схему `ISignClient`.

Адрес backend вшивается в приложение при сборке. В настройках репозитория **Settings → Secrets and variables → Actions → Variables** задайте `ISIGN_ORIGIN`: публичный HTTPS-адрес сервиса без пути, query и fragment. CI передаёт его в Xcode как `ISIGN_SERVICE_ORIGIN`. Пользователь приложения адрес сервера не вводит. Для локальной сборки передайте ту же настройку командой ниже или через Build Settings в Xcode.

Сборка из корня репозитория без подписи:

```sh
xcodebuild -project ios/ISignClient.xcodeproj -scheme ISignClient -configuration Release \
  -destination 'generic/platform=iOS' \
  -derivedDataPath /tmp/isign-client-build \
  -disableAutomaticPackageResolution -skipPackagePluginValidation \
  ISIGN_SERVICE_ORIGIN="$ISIGN_ORIGIN" \
  CODE_SIGNING_ALLOWED=NO build
```

Упакуйте сборку для серверного установщика:

```sh
node backend/scripts/package-client.mjs \
  --app ios/_build/Applications/ISignClient.app \
  --out ios/packages/ISignClient.ipa
```

Команда проверяет вшитый HTTPS-адрес и создаёт IPA и `ISignClient.ipa.json` с адресом сервиса, версией и SHA256. CI также сохраняет их как артефакт сборки. Это шаблон для последующей подписи сервером под устройство пользователя.

Для режима Fully Local нужен действующий TLS-комплект в ресурсах приложения. Подготовьте его перед сборкой через `make -C ios deps CERT_JSON_URL=...`; команда упаковки не загружает TLS-ресурсы.

В приложении откройте **Settings → iSign** и войдите по passkey. Подключённый на сайте аккаунт и устройства загрузятся автоматически. Для подключения другой команды используйте issuer ID, key ID и P8-файл. Для добавления устройства установите предложенный профиль сбора UDID и подтвердите его регистрацию в Apple.

Выберите **Use iSign Managed Certificate** для подписи через аккаунт. Приложение получит сертификат и профили для итоговых Bundle ID, устройств и расширений. Управляемые ключи и профили хранятся в зашифрованном кэше, токены сессии — в device-only Keychain.

## Логотип и иконки

Общий векторный исходник находится в `web/public/brand/isign-mark.svg`. Из него создаются иконки iOS, слой Icon Composer, логотипы для светлого и тёмного фона и иконки сайта.

```sh
pnpm brand:assets
pnpm brand:assets --check
```

## Проверки

```sh
pnpm typecheck
pnpm lint
pnpm test
pnpm build
swift test --package-path ios
swift test --package-path ios/AltSourceKit
```

CI проверяет backend, Linux runner и iOS-клиент, включая сборку без подписи. Для создания IPA задайте переменную репозитория `ISIGN_ORIGIN`. Автоматический деплой включается переменной репозитория `ISIGN_DEPLOY_ENABLED=true` после настройки окружения `production`. Для проверки установки приложений и системного сценария Profile Service нужен физический iPhone.

## Лицензия

iOS-клиент основан на [Feather](https://github.com/claration/Feather) и распространяется по [GPL-3.0](ios/LICENSE). Авторство указано в исходниках и разделе About приложения.
