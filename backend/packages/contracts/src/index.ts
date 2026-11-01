import { z } from 'zod';

// Object schemas deliberately project an allowlist at every nesting level.
// Additional database columns never become part of the public DTO.
const timestamp = z.number().finite();
export const appleSchema = z.object({
  connection: z
    .object({
      id: z.string(),
      team_id: z.string().nullable(),
      state: z.string(),
      shared: z.boolean(),
      last_error: z.string().nullable(),
      identityReady: z.boolean(),
    })
    .nullable(),
  uploadAllowed: z.boolean(),
  shares: z.array(
    z.object({
      id: z.string(),
      generation: z.number().int(),
      state: z.string(),
      connectionId: z.string(),
      teamId: z.string(),
      direction: z.string(),
      profileId: z.string(),
    }),
  ),
});
export const deviceSchema = z.object({
  id: z.string(),
  name: z.string(),
  status: z.string(),
  os_version: z.string().nullable(),
  selected: z.boolean(),
  team_id: z.string().nullable(),
  os_version_source: z.string().nullable(),
});
export const collectionSchema = z.object({
  id: z.string(),
  name: z.string(),
  udid: z.string(),
  product: z.string().nullable(),
  osVersion: z.string().nullable(),
  createdAt: timestamp,
  verifiedAt: timestamp,
  status: z.string(),
  bindings: z.array(
    z.object({
      deviceId: z.string(),
      connectionId: z.string(),
      teamId: z.string(),
      generation: z.number().int(),
      status: z.string(),
      shared: z.boolean(),
    }),
  ),
});
export const devicesSchema = z.object({
  devices: z.array(deviceSchema),
  collectedDevices: z.array(collectionSchema),
});
export const sessionSchema = z.object({
  authenticated: z.literal(true),
  csrf: z.string(),
  profile: z.object({
    id: z.string(),
    loginName: z.string(),
    role: z.enum(['user', 'admin']),
    publicProfileId: z.string(),
  }),
  capabilities: z.object({
    runner: z.boolean(),
    appleOnboarding: z.boolean(),
    bootstrap: z.boolean(),
    deviceEnrollment: z.boolean(),
  }),
});
export const adminUserSchema = z.object({
  id: z.string(),
  loginName: z.string(),
  role: z.enum(['user', 'admin']),
  status: z.enum(['invited', 'active', 'blocked']),
});
export const adminUsersSchema = z.object({ users: z.array(adminUserSchema) });
export const inviteSchema = z.object({ token: z.string(), expiresAt: timestamp });
export type UiDevice = z.infer<typeof deviceSchema>;
export type Collection = z.infer<typeof collectionSchema>;
export type AuthSession = z.infer<typeof sessionSchema>;
export type AppleData = z.infer<typeof appleSchema>;
export type DeviceData = z.infer<typeof devicesSchema>;
export type AdminUser = z.infer<typeof adminUserSchema>;

// Native catalog DTOs intentionally have a separate projection from the web UI.
const featherText = z.string().max(20000);
const featherUrl = z.string().max(2048);
// Match DateParsed's numeric, ISO and explicit legacy formats. JavaScript's
// permissive Date.parse alone also accepts strings Swift rejects (e.g. US dates).
function normalizeFeatherDate(value: string | number): string | number | undefined {
  if (typeof value === 'number') return value;
  const date = value.trim();
  if (/^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/.test(date))
    return Number.isFinite(Number(date)) ? date : undefined;
  const validParts = (
    year: number,
    month: number,
    day: number,
    hour = 0,
    minute = 0,
    second = 0,
  ) => {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    return (
      month >= 1 &&
      month <= 12 &&
      day >= 1 &&
      day <= days[month - 1] &&
      hour >= 0 &&
      hour < 24 &&
      minute >= 0 &&
      minute < 60 &&
      second >= 0 &&
      second < 60
    );
  };
  const iso =
    /^(\d{4})-(\d{2})-(\d{2})(?:([T ])(\d{2}):(\d{2})(?::(\d{2})(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$/.exec(
      date,
    );
  if (iso) {
    const [, year, month, day, separator, hour, minute, second, fraction, zone] = iso;
    if (!validParts(+year, +month, +day, +(hour ?? 0), +(minute ?? 0), +(second ?? 0)))
      return undefined;
    // The Swift legacy space-separated format requires seconds and no zone.
    if (separator === ' ' && (!second || fraction || zone)) return undefined;
    if (((fraction || zone) && !second) || (fraction && !zone)) return undefined;
    return Number.isFinite(Date.parse(date)) ? date : undefined;
  }
  const months = [
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec',
  ];
  const rfc =
    /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{1,2}) ([A-Z][a-z]{2}) (\d{4}) (\d{2}):(\d{2}):(\d{2}) (?:[A-Za-z]{1,5}|GMT[+-]\d{2}:?\d{2}|[+-]\d{4})$/.exec(
      date,
    );
  const twitter =
    /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) ([A-Z][a-z]{2}) (\d{1,2}) (\d{2}):(\d{2}):(\d{2}) [+-]\d{4} (\d{4})$/.exec(
      date,
    );
  if (
    (rfc && validParts(+rfc[3], months.indexOf(rfc[2]) + 1, +rfc[1], +rfc[4], +rfc[5], +rfc[6])) ||
    (twitter &&
      validParts(
        +twitter[6],
        months.indexOf(twitter[1]) + 1,
        +twitter[2],
        +twitter[3],
        +twitter[4],
        +twitter[5],
      ))
  )
    return Number.isFinite(Date.parse(date)) ? date : undefined;
  return undefined;
}
const featherDate = z
  .union([z.string().max(100), z.number().finite()])
  .transform(normalizeFeatherDate);
const featherSize = z.union([
  z.number().int().nonnegative().safe(),
  z.string().regex(/^\d{1,20}$/),
]);
const featherScreenshot = z.union([
  featherUrl,
  z.object({
    url: featherUrl.optional(),
    imageURL: featherUrl.optional(),
    width: z.number().nonnegative().optional(),
    height: z.number().nonnegative().optional(),
  }),
]);
const featherScreenshotList = z.array(featherScreenshot).max(100);
export const featherVersionSchema = z.object({
  version: z.string().min(1).max(500),
  buildVersion: z.string().max(100).optional(),
  date: featherDate.optional(),
  localizedDescription: featherText.optional(),
  downloadURL: featherUrl.optional(),
  size: featherSize.optional(),
  minOSVersion: z.string().max(100).optional(),
});
export const featherAppSchema = z.object({
  bundleIdentifier: z.string().min(1).max(500).optional(),
  name: z.string().min(1).max(500).optional(),
  developerName: z.string().max(500).optional(),
  subtitle: featherText.optional(),
  description: featherText.optional(),
  localizedDescription: featherText.optional(),
  version: z.string().max(500).optional(),
  versionDate: featherDate.optional(),
  date: featherDate.optional(),
  versionDescription: featherText.optional(),
  downloadURL: featherUrl.optional(),
  iconURL: featherUrl.optional(),
  tintColor: z.string().max(100).optional(),
  size: featherSize.optional(),
  category: z.string().max(100).optional(),
  beta: z.boolean().optional(),
  permissions: z
    .array(z.object({ type: z.string().max(500), usageDescription: featherText }))
    .max(100)
    .optional(),
  appPermissions: z
    .object({
      entitlements: z.array(z.string().max(500)).max(500).optional(),
      privacy: z
        .union([
          z.array(z.object({ name: z.string().max(500), usageDescription: featherText })).max(500),
          z.record(z.string().max(500), featherText),
        ])
        .optional(),
    })
    .optional(),
  screenshots: z
    .union([
      featherScreenshotList,
      z.object({
        iphone: featherScreenshotList.optional(),
        ipad: featherScreenshotList.optional(),
      }),
    ])
    .optional(),
  screenshotURLs: z.array(featherUrl).max(100).optional(),
  marketplaceID: z.string().max(500).optional(),
  versions: z.array(featherVersionSchema).max(1000).optional(),
});
export const featherRepositorySchema = z.object({
  identifier: z.string().max(500).optional(),
  name: z.string().max(500).optional(),
  subtitle: featherText.optional(),
  description: featherText.optional(),
  website: featherUrl.optional(),
  iconURL: featherUrl.optional(),
  headerURL: featherUrl.optional(),
  tintColor: z.string().max(100).optional(),
  patreonURL: featherUrl.optional(),
  featuredApps: z.array(z.string().max(500)).max(20000).optional(),
  news: z
    .array(
      z.object({
        identifier: z.string().max(500),
        title: z.string().max(500),
        caption: featherText,
        tintColor: z.string().max(100).optional(),
        imageURL: featherUrl.optional(),
        url: featherUrl.optional(),
        appID: z.string().max(500).optional(),
        date: featherDate.optional(),
        notify: z.boolean().optional(),
      }),
    )
    .max(20000)
    .optional(),
  apps: z.array(featherAppSchema).min(1).max(20000),
});
export const featherSourcesSchema = z.object({
  sources: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      revision: z.number().int(),
      state: z.string(),
      canonicalUrl: z.string().nullable(),
    }),
  ),
});
export const featherFeedSchema = z.object({
  sourceId: z.string(),
  snapshot: z.string(),
  repository: featherRepositorySchema,
});
export const featherDownloadInputSchema = z.object({
  sourceId: z.string().min(1).max(200),
  releaseId: z.string().min(1).max(200),
  snapshot: z.string().min(1).max(200),
});
export const featherDownloadSchema = z.object({
  url: featherUrl,
  headers: z.object({}).strict(),
  expiresAt: timestamp,
});
export type FeatherRepository = z.infer<typeof featherRepositorySchema>;
export type FeatherFeed = z.infer<typeof featherFeedSchema>;
export type FeatherDownloadInput = z.infer<typeof featherDownloadInputSchema>;
