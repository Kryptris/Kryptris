import { z } from 'zod';

import { ENTRY_TYPES } from './models';

const idSchema = z.string().uuid();
const titleSchema = z.string().trim().min(1).max(200);
const shortTextSchema = z.string().max(2_000);
const longTextSchema = z.string().max(1_000_000);
const passwordSchema = z.string().min(12).max(1_024);
const colorSchema = z.string().regex(/^#[0-9a-fA-F]{6}$/);
const fieldPathSchema = z
  .string()
  .min(1)
  .max(160)
  .regex(/^[a-zA-Z0-9_.[\]-]+$/);
const localWindowsFolderPathSchema = z
  .string()
  .min(3)
  .max(32_767)
  .refine(
    (value) => /^[A-Za-z]:[\\/](?![\\/])/u.test(value) && !value.includes('\0'),
    'Ein lokaler absoluter Windows-Pfad ist erforderlich.',
  );

const customFieldSchema = z
  .object({
    id: idSchema,
    label: z.string().trim().min(1).max(100),
    type: z.enum(['text', 'secret', 'url', 'number', 'date', 'boolean']),
    value: z.union([longTextSchema, z.number().finite(), z.boolean()]),
    secret: z.boolean(),
    searchable: z.boolean(),
    order: z.number().int().min(0).max(1_000),
  })
  .strict();

const totpConfigurationSchema = z
  .object({
    secret: z.string().trim().min(16).max(512),
    issuer: z.string().max(200),
    account: z.string().max(320),
    algorithm: z.enum(['SHA1', 'SHA256', 'SHA512']),
    digits: z.union([z.literal(6), z.literal(8)]),
    period: z.number().int().min(15).max(120),
  })
  .strict();

const credentialDataSchema = z
  .object({
    username: shortTextSchema,
    password: longTextSchema,
    websites: z.array(z.string().max(2_048)).max(50),
    appNames: z.array(z.string().max(200)).max(50),
    totp: totpConfigurationSchema.optional(),
  })
  .strict();

const identityAddressSchema = z
  .object({
    id: idSchema,
    label: z.string().max(100),
    street: shortTextSchema,
    postalCode: z.string().max(40),
    city: z.string().max(200),
    region: z.string().max(200),
    country: z.string().max(200),
  })
  .strict();

const entryDataSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('credential'), value: credentialDataSchema }).strict(),
  z
    .object({
      type: z.literal('secure-note'),
      value: z.object({ markdown: longTextSchema }).strict(),
    })
    .strict(),
  z
    .object({
      type: z.literal('credit-card'),
      value: z
        .object({
          cardName: shortTextSchema,
          cardholder: shortTextSchema,
          number: z.string().max(40),
          expiryMonth: z.number().int().min(0).max(12),
          expiryYear: z.number().int().min(0).max(9_999),
          cvc: z.string().max(12),
          pin: z.string().max(32),
          issuer: shortTextSchema,
          cardType: z.string().max(100),
          billingAddress: longTextSchema,
          servicePhone: z.string().max(100),
          website: z.string().max(2_048),
        })
        .strict(),
    })
    .strict(),
  z
    .object({
      type: z.literal('identity'),
      value: z
        .object({
          salutation: z.string().max(100),
          firstName: shortTextSchema,
          middleName: shortTextSchema,
          lastName: shortTextSchema,
          birthDate: z.string().max(64),
          emails: z.array(z.string().max(320)).max(20),
          phones: z.array(z.string().max(100)).max(20),
          addresses: z.array(identityAddressSchema).max(20),
          idNumber: shortTextSchema,
          passportNumber: shortTextSchema,
          taxNumber: shortTextSchema,
        })
        .strict(),
    })
    .strict(),
  z
    .object({
      type: z.literal('wifi'),
      value: z
        .object({
          ssid: shortTextSchema,
          password: longTextSchema,
          security: z.enum(['WPA3', 'WPA2', 'WPA', 'WEP', 'Offen', 'Andere']),
          hidden: z.boolean(),
          routerAddress: shortTextSchema,
          routerUsername: shortTextSchema,
        })
        .strict(),
    })
    .strict(),
  z
    .object({
      type: z.literal('software-license'),
      value: z
        .object({
          product: shortTextSchema,
          manufacturer: shortTextSchema,
          version: z.string().max(100),
          licenseKey: longTextSchema,
          licensedTo: shortTextSchema,
          purchaseDate: z.string().max(64),
          activationDate: z.string().max(64),
          expiryDate: z.string().max(64),
          orderNumber: shortTextSchema,
          downloadUrl: z.string().max(2_048),
          purchasePrice: z.string().max(100),
        })
        .strict(),
    })
    .strict(),
  z
    .object({
      type: z.literal('ssh-key'),
      value: z
        .object({
          host: shortTextSchema,
          port: z.number().int().min(1).max(65_535),
          username: shortTextSchema,
          keyType: z.string().max(100),
          fingerprint: z.string().max(512),
          publicKey: longTextSchema,
          privateKey: longTextSchema,
          passphrase: longTextSchema,
        })
        .strict(),
    })
    .strict(),
  z
    .object({
      type: z.literal('file'),
      value: z.object({ description: longTextSchema }).strict(),
    })
    .strict(),
  z
    .object({
      type: z.literal('custom'),
      value: z.object({ description: longTextSchema }).strict(),
    })
    .strict(),
]);

export const entryInputSchema = z
  .object({
    id: idSchema.optional(),
    title: titleSchema,
    folderId: idSchema.nullable(),
    tags: z.array(z.string().trim().min(1).max(80)).max(50),
    favorite: z.boolean(),
    note: longTextSchema,
    customFields: z.array(customFieldSchema).max(100),
    data: entryDataSchema,
  })
  .strict();

export const entryListQuerySchema = z
  .object({
    vaultId: idSchema,
    search: z.string().max(500),
    view: z.enum(['all', 'favorites', 'trash', 'recent']),
    types: z.array(z.enum(ENTRY_TYPES)).max(ENTRY_TYPES.length),
    tags: z.array(z.string().max(80)).max(50),
    folderId: idSchema.nullable(),
    security: z.array(z.enum(['good', 'info', 'warning', 'critical'])).max(4),
  })
  .strict();

export const passwordGeneratorOptionsSchema = z
  .object({
    mode: z.enum(['password', 'passphrase']),
    length: z.number().int().min(8).max(512),
    uppercase: z.boolean(),
    lowercase: z.boolean(),
    numbers: z.boolean(),
    symbols: z.boolean(),
    excludeSimilar: z.boolean(),
    excludedCharacters: z.string().max(256),
    requiredCharacters: z.string().max(256),
    minimumUppercase: z.number().int().min(0).max(512),
    minimumLowercase: z.number().int().min(0).max(512),
    minimumNumbers: z.number().int().min(0).max(512),
    minimumSymbols: z.number().int().min(0).max(512),
    wordCount: z.number().int().min(3).max(20),
    separator: z.string().min(1).max(10),
    capitalizeWords: z.boolean(),
    includeNumber: z.boolean(),
  })
  .strict();

export const vaultaSettingsSchema = z
  .object({
    autoLockSeconds: z.number().int().min(0).max(86_400),
    lockOnMinimize: z.boolean(),
    lockOnSystemLock: z.boolean(),
    lockOnSuspend: z.boolean(),
    clipboardClearSeconds: z.number().int().min(5).max(120),
    requireMasterForReveal: z.boolean(),
    contentProtection: z.boolean(),
    attachmentMaxBytes: z.number().int().min(1_048_576).max(1_073_741_824),
    backupFolder: localWindowsFolderPathSchema.nullable(),
    automaticBackups: z.boolean(),
    backupRotation: z
      .object({
        daily: z.number().int().min(0).max(365),
        weekly: z.number().int().min(0).max(104),
        monthly: z.number().int().min(0).max(120),
      })
      .strict(),
    auditMaxEvents: z.number().int().min(100).max(100_000),
    auditRetentionDays: z.number().int().min(1).max(3_650),
    reducedMotion: z.boolean(),
  })
  .strict();

const templateFieldSchema = z
  .object({
    label: z.string().trim().min(1).max(100),
    type: z.enum(['text', 'secret', 'url', 'number', 'date', 'boolean']),
    secret: z.boolean(),
    defaultValue: z.union([longTextSchema, z.number().finite(), z.boolean()]),
  })
  .strict();

export const entryTemplateSchema = z
  .object({
    id: idSchema,
    name: titleSchema,
    entryType: z.enum(ENTRY_TYPES),
    fields: z.array(templateFieldSchema).max(100),
    createdAt: z.string().datetime({ offset: true }),
    updatedAt: z.string().datetime({ offset: true }),
  })
  .strict();

export const importMappingSchema = z
  .object({
    title: z.string().max(200),
    username: z.string().max(200),
    password: z.string().max(200),
    url: z.string().max(200),
    note: z.string().max(200),
    folder: z.string().max(200),
    tags: z.string().max(200),
  })
  .strict();

const webauthnBase64UrlSchema = z
  .string()
  .min(1)
  .max(4_000_000)
  .regex(/^[A-Za-z0-9_-]+$/);

const webauthnRegistrationResponseSchema = z
  .object({
    clientDataJSON: webauthnBase64UrlSchema.max(64_000),
    attestationObject: webauthnBase64UrlSchema,
    transports: z.array(z.string().min(1).max(32)).max(16).optional(),
    publicKeyAlgorithm: z.number().int().optional(),
    publicKey: webauthnBase64UrlSchema.max(64_000).optional(),
    authenticatorData: webauthnBase64UrlSchema.max(64_000).optional(),
  })
  .strict();

const webauthnAuthenticationResponseSchema = z
  .object({
    clientDataJSON: webauthnBase64UrlSchema.max(64_000),
    authenticatorData: webauthnBase64UrlSchema.max(64_000),
    signature: webauthnBase64UrlSchema.max(64_000),
    userHandle: webauthnBase64UrlSchema.max(64_000).nullable().optional(),
  })
  .strict();

const webauthnResponseSchema = z
  .object({
    id: webauthnBase64UrlSchema.max(4_096),
    rawId: webauthnBase64UrlSchema.max(4_096),
    response: z.union([webauthnRegistrationResponseSchema, webauthnAuthenticationResponseSchema]),
    type: z.literal('public-key'),
    clientExtensionResults: z.object({}).strip(),
    authenticatorAttachment: z.enum(['platform', 'cross-platform']).optional(),
  })
  .strict();

export const IPC_REQUEST_SCHEMAS: Record<string, z.ZodType> = {
  'vaulta:system:state': z.undefined(),
  'vaulta:system:lock': z.undefined(),
  'vaulta:system:clear-clipboard': z.undefined(),
  'vaulta:setup:begin': z
    .object({ masterPassword: passwordSchema, vaultName: titleSchema, enableRecovery: z.boolean() })
    .strict(),
  'vaulta:setup:complete': z
    .object({
      pendingId: idSchema,
      confirmation: z.record(z.string().regex(/^\d+$/), z.string().max(16)),
    })
    .strict(),
  'vaulta:auth:unlock': z
    .object({
      masterPassword: z.string().min(1).max(1_024),
      totpCode: z
        .string()
        .regex(/^\d{6,8}$/)
        .optional(),
    })
    .strict(),
  'vaulta:auth:security-key-complete': z
    .object({
      challengeId: idSchema,
      response: webauthnResponseSchema,
      prfResult: z.string().max(512).optional(),
    })
    .strict(),
  'vaulta:auth:security-key-cancel': z.object({ challengeId: idSchema }).strict(),
  'vaulta:auth:recover': z
    .object({ recoveryKey: z.string().min(32).max(256), newMasterPassword: passwordSchema })
    .strict(),
  'vaulta:auth:change-master-password': z
    .object({ currentPassword: z.string().min(1).max(1_024), newPassword: passwordSchema })
    .strict(),
  'vaulta:vault:list': z.undefined(),
  'vaulta:vault:create': z.object({ name: titleSchema, color: colorSchema }).strict(),
  'vaulta:vault:update': z.object({ id: idSchema, name: titleSchema, color: colorSchema }).strict(),
  'vaulta:vault:delete': z
    .object({ id: idSchema, masterPassword: z.string().min(1).max(1_024) })
    .strict(),
  'vaulta:vault:select': idSchema,
  'vaulta:folder:list': idSchema,
  'vaulta:folder:create': z
    .object({ vaultId: idSchema, name: titleSchema, color: colorSchema })
    .strict(),
  'vaulta:folder:update': z
    .object({ vaultId: idSchema, id: idSchema, name: titleSchema, color: colorSchema })
    .strict(),
  'vaulta:folder:delete': z.object({ vaultId: idSchema, id: idSchema }).strict(),
  'vaulta:entry:list': entryListQuerySchema,
  'vaulta:entry:detail': z.object({ vaultId: idSchema, entryId: idSchema }).strict(),
  'vaulta:entry:edit-model': z.object({ vaultId: idSchema, entryId: idSchema }).strict(),
  'vaulta:entry:create': z.object({ vaultId: idSchema, entry: entryInputSchema }).strict(),
  'vaulta:entry:update': z
    .object({ vaultId: idSchema, entryId: idSchema, entry: entryInputSchema })
    .strict(),
  'vaulta:entry:trash': z.object({ vaultId: idSchema, entryId: idSchema }).strict(),
  'vaulta:entry:restore': z.object({ vaultId: idSchema, entryId: idSchema }).strict(),
  'vaulta:entry:purge': z
    .object({ vaultId: idSchema, entryId: idSchema, masterPassword: z.string().min(1).max(1_024) })
    .strict(),
  'vaulta:entry:toggle-favorite': z.object({ vaultId: idSchema, entryId: idSchema }).strict(),
  'vaulta:entry:reveal': z
    .object({
      vaultId: idSchema,
      entryId: idSchema,
      fieldPath: fieldPathSchema,
      masterPassword: z.string().min(1).max(1_024).optional(),
    })
    .strict(),
  'vaulta:entry:copy': z
    .object({ vaultId: idSchema, entryId: idSchema, fieldPath: fieldPathSchema })
    .strict(),
  'vaulta:entry:export-private-key': z
    .object({
      vaultId: idSchema,
      entryId: idSchema,
      masterPassword: z.string().min(1).max(1_024),
      confirmation: z.string().max(64),
    })
    .strict(),
  'vaulta:entry:wifi-qr': z.object({ vaultId: idSchema, entryId: idSchema }).strict(),
  'vaulta:attachment:add': z.object({ vaultId: idSchema, entryId: idSchema }).strict(),
  'vaulta:attachment:remove': z
    .object({ vaultId: idSchema, entryId: idSchema, attachmentId: idSchema })
    .strict(),
  'vaulta:attachment:export': z
    .object({ vaultId: idSchema, entryId: idSchema, attachmentId: idSchema })
    .strict(),
  'vaulta:attachment:preview': z
    .object({ vaultId: idSchema, entryId: idSchema, attachmentId: idSchema })
    .strict(),
  'vaulta:generator:generate': passwordGeneratorOptionsSchema,
  'vaulta:totp:code': z.object({ vaultId: idSchema, entryId: idSchema }).strict(),
  'vaulta:totp:copy': z.object({ vaultId: idSchema, entryId: idSchema }).strict(),
  'vaulta:totp:import-qr': z.enum(['file', 'screen']),
  'vaulta:security:scan': idSchema.optional(),
  'vaulta:backup:create': z.object({ automatic: z.boolean().optional() }).strict().optional(),
  'vaulta:backup:restore': z
    .object({
      credential: z.discriminatedUnion('type', [
        z.object({ type: z.literal('master'), value: z.string().min(1).max(1_024) }).strict(),
        z.object({ type: z.literal('recovery'), value: z.string().min(32).max(256) }).strict(),
      ]),
      newMasterPassword: passwordSchema.optional(),
    })
    .strict(),
  'vaulta:backup:choose-folder': z.undefined(),
  'vaulta:import:preview': z
    .object({
      vaultId: idSchema,
      format: z
        .enum([
          'bitwarden-json',
          'onepassword-csv',
          'lastpass-csv',
          'keepass-csv',
          'protonpass-json',
          'chrome-csv',
          'edge-csv',
          'firefox-csv',
          'generic-csv',
          'generic-json',
        ])
        .optional(),
      mapping: importMappingSchema.optional(),
    })
    .strict(),
  'vaulta:import:remap': z.object({ token: idSchema, mapping: importMappingSchema }).strict(),
  'vaulta:import:execute': z
    .object({
      token: idSchema,
      vaultId: idSchema,
      selectedRows: z.array(z.number().int().min(0)).max(100_000),
    })
    .strict(),
  'vaulta:export:execute': z
    .object({
      format: z.enum(['vaulta-backup', 'json', 'csv']),
      vaultIds: z.array(idSchema).min(1).max(1_000),
      masterPassword: z.string().min(1).max(1_024).optional(),
      warningAccepted: z.boolean(),
      confirmation: z.string().max(64),
      includeAttachments: z.boolean(),
    })
    .strict(),
  'vaulta:audit:list': z
    .object({
      offset: z.number().int().min(0).optional(),
      limit: z.number().int().min(1).max(1_000).optional(),
    })
    .strict()
    .optional(),
  'vaulta:settings:get': z.undefined(),
  'vaulta:settings:update': z
    .object({
      settings: vaultaSettingsSchema,
      masterPassword: z.string().min(1).max(1_024).optional(),
    })
    .strict(),
  'vaulta:factor:status': z.undefined(),
  'vaulta:factor:totp-begin': z.object({ masterPassword: z.string().min(1).max(1_024) }).strict(),
  'vaulta:factor:totp-complete': z
    .object({ setupId: idSchema, code: z.string().regex(/^\d{6,8}$/) })
    .strict(),
  'vaulta:factor:totp-remove': z.object({ masterPassword: z.string().min(1).max(1_024) }).strict(),
  'vaulta:factor:security-key-begin': z
    .object({ name: titleSchema, masterPassword: z.string().min(1).max(1_024) })
    .strict(),
  'vaulta:factor:security-key-complete': z
    .object({
      challengeId: idSchema,
      response: webauthnResponseSchema,
      prfResult: z.string().max(512).optional(),
    })
    .strict(),
  'vaulta:factor:security-key-remove': z
    .object({ id: idSchema, masterPassword: z.string().min(1).max(1_024) })
    .strict(),
  'vaulta:recovery:rotate': z.object({ masterPassword: z.string().min(1).max(1_024) }).strict(),
  'vaulta:recovery:rotate-complete': z
    .object({
      pendingId: idSchema,
      confirmation: z.record(z.string().regex(/^\d+$/), z.string().max(16)),
    })
    .strict(),
  'vaulta:template:list': z.undefined(),
  'vaulta:template:save': z
    .object({
      id: idSchema.optional(),
      name: titleSchema,
      entryType: z.enum(ENTRY_TYPES),
      fields: z.array(templateFieldSchema).max(100),
    })
    .strict(),
  'vaulta:template:delete': idSchema,
  'vaulta:report:generate': z.undefined(),
  'vaulta:window:minimize': z.undefined(),
  'vaulta:window:toggle-maximize': z.undefined(),
  'vaulta:window:close': z.undefined(),
};
