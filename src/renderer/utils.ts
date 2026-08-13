import {
  createDefaultEntryLifecycleMetadata,
  type CustomField,
  type EntryInput,
  type EntryTemplate,
  type EntryType,
  type VaultEntry,
} from '../shared/models';

export const ENTRY_ACCENTS: Record<EntryType, string> = {
  credential: '#23d5cc',
  'secure-note': '#f2bd28',
  'credit-card': '#bb78ef',
  identity: '#67a6ff',
  wifi: '#31d6e4',
  'software-license': '#ef8e57',
  'ssh-key': '#77da70',
  file: '#7bb8fb',
  custom: '#a18afe',
};

export const formatDate = (value: string): string =>
  new Intl.DateTimeFormat('de-DE', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value));

export const formatBytes = (bytes: number): string =>
  new Intl.NumberFormat('de-DE', {
    style: 'unit',
    unit: bytes >= 1024 * 1024 ? 'megabyte' : 'kilobyte',
    unitDisplay: 'short',
    maximumFractionDigits: 1,
  }).format(bytes / (bytes >= 1024 * 1024 ? 1024 * 1024 : 1024));

export const getErrorMessage = (error: unknown): string => {
  if (error instanceof Error && error.message.trim()) return error.message;
  return 'Die Aktion konnte nicht abgeschlossen werden.';
};

const customField = (order: number): CustomField => ({
  id: crypto.randomUUID(),
  label: '',
  type: 'text',
  value: '',
  secret: false,
  searchable: true,
  order,
});

export const newCustomField = customField;

export const createEmptyEntry = (type: EntryType): EntryInput => {
  const common = {
    title: '',
    folderId: null,
    tags: [] as string[],
    favorite: false,
    note: '',
    customFields: [] as CustomField[],
    lifecycle: createDefaultEntryLifecycleMetadata(),
  };

  switch (type) {
    case 'credential':
      return {
        ...common,
        data: {
          type,
          value: { username: '', password: '', websites: [], appNames: [] },
        },
      };
    case 'secure-note':
      return { ...common, data: { type, value: { markdown: '' } } };
    case 'credit-card':
      return {
        ...common,
        data: {
          type,
          value: {
            cardName: '',
            cardholder: '',
            number: '',
            expiryMonth: 1,
            expiryYear: new Date().getFullYear(),
            cvc: '',
            pin: '',
            issuer: '',
            cardType: '',
            billingAddress: '',
            servicePhone: '',
            website: '',
          },
        },
      };
    case 'identity':
      return {
        ...common,
        data: {
          type,
          value: {
            salutation: '',
            firstName: '',
            middleName: '',
            lastName: '',
            birthDate: '',
            emails: [],
            phones: [],
            addresses: [],
            idNumber: '',
            passportNumber: '',
            taxNumber: '',
          },
        },
      };
    case 'wifi':
      return {
        ...common,
        data: {
          type,
          value: {
            ssid: '',
            password: '',
            security: 'WPA3',
            hidden: false,
            routerAddress: '',
            routerUsername: '',
          },
        },
      };
    case 'software-license':
      return {
        ...common,
        data: {
          type,
          value: {
            product: '',
            manufacturer: '',
            version: '',
            licenseKey: '',
            licensedTo: '',
            purchaseDate: '',
            activationDate: '',
            expiryDate: '',
            orderNumber: '',
            downloadUrl: '',
            purchasePrice: '',
          },
        },
      };
    case 'ssh-key':
      return {
        ...common,
        data: {
          type,
          value: {
            host: '',
            port: 22,
            username: '',
            keyType: 'Ed25519',
            fingerprint: '',
            publicKey: '',
            privateKey: '',
            passphrase: '',
          },
        },
      };
    case 'file':
      return { ...common, data: { type, value: { description: '' } } };
    case 'custom':
      return { ...common, data: { type, value: { description: '' } } };
  }
};

export const createEntryFromTemplate = (template: EntryTemplate): EntryInput => {
  const entry = createEmptyEntry(template.entryType);
  entry.title = template.name;
  entry.customFields = template.fields.map((field, order) => {
    const secret = field.secret || field.type === 'secret';
    return {
      id: crypto.randomUUID(),
      label: field.label,
      type: field.type,
      value: field.defaultValue,
      secret,
      searchable: !secret,
      order,
    };
  });
  return entry;
};

export const toEntryInput = (entry: VaultEntry): EntryInput => ({
  id: entry.id,
  title: entry.title,
  folderId: entry.folderId,
  tags: [...entry.tags],
  favorite: entry.favorite,
  note: entry.note,
  customFields: entry.customFields.map((field) => ({ ...field })),
  data: structuredClone(entry.data),
  lifecycle: { ...entry.lifecycle },
});
