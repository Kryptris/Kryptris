import type { EntryData, EntryInput, EntryType, VaultEntry } from '../../shared/models';

export function emptyEntryData(type: EntryType): EntryData {
  switch (type) {
    case 'credential':
      return {
        type,
        value: { username: '', password: '', websites: [], appNames: [] },
      };
    case 'secure-note':
      return { type, value: { markdown: '' } };
    case 'credit-card':
      return {
        type,
        value: {
          cardName: '',
          cardholder: '',
          number: '',
          expiryMonth: 0,
          expiryYear: 0,
          cvc: '',
          pin: '',
          issuer: '',
          cardType: '',
          billingAddress: '',
          servicePhone: '',
          website: '',
        },
      };
    case 'identity':
      return {
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
      };
    case 'wifi':
      return {
        type,
        value: {
          ssid: '',
          password: '',
          security: 'WPA2',
          hidden: false,
          routerAddress: '',
          routerUsername: '',
        },
      };
    case 'software-license':
      return {
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
      };
    case 'ssh-key':
      return {
        type,
        value: {
          host: '',
          port: 22,
          username: '',
          keyType: '',
          fingerprint: '',
          publicKey: '',
          privateKey: '',
          passphrase: '',
        },
      };
    case 'file':
      return { type, value: { description: '' } };
    case 'custom':
      return { type, value: { description: '' } };
  }
}

export function emptyEntryInput(type: EntryType, title = ''): EntryInput {
  return {
    title,
    folderId: null,
    tags: [],
    favorite: false,
    note: '',
    customFields: [],
    data: emptyEntryData(type),
  };
}

export function entrySubtitle(entry: VaultEntry): string {
  switch (entry.data.type) {
    case 'credential':
      return entry.data.value.username || entry.data.value.websites[0] || 'Zugangsdaten';
    case 'secure-note':
      return 'Sichere Notiz';
    case 'credit-card':
      return entry.data.value.cardholder || entry.data.value.issuer || 'Kreditkarte';
    case 'identity':
      return (
        [entry.data.value.firstName, entry.data.value.lastName].filter(Boolean).join(' ') ||
        'Identitaet'
      );
    case 'wifi':
      return entry.data.value.ssid || 'WLAN';
    case 'software-license':
      return entry.data.value.manufacturer || entry.data.value.product || 'Softwarelizenz';
    case 'ssh-key':
      return entry.data.value.host || 'SSH-Schluessel';
    case 'file':
      return 'Datei';
    case 'custom':
      return 'Sonstiger Eintrag';
  }
}
