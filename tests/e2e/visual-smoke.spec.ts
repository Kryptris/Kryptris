import { access, readFile } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';
import { createServer, type Server } from 'node:http';

import { expect, test } from '@playwright/test';

const RENDERER_ROOT = resolve(process.cwd(), 'dist', 'renderer');
const MIME_TYPES: Record<string, string> = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
};

let server: Server | undefined;
let rendererOrigin = '';

test.beforeAll(async () => {
  await access(resolve(RENDERER_ROOT, 'index.html')).catch(() => {
    throw new Error('Das Produktionsbundle fehlt. Vor dem E2E-Test `npm run build` ausführen.');
  });

  server = createServer((request, response) => {
    try {
      const pathname = decodeURIComponent(new URL(request.url ?? '/', 'http://127.0.0.1').pathname);
      const relativePath = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
      const filePath = resolve(RENDERER_ROOT, relativePath);

      if (filePath !== RENDERER_ROOT && !filePath.startsWith(`${RENDERER_ROOT}${sep}`)) {
        response.writeHead(403).end('Forbidden');
        return;
      }

      void readFile(filePath)
        .then((content) => {
          response.writeHead(200, {
            'Cache-Control': 'no-store',
            'Content-Type':
              MIME_TYPES[extname(filePath).toLowerCase()] ?? 'application/octet-stream',
          });
          response.end(content);
        })
        .catch(() => {
          response.writeHead(404).end('Not found');
        });
    } catch {
      response.writeHead(400).end('Bad request');
    }
  });

  await new Promise<void>((resolveStart, rejectStart) => {
    server?.once('error', rejectStart);
    server?.listen(0, '127.0.0.1', () => resolveStart());
  });

  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('E2E-Server konnte nicht starten.');
  rendererOrigin = `http://127.0.0.1:${String(address.port)}`;
});

test.afterAll(async () => {
  if (!server) return;
  await new Promise<void>((resolveClose, rejectClose) => {
    server?.close((error) => (error ? rejectClose(error) : resolveClose()));
  });
});

test('lädt das Produktionsbundle im dreispaltigen Workspace', async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'dark' });
  await page.addInitScript(installSyntheticVaultaApi, 'workspace');

  const response = await page.goto(rendererOrigin, { waitUntil: 'networkidle' });
  expect(response?.ok()).toBe(true);

  const sidebar = page.locator('.sidebar');
  const entryList = page.locator('.entry-list-panel');
  const detailPanel = page.getByRole('region', { name: 'Details für GitHub' });

  await expect(page.getByPlaceholder('Tresor durchsuchen')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'GitHub' })).toBeVisible();
  await expect(sidebar).toBeVisible();
  await expect(entryList).toBeVisible();
  await expect(detailPanel).toBeVisible();

  const [sidebarBox, entryListBox, detailBox] = await Promise.all([
    sidebar.boundingBox(),
    entryList.boundingBox(),
    detailPanel.boundingBox(),
  ]);
  expect(sidebarBox).not.toBeNull();
  expect(entryListBox).not.toBeNull();
  expect(detailBox).not.toBeNull();
  expect(sidebarBox!.x + sidebarBox!.width).toBeLessThanOrEqual(entryListBox!.x + 1);
  expect(entryListBox!.x + entryListBox!.width).toBeLessThanOrEqual(detailBox!.x + 1);

  const screenshotPath = testInfo.outputPath('vaulta-workspace.png');
  await page.screenshot({
    path: screenshotPath,
    fullPage: true,
    animations: 'disabled',
    caret: 'hide',
  });
  await testInfo.attach('vaulta-production-workspace', {
    path: screenshotPath,
    contentType: 'image/png',
  });
});

test('hält das Setup in der minimalen Fenstergröße vollständig bedienbar', async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 1080, height: 680 });
  await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'dark' });
  await page.addInitScript(installSyntheticVaultaApi, 'setup');

  const response = await page.goto(rendererOrigin, { waitUntil: 'networkidle' });
  expect(response?.ok()).toBe(true);

  await expect(page.getByRole('heading', { name: 'Dein sicherer, lokaler Tresor' })).toBeVisible();
  await page.getByLabel('Master-Passwort', { exact: true }).fill('SehrLange-Testpassphrase-2026');
  await page
    .getByLabel('Master-Passwort wiederholen', { exact: true })
    .fill('SehrLange-Testpassphrase-2026');

  const submit = page.getByRole('button', { name: 'Profil sicher einrichten' });
  await expect(submit).toBeEnabled();
  await expect(submit).toBeInViewport({ ratio: 1 });

  const screenshotPath = testInfo.outputPath('vaulta-setup-minimum-window.png');
  await page.screenshot({
    path: screenshotPath,
    animations: 'disabled',
    caret: 'hide',
  });
  await testInfo.attach('vaulta-setup-minimum-window', {
    path: screenshotPath,
    contentType: 'image/png',
  });
});

test('hält die Sicherheitszentrale bei 200-Prozent-äquivalenter Breite bedienbar', async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 720, height: 800 });
  await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'dark' });
  await page.addInitScript(installSyntheticVaultaApi, 'workspace');

  const response = await page.goto(rendererOrigin, { waitUntil: 'networkidle' });
  expect(response?.ok()).toBe(true);

  await page.getByRole('button', { name: 'Navigation öffnen' }).click();
  await page.getByRole('button', { name: 'Sicherheitszentrale' }).click();

  await expect(page.getByRole('heading', { name: 'Sicherheitszentrale' })).toBeVisible();
  await expect(page.getByText(/keine Aussage über Malware/u)).toBeVisible();
  await expect(page.getByLabel(/Lokaler Vorsorgewert 78 von 100/u)).toBeVisible();

  const recoveryPanel = page
    .getByRole('heading', { name: 'Wiederherstellungsbereitschaft' })
    .locator('xpath=ancestor::section[1]');
  await recoveryPanel.getByRole('button', { name: 'Schlüssel lokal testen' }).click();
  const dialog = page.getByRole('dialog', { name: 'Wiederherstellungsschlüssel testen' });
  await dialog.getByLabel('Wiederherstellungsschlüssel').fill('TEST-SCHLUESSEL-NUR-E2E');
  await dialog.getByRole('button', { name: 'Schlüssel lokal prüfen' }).click();
  await expect(dialog).not.toBeVisible();

  const noHorizontalOverflow = await page
    .locator('.security-center')
    .evaluate((element) => element.scrollWidth <= element.clientWidth);
  expect(noHorizontalOverflow).toBe(true);

  const screenshotPath = testInfo.outputPath('kryptris-security-center-scaled.png');
  await page.screenshot({
    path: screenshotPath,
    fullPage: true,
    animations: 'disabled',
    caret: 'hide',
  });
  await testInfo.attach('kryptris-security-center-scaled', {
    path: screenshotPath,
    contentType: 'image/png',
  });
});

test('durchläuft die lokale Dubletten- und Datenqualitätsprüfung', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'dark' });
  await page.addInitScript(installSyntheticVaultaApi, 'workspace');

  const response = await page.goto(rendererOrigin, { waitUntil: 'networkidle' });
  expect(response?.ok()).toBe(true);

  await page.getByRole('button', { name: 'Datenpflege' }).click();
  await expect(page.getByRole('heading', { name: 'Dubletten und Datenqualität' })).toBeVisible();
  await page.getByRole('button', { name: 'Dubletten prüfen', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Keine möglichen Dubletten' })).toBeVisible();

  await page.getByRole('tab', { name: /Datenqualität/u }).click();
  await page.getByRole('button', { name: 'Datenqualität prüfen', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Keine Datenqualitätsbefunde' })).toBeVisible();
  await expect(page.getByText('Die Prüfung hat keinen Netzwerkzugriff verwendet.')).toBeVisible();
});

test('öffnet in Chromium einen neuen Zugangsdaten-Eintrag mit stabilen Formularfeldern', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'dark' });
  await page.addInitScript(installSyntheticVaultaApi, 'workspace');

  const response = await page.goto(rendererOrigin, { waitUntil: 'networkidle' });
  expect(response?.ok()).toBe(true);

  await page.locator('.topbar__new').click();
  const dialog = page.getByRole('dialog', { name: 'Neuen Eintrag anlegen' });
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Zugangsdaten', exact: true }).click();
  await dialog.locator('input[name="username"]').fill('smoke@example.test');
  await dialog.locator('input[name="password"]').fill('Smoke-Test-Passwort!123');

  await expect(dialog.locator('input[name="username"]')).toHaveValue('smoke@example.test');
  await expect(dialog.locator('input[name="password"]')).toHaveValue('Smoke-Test-Passwort!123');
});

test('virtualisiert einen synthetischen Tresor mit 10.000 EintrÃ¤gen und behÃ¤lt die Tastaturfokussierung', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'dark' });
  await page.addInitScript(installSyntheticVaultaApi, 'large-vault');

  const response = await page.goto(rendererOrigin, { waitUntil: 'networkidle' });
  expect(response?.ok()).toBe(true);

  const entryList = page.locator('.entry-list[role="listbox"]');
  await expect(entryList).toBeVisible();
  const initialOptionCount = await entryList.getByRole('option').count();
  expect(initialOptionCount).toBeGreaterThan(0);
  expect(initialOptionCount).toBeLessThan(40);

  await entryList.getByRole('option').first().focus();
  await page.keyboard.press('End');
  await expect(entryList.getByText('Synthetischer Eintrag 10000')).toBeVisible();
  await expect(page.locator('.entry-row:focus')).toContainText('Synthetischer Eintrag 10000');

  await page.getByPlaceholder('Tresor durchsuchen').fill('Eintrag 09999');
  await expect(entryList.getByText('Synthetischer Eintrag 09999')).toBeVisible();
  await expect(entryList.getByRole('option')).toHaveCount(1);
});

/**
 * Läuft vollständig im Browserkontext. Die Bridge enthält ausschließlich statische
 * Beispieldaten und berührt weder Electron noch das lokale Vaulta-Datenverzeichnis.
 */
function installSyntheticVaultaApi(mode: string) {
  const now = '2026-07-14T10:30:00.000Z';
  const syntheticEntryCount = mode === 'large-vault' ? 10_000 : 4;
  const settings = {
    autoLockSeconds: 300,
    lockOnMinimize: false,
    lockOnSystemLock: true,
    lockOnSuspend: true,
    clipboardClearSeconds: 30,
    requireMasterForReveal: false,
    contentProtection: true,
    minimizeToTray: false,
    closeToTray: false,
    startWithWindows: false,
    startMinimized: false,
    focusMode: false,
    localReminders: { rotation: false, expiry: false, backup: false },
    onboardingCompleted: true,
    attachmentMaxBytes: 104_857_600,
    backupFolder: null,
    automaticBackups: false,
    backupRotation: { daily: 7, weekly: 4, monthly: 6 },
    auditMaxEvents: 5_000,
    auditRetentionDays: 180,
    trashRetentionDays: null,
    reducedMotion: true,
  };
  const vault = {
    id: 'synthetic-vault',
    name: 'Privat',
    color: '#25d2c8',
    entryCount: syntheticEntryCount,
    deletedCount: 0,
    updatedAt: now,
  };
  const state = {
    hasProfile: true,
    locked: false,
    activeVaultId: vault.id,
    vaults: [vault],
    factorStatus: { totpEnabled: true, securityKeys: [], recoveryEnabled: true },
    settings,
    autoLockAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    version: '1.0.0-smoke',
  };
  const initialState =
    mode === 'setup'
      ? {
          ...state,
          hasProfile: false,
          locked: true,
          activeVaultId: null,
          vaults: [],
          factorStatus: { totpEnabled: false, securityKeys: [], recoveryEnabled: false },
          settings: null,
          autoLockAt: null,
        }
      : state;
  const defaultSummaries = [
    {
      id: 'github',
      vaultId: vault.id,
      type: 'credential',
      title: 'GitHub',
      subtitle: 'lauri@example.de',
      favorite: true,
      tags: ['Entwicklung', 'Arbeit'],
      folderId: 'work',
      securityState: 'good',
      updatedAt: now,
      deletedAt: null,
    },
    {
      id: 'mail',
      vaultId: vault.id,
      type: 'credential',
      title: 'Proton Mail',
      subtitle: 'lauri@example.de',
      favorite: true,
      tags: ['Privat'],
      folderId: null,
      securityState: 'good',
      updatedAt: '2026-07-13T20:15:00.000Z',
      deletedAt: null,
    },
    {
      id: 'wifi',
      vaultId: vault.id,
      type: 'wifi',
      title: 'Zuhause WLAN',
      subtitle: 'Vaulta-Netz',
      favorite: false,
      tags: ['Zuhause'],
      folderId: null,
      securityState: 'info',
      updatedAt: '2026-07-12T08:00:00.000Z',
      deletedAt: null,
    },
    {
      id: 'card',
      vaultId: vault.id,
      type: 'credit-card',
      title: 'Reisekarte',
      subtitle: '•••• 4242',
      favorite: false,
      tags: ['Finanzen'],
      folderId: 'finance',
      securityState: 'warning',
      updatedAt: '2026-07-10T16:45:00.000Z',
      deletedAt: null,
    },
  ];
  const summaries =
    mode === 'large-vault'
      ? Array.from({ length: syntheticEntryCount }, (_, index) => {
          const ordinal = String(index + 1).padStart(5, '0');
          return {
            id: `synthetic-entry-${ordinal}`,
            vaultId: vault.id,
            type: 'credential',
            title: `Synthetischer Eintrag ${ordinal}`,
            subtitle: 'synthetisch@example.test',
            favorite: false,
            tags: [],
            folderId: null,
            securityState: 'good',
            updatedAt: now,
            deletedAt: null,
          };
        })
      : defaultSummaries;
  const detail = {
    id: 'github',
    vaultId: vault.id,
    type: 'credential',
    title: 'GitHub',
    favorite: true,
    tags: ['Entwicklung', 'Arbeit'],
    folderId: 'work',
    note: 'Primärer Entwicklungsaccount mit Zwei-Faktor-Authentifizierung.',
    fields: [
      {
        path: 'data.username',
        label: 'Benutzername',
        kind: 'text',
        secret: false,
        value: 'lauri@example.de',
        copyable: true,
        openable: false,
      },
      {
        path: 'data.password',
        label: 'Passwort',
        kind: 'secret',
        secret: true,
        copyable: true,
        openable: false,
      },
      {
        path: 'data.websites.0',
        label: 'Webseite',
        kind: 'url',
        secret: false,
        value: 'https://github.com',
        copyable: true,
        openable: true,
      },
    ],
    attachments: [],
    lifecycle: {
      rotationIntervalDays: 90,
      nextRotationDate: '2026-10-12',
      rotationExcluded: false,
      twoFactorStatus: 'active',
      expiryReminderDate: null,
    },
    createdAt: '2026-01-10T09:00:00.000Z',
    updatedAt: now,
    deletedAt: null,
  };
  const securityReport = {
    generatedAt: now,
    score: 92,
    counts: { good: 3, info: 1, warning: 0, critical: 0 },
    findings: [],
    networkUsed: false,
  };
  const securityCenterReport = {
    generatedAt: now,
    score: 78,
    cards: [
      {
        id: 'credentials',
        severity: 'warning',
        findingCodes: ['credential-findings'],
        count: 1,
        calculatedAt: now,
        action: 'review-credentials',
      },
      {
        id: 'data-quality',
        severity: 'good',
        findingCodes: [],
        count: 0,
        calculatedAt: now,
        action: 'none',
      },
      {
        id: 'factors',
        severity: 'good',
        findingCodes: [],
        count: 0,
        calculatedAt: now,
        action: 'none',
      },
      {
        id: 'backup',
        severity: 'warning',
        findingCodes: ['automatic-backup-disabled'],
        count: 1,
        calculatedAt: now,
        action: 'open-backups',
      },
      {
        id: 'recovery',
        severity: 'warning',
        findingCodes: ['recovery-never-tested'],
        count: 1,
        calculatedAt: now,
        action: 'test-recovery',
      },
      {
        id: 'kdf',
        severity: 'good',
        findingCodes: [],
        count: 0,
        calculatedAt: now,
        action: 'none',
      },
      {
        id: 'integrity',
        severity: 'info',
        findingCodes: ['integrity-not-run'],
        count: 1,
        calculatedAt: null,
        action: 'run-integrity',
      },
      {
        id: 'breach-list',
        severity: 'good',
        findingCodes: [],
        count: 0,
        calculatedAt: now,
        action: 'none',
      },
    ],
    entryFindings: [
      {
        id: 'security-finding-1',
        vaultId: vault.id,
        vaultName: vault.name,
        entryId: 'mail',
        entryTitle: 'Proton Mail',
        kind: 'old',
        severity: 'warning',
        title: 'Passwort ist schon länger unverändert',
        recommendation: 'Prüfe, ob eine Rotation beim Dienst sinnvoll ist.',
      },
    ],
    networkUsed: false,
  };
  const recoveryReadiness = {
    state: 'never-tested',
    lastTestedAt: null,
    lastTestSucceeded: null,
    staleAfterDays: 180,
  };
  const breachListStatus = {
    state: 'ready',
    sourceLabel: 'Anonymisierte Testliste',
    sourceDate: '2026-07-01',
    importedAt: now,
    recordCount: 42_000,
    corpusSha256: '0'.repeat(64),
    networkUsed: false,
  };
  const noOp = () => Promise.resolve();
  const noSubscription = () => () => undefined;

  const api = {
    system: {
      getState: () => Promise.resolve(initialState),
      lock: noOp,
      clearClipboard: () => Promise.resolve(true),
    },
    setup: {
      begin: () => Promise.resolve({ pendingId: 'synthetic-setup', recovery: null }),
      complete: () => Promise.resolve(state),
    },
    auth: {
      unlock: () => Promise.resolve({ status: 'unlocked' }),
      completeSecurityKey: () => Promise.resolve({ verified: true, unlocked: true }),
      cancelSecurityKey: noOp,
      recover: () => Promise.resolve(state),
      changeMasterPassword: noOp,
    },
    vaults: {
      list: () => Promise.resolve([vault]),
      create: () => Promise.resolve(vault),
      update: () => Promise.resolve(vault),
      delete: noOp,
      select: noOp,
      listFolders: () =>
        Promise.resolve([
          { id: 'work', name: 'Arbeit', color: '#8b5cf6', createdAt: now },
          { id: 'finance', name: 'Finanzen', color: '#25d2c8', createdAt: now },
        ]),
      createFolder: () =>
        Promise.resolve({ id: 'folder', name: 'Neu', color: '#25d2c8', createdAt: now }),
      updateFolder: () =>
        Promise.resolve({ id: 'folder', name: 'Neu', color: '#25d2c8', createdAt: now }),
      deleteFolder: noOp,
    },
    entries: {
      list: (query: { search?: string }) => {
        const search = query.search?.trim().toLocaleLowerCase('de-DE') ?? '';
        return Promise.resolve(
          search.length === 0
            ? summaries
            : summaries.filter((entry) => entry.title.toLocaleLowerCase('de-DE').includes(search)),
        );
      },
      getDetail: () => Promise.resolve(detail),
      getEditModel: () => Promise.reject(new Error('Im visuellen Smoke-Test nicht benötigt.')),
      create: () => Promise.resolve(summaries[0]),
      update: () => Promise.resolve(summaries[0]),
      moveToTrash: noOp,
      restore: noOp,
      purge: noOp,
      toggleFavorite: () => Promise.resolve(false),
      reveal: () => Promise.resolve('synthetisches-geheimnis'),
      copy: noOp,
      exportPrivateKey: () => Promise.resolve(true),
      wifiQr: () => Promise.resolve('data:image/png;base64,iVBORw0KGgo='),
    },
    attachments: {
      add: () => Promise.resolve(null),
      remove: noOp,
      export: () => Promise.resolve(true),
      preview: () => Promise.resolve({ kind: 'text', mediaType: 'text/plain', data: '' }),
    },
    generator: {
      generate: () =>
        Promise.resolve({
          value: 'synthetisch-Nur-Für-Tests-42!',
          score: 4,
          label: 'Stark',
          crackTime: 'sehr lange',
        }),
    },
    totp: {
      getCode: () => Promise.resolve({ code: '123456', period: 30, remainingSeconds: 24 }),
      copy: noOp,
      importQr: () => Promise.resolve(null),
    },
    security: {
      scan: () => Promise.resolve(securityReport),
      scanCenter: () => Promise.resolve(securityCenterReport),
      getRecoveryReadiness: () => Promise.resolve(recoveryReadiness),
      testRecoveryReadiness: () =>
        Promise.resolve({
          ...recoveryReadiness,
          state: 'ready',
          lastTestedAt: now,
          lastTestSucceeded: true,
        }),
      scanIntegrity: () =>
        Promise.resolve({
          reportId: 'synthetic-integrity-report',
          generatedAt: now,
          success: true,
          scannedVaults: 1,
          scannedEntries: summaries.length,
          scannedAttachments: 0,
          findings: [],
          networkUsed: false,
        }),
      saveIntegrityReport: () => Promise.resolve(true),
      getBreachListStatus: () => Promise.resolve(breachListStatus),
      importBreachList: () => Promise.resolve(breachListStatus),
      scanBreachList: () =>
        Promise.resolve({
          generatedAt: now,
          checkedEntries: 2,
          checkedPasswords: 2,
          findings: [],
          networkUsed: false,
        }),
      removeBreachList: () =>
        Promise.resolve({
          state: 'not-configured',
          sourceLabel: null,
          sourceDate: null,
          importedAt: null,
          recordCount: 0,
          corpusSha256: null,
          networkUsed: false,
        }),
    },
    backup: {
      create: () => Promise.resolve(null),
      restore: () => Promise.resolve(null),
      chooseFolder: () => Promise.resolve(null),
    },
    transfer: {
      previewImport: () => Promise.resolve(null),
      previewDroppedImport: () => Promise.resolve(null),
      onDroppedImport: noSubscription,
      remapImport: () => Promise.reject(new Error('Im visuellen Smoke-Test nicht benötigt.')),
      executeImport: () => Promise.resolve({ imported: 0, skipped: 0, entryIds: [] }),
      export: () => Promise.resolve(null),
    },
    audit: { list: () => Promise.resolve([]) },
    settings: {
      get: () => Promise.resolve(settings),
      update: () => Promise.resolve(settings),
    },
    factors: {
      status: () => Promise.resolve(state.factorStatus),
      beginTotp: () =>
        Promise.resolve({
          setupId: 'synthetic-totp',
          secret: 'SYNTHETIC',
          uri: 'otpauth://totp/Vaulta:synthetic',
          qrDataUrl: 'data:image/png;base64,iVBORw0KGgo=',
          explanation: 'Synthetischer Testfaktor',
        }),
      completeTotp: noOp,
      removeTotp: noOp,
      beginSecurityKey: () =>
        Promise.resolve({ challengeId: 'synthetic-key', options: {}, prfSalt: 'AA' }),
      completeSecurityKey: () => Promise.resolve({ verified: true, mode: 'prf', warning: null }),
      removeSecurityKey: noOp,
      rotateRecovery: () =>
        Promise.resolve({
          pendingId: 'synthetic-recovery',
          recovery: {
            displayKey: 'AAAA-BBBB-CCCC',
            groups: ['AAAA', 'BBBB', 'CCCC'],
            confirmationIndexes: [0, 2],
          },
        }),
      completeRecoveryRotation: noOp,
    },
    templates: {
      list: () => Promise.resolve([]),
      save: () => Promise.reject(new Error('Im visuellen Smoke-Test nicht benötigt.')),
      delete: noOp,
    },
    reports: {
      generate: () =>
        Promise.resolve({
          generatedAt: now,
          vaultCount: 1,
          entryCount: summaries.length,
          favoriteCount: 2,
          trashCount: 0,
          attachmentCount: 0,
          attachmentBytes: 0,
          typeCounts: {
            credential: 2,
            'secure-note': 0,
            'credit-card': 1,
            identity: 0,
            wifi: 1,
            'software-license': 0,
            'ssh-key': 0,
            file: 0,
            custom: 0,
          },
          security: securityReport,
          oldestEntries: summaries,
          networkUsed: false,
        }),
    },
    productivity: {
      batch: ({ entryIds }: { entryIds: string[] }) =>
        Promise.resolve({ affected: entryIds.length, entryIds }),
      listSavedViews: () => Promise.resolve([]),
      saveSavedView: () => Promise.reject(new Error('Im visuellen Smoke-Test nicht benötigt.')),
      reorderSavedViews: () => Promise.resolve([]),
      deleteSavedView: noOp,
      listTags: () => Promise.resolve([]),
      renameTag: () => Promise.resolve(0),
      mergeTags: () => Promise.resolve(0),
      deleteTag: () => Promise.resolve(0),
    },
    quality: {
      scanDuplicates: () =>
        Promise.resolve({ candidates: [], activeEntryCount: summaries.length, truncated: false }),
      describeDuplicateMerge: () =>
        Promise.reject(new Error('Im visuellen Smoke-Test nicht benötigt.')),
      mergeDuplicates: () => Promise.reject(new Error('Im visuellen Smoke-Test nicht benötigt.')),
      scanDataQuality: () =>
        Promise.resolve({
          generatedAt: now,
          vaultId: vault.id,
          scannedEntries: summaries.length,
          findings: [],
          networkUsed: false,
        }),
      previewDataQualityFix: () =>
        Promise.reject(new Error('Im visuellen Smoke-Test nicht benötigt.')),
      applyDataQualityFix: () =>
        Promise.reject(new Error('Im visuellen Smoke-Test nicht benötigt.')),
      cancelJob: () => Promise.resolve(false),
    },
    window: {
      minimize: noOp,
      toggleMaximize: () => Promise.resolve(false),
      close: noOp,
    },
    events: {
      onLocked: noSubscription,
      onStateChanged: noSubscription,
      onClipboardCleared: noSubscription,
      onBackgroundWarning: noSubscription,
      onLocalJobProgress: noSubscription,
    },
  };

  Object.defineProperty(window, 'vaulta', {
    configurable: false,
    enumerable: true,
    writable: false,
    value: api,
  });
}
