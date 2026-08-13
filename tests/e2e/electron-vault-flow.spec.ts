import { randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { _electron as electron, expect, type Page, test } from '@playwright/test';

type VaultaElectronApp = Awaited<ReturnType<typeof electron.launch>>;

interface DialogTargets {
  importPath?: string;
  backupPath?: string;
  cleartextPath?: string;
}

test.use({ trace: 'off' });

test.skip(
  process.env.CODEX_SHELL === '1',
  'Die Codex-Desktop-Sandbox darf keine echte Workspace-GUI starten; Windows CI führt diesen Test aus.',
);

test('durchläuft Setup, vollständiges CRUD, Navigation-Härtung und Fresh-Restore in Electron', async () => {
  test.setTimeout(240_000);
  const testRoot = await mkdtemp(path.join(os.tmpdir(), 'vaulta-electron-e2e-'));
  const sourceUserData = path.join(testRoot, 'source-user-data');
  const restoredUserData = path.join(testRoot, 'restored-user-data');
  const importPath = path.join(testRoot, 'chrome-import.csv');
  const backupPath = path.join(testRoot, 'Vaulta-E2E.vaulta-backup');
  const cleartextPath = path.join(testRoot, 'Vaulta-E2E.json');
  const masterPassword = `Vaulta-E2E-Master-${randomUUID()}!Aa1`;
  const entryPassword = `Vaulta-E2E-Entry-${randomUUID()}!Aa1`;
  const importPassword = `Vaulta-E2E-Import-${randomUUID()}!Aa1`;
  const originalTitle = 'E2E Dienst';
  const updatedTitle = 'E2E Dienst aktualisiert';
  let sourceApp: VaultaElectronApp | undefined;
  let restoredApp: VaultaElectronApp | undefined;

  await writeFile(
    importPath,
    [
      'name,url,username,password,note',
      `E2E Importierter Dienst,https://import.example.test,import@example.test,${importPassword},Lokaler E2E-Import`,
    ].join('\r\n'),
    { encoding: 'utf8', mode: 0o600 },
  );

  try {
    sourceApp = await launchVaulta(sourceUserData);
    const page = await sourceApp.firstWindow();
    page.on('console', (message) =>
      console.log('Electron-Renderer-Konsole', message.type(), message.text()),
    );
    page.on('crash', () => console.log('Electron-Renderer-Crash'));
    page.on('pageerror', (error) =>
      console.log('Electron-Renderer-Fehler', error.message, '\n', error.stack),
    );
    await installControlledDialogs(sourceApp, { importPath, backupPath, cleartextPath });
    await waitForSetupScreen(page);

    const isolation = await page.evaluate(() => ({
      requireType: typeof (globalThis as Record<string, unknown>).require,
      processType: typeof (globalThis as Record<string, unknown>).process,
      bridgeKeys: Object.keys(window.vaulta).sort(),
      systemBridgeKeys: Object.keys(window.vaulta.system).sort(),
    }));
    expect(isolation.requireType).toBe('undefined');
    expect(isolation.processType).toBe('undefined');
    expect(isolation.bridgeKeys).toEqual([
      'attachments',
      'audit',
      'auth',
      'backup',
      'entries',
      'events',
      'factors',
      'generator',
      'productivity',
      'quality',
      'reports',
      'security',
      'settings',
      'setup',
      'system',
      'templates',
      'totp',
      'transfer',
      'vaults',
      'window',
    ]);
    expect(isolation.systemBridgeKeys).toEqual(['clearClipboard', 'getState', 'lock']);

    await fillInitialSetup(page, masterPassword);
    await page.getByRole('button', { name: 'Profil sicher einrichten' }).click();
    await expect(
      page.getByRole('heading', { name: 'Wiederherstellungsschlüssel sichern' }),
    ).toBeVisible({ timeout: 45_000 });

    await page.evaluate(() => window.vaulta.window.minimize());
    await expect
      .poll(async () => page.evaluate(async () => (await window.vaulta.system.getState()).locked))
      .toBe(true);
    await sourceApp.evaluate(({ BrowserWindow }) => {
      const window = BrowserWindow.getAllWindows()[0];
      window?.restore();
      window?.show();
      window?.focus();
    });
    await waitForSetupScreen(page);

    await fillInitialSetup(page, masterPassword);
    await page.getByRole('checkbox', { name: /Wiederherstellungsschlüssel erzeugen/u }).uncheck();
    await page.getByRole('button', { name: 'Profil sicher einrichten' }).click();

    const onboarding = page.getByRole('dialog', { name: 'Willkommen bei Kryptris' });
    await expect(onboarding).toBeVisible({ timeout: 45_000 });
    await onboarding.getByRole('button', { name: 'Einführung überspringen' }).click();
    await expect(onboarding).toHaveCount(0);
    await expect(page.getByPlaceholder('Tresor durchsuchen')).toBeVisible({ timeout: 45_000 });
    await page.getByLabel('Eintragsliste').getByRole('button', { name: 'Neuer Eintrag' }).click();
    const newEntryDialog = page.getByRole('dialog', { name: 'Neuen Eintrag anlegen' });
    await expect(newEntryDialog).toBeVisible();
    await newEntryDialog.getByRole('button', { name: 'Zugangsdaten', exact: true }).click();
    await newEntryDialog.getByLabel('Titel', { exact: true }).fill(originalTitle);
    const editorDiagnostics = await page.evaluate(() => ({
      readyState: document.readyState,
      url: window.location.href,
      dialogs: Array.from(document.querySelectorAll<HTMLElement>('[role="dialog"]')).map(
        (dialog) => ({
          activeTypes: Array.from(dialog.querySelectorAll<HTMLButtonElement>('.type-picker button'))
            .filter((button) => button.getAttribute('aria-pressed') === 'true')
            .map((button) => button.textContent?.trim() ?? ''),
          headings: Array.from(dialog.querySelectorAll('h2, h3')).map(
            (heading) => heading.textContent?.trim() ?? '',
          ),
          inputs: Array.from(dialog.querySelectorAll<HTMLInputElement>('input')).map((input) => ({
            ariaLabel: input.getAttribute('aria-label'),
            name: input.name,
            type: input.type,
          })),
        }),
      ),
      pageHeadings: Array.from(document.querySelectorAll('h1, h2, h3')).map(
        (heading) => heading.textContent?.trim() ?? '',
      ),
      text: document.body.textContent?.replace(/\s+/gu, ' ').trim().slice(0, 1_000) ?? '',
    }));
    const electronDiagnostics = await sourceApp.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows().map((window) => ({
        destroyed: window.isDestroyed(),
        rendererCrashed: window.webContents.isCrashed(),
        url: window.webContents.getURL(),
        visible: window.isVisible(),
      })),
    );
    console.log(
      'Electron-EntryEditor-Diagnose',
      JSON.stringify({ editorDiagnostics, electronDiagnostics, playwrightUrl: page.url() }),
    );
    await newEntryDialog.locator('input[name="username"]').fill('e2e@example.test');
    await newEntryDialog.locator('input[name="password"]').fill(entryPassword);
    await newEntryDialog.getByRole('button', { name: 'Eintrag verschlüsselt speichern' }).click();

    await expect(page.getByRole('heading', { name: originalTitle })).toBeVisible();
    const detailDiagnostics = await page.evaluate(() => ({
      buttons: Array.from(
        document.querySelectorAll<HTMLButtonElement>('.detail-header button'),
      ).map((button) => button.textContent?.trim() ?? ''),
      detailHeaderActionsHtml:
        document.querySelector('.detail-header__actions')?.outerHTML ?? '<fehlt>',
      toasts: Array.from(document.querySelectorAll('[role="status"], [role="alert"]')).map(
        (node) => node.textContent?.trim() ?? '',
      ),
    }));
    console.log('Electron-DetailPanel-Diagnose', JSON.stringify(detailDiagnostics));
    const actionabilitySamples: unknown[] = [];
    for (let index = 0; index < 5; index += 1) {
      const sample = await page.evaluate(() => {
        const button = Array.from(
          document.querySelectorAll<HTMLButtonElement>('.detail-header__actions button'),
        ).find((candidate) => candidate.textContent?.includes('Bearbeiten'));
        if (!button) return { found: false };
        const rect = button.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        const atPoint = document.elementFromPoint(centerX, centerY);
        return {
          found: true,
          rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
          disabled: button.disabled,
          visibility: getComputedStyle(button).visibility,
          display: getComputedStyle(button).display,
          opacity: getComputedStyle(button).opacity,
          pointerEvents: getComputedStyle(button).pointerEvents,
          elementAtPointIsButton: atPoint === button,
          elementAtPointTag: atPoint?.tagName ?? null,
          elementAtPointClass: atPoint instanceof HTMLElement ? atPoint.className : null,
        };
      });
      actionabilitySamples.push(sample);
      await page.waitForTimeout(200);
    }
    console.log('Electron-Bearbeiten-Actionability', JSON.stringify(actionabilitySamples));
    await page.getByTestId('edit-entry-button').click();
    await page.getByLabel('Titel').fill(updatedTitle);
    await page.getByRole('button', { name: 'Änderungen speichern' }).click();
    await expect(page.getByRole('heading', { name: updatedTitle })).toBeVisible();

    await page.getByRole('button', { name: 'In Papierkorb verschieben' }).click();
    await expect(page.getByText('Eintrag in den Papierkorb verschoben')).toBeVisible();
    await openSidebarNavigation(page);
    await page.getByRole('button', { name: 'Papierkorb', exact: true }).click();
    await page.getByRole('option', { name: new RegExp(updatedTitle, 'u') }).click();
    await page.getByTestId('restore-entry-button').click();
    await page.waitForTimeout(300);
    const restoreToastDiagnostics = await page.evaluate(() =>
      Array.from(document.querySelectorAll('[role="status"]')).map((node) => ({
        text: node.textContent?.trim() ?? '',
        className: node.getAttribute('class'),
      })),
    );
    console.log('Electron-Restore-Toast-Diagnose', JSON.stringify(restoreToastDiagnostics));
    await expect(page.getByText('Eintrag wiederhergestellt')).toBeVisible();
    await openSidebarNavigation(page);
    await page.getByRole('button', { name: 'Alle Einträge', exact: true }).first().click();
    await page.getByRole('option', { name: new RegExp(updatedTitle, 'u') }).click();
    await expect(page.getByRole('heading', { name: updatedTitle })).toBeVisible();

    await page.getByRole('button', { name: 'Kryptris jetzt sperren' }).click();
    await expect(page.getByRole('heading', { name: 'Willkommen zurück' })).toBeVisible();
    await page.getByLabel('Master-Passwort').fill(masterPassword);
    await page.getByRole('button', { name: 'Kryptris entsperren' }).click();

    await expect(page.getByPlaceholder('Tresor durchsuchen')).toBeVisible({ timeout: 30_000 });
    await expect(page.getByRole('heading', { name: updatedTitle })).toBeVisible();

    await openSidebarNavigation(page);
    await page.getByRole('button', { name: 'Sicherheitszentrale', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Sicherheitszentrale' })).toBeVisible();
    await expect(page.getByLabel(/Lokaler Vorsorgewert \d+ von 100/u)).toBeVisible({
      timeout: 30_000,
    });
    const integrityCard = page
      .locator('.security-center__detail-card')
      .filter({ hasText: 'Technische Integritätsprüfung' });
    await integrityCard.getByRole('button', { name: 'Integrität prüfen', exact: true }).click();
    await expect(integrityCard.getByText('Ohne Befund abgeschlossen', { exact: true })).toBeVisible(
      {
        timeout: 30_000,
      },
    );

    await openSidebarNavigation(page);
    await page.getByRole('button', { name: 'Import', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Daten importieren' })).toBeVisible();
    await page.getByRole('button', { name: /Google Chrome/u }).click();
    await page.getByRole('button', { name: 'Datei auswählen und lokal prüfen' }).click();
    await expect(page.getByText('E2E Importierter Dienst')).toBeVisible();
    await page.getByRole('button', { name: 'Auswahl verschlüsselt importieren' }).click();
    await expect(page.getByText('1 Einträge importiert')).toBeVisible();
    await openSidebarNavigation(page);
    await page.getByRole('button', { name: 'Alle Einträge', exact: true }).first().click();
    await expect(page.getByRole('heading', { name: 'E2E Importierter Dienst' })).toBeVisible();

    await openSidebarNavigation(page);
    await page.getByRole('button', { name: 'Export', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Daten exportieren' })).toBeVisible();
    await page.getByRole('button', { name: 'Exportziel wählen' }).click();
    await expect(page.getByText('Verschlüsseltes Backup exportiert')).toBeVisible();
    await expect.poll(async () => (await stat(backupPath)).size).toBeGreaterThan(0);

    await page.getByRole('button', { name: /^JSON/u }).click();
    await page
      .getByRole('checkbox', { name: 'Ich verstehe, dass die Datei unverschlüsselt ist.' })
      .check();
    await page.getByLabel('Zur Bestätigung EXPORTIEREN eingeben').fill('EXPORTIEREN');
    await page.getByLabel('Master-Passwort').fill(masterPassword);
    await page.getByRole('button', { name: 'Exportziel wählen' }).click();
    await expect(page.getByText('Klartextexport erstellt')).toBeVisible();

    const cleartextExport = JSON.parse(await readFile(cleartextPath, 'utf8')) as {
      format: string;
      vaults: Array<{ entries: Array<{ title: string }> }>;
    };
    expect(cleartextExport.format).toBe('vaulta-cleartext-json');
    expect(
      cleartextExport.vaults.flatMap((vault) => vault.entries.map((entry) => entry.title)),
    ).toEqual(expect.arrayContaining([updatedTitle, 'E2E Importierter Dienst']));
    expect((await readdir(testRoot)).some((name) => name.endsWith('.tmp'))).toBe(false);

    const remoteFetch = await page.evaluate(async () => {
      try {
        await fetch('https://example.com/vaulta-must-stay-offline');
        return 'allowed';
      } catch {
        return 'blocked';
      }
    });
    expect(remoteFetch).toBe('blocked');

    // Der eigentliche Navigations-Härtungstest (Popup-Block, blockierter
    // window.location.assign) läuft bewusst ganz am Ende des Tests, direkt vor
    // closeVaulta(sourceApp): Nach einem geblockten window.location.assign
    // bleibt Playwrights CDP-Verbindung zu diesem Fenster dauerhaft in einem
    // "Navigation läuft noch"-Zustand hängen (bekannter Electron/CDP-Quirk),
    // wodurch praktisch jede Locator-Interaktion (click, fill, expect, sogar
    // dispatchEvent/boundingBox) im Fenster danach nicht mehr zuverlässig
    // funktioniert. Deshalb erst alle CRUD-/Trash-/Import-/Export-Schritte mit
    // normalen, unbeeinträchtigten Locators erledigen und den Härtungscheck
    // zuletzt ausführen, wo direkt danach nur noch closeVaulta() folgt.

    await openSidebarNavigation(page);
    await page.getByRole('button', { name: 'Alle Einträge', exact: true }).first().click();
    await page.getByRole('option', { name: new RegExp(updatedTitle, 'u') }).click();
    await page.getByRole('button', { name: 'In Papierkorb verschieben' }).click();
    await expect(page.getByText('Eintrag in den Papierkorb verschoben')).toBeVisible();
    await openSidebarNavigation(page);
    await page.getByRole('button', { name: 'Papierkorb', exact: true }).click();
    await page.getByRole('option', { name: new RegExp(updatedTitle, 'u') }).click();
    await expect(page.getByRole('heading', { name: updatedTitle })).toBeVisible();
    await page.getByTestId('purge-entry-button').click();
    const purgeDialog = page.getByRole('dialog', { name: 'Eintrag endgültig löschen?' });
    await purgeDialog.getByLabel('Master-Passwort').fill(masterPassword);
    await purgeDialog.getByRole('button', { name: 'Endgültig löschen', exact: true }).click();
    await expect(page.getByText('Eintrag endgültig gelöscht')).toBeVisible();
    await expect(page.getByRole('option', { name: new RegExp(updatedTitle, 'u') })).toHaveCount(0);

    const sourceUrl = page.url();
    const windowCount = sourceApp.windows().length;
    await page.evaluate(() => {
      window.open('https://example.com/vaulta-popup-must-be-blocked', '_blank');
    });
    await page.waitForTimeout(300);
    expect(sourceApp.windows()).toHaveLength(windowCount);

    await page.evaluate(() => {
      window.location.assign('https://example.com/vaulta-navigation-must-be-blocked');
    });
    await page.waitForTimeout(500);

    const stillOnSourceUrl = await sourceApp.evaluate(({ BrowserWindow }) => {
      const win = BrowserWindow.getAllWindows()[0];
      return win ? win.webContents.getURL() : null;
    });
    expect(stillOnSourceUrl).toBe(sourceUrl);

    const searchInputPresent = await page.evaluate(
      () => document.querySelector('input[aria-label="Tresor durchsuchen"]') !== null,
    );
    expect(searchInputPresent).toBe(true);

    await closeVaulta(sourceApp);
    sourceApp = undefined;

    restoredApp = await launchVaulta(restoredUserData);
    const restoredPage = await restoredApp.firstWindow();
    await installControlledDialogs(restoredApp, { backupPath });
    await waitForSetupScreen(restoredPage);
    await restoredPage.getByRole('button', { name: 'Backup wiederherstellen' }).click();
    await restoredPage.getByLabel('Master-Passwort des Backups').fill(masterPassword);
    await restoredPage.getByRole('button', { name: 'Backup auswählen und prüfen' }).click();
    await expect(restoredPage.getByRole('heading', { name: 'Willkommen zurück' })).toBeVisible({
      timeout: 45_000,
    });
    await restoredPage.getByLabel('Master-Passwort').fill(masterPassword);
    await restoredPage.getByRole('button', { name: 'Kryptris entsperren' }).click();
    await expect(restoredPage.getByPlaceholder('Tresor durchsuchen')).toBeVisible({
      timeout: 45_000,
    });
    await openSidebarNavigation(restoredPage);
    await restoredPage.getByRole('button', { name: 'Alle Einträge', exact: true }).first().click();
    const restoredUpdatedEntry = restoredPage.getByRole('option', {
      name: new RegExp(updatedTitle, 'u'),
    });
    await expect(restoredUpdatedEntry).toBeVisible();
    await restoredUpdatedEntry.click();
    const restoredDetailPanel = restoredPage.getByLabel(`Details für ${updatedTitle}`);
    await expect(restoredDetailPanel.getByText('e2e@example.test', { exact: true })).toBeVisible();
    await restoredPage.getByRole('button', { name: 'Passwort anzeigen' }).click();
    await expect(restoredPage.getByText(entryPassword, { exact: true })).toBeVisible();
    await restoredPage.getByRole('button', { name: 'Passwort ausblenden' }).click();
    await expect(
      restoredPage.getByRole('option', { name: /E2E Importierter Dienst/u }),
    ).toBeVisible();
  } finally {
    if (restoredApp) await closeVaulta(restoredApp);
    if (sourceApp) await closeVaulta(sourceApp);
    await rm(testRoot, { recursive: true, force: true });
  }
});

async function openSidebarNavigation(page: Page): Promise<void> {
  const openButton = page.getByRole('button', { name: 'Navigation öffnen' });
  if (await openButton.isVisible()) await openButton.click();
}

async function fillInitialSetup(page: Page, masterPassword: string): Promise<void> {
  await page.getByLabel('Name des ersten Tresors').fill('Privat');
  await page.getByLabel('Master-Passwort', { exact: true }).fill(masterPassword);
  await page.getByLabel('Master-Passwort wiederholen').fill(masterPassword);
}

async function waitForSetupScreen(page: Page): Promise<void> {
  try {
    await page.waitForURL((url) => url.protocol === 'http:' && url.hostname === 'localhost', {
      timeout: 30_000,
      waitUntil: 'domcontentloaded',
    });
    const setupHeading = page.getByRole('heading', { name: 'Dein sicherer, lokaler Tresor' });
    const fatalHeading = page.getByRole('heading', {
      name: 'Vaulta konnte nicht gestartet werden',
    });
    await expect(setupHeading.or(fatalHeading)).toBeVisible({ timeout: 30_000 });
    if (await fatalHeading.isVisible()) {
      throw new Error(await page.locator('main').innerText());
    }
  } catch (error) {
    const body = await page
      .locator('body')
      .innerText()
      .then((value) => value.replace(/\s+/gu, ' ').slice(0, 500))
      .catch(() => '<nicht lesbar>');
    throw new Error(
      `Vaulta erreichte den Setup-Screen nicht. URL: ${page.url()}; Inhalt: ${body}`,
      { cause: error },
    );
  }
}

async function launchVaulta(userData: string): Promise<VaultaElectronApp> {
  await mkdir(userData, { recursive: true });
  const packagedExecutable =
    process.env.VAULTA_E2E_MODE === 'workspace' ? undefined : process.env.VAULTA_E2E_EXECUTABLE;
  const executablePath =
    packagedExecutable === undefined ? undefined : path.resolve(packagedExecutable);
  return electron.launch({
    timeout: 30_000,
    ...(executablePath === undefined ? {} : { executablePath }),
    args: [
      '--disable-gpu',
      `--user-data-dir=${path.join(userData, 'chromium')}`,
      ...(executablePath === undefined ? [process.cwd()] : []),
    ],
    env: createLaunchEnvironment(userData),
  });
}

function createLaunchEnvironment(userData: string): Record<string, string> {
  const inheritedPath = process.env.Path ?? process.env.PATH ?? '';
  const launchPath =
    process.platform === 'win32'
      ? `${process.env.SystemRoot ?? 'C:\\Windows'}\\System32;${inheritedPath}`
      : inheritedPath;
  const environment: Record<string, string> = {
    APPDATA: userData,
    LOCALAPPDATA: userData,
    KRYPTRIS_E2E_DATA_DIR: userData,
    NODE_ENV: 'test',
    Path: launchPath,
    PATH: launchPath,
  };
  for (const name of ['SystemRoot', 'WINDIR', 'ComSpec', 'TEMP', 'TMP', 'USERPROFILE', 'HOME']) {
    const value = process.env[name];
    if (value !== undefined) environment[name] = value;
  }
  return environment;
}

async function installControlledDialogs(
  app: VaultaElectronApp,
  targets: DialogTargets,
): Promise<void> {
  await app.evaluate(({ dialog }, controlledTargets) => {
    const controlledDialog = dialog as unknown as {
      showOpenDialog: (...args: unknown[]) => Promise<{
        canceled: boolean;
        filePaths: string[];
      }>;
      showSaveDialog: (...args: unknown[]) => Promise<{
        canceled: boolean;
        filePath: string;
      }>;
      showMessageBox: (...args: unknown[]) => Promise<{
        response: number;
        checkboxChecked: boolean;
      }>;
    };
    controlledDialog.showOpenDialog = (...args: unknown[]) => {
      const options = args.at(-1) as { title?: string } | undefined;
      if (
        options?.title?.includes('Passwortdaten importieren') === true &&
        controlledTargets.importPath !== undefined
      ) {
        return Promise.resolve({ canceled: false, filePaths: [controlledTargets.importPath] });
      }
      if (
        options?.title?.includes('Vaulta-Backup wiederherstellen') === true &&
        controlledTargets.backupPath !== undefined
      ) {
        return Promise.resolve({ canceled: false, filePaths: [controlledTargets.backupPath] });
      }
      return Promise.resolve({ canceled: true, filePaths: [] });
    };
    controlledDialog.showSaveDialog = (...args: unknown[]) => {
      const options = args.at(-1) as { title?: string } | undefined;
      if (
        options?.title?.includes('Vaulta-Backup') === true &&
        controlledTargets.backupPath !== undefined
      ) {
        return Promise.resolve({ canceled: false, filePath: controlledTargets.backupPath });
      }
      if (
        options?.title?.includes('Daten exportieren') === true &&
        controlledTargets.cleartextPath !== undefined
      ) {
        return Promise.resolve({ canceled: false, filePath: controlledTargets.cleartextPath });
      }
      return Promise.resolve({ canceled: true, filePath: '' });
    };
    controlledDialog.showMessageBox = (...args: unknown[]) => {
      const options = args.at(-1) as { title?: string } | undefined;
      const confirmed = options?.title?.includes('Lokale Daten ersetzen') === true;
      return Promise.resolve({ response: confirmed ? 1 : 0, checkboxChecked: false });
    };
  }, targets);
}

async function closeVaulta(app: VaultaElectronApp): Promise<void> {
  const electronProcess = app.process();
  let timeout: NodeJS.Timeout | undefined;
  try {
    await app.evaluate(({ app: electronApp }) => electronApp.exit(0)).catch(() => undefined);
    await Promise.race([
      app.close().catch(() => undefined),
      new Promise<void>((resolve) => {
        timeout = setTimeout(resolve, 5_000);
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
    if (electronProcess.exitCode === null && electronProcess.signalCode === null) {
      electronProcess.kill();
    }
  }
}
