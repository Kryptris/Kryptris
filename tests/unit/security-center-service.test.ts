import { describe, expect, it } from 'vitest';

import type {
  BreachListStatusDto,
  RecoveryReadinessStatusDto,
  SecurityReport,
} from '../../src/shared/models';
import {
  SecurityCenterService,
  type SecurityCenterInput,
} from '../../src/main/services/security-center-service';

const NOW = new Date('2026-07-26T12:00:00.000Z');
const EMPTY_SECURITY: SecurityReport = {
  generatedAt: '2026-07-26T11:00:00.000Z',
  score: 100,
  counts: { good: 1, info: 0, warning: 0, critical: 0 },
  findings: [],
  networkUsed: false,
};
const READY_RECOVERY: RecoveryReadinessStatusDto = {
  state: 'ready',
  lastTestedAt: '2026-07-25T12:00:00.000Z',
  lastTestSucceeded: true,
  staleAfterDays: 180,
};
const READY_BREACH: BreachListStatusDto = {
  state: 'ready',
  sourceLabel: 'Anonymisierte Testliste',
  sourceDate: '2026-07-20',
  importedAt: '2026-07-21T12:00:00.000Z',
  recordCount: 2,
  corpusSha256: 'a'.repeat(64),
  networkUsed: false,
};

describe('SecurityCenterService', () => {
  it('aggregiert alle lokalen Vorsorgebereiche ohne Netzwerknutzung', () => {
    const report = new SecurityCenterService().build(baseInput(), { now: NOW });

    expect(report.cards.map((card) => card.id)).toEqual([
      'credentials',
      'data-quality',
      'factors',
      'backup',
      'recovery',
      'kdf',
      'integrity',
      'breach-list',
    ]);
    expect(report.cards.every((card) => card.findingCodes.length === 0)).toBe(true);
    expect(report.score).toBe(100);
    expect(report.networkUsed).toBe(false);
  });

  it('bewertet konkrete Ursachen und behält Entry-Referenzen tresoreindeutig', () => {
    const input = baseInput();
    input.credentialReports[0]!.report.findings.push({
      id: 'entry-1:reused',
      entryId: 'entry-1',
      entryTitle: 'Lokaler Testeintrag',
      kind: 'reused',
      severity: 'critical',
      title: 'Mehrfach verwendetes Passwort',
      recommendation: 'Lokal ändern.',
    });
    input.dataQualityFindingCount = 3;
    input.factorStatus = { ...input.factorStatus, totpEnabled: false };
    input.automaticBackups = false;
    input.recovery = {
      state: 'failed',
      lastTestedAt: '2026-07-26T10:00:00.000Z',
      lastTestSucceeded: false,
      staleAfterDays: 180,
    };
    input.kdfCurrent = false;
    input.integrity = {
      checkedAt: '2026-07-26T10:30:00.000Z',
      success: false,
      findingCount: 2,
    };
    input.breachReport = {
      generatedAt: '2026-07-26T10:45:00.000Z',
      checkedEntries: 1,
      checkedPasswords: 1,
      findings: [
        {
          id: 'breach-1',
          vaultId: 'vault-1',
          vaultName: 'Privat',
          entryId: 'entry-1',
          entryTitle: 'Lokaler Testeintrag',
          entryUpdatedAt: '2026-07-26T09:00:00.000Z',
          code: 'known-breached-password',
          severity: 'critical',
        },
      ],
      networkUsed: false,
    };

    const report = new SecurityCenterService().build(input, { now: NOW });

    expect(report.entryFindings).toMatchObject([
      { vaultId: 'vault-1', vaultName: 'Privat', entryId: 'entry-1' },
    ]);
    expect(report.cards.find((card) => card.id === 'recovery')?.findingCodes).toEqual([
      'recovery-test-failed',
    ]);
    expect(report.cards.find((card) => card.id === 'breach-list')?.findingCodes).toEqual([
      'breached-passwords-found',
    ]);
    expect(report.score).toBeLessThan(50);
  });

  it('unterscheidet fehlende, alte und deaktivierte automatische Backups', () => {
    const service = new SecurityCenterService();
    const disabled = baseInput();
    disabled.automaticBackups = false;
    expect(
      service.build(disabled, { now: NOW }).cards.find((card) => card.id === 'backup')
        ?.findingCodes,
    ).toEqual(['automatic-backup-disabled']);

    const missing = baseInput();
    missing.lastAutomaticBackupAt = null;
    expect(
      service.build(missing, { now: NOW }).cards.find((card) => card.id === 'backup')?.findingCodes,
    ).toEqual(['automatic-backup-missing']);

    const stale = baseInput();
    stale.lastAutomaticBackupAt = '2026-07-23T11:59:59.000Z';
    expect(
      service.build(stale, { now: NOW }).cards.find((card) => card.id === 'backup')?.findingCodes,
    ).toEqual(['automatic-backup-stale']);
  });

  it('persistiert für Integritätsprüfungen ausschließlich redigierte technische Metadaten', () => {
    const service = new SecurityCenterService();
    const status = service.createIntegrityStatus({
      generatedAt: '2026-07-26T12:00:00.000Z',
      success: false,
      findings: [
        {
          id: 'integrity-finding-0001',
          code: 'attachment-missing',
          severity: 'critical',
          scope: 'attachment',
        },
      ],
    });

    expect(status).toEqual({
      checkedAt: '2026-07-26T12:00:00.000Z',
      success: false,
      findingCount: 1,
    });
    expect(service.parseIntegrityStatus(status)).toEqual(status);
    expect(JSON.stringify(status)).not.toMatch(/path|title|hash|attachment-missing/iu);
  });

  it('lehnt beschädigte oder erweiterte Integritätsmetadaten ab', () => {
    const service = new SecurityCenterService();

    expect(() =>
      service.parseIntegrityStatus({
        checkedAt: 'kein-zeitpunkt',
        success: true,
        findingCount: 0,
      }),
    ).toThrow(/beschädigt/u);
    expect(() =>
      service.parseIntegrityStatus({
        checkedAt: '2026-07-26T12:00:00.000Z',
        success: true,
        findingCount: 0,
        path: 'C:\\nicht-speichern',
      }),
    ).toThrow(/beschädigt/u);
  });
});

function baseInput(): { -readonly [Key in keyof SecurityCenterInput]: SecurityCenterInput[Key] } {
  return {
    credentialReports: [
      {
        vaultId: 'vault-1',
        vaultName: 'Privat',
        report: structuredClone(EMPTY_SECURITY),
      },
    ],
    dataQualityFindingCount: 0,
    dataQualityCalculatedAt: '2026-07-26T11:30:00.000Z',
    factorStatus: {
      totpEnabled: true,
      securityKeys: [],
      recoveryEnabled: true,
    },
    automaticBackups: true,
    lastAutomaticBackupAt: '2026-07-26T08:00:00.000Z',
    recovery: structuredClone(READY_RECOVERY),
    kdfCurrent: true,
    integrity: {
      checkedAt: '2026-07-26T09:00:00.000Z',
      success: true,
      findingCount: 0,
    },
    breachList: structuredClone(READY_BREACH),
    breachReport: {
      generatedAt: '2026-07-26T09:30:00.000Z',
      checkedEntries: 1,
      checkedPasswords: 1,
      findings: [],
      networkUsed: false as const,
    },
  };
}
