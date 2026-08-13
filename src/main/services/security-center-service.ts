import { z } from 'zod';

import { VaultaError } from '../../shared/errors';
import type {
  BreachListStatusDto,
  BreachScanReportDto,
  FactorStatus,
  IntegrityReportDto,
  RecoveryReadinessStatusDto,
  SecurityCenterCardDto,
  SecurityCenterEntryFindingDto,
  SecurityCenterFindingCode,
  SecurityCenterReportDto,
  SecurityReport,
  SecuritySeverity,
} from '../../shared/models';

const BACKUP_STALE_AFTER_MS = 48 * 60 * 60 * 1_000;
export const INTEGRITY_STATUS_NAMESPACE = 'integrity-status';

const integrityStatusSchema = z
  .object({
    checkedAt: z.iso.datetime(),
    success: z.boolean(),
    findingCount: z.number().int().min(0).max(1_000_000),
  })
  .strict();

export interface SecurityCenterCredentialReport {
  readonly vaultId: string;
  readonly vaultName: string;
  readonly report: SecurityReport;
}

export interface SecurityCenterIntegrityStatus {
  readonly checkedAt: string;
  readonly success: boolean;
  readonly findingCount: number;
}

export interface SecurityCenterInput {
  readonly credentialReports: readonly SecurityCenterCredentialReport[];
  readonly dataQualityFindingCount: number;
  readonly dataQualityCalculatedAt: string | null;
  readonly factorStatus: FactorStatus;
  readonly automaticBackups: boolean;
  readonly lastAutomaticBackupAt: string | null;
  readonly recovery: RecoveryReadinessStatusDto;
  readonly kdfCurrent: boolean;
  readonly integrity: SecurityCenterIntegrityStatus | null;
  readonly breachList: BreachListStatusDto;
  readonly breachReport: BreachScanReportDto | null;
}

export interface SecurityCenterOptions {
  readonly now?: Date;
}

/** Aggregates already-redacted local checks into a deterministic preparedness dashboard. */
export class SecurityCenterService {
  public createIntegrityStatus(
    report: Pick<IntegrityReportDto, 'generatedAt' | 'success' | 'findings'>,
  ): SecurityCenterIntegrityStatus {
    const parsed = integrityStatusSchema.safeParse({
      checkedAt: report.generatedAt,
      success: report.success,
      findingCount: report.findings.length,
    });
    if (!parsed.success) {
      throw new VaultaError('INVALID_INPUT', 'Der technische Integritätsstatus ist ungültig.');
    }
    return parsed.data;
  }

  public parseIntegrityStatus(value: unknown): SecurityCenterIntegrityStatus | null {
    if (value === null || value === undefined) return null;
    const parsed = integrityStatusSchema.safeParse(value);
    if (!parsed.success) {
      throw new VaultaError(
        'CORRUPT_DATA',
        'Der gespeicherte technische Integritätsstatus ist beschädigt.',
      );
    }
    return parsed.data;
  }

  public build(
    input: SecurityCenterInput,
    options: SecurityCenterOptions = {},
  ): SecurityCenterReportDto {
    const now = options.now ?? new Date();
    if (Number.isNaN(now.getTime())) {
      throw new VaultaError('INVALID_INPUT', 'Der Zeitpunkt der Sicherheitszentrale ist ungültig.');
    }
    if (!Number.isSafeInteger(input.dataQualityFindingCount) || input.dataQualityFindingCount < 0) {
      throw new VaultaError('INVALID_INPUT', 'Die Anzahl der Datenqualitätsbefunde ist ungültig.');
    }

    const entryFindings = input.credentialReports
      .flatMap(({ vaultId, vaultName, report }) =>
        report.findings.map((finding): SecurityCenterEntryFindingDto => ({
          ...structuredClone(finding),
          vaultId,
          vaultName,
        })),
      )
      .sort(compareEntryFindings);
    const cards = [
      this.credentialsCard(input.credentialReports, entryFindings),
      this.dataQualityCard(input),
      this.factorCard(input.factorStatus, now),
      this.backupCard(input, now),
      this.recoveryCard(input.recovery),
      this.kdfCard(input.kdfCurrent, now),
      this.integrityCard(input.integrity),
      this.breachCard(input.breachList, input.breachReport),
    ];

    const penalty = cards.reduce((total, card) => total + cardPenalty(card), 0);
    return {
      generatedAt: now.toISOString(),
      score: Math.max(0, 100 - penalty),
      cards,
      entryFindings,
      networkUsed: false,
    };
  }

  private credentialsCard(
    reports: readonly SecurityCenterCredentialReport[],
    findings: readonly SecurityCenterEntryFindingDto[],
  ): SecurityCenterCardDto {
    return card({
      id: 'credentials',
      severity: highestSeverity(findings.map((finding) => finding.severity)),
      findingCodes: findings.length > 0 ? ['credential-findings'] : [],
      count: findings.length,
      calculatedAt: latestTimestamp(reports.map(({ report }) => report.generatedAt)),
      action: 'review-credentials',
    });
  }

  private dataQualityCard(input: SecurityCenterInput): SecurityCenterCardDto {
    return card({
      id: 'data-quality',
      severity: input.dataQualityFindingCount > 0 ? 'warning' : 'good',
      findingCodes: input.dataQualityFindingCount > 0 ? ['data-quality-findings'] : [],
      count: input.dataQualityFindingCount,
      calculatedAt: input.dataQualityCalculatedAt,
      action: 'review-data-quality',
    });
  }

  private factorCard(status: FactorStatus, now: Date): SecurityCenterCardDto {
    const missing = !status.totpEnabled && status.securityKeys.length === 0;
    return card({
      id: 'factors',
      severity: missing ? 'info' : 'good',
      findingCodes: missing ? ['additional-factor-missing'] : [],
      count: Number(status.totpEnabled) + status.securityKeys.length,
      calculatedAt: now.toISOString(),
      action: 'open-factor-settings',
    });
  }

  private backupCard(input: SecurityCenterInput, now: Date): SecurityCenterCardDto {
    let findingCodes: SecurityCenterFindingCode[] = [];
    if (!input.automaticBackups) {
      findingCodes = ['automatic-backup-disabled'];
    } else if (input.lastAutomaticBackupAt === null) {
      findingCodes = ['automatic-backup-missing'];
    } else if (
      !validTimestamp(input.lastAutomaticBackupAt) ||
      now.getTime() - Date.parse(input.lastAutomaticBackupAt) > BACKUP_STALE_AFTER_MS
    ) {
      findingCodes = ['automatic-backup-stale'];
    }
    return card({
      id: 'backup',
      severity: findingCodes.length > 0 ? 'warning' : 'good',
      findingCodes,
      count: findingCodes.length,
      calculatedAt: input.lastAutomaticBackupAt,
      action: 'open-backups',
    });
  }

  private recoveryCard(status: RecoveryReadinessStatusDto): SecurityCenterCardDto {
    const findingCodes: SecurityCenterFindingCode[] =
      status.state === 'not-configured'
        ? ['recovery-not-configured']
        : status.state === 'never-tested'
          ? ['recovery-never-tested']
          : status.state === 'failed'
            ? ['recovery-test-failed']
            : status.state === 'stale'
              ? ['recovery-test-stale']
              : [];
    return card({
      id: 'recovery',
      severity:
        status.state === 'failed' ? 'critical' : findingCodes.length > 0 ? 'warning' : 'good',
      findingCodes,
      count: findingCodes.length,
      calculatedAt: status.lastTestedAt,
      action: status.state === 'not-configured' ? 'open-factor-settings' : 'test-recovery',
    });
  }

  private kdfCard(current: boolean, now: Date): SecurityCenterCardDto {
    return card({
      id: 'kdf',
      severity: current ? 'good' : 'critical',
      findingCodes: current ? [] : ['kdf-outdated'],
      count: current ? 0 : 1,
      calculatedAt: now.toISOString(),
      action: current ? 'none' : 'change-master-password',
    });
  }

  private integrityCard(status: SecurityCenterIntegrityStatus | null): SecurityCenterCardDto {
    return card({
      id: 'integrity',
      severity: status === null ? 'info' : status.success ? 'good' : 'critical',
      findingCodes:
        status === null ? ['integrity-not-run'] : status.success ? [] : ['integrity-failed'],
      count: status?.findingCount ?? 0,
      calculatedAt: status?.checkedAt ?? null,
      action: 'run-integrity',
    });
  }

  private breachCard(
    status: BreachListStatusDto,
    report: BreachScanReportDto | null,
  ): SecurityCenterCardDto {
    let findingCodes: SecurityCenterFindingCode[] = [];
    let severity: SecuritySeverity = 'good';
    if (status.state === 'not-configured') {
      findingCodes = ['breach-list-not-configured'];
      severity = 'info';
    } else if (status.state === 'missing') {
      findingCodes = ['breach-list-missing'];
      severity = 'warning';
    } else if (status.state === 'corrupt') {
      findingCodes = ['breach-list-corrupt'];
      severity = 'warning';
    } else if (report !== null && report.findings.length > 0) {
      findingCodes = ['breached-passwords-found'];
      severity = 'critical';
    }
    return card({
      id: 'breach-list',
      severity,
      findingCodes,
      count: report?.findings.length ?? 0,
      calculatedAt: report?.generatedAt ?? status.importedAt,
      action:
        report !== null && report.findings.length > 0
          ? 'review-breach-findings'
          : 'configure-breach-list',
    });
  }
}

function card(value: SecurityCenterCardDto): SecurityCenterCardDto {
  return value;
}

function highestSeverity(severities: readonly SecuritySeverity[]): SecuritySeverity {
  const rank: Record<SecuritySeverity, number> = { good: 0, info: 1, warning: 2, critical: 3 };
  return severities.reduce<SecuritySeverity>(
    (highest, severity) => (rank[severity] > rank[highest] ? severity : highest),
    'good',
  );
}

function latestTimestamp(values: readonly string[]): string | null {
  const valid = values.filter(validTimestamp).sort();
  return valid.at(-1) ?? null;
}

function validTimestamp(value: string): boolean {
  return Number.isFinite(Date.parse(value));
}

function compareEntryFindings(
  left: SecurityCenterEntryFindingDto,
  right: SecurityCenterEntryFindingDto,
): number {
  const rank: Record<SecuritySeverity, number> = { critical: 0, warning: 1, info: 2, good: 3 };
  return (
    rank[left.severity] - rank[right.severity] ||
    left.vaultName.localeCompare(right.vaultName, 'de') ||
    left.entryTitle.localeCompare(right.entryTitle, 'de') ||
    left.id.localeCompare(right.id, 'en')
  );
}

function cardPenalty(cardValue: SecurityCenterCardDto): number {
  if (cardValue.findingCodes.length === 0) return 0;
  if (cardValue.severity === 'critical') return 18;
  if (cardValue.severity === 'warning') return 8;
  if (cardValue.severity === 'info') return 2;
  return 0;
}
