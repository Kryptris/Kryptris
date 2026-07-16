import { VaultaError } from '../../shared/errors';
import {
  ENTRY_TYPES,
  type EntrySummary,
  type EntryType,
  type LocalReport,
  type SecuritySeverity,
  type VaultDocument,
  type VaultEntry,
} from '../../shared/models';
import { entrySubtitle } from './entry-utils';
import { SecurityCheckService } from './security-check-service';

export interface LocalReportOptions {
  oldestLimit?: number;
  now?: Date;
}

interface ReportState {
  now: Date;
  oldestLimit: number;
  vaults: readonly VaultDocument[];
  activeEntries: VaultEntry[];
  trashedEntries: VaultEntry[];
}

export class ReportService {
  public constructor(private readonly securityService = new SecurityCheckService()) {}

  public generate(vaults: readonly VaultDocument[], options: LocalReportOptions = {}): LocalReport {
    const state = this.createState(vaults, options);
    return this.createReport(
      state,
      this.securityService.scan(state.activeEntries, { now: state.now }),
    );
  }

  public async generateAsync(
    vaults: readonly VaultDocument[],
    options: LocalReportOptions = {},
  ): Promise<LocalReport> {
    const state = this.createState(vaults, options);
    const security = await this.securityService.scanAsync(state.activeEntries, { now: state.now });
    return this.createReport(state, security);
  }

  private createState(vaults: readonly VaultDocument[], options: LocalReportOptions): ReportState {
    const now = options.now ?? new Date();
    const oldestLimit = options.oldestLimit ?? 10;
    if (Number.isNaN(now.getTime())) throw invalid('Der Berichtszeitpunkt ist ungueltig.');
    if (!Number.isInteger(oldestLimit) || oldestLimit < 0 || oldestLimit > 100) {
      throw invalid('Die Anzahl der aeltesten Eintraege ist ungueltig.');
    }
    const allEntries = vaults.flatMap((vault) => vault.entries);
    return {
      now,
      oldestLimit,
      vaults,
      activeEntries: allEntries.filter((entry) => entry.deletedAt === null),
      trashedEntries: allEntries.filter((entry) => entry.deletedAt !== null),
    };
  }

  private createReport(state: ReportState, security: LocalReport['security']): LocalReport {
    const { activeEntries, oldestLimit, trashedEntries, vaults } = state;
    const severityByEntry = new Map<string, SecuritySeverity>();
    for (const finding of security.findings) {
      const current = severityByEntry.get(finding.entryId) ?? 'good';
      if (severityRank(finding.severity) > severityRank(current)) {
        severityByEntry.set(finding.entryId, finding.severity);
      }
    }

    const typeCounts = Object.fromEntries(ENTRY_TYPES.map((type) => [type, 0])) as Record<
      EntryType,
      number
    >;
    for (const entry of activeEntries) typeCounts[entry.data.type] += 1;

    const oldestEntries: EntrySummary[] = [...activeEntries]
      .sort((left, right) => timestamp(left.createdAt) - timestamp(right.createdAt))
      .slice(0, oldestLimit)
      .map((entry) => ({
        id: entry.id,
        vaultId: entry.vaultId,
        type: entry.data.type,
        title: entry.title,
        subtitle: entrySubtitle(entry),
        favorite: entry.favorite,
        tags: [...entry.tags],
        folderId: entry.folderId,
        securityState: severityByEntry.get(entry.id) ?? 'good',
        updatedAt: entry.updatedAt,
        deletedAt: null,
      }));

    return {
      generatedAt: state.now.toISOString(),
      vaultCount: vaults.length,
      entryCount: activeEntries.length,
      favoriteCount: activeEntries.filter((entry) => entry.favorite).length,
      trashCount: trashedEntries.length,
      attachmentCount: activeEntries.reduce((sum, entry) => sum + entry.attachments.length, 0),
      attachmentBytes: activeEntries.reduce(
        (sum, entry) => sum + entry.attachments.reduce((bytes, item) => bytes + item.size, 0),
        0,
      ),
      typeCounts,
      security,
      oldestEntries,
      networkUsed: false,
    };
  }
}

function severityRank(severity: SecuritySeverity): number {
  return { good: 0, info: 1, warning: 2, critical: 3 }[severity];
}

function timestamp(value: string): number {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : Number.MAX_SAFE_INTEGER;
}

function invalid(message: string): VaultaError {
  return new VaultaError('INVALID_INPUT', message);
}
