import { createHash } from 'node:crypto';

import { VaultaError } from '../../shared/errors';
import type {
  SecurityFinding,
  SecurityReport,
  SecuritySeverity,
  VaultEntry,
} from '../../shared/models';
import { evaluatePassword } from './password-strength';

export interface SecurityScanOptions {
  now?: Date;
  oldAfterDays?: number;
}

interface SecurityScanState {
  now: Date;
  oldAfterDays: number;
  activeEntries: VaultEntry[];
  findings: SecurityFinding[];
  passwordGroups: Map<string, VaultEntry[]>;
}

const SENSITIVE_LABEL =
  /(?:passwort|password|kennwort|secret|geheim|token|api[ _-]?key|private[ _-]?key|pin|cvc|cvv)/iu;
const ASYNC_BATCH_SIZE = 10;

export class SecurityCheckService {
  public scan(entries: readonly VaultEntry[], options: SecurityScanOptions = {}): SecurityReport {
    const state = this.createState(entries, options);
    for (const entry of state.activeEntries) this.inspectEntry(entry, state);
    return this.finish(state);
  }

  /**
   * Runs expensive password-strength checks in short batches. This keeps Electron's main process
   * responsive while a large vault is being analyzed.
   */
  public async scanAsync(
    entries: readonly VaultEntry[],
    options: SecurityScanOptions = {},
  ): Promise<SecurityReport> {
    const state = this.createState(entries, options);
    for (let index = 0; index < state.activeEntries.length; index += 1) {
      this.inspectEntry(state.activeEntries[index]!, state);
      if ((index + 1) % ASYNC_BATCH_SIZE === 0) await yieldToEventLoop();
    }
    return this.finish(state);
  }

  private createState(
    entries: readonly VaultEntry[],
    options: SecurityScanOptions,
  ): SecurityScanState {
    const now = options.now ?? new Date();
    const oldAfterDays = options.oldAfterDays ?? 365;
    if (Number.isNaN(now.getTime())) throw invalid('Der Pruefzeitpunkt ist ungueltig.');
    if (!Number.isInteger(oldAfterDays) || oldAfterDays < 30 || oldAfterDays > 3_650) {
      throw invalid('Der Zeitraum fuer alte Passwoerter ist ungueltig.');
    }
    return {
      now,
      oldAfterDays,
      activeEntries: entries.filter((entry) => entry.deletedAt === null),
      findings: [],
      passwordGroups: new Map(),
    };
  }

  private inspectEntry(entry: VaultEntry, state: SecurityScanState): void {
    const password = passwordOf(entry);
    if (password.length > 0) {
      const digest = createHash('sha256').update(password, 'utf8').digest('hex');
      const group = state.passwordGroups.get(digest) ?? [];
      group.push(entry);
      state.passwordGroups.set(digest, group);

      const strength = evaluatePassword(password, passwordInputs(entry));
      if (strength.score <= 2) {
        state.findings.push(
          finding(
            entry,
            'weak',
            strength.score <= 1 ? 'critical' : 'warning',
            'Schwaches Passwort',
            'Ersetze es durch ein langes, einzigartiges Passwort oder eine Passphrase.',
          ),
        );
      }

      const changedAt = Date.parse(entry.secretChangedAt);
      const ageMilliseconds = state.now.getTime() - changedAt;
      if (
        Number.isFinite(changedAt) &&
        ageMilliseconds > state.oldAfterDays * 24 * 60 * 60 * 1_000
      ) {
        state.findings.push(
          finding(
            entry,
            'old',
            'info',
            'Lange nicht geaendert',
            `Pruefe, ob dieses Geheimnis nach mehr als ${state.oldAfterDays} Tagen erneuert werden sollte.`,
          ),
        );
      }
    }

    if (isIncomplete(entry)) {
      state.findings.push(
        finding(
          entry,
          'incomplete',
          'warning',
          'Unvollstaendiger Eintrag',
          'Ergaenze die fuer die Anmeldung erforderlichen Angaben.',
        ),
      );
    }

    if (
      entry.data.type === 'ssh-key' &&
      entry.data.value.privateKey.trim().length > 0 &&
      entry.data.value.passphrase.trim().length === 0
    ) {
      state.findings.push(
        finding(
          entry,
          'unprotected-key',
          'critical',
          'Privater Schluessel ohne Passphrase',
          'Schuetze den privaten Schluessel mit einer starken, separaten Passphrase.',
        ),
      );
    }

    for (const field of entry.customFields) {
      if (!field.secret && SENSITIVE_LABEL.test(field.label) && String(field.value).length > 0) {
        state.findings.push({
          ...finding(
            entry,
            'sensitive-field',
            'warning',
            'Sichtbares sensibles Feld',
            `Markiere das Feld „${field.label}“ als Geheimnis.`,
          ),
          id: `${entry.id}:sensitive-field:${field.id}`,
        });
      }
    }
  }

  private finish(state: SecurityScanState): SecurityReport {
    for (const group of state.passwordGroups.values()) {
      if (group.length < 2) continue;
      for (const entry of group) {
        state.findings.push(
          finding(
            entry,
            'reused',
            'critical',
            'Mehrfach verwendetes Passwort',
            'Vergib fuer jeden Zugang ein eigenes zufaelliges Passwort.',
          ),
        );
      }
    }

    state.findings.sort(compareFindings);
    const affected = new Set(state.findings.map((item) => item.entryId));
    const counts: Record<SecuritySeverity, number> = {
      good: state.activeEntries.length - affected.size,
      info: state.findings.filter((item) => item.severity === 'info').length,
      warning: state.findings.filter((item) => item.severity === 'warning').length,
      critical: state.findings.filter((item) => item.severity === 'critical').length,
    };
    const penalty = counts.critical * 20 + counts.warning * 8 + counts.info * 3;

    return {
      generatedAt: state.now.toISOString(),
      score: Math.max(0, Math.min(100, 100 - penalty)),
      counts,
      findings: state.findings,
      networkUsed: false,
    };
  }
}

function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

function passwordOf(entry: VaultEntry): string {
  if (entry.data.type === 'credential') return entry.data.value.password;
  if (entry.data.type === 'wifi') return entry.data.value.password;
  return '';
}

function passwordInputs(entry: VaultEntry): string[] {
  if (entry.data.type === 'credential') {
    return [
      entry.title,
      entry.data.value.username,
      ...entry.data.value.websites,
      ...entry.data.value.appNames,
      ...entry.tags,
    ];
  }
  return [entry.title, ...entry.tags];
}

function isIncomplete(entry: VaultEntry): boolean {
  if (entry.data.type !== 'credential') return entry.title.trim().length === 0;
  const credential = entry.data.value;
  return (
    entry.title.trim().length === 0 ||
    credential.username.trim().length === 0 ||
    credential.password.length === 0 ||
    (credential.websites.every((value) => value.trim().length === 0) &&
      credential.appNames.every((value) => value.trim().length === 0))
  );
}

function finding(
  entry: VaultEntry,
  kind: SecurityFinding['kind'],
  severity: SecuritySeverity,
  title: string,
  recommendation: string,
): SecurityFinding {
  return {
    id: `${entry.id}:${kind}`,
    entryId: entry.id,
    entryTitle: entry.title,
    kind,
    severity,
    title,
    recommendation,
  };
}

function compareFindings(left: SecurityFinding, right: SecurityFinding): number {
  const rank: Record<SecuritySeverity, number> = { critical: 0, warning: 1, info: 2, good: 3 };
  return (
    rank[left.severity] - rank[right.severity] ||
    left.entryTitle.localeCompare(right.entryTitle, 'de')
  );
}

function invalid(message: string): VaultaError {
  return new VaultaError('INVALID_INPUT', message);
}
