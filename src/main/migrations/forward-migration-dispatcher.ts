import { VaultaError } from '../../shared/errors';

export interface ForwardMigrationStep<T> {
  readonly fromVersion: number;
  readonly toVersion: number;
  readonly migrate: (value: T) => Promise<T> | T;
}

export interface ForwardMigrationResult<T> {
  readonly value: T;
  readonly sourceVersion: number;
  readonly targetVersion: number;
  readonly migrated: boolean;
  readonly appliedVersions: readonly number[];
}

export interface ForwardMigrationDispatcherOptions<T> {
  readonly formatName: string;
  readonly currentVersion: number;
  readonly readVersion: (value: T) => number;
  readonly validateCurrent: (value: T) => Promise<void> | void;
  readonly steps?: readonly ForwardMigrationStep<T>[];
}

/**
 * Builds and executes a contiguous, forward-only migration chain in memory.
 * Persistent writes and their mandatory pre-migration snapshot are deliberately
 * owned by {@link PersistentMigrationService}.
 */
export class ForwardMigrationDispatcher<T> {
  private readonly formatName: string;
  private readonly currentVersion: number;
  private readonly readVersion: (value: T) => number;
  private readonly validateCurrent: (value: T) => Promise<void> | void;
  private readonly steps = new Map<number, ForwardMigrationStep<T>>();

  public constructor(options: ForwardMigrationDispatcherOptions<T>) {
    this.formatName = options.formatName;
    this.currentVersion = requireVersion(options.currentVersion, 'Aktuelle Formatversion');
    this.readVersion = options.readVersion;
    this.validateCurrent = options.validateCurrent;

    for (const step of options.steps ?? []) {
      const fromVersion = requireVersion(step.fromVersion, 'Quellversion');
      const toVersion = requireVersion(step.toVersion, 'Zielversion');
      if (toVersion !== fromVersion + 1) {
        throw new VaultaError(
          'INTERNAL',
          `${this.formatName}: Migrationen müssen genau eine Formatversion vorwärts führen.`,
        );
      }
      if (toVersion > this.currentVersion || this.steps.has(fromVersion)) {
        throw new VaultaError(
          'INTERNAL',
          `${this.formatName}: Die registrierte Migrationskette ist widersprüchlich.`,
        );
      }
      this.steps.set(fromVersion, step);
    }
  }

  public plan(sourceVersion: number): readonly ForwardMigrationStep<T>[] {
    let version = requireVersion(sourceVersion, `${this.formatName}-Formatversion`);
    if (version > this.currentVersion) {
      throw new VaultaError(
        'UNSUPPORTED_FORMAT',
        `${this.formatName} verwendet die neuere Formatversion ${version}; unterstützt wird Version ${this.currentVersion}.`,
        'Öffne diese Daten mit einer neueren Vaulta-Version. Die Datei wurde nicht verändert.',
      );
    }

    const plan: ForwardMigrationStep<T>[] = [];
    while (version < this.currentVersion) {
      const step = this.steps.get(version);
      if (step === undefined) {
        throw new VaultaError(
          'UNSUPPORTED_FORMAT',
          `${this.formatName} verwendet Formatversion ${version}; dafür ist kein verlustfreier Migrationspfad registriert.`,
          'Die Datei wurde nicht verändert. Stelle eine kompatible Vaulta-Version oder ein gültiges Backup bereit.',
        );
      }
      plan.push(step);
      version = step.toVersion;
    }
    return plan;
  }

  public async migrate(value: T): Promise<ForwardMigrationResult<T>> {
    const sourceVersion = requireVersion(
      this.readVersion(value),
      `${this.formatName}-Formatversion`,
    );
    const plan = this.plan(sourceVersion);
    let migrated = value;
    const appliedVersions: number[] = [];

    for (const step of plan) {
      migrated = await step.migrate(migrated);
      const actualVersion = requireVersion(
        this.readVersion(migrated),
        `${this.formatName}-Formatversion`,
      );
      if (actualVersion !== step.toVersion) {
        throw new VaultaError(
          'INTERNAL',
          `${this.formatName}: Migration ${step.fromVersion}→${step.toVersion} erzeugte Formatversion ${actualVersion}.`,
        );
      }
      appliedVersions.push(step.toVersion);
    }

    await this.validateCurrent(migrated);
    return {
      value: migrated,
      sourceVersion,
      targetVersion: this.currentVersion,
      migrated: plan.length > 0,
      appliedVersions,
    };
  }
}

function requireVersion(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new VaultaError('CORRUPT_DATA', `${label} ist ungültig.`);
  }
  return value;
}
