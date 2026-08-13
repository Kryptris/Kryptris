import { cpus, freemem, platform, release, totalmem } from 'node:os';
import { performance } from 'node:perf_hooks';

import { VaultaError } from '../../shared/errors';
import {
  createDefaultEntryLifecycleMetadata,
  type EntryListQuery,
  type VaultEntry,
} from '../../shared/models';
import { DuplicateService } from './duplicate-service';
import { EntryViewService } from './entry-view-service';
import { SecurityCheckService } from './security-check-service';

/** The only data set sizes tracked by the extension-roadmap performance gate. */
export const PERFORMANCE_BENCHMARK_SIZES = [1_000, 5_000, 10_000] as const;

export type PerformanceBenchmarkSize = (typeof PERFORMANCE_BENCHMARK_SIZES)[number];

export interface PerformanceBenchmarkOptions {
  /** A subset of the fixed roadmap sizes. Defaults to every size in ascending order. */
  readonly sizes?: readonly number[];
  /** Makes lifecycle and security checks deterministic. Defaults to a fixed UTC instant. */
  readonly now?: Date;
}

export interface PerformanceBenchmarkEnvironment {
  readonly node: string;
  readonly platform: string;
  readonly osRelease: string;
  readonly architecture: string;
  readonly cpuModel: string;
  readonly logicalCpuCount: number;
  readonly totalMemoryBytes: number;
  readonly freeMemoryBytes: number;
}

export interface PerformanceBenchmarkTiming {
  /** Monotonic elapsed time measured in the current process. */
  readonly durationMs: number;
}

export interface EntryListBenchmarkResult {
  readonly coldList: PerformanceBenchmarkTiming & {
    readonly resultCount: number;
  };
  /**
   * A fresh search query after EntryViewService has cached its security report for this revision.
   * EntryViewService does not cache query results, so this timing deliberately includes search,
   * filtering, sorting, and summary mapping work.
   */
  readonly searchWithCachedSecurityReport: PerformanceBenchmarkTiming & {
    readonly resultCount: number;
    readonly securityReportCache: 'warm';
    readonly searchResultCache: 'not-cached';
  };
}

export interface SecurityScanBenchmarkResult {
  /** The benchmark deliberately inherits SecurityCheckService's current production default. */
  readonly batchScheduling: {
    readonly usesProductionDefault: true;
    readonly explicitBatchSize: null;
  };
  readonly fullScan: PerformanceBenchmarkTiming & {
    readonly findingCount: number;
    readonly progressEvents: number;
    readonly yieldCount: number;
  };
  /**
   * Exercises the real cooperative authorization checkpoints. This is not a timeout: the
   * benchmark cancels at its first yielded batch and records the observed response.
   */
  readonly cancellation: PerformanceBenchmarkTiming & {
    readonly cancelled: boolean;
    readonly timeToFirstYieldMs: number | null;
    readonly yieldCount: number;
  };
}

export interface DuplicateScanBenchmarkResult {
  readonly fullScan: PerformanceBenchmarkTiming & {
    readonly activeEntryCount: number;
    readonly candidateCount: number;
    readonly progressEvents: number;
    readonly truncated: boolean;
    readonly yieldCount: number;
  };
  /** Cancellation is injected at the first real DuplicateService yield checkpoint. */
  readonly cancellation: PerformanceBenchmarkTiming & {
    readonly cancelled: boolean;
    readonly timeToFirstYieldMs: number | null;
    readonly yieldCount: number;
  };
}

export interface PerformanceBenchmarkDatasetResult {
  readonly entryCount: PerformanceBenchmarkSize;
  readonly entryList: EntryListBenchmarkResult;
  readonly securityScan: SecurityScanBenchmarkResult;
  readonly duplicateScan: DuplicateScanBenchmarkResult;
}

export interface PerformanceBenchmarkReport {
  readonly schemaVersion: 1;
  readonly generatedAt: string;
  readonly dataset: 'synthetic-non-secret-v1';
  /** Deliberately names only the measured main-process paths. */
  readonly scope: {
    readonly process: 'main';
    readonly entryList: 'EntryViewService.listAsync: cold list and fresh search with cached security report';
    readonly securityScan: 'SecurityCheckService.scanAsync: full scan and cooperative authorization cancellation';
    readonly duplicateScan: 'DuplicateService.scan: full scan and cooperative AbortSignal cancellation';
  };
  readonly environment: PerformanceBenchmarkEnvironment;
  readonly datasets: PerformanceBenchmarkDatasetResult[];
}

const DEFAULT_NOW = new Date('2030-01-01T12:00:00.000Z');
const FIXTURE_TIMESTAMP = '2029-12-01T12:00:00.000Z';
const DUPLICATE_PAIR_INTERVAL = 200;

/**
 * Creates deterministic, deliberately non-secret data. It is never persisted and must not be
 * used as a real vault fixture. The credential value is a public marker solely so the actual
 * security and duplicate services exercise their credential code paths.
 */
export function createSyntheticBenchmarkEntries(entryCount: number): VaultEntry[] {
  validateEntryCount(entryCount);
  return Array.from({ length: entryCount }, (_, index) => {
    const ordinal = String(index + 1).padStart(5, '0');
    const duplicatePair = index % DUPLICATE_PAIR_INTERVAL < 2;
    const duplicateOrdinal = String(index - (index % DUPLICATE_PAIR_INTERVAL)).padStart(5, '0');
    const username = duplicatePair
      ? `synthetic-match-${duplicateOrdinal}@benchmark.invalid`
      : `synthetic-user-${ordinal}@benchmark.invalid`;
    const websiteHost = duplicatePair ? `pair-${duplicateOrdinal}` : `entry-${ordinal}`;
    return {
      id: `benchmark-entry-${ordinal}`,
      vaultId: 'benchmark-vault',
      title: `Synthetischer Benchmark-Eintrag ${ordinal}`,
      folderId: index % 3 === 0 ? 'benchmark-folder-a' : null,
      tags: ['synthetisch', `gruppe-${String(index % 10)}`],
      favorite: index % 17 === 0,
      note: `Oeffentliche Benchmark-Markierung ${ordinal}`,
      customFields: [],
      attachments: [],
      data: {
        type: 'credential',
        value: {
          username,
          // This short, unique string is an explicit public marker, never a user value or
          // generated secret. Keeping it short avoids making zxcvbn's combinatorics the
          // benchmark instead of the application's scan scheduling.
          password: `x!${index.toString(36)}`,
          websites: [`https://benchmark-${websiteHost}.invalid`],
          appNames: [],
        },
      },
      lifecycle: {
        ...createDefaultEntryLifecycleMetadata(),
        rotationIntervalDays: index % 257 === 0 ? 90 : null,
        nextRotationDate: index % 257 === 0 ? '2029-10-01' : null,
        expiryReminderDate: index % 401 === 0 ? '2029-11-01' : null,
      },
      createdAt: FIXTURE_TIMESTAMP,
      updatedAt: FIXTURE_TIMESTAMP,
      secretChangedAt: FIXTURE_TIMESTAMP,
      lastUsedAt: index % 11 === 0 ? FIXTURE_TIMESTAMP : null,
      deletedAt: null,
    };
  });
}

/** Runs every benchmark locally and returns redacted measurements suitable for JSON serialization. */
export async function runPerformanceBenchmark(
  options: PerformanceBenchmarkOptions = {},
): Promise<PerformanceBenchmarkReport> {
  const sizes = validateBenchmarkSizes(options.sizes);
  const now = validateNow(options.now);
  const datasets: PerformanceBenchmarkDatasetResult[] = [];

  for (const entryCount of sizes) {
    const entries = createSyntheticBenchmarkEntries(entryCount);
    datasets.push({
      entryCount,
      entryList: await benchmarkEntryList(entries, now),
      securityScan: await benchmarkSecurityScan(entries, now),
      duplicateScan: await benchmarkDuplicateScan(entries),
    });
  }

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    dataset: 'synthetic-non-secret-v1',
    scope: {
      process: 'main',
      entryList:
        'EntryViewService.listAsync: cold list and fresh search with cached security report',
      securityScan:
        'SecurityCheckService.scanAsync: full scan and cooperative authorization cancellation',
      duplicateScan: 'DuplicateService.scan: full scan and cooperative AbortSignal cancellation',
    },
    environment: benchmarkEnvironment(),
    datasets,
  };
}

function benchmarkEnvironment(): PerformanceBenchmarkEnvironment {
  const availableCpus = cpus();
  return {
    node: process.version,
    platform: platform(),
    osRelease: release(),
    architecture: process.arch,
    cpuModel: availableCpus[0]?.model ?? 'unbekannt',
    logicalCpuCount: availableCpus.length,
    totalMemoryBytes: totalmem(),
    freeMemoryBytes: freemem(),
  };
}

async function benchmarkEntryList(
  entries: readonly VaultEntry[],
  now: Date,
): Promise<EntryListBenchmarkResult> {
  const service = new EntryViewService(undefined, () => now);
  const fullQuery = baseQuery();
  const coldList = await measure(() => service.listAsync(entries, fullQuery));
  const searchOrdinal = String(Math.floor(entries.length / 2) + 1).padStart(5, '0');
  const searchWithCachedSecurityReport = await measure(() =>
    service.listAsync(entries, {
      ...fullQuery,
      search: `benchmark-eintrag ${searchOrdinal}`,
    }),
  );
  return {
    coldList: { durationMs: coldList.durationMs, resultCount: coldList.result.length },
    searchWithCachedSecurityReport: {
      durationMs: searchWithCachedSecurityReport.durationMs,
      resultCount: searchWithCachedSecurityReport.result.length,
      securityReportCache: 'warm',
      searchResultCache: 'not-cached',
    },
  };
}

async function benchmarkSecurityScan(
  entries: readonly VaultEntry[],
  now: Date,
): Promise<SecurityScanBenchmarkResult> {
  let fullProgressEvents = 0;
  let fullYieldCount = 0;
  const fullScan = await measure(() =>
    new SecurityCheckService().scanAsync(entries, {
      now,
      onProgress: () => {
        fullProgressEvents += 1;
      },
      yieldControl: async () => {
        fullYieldCount += 1;
        await yieldToEventLoop();
      },
    }),
  );

  const cancellation = await benchmarkSecurityCancellation(entries, now);
  return {
    batchScheduling: {
      usesProductionDefault: true,
      explicitBatchSize: null,
    },
    fullScan: {
      durationMs: fullScan.durationMs,
      findingCount: fullScan.result.findings.length,
      progressEvents: fullProgressEvents,
      yieldCount: fullYieldCount,
    },
    cancellation,
  };
}

async function benchmarkSecurityCancellation(
  entries: readonly VaultEntry[],
  now: Date,
): Promise<SecurityScanBenchmarkResult['cancellation']> {
  const controller = new AbortController();
  const startedAt = performance.now();
  let firstYieldAt: number | null = null;
  let yieldCount = 0;
  const result = await measure(async () => {
    try {
      await new SecurityCheckService().scanAsync(entries, {
        now,
        assertAuthorized: () => {
          if (controller.signal.aborted) {
            throw new VaultaError('CANCELLED', 'Synthetischer Benchmark-Abbruch.');
          }
        },
        yieldControl: async () => {
          yieldCount += 1;
          if (firstYieldAt === null) firstYieldAt = elapsedMs(startedAt);
          controller.abort();
          await yieldToEventLoop();
        },
      });
      return false;
    } catch (error) {
      if (error instanceof VaultaError && error.code === 'CANCELLED') return true;
      throw error;
    }
  });
  return {
    durationMs: result.durationMs,
    cancelled: result.result,
    timeToFirstYieldMs: firstYieldAt,
    yieldCount,
  };
}

async function benchmarkDuplicateScan(
  entries: readonly VaultEntry[],
): Promise<DuplicateScanBenchmarkResult> {
  let fullProgressEvents = 0;
  let fullYieldCount = 0;
  const service = new DuplicateService({
    yieldControl: async () => {
      fullYieldCount += 1;
      await yieldToEventLoop();
    },
  });
  const fullScan = await measure(() =>
    service.scan(entries, {
      candidateLimit: 10_000,
      onProgress: () => {
        fullProgressEvents += 1;
      },
    }),
  );

  const cancellation = await benchmarkDuplicateCancellation(entries);
  return {
    fullScan: {
      durationMs: fullScan.durationMs,
      activeEntryCount: fullScan.result.activeEntryCount,
      candidateCount: fullScan.result.candidates.length,
      progressEvents: fullProgressEvents,
      truncated: fullScan.result.truncated,
      yieldCount: fullYieldCount,
    },
    cancellation,
  };
}

async function benchmarkDuplicateCancellation(
  entries: readonly VaultEntry[],
): Promise<DuplicateScanBenchmarkResult['cancellation']> {
  const controller = new AbortController();
  const startedAt = performance.now();
  let firstYieldAt: number | null = null;
  let yieldCount = 0;
  const service = new DuplicateService({
    yieldControl: async () => {
      yieldCount += 1;
      if (firstYieldAt === null) firstYieldAt = elapsedMs(startedAt);
      controller.abort();
      await yieldToEventLoop();
    },
  });
  const result = await measure(async () => {
    try {
      await service.scan(entries, { signal: controller.signal });
      return false;
    } catch (error) {
      if (error instanceof VaultaError && error.code === 'CANCELLED') return true;
      throw error;
    }
  });
  return {
    durationMs: result.durationMs,
    cancelled: result.result,
    timeToFirstYieldMs: firstYieldAt,
    yieldCount,
  };
}

function baseQuery(): EntryListQuery {
  return {
    vaultId: 'benchmark-vault',
    search: '',
    view: 'all',
    types: [],
    tags: [],
    folderId: null,
    security: [],
  };
}

async function measure<T>(
  operation: () => T | Promise<T>,
): Promise<PerformanceBenchmarkTiming & { result: T }> {
  const startedAt = performance.now();
  const result = await operation();
  return { durationMs: elapsedMs(startedAt), result };
}

function elapsedMs(startedAt: number): number {
  return Number((performance.now() - startedAt).toFixed(3));
}

function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

function validateEntryCount(value: number): asserts value is PerformanceBenchmarkSize {
  if (!PERFORMANCE_BENCHMARK_SIZES.includes(value as PerformanceBenchmarkSize)) {
    throw new VaultaError('INVALID_INPUT', 'Die Benchmark-Datensatzgroesse ist nicht zugelassen.');
  }
}

function validateBenchmarkSizes(values: readonly number[] | undefined): PerformanceBenchmarkSize[] {
  const requested = values === undefined ? [...PERFORMANCE_BENCHMARK_SIZES] : [...values];
  if (requested.length === 0) {
    throw new VaultaError(
      'INVALID_INPUT',
      'Mindestens eine Benchmark-Datensatzgroesse ist erforderlich.',
    );
  }
  for (const value of requested) validateEntryCount(value);
  const unique = [...new Set(requested)] as PerformanceBenchmarkSize[];
  return unique.sort((left, right) => left - right);
}

function validateNow(value: Date | undefined): Date {
  const now = value === undefined ? new Date(DEFAULT_NOW) : new Date(value);
  if (Number.isNaN(now.getTime())) {
    throw new VaultaError('INVALID_INPUT', 'Der Benchmark-Zeitpunkt ist ungueltig.');
  }
  return now;
}
