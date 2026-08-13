import { describe, expect, it } from 'vitest';

import { VaultaError } from '../../src/shared/errors';
import { DuplicateService } from '../../src/main/services/duplicate-service';
import {
  PERFORMANCE_BENCHMARK_SIZES,
  createSyntheticBenchmarkEntries,
  runPerformanceBenchmark,
} from '../../src/main/services/performance-benchmark';

describe('Performance-Benchmark-Fixture', () => {
  it('erzeugt fuer jede Roadmap-Groesse deterministische, ausschliesslich synthetische Daten', () => {
    for (const size of PERFORMANCE_BENCHMARK_SIZES) {
      const first = createSyntheticBenchmarkEntries(size);
      const second = createSyntheticBenchmarkEntries(size);

      expect(first).toEqual(second);
      expect(first).toHaveLength(size);
      expect(first.every((entry) => entry.vaultId === 'benchmark-vault')).toBe(true);
      expect(
        first.every((entry) => entry.title.startsWith('Synthetischer Benchmark-Eintrag ')),
      ).toBe(true);
      expect(first.every((entry) => entry.data.type === 'credential')).toBe(true);
      expect(
        first.every(
          (entry) =>
            entry.data.type !== 'credential' || /^x![0-9a-z]+$/u.test(entry.data.value.password),
        ),
      ).toBe(true);
    }
  });

  it('erzeugt wenige, feste Paar-Kandidaten ohne grossflaechige Gleichwerte', async () => {
    const entries = createSyntheticBenchmarkEntries(1_000);
    const usernames = entries.map((entry) =>
      entry.data.type === 'credential' ? entry.data.value.username : '',
    );
    const repeated = usernames.filter((username, index) => usernames.indexOf(username) !== index);

    expect(repeated).toHaveLength(5);
    expect(new Set(repeated)).toHaveLength(5);
    const websites = entries.map((entry) =>
      entry.data.type === 'credential' ? entry.data.value.websites[0] : '',
    );
    expect(websites.filter((website, index) => websites.indexOf(website) !== index)).toHaveLength(
      5,
    );

    const duplicateResult = await new DuplicateService().scan(entries, { candidateLimit: 10_000 });
    expect(duplicateResult).toMatchObject({ activeEntryCount: 1_000, truncated: false });
    expect(duplicateResult.candidates).toHaveLength(5);
  });

  it('lehnt andere oder leere Groessen fail-closed ab', () => {
    expect(() => createSyntheticBenchmarkEntries(999)).toThrow(VaultaError);
    expect(() => createSyntheticBenchmarkEntries(0)).toThrow(/nicht zugelassen/u);
  });

  it('lehnt unzulaessige oder leere Benchmark-Konfigurationen vor der Auswertung ab', async () => {
    await expect(runPerformanceBenchmark({ sizes: [999] })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(runPerformanceBenchmark({ sizes: [] })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
  });

  it('kennzeichnet die gemessenen Main-Prozess-Pfade und ihre Cache- und Batch-Semantik', async () => {
    const report = await runPerformanceBenchmark({ sizes: [1_000] });
    const dataset = report.datasets[0]!;

    expect(report.scope).toEqual({
      process: 'main',
      entryList:
        'EntryViewService.listAsync: cold list and fresh search with cached security report',
      securityScan:
        'SecurityCheckService.scanAsync: full scan and cooperative authorization cancellation',
      duplicateScan: 'DuplicateService.scan: full scan and cooperative AbortSignal cancellation',
    });
    expect(dataset.entryList).toMatchObject({
      coldList: { resultCount: 1_000 },
      searchWithCachedSecurityReport: {
        resultCount: 1,
        securityReportCache: 'warm',
        searchResultCache: 'not-cached',
      },
    });
    expect(dataset.entryList).not.toHaveProperty('cachedSearch');
    expect(dataset.securityScan.batchScheduling).toEqual({
      usesProductionDefault: true,
      explicitBatchSize: null,
    });
    // The default production batch size is ten entries. Its yield count proves this benchmark
    // uses that default instead of an explicit, benchmark-only override.
    expect(dataset.securityScan.fullScan.yieldCount).toBe(100);
  });
});
