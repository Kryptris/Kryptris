import { describe, expect, it, vi } from 'vitest';

import { LocalJobCoordinator } from '../../src/main/services/local-job-coordinator';

describe('LocalJobCoordinator', () => {
  it('koalesziert dieselbe Revision und liefert technischen Fortschritt an beide Aufrufer', async () => {
    const coordinator = new LocalJobCoordinator();
    const firstProgress = vi.fn();
    const secondProgress = vi.fn();
    let finish: ((value: { count: number }) => void) | undefined;
    const worker = vi.fn(
      (context: {
        reportProgress(progress: { phase: string; completed: number; total: number }): void;
      }) => {
        context.reportProgress({ phase: 'scan', completed: 1, total: 2 });
        return new Promise<{ count: number }>((resolve) => {
          finish = resolve;
        });
      },
    );

    const first = coordinator.run(
      { requestId: 'one', jobKey: 'quality:vault', revision: 'r1', onProgress: firstProgress },
      worker,
    );
    await vi.waitFor(() => expect(worker).toHaveBeenCalledTimes(1));
    const second = coordinator.run(
      { requestId: 'two', jobKey: 'quality:vault', revision: 'r1', onProgress: secondProgress },
      worker,
    );
    finish?.({ count: 2 });

    await expect(first).resolves.toEqual({ count: 2 });
    await expect(second).resolves.toEqual({ count: 2 });
    expect(worker).toHaveBeenCalledTimes(1);
    expect(firstProgress).toHaveBeenCalledWith({ phase: 'scan', completed: 1, total: 2 });
    expect(coordinator.activeCount()).toBe(0);
  });

  it('bricht synchron signalisiert ab und cached keinen Teilwert', async () => {
    const coordinator = new LocalJobCoordinator();
    let continueWorker: (() => void) | undefined;
    const pending = coordinator.run(
      { requestId: 'cancel-me', jobKey: 'duplicates', revision: 'r1' },
      async ({ assertActive }) => {
        await new Promise<void>((resolve) => {
          continueWorker = resolve;
        });
        assertActive();
        return { secret: 'nicht-cachen' };
      },
    );
    await vi.waitFor(() => expect(continueWorker).toBeTypeOf('function'));
    expect(coordinator.cancel('cancel-me')).toBe(true);
    continueWorker?.();
    await expect(pending).rejects.toMatchObject({ code: 'CANCELLED' });

    const worker = vi.fn(() => Promise.resolve({ fresh: true }));
    await expect(
      coordinator.run({ requestId: 'retry', jobKey: 'duplicates', revision: 'r1' }, worker),
    ).resolves.toEqual({ fresh: true });
    expect(worker).toHaveBeenCalledTimes(1);
  });

  it('invalidiert Aufgaben und Cache beim Sperren vollständig', async () => {
    const coordinator = new LocalJobCoordinator();
    await coordinator.run({ requestId: 'cached', jobKey: 'security', revision: 'r1' }, () =>
      Promise.resolve({ findings: [1] }),
    );
    coordinator.clear();
    const worker = vi.fn(() => Promise.resolve({ findings: [2] }));
    await expect(
      coordinator.run({ requestId: 'after-lock', jobKey: 'security', revision: 'r1' }, worker),
    ).resolves.toEqual({ findings: [2] });
    expect(worker).toHaveBeenCalledTimes(1);
  });

  it('bricht einen bestimmten Job ab und verwirft dessen Cache', async () => {
    const coordinator = new LocalJobCoordinator();
    let release: (() => void) | undefined;
    const running = coordinator.run(
      { requestId: 'abort-one', jobKey: 'integrity', revision: 'r1' },
      async ({ assertActive }) => {
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        assertActive();
        return 'unerreichbar';
      },
    );
    await vi.waitFor(() => expect(release).toBeTypeOf('function'));

    expect(coordinator.abort('integrity')).toBe(true);
    release?.();
    await expect(running).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(coordinator.abort('integrity')).toBe(false);
  });

  it('wartet beim gezielten Abbruch auf den Workerabschluss', async () => {
    const coordinator = new LocalJobCoordinator();
    let release: (() => void) | undefined;
    const running = coordinator.run(
      { requestId: 'abort-wait', jobKey: 'breach-scan', revision: 'r1' },
      async ({ assertActive }) => {
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        assertActive();
        return 'unerreichbar';
      },
    );
    await vi.waitFor(() => expect(release).toBeTypeOf('function'));
    const cancellation = coordinator.abortAndWait('breach-scan');
    release?.();

    await expect(cancellation).resolves.toBe(true);
    await expect(running).rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('lehnt eine konkurrierende Revision ab und signalisiert dem alten Lauf Abbruch', async () => {
    const coordinator = new LocalJobCoordinator();
    let release: (() => void) | undefined;
    const first = coordinator.run(
      { requestId: 'old', jobKey: 'quality', revision: 'r1' },
      async ({ assertActive }) => {
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        assertActive();
        return 'old';
      },
    );
    await vi.waitFor(() => expect(release).toBeTypeOf('function'));
    await expect(
      coordinator.run({ requestId: 'new', jobKey: 'quality', revision: 'r2' }, () =>
        Promise.resolve('new'),
      ),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    release?.();
    await expect(first).rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('bindet ein abgeschlossenes Ergebnis geklont an die nachfolgende technische Revision', async () => {
    const coordinator = new LocalJobCoordinator();
    const original = { findings: [{ code: 'ok' }] };
    await coordinator.run(
      { requestId: 'initial', jobKey: 'integrity', revision: 'before-commit' },
      () => Promise.resolve(original),
    );

    coordinator.cacheResult('integrity', 'after-commit', original);
    original.findings[0]!.code = 'mutated-by-caller';
    const worker = vi.fn(() => Promise.resolve({ findings: [{ code: 'recalculated' }] }));
    const cached = await coordinator.run(
      { requestId: 'cached-after-commit', jobKey: 'integrity', revision: 'after-commit' },
      worker,
    );
    cached.findings[0]!.code = 'mutated-return-value';
    const cachedAgain = await coordinator.run(
      { requestId: 'cached-again', jobKey: 'integrity', revision: 'after-commit' },
      worker,
    );

    expect(cachedAgain).toEqual({ findings: [{ code: 'ok' }] });
    expect(worker).not.toHaveBeenCalled();
  });
});
