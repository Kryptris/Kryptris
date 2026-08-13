import { VaultaError } from '../../shared/errors';

export interface LocalJobProgress {
  readonly phase: string;
  readonly completed: number;
  readonly total: number;
}

export interface LocalJobContext {
  readonly signal: AbortSignal;
  readonly assertActive: () => void;
  readonly reportProgress: (progress: LocalJobProgress) => void;
  readonly yieldToEventLoop: () => Promise<void>;
}

export interface LocalJobRequest {
  readonly requestId: string;
  readonly jobKey: string;
  readonly revision: string;
  readonly onProgress?: (progress: LocalJobProgress) => void;
}

interface ActiveJob<T = unknown> {
  readonly requestIds: Set<string>;
  readonly revision: string;
  readonly controller: AbortController;
  readonly listeners: Set<(progress: LocalJobProgress) => void>;
  readonly promise: Promise<T>;
}

interface CachedJob<T = unknown> {
  readonly revision: string;
  readonly value: T;
}

/** Coordinates expensive local scans and gives lock/cancel a synchronous priority signal. */
export class LocalJobCoordinator {
  private readonly active = new Map<string, ActiveJob>();
  private readonly requestToJob = new Map<string, string>();
  private readonly cache = new Map<string, CachedJob>();
  private generation = 0;

  public async run<T>(
    request: LocalJobRequest,
    worker: (context: LocalJobContext) => Promise<T>,
  ): Promise<T> {
    this.validateRequest(request);
    const cached = this.cache.get(request.jobKey);
    if (cached?.revision === request.revision) return structuredClone(cached.value) as T;

    const current = this.active.get(request.jobKey) as ActiveJob<T> | undefined;
    if (current !== undefined) {
      if (current.revision !== request.revision) {
        current.controller.abort();
        throw new VaultaError(
          'CONFLICT',
          'Für diese Auswertung läuft bereits eine andere Datenrevision.',
        );
      }
      current.requestIds.add(request.requestId);
      this.requestToJob.set(request.requestId, request.jobKey);
      if (request.onProgress !== undefined) current.listeners.add(request.onProgress);
      try {
        return structuredClone(await current.promise);
      } finally {
        this.requestToJob.delete(request.requestId);
      }
    }

    const generation = this.generation;
    const controller = new AbortController();
    const requestIds = new Set([request.requestId]);
    const listeners = new Set<(progress: LocalJobProgress) => void>();
    if (request.onProgress !== undefined) listeners.add(request.onProgress);
    const assertActive = () => {
      if (controller.signal.aborted || generation !== this.generation) {
        throw new VaultaError('CANCELLED', 'Die lokale Auswertung wurde abgebrochen.');
      }
    };
    const reportProgress = (progress: LocalJobProgress) => {
      assertActive();
      this.validateProgress(progress);
      for (const listener of listeners) listener(structuredClone(progress));
    };
    const promise = (async () => {
      const value = await worker({
        signal: controller.signal,
        assertActive,
        reportProgress,
        yieldToEventLoop: async () => {
          await new Promise<void>((resolve) => setImmediate(resolve));
          assertActive();
        },
      });
      assertActive();
      this.cache.set(request.jobKey, { revision: request.revision, value: structuredClone(value) });
      return value;
    })();
    const active: ActiveJob<T> = {
      requestIds,
      revision: request.revision,
      controller,
      listeners,
      promise,
    };
    this.active.set(request.jobKey, active);
    this.requestToJob.set(request.requestId, request.jobKey);
    try {
      return structuredClone(await promise);
    } finally {
      if (this.active.get(request.jobKey) === active) this.active.delete(request.jobKey);
      for (const requestId of requestIds) this.requestToJob.delete(requestId);
    }
  }

  public cancel(requestId: string): boolean {
    const jobKey = this.requestToJob.get(requestId);
    if (jobKey === undefined) return false;
    const job = this.active.get(jobKey);
    if (job === undefined) return false;
    job.controller.abort();
    return true;
  }

  public clear(): void {
    this.generation += 1;
    for (const job of this.active.values()) job.controller.abort();
    this.active.clear();
    this.requestToJob.clear();
    this.cache.clear();
  }

  public invalidate(jobKey?: string): void {
    if (jobKey === undefined) this.cache.clear();
    else this.cache.delete(jobKey);
  }

  /**
   * Rebinds a completed result to the technical revision produced by its own
   * atomic status commit. The value is cloned so no caller can mutate the cache.
   */
  public cacheResult<T>(jobKey: string, revision: string, value: T): void {
    if (jobKey.length < 1 || jobKey.length > 200 || revision.length < 1 || revision.length > 500) {
      throw new VaultaError('INVALID_INPUT', 'Der lokale Cache-Schlüssel ist ungültig.');
    }
    this.cache.set(jobKey, { revision, value: structuredClone(value) });
  }

  public abort(jobKey: string): boolean {
    const active = this.active.get(jobKey);
    this.cache.delete(jobKey);
    if (active === undefined) return false;
    active.controller.abort();
    return true;
  }

  public async abortAndWait(jobKey: string): Promise<boolean> {
    const active = this.active.get(jobKey);
    this.cache.delete(jobKey);
    if (active === undefined) return false;
    active.controller.abort();
    try {
      await active.promise;
    } catch {
      // Cancellation is the intended terminal state; the original caller receives its own error.
    }
    return true;
  }

  public activeCount(): number {
    return this.active.size;
  }

  private validateRequest(request: LocalJobRequest): void {
    if (
      request.requestId.length < 1 ||
      request.requestId.length > 200 ||
      request.jobKey.length < 1 ||
      request.jobKey.length > 200 ||
      request.revision.length < 1 ||
      request.revision.length > 500 ||
      this.requestToJob.has(request.requestId)
    ) {
      throw new VaultaError('INVALID_INPUT', 'Die lokale Auswertungsanfrage ist ungültig.');
    }
  }

  private validateProgress(progress: LocalJobProgress): void {
    if (
      progress.phase.length < 1 ||
      progress.phase.length > 100 ||
      !Number.isSafeInteger(progress.completed) ||
      !Number.isSafeInteger(progress.total) ||
      progress.completed < 0 ||
      progress.total < 0 ||
      progress.completed > progress.total
    ) {
      throw new VaultaError('INTERNAL', 'Ein lokaler Fortschrittswert ist ungültig.');
    }
  }
}
