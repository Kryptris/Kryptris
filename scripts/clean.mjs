import { rm } from 'node:fs/promises';

await Promise.all(
  ['dist', 'coverage', 'playwright-report', 'test-results'].map((path) =>
    rm(path, { recursive: true, force: true }),
  ),
);
