import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { runInNewContext } from 'node:vm';

const preloadPath = path.resolve('dist/main/preload/index.js');
const source = await readFile(preloadPath, 'utf8');
const requiredModules = [...source.matchAll(/\brequire\((['"])([^'"]+)\1\)/gu)].map(
  (match) => match[2],
);
const unexpectedModules = requiredModules.filter((specifier) => specifier !== 'electron');

if (requiredModules.length === 0 || !requiredModules.includes('electron')) {
  throw new Error('Das Preload-Bundle enthält keinen statisch prüfbaren Electron-Import.');
}
if (unexpectedModules.length > 0) {
  throw new Error(
    `Sandbox-Preload enthält unerlaubte Laufzeitabhängigkeiten: ${unexpectedModules.join(', ')}`,
  );
}
if (!source.includes('exposeInMainWorld')) {
  throw new Error('Das Preload-Bundle exponiert die Vaulta-API nicht.');
}

let exposedApi;
runInNewContext(source, {
  require: (specifier) => {
    if (specifier !== 'electron') {
      throw new Error(`Unerlaubter Sandbox-Import: ${String(specifier)}`);
    }
    return {
      contextBridge: {
        exposeInMainWorld: (key, value) => {
          if (key === 'vaulta') exposedApi = value;
        },
      },
      ipcRenderer: {
        invoke: () => Promise.resolve({ ok: true, value: undefined }),
        on: () => undefined,
        removeListener: () => undefined,
      },
    };
  },
});
if (
  exposedApi === undefined ||
  typeof exposedApi !== 'object' ||
  typeof exposedApi.system?.getState !== 'function'
) {
  throw new Error('Das gebaute Preload-Bundle exponiert keine gültige Vaulta-API.');
}

process.stdout.write(
  'Sandbox-Preload ist ein selbstständiges Bundle mit ausschließlich Electron.\n',
);
