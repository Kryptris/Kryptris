import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer, type RequestListener, type Server } from 'node:http';
import { extname, normalize, resolve, sep } from 'node:path';

import { VaultaError } from '../shared/errors';

const CONTENT_TYPES: Record<string, string> = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.webp': 'image/webp',
  '.woff2': 'font/woff2',
};

const SECURITY_HEADERS = {
  'Cache-Control': 'no-store',
  'Content-Security-Policy': [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-src 'self' data: blob:",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
  ].join('; '),
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy':
    'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), publickey-credentials-get=(self)',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
} as const;

function safeAssetPath(root: string, requestPath: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(requestPath.split('?')[0] ?? '/');
  } catch {
    return null;
  }
  if (
    decoded.includes('\0') ||
    decoded.includes('\\') ||
    decoded.split('/').some((part) => part.startsWith('.'))
  ) {
    return null;
  }
  const relative = normalize(decoded).replace(/^[/\\]+/, '');
  const candidate = resolve(root, relative.length === 0 ? 'index.html' : relative);
  const normalizedRoot = resolve(root);
  if (candidate !== normalizedRoot && !candidate.startsWith(`${normalizedRoot}${sep}`)) return null;
  return candidate;
}

export class RendererServer {
  private servers: Server[] = [];
  private origin: string | null = null;

  public constructor(private readonly rendererRoot: string) {}

  public async start(): Promise<string> {
    if (this.origin !== null) return this.origin;

    const handleRequest: RequestListener = (request, response) => {
      void (async () => {
        const host = request.headers.host ?? '';
        if (!/^localhost:\d+$/.test(host) || !['GET', 'HEAD'].includes(request.method ?? '')) {
          response.writeHead(404, SECURITY_HEADERS);
          response.end();
          return;
        }

        const candidate = safeAssetPath(this.rendererRoot, request.url ?? '/');
        if (candidate === null) {
          response.writeHead(404, SECURITY_HEADERS);
          response.end();
          return;
        }

        let assetPath = candidate;
        try {
          const info = await stat(assetPath);
          if (!info.isFile()) throw new Error('not a file');
        } catch {
          assetPath = resolve(this.rendererRoot, 'index.html');
        }

        try {
          const info = await stat(assetPath);
          const contentType =
            CONTENT_TYPES[extname(assetPath).toLowerCase()] ?? 'application/octet-stream';
          response.writeHead(200, {
            ...SECURITY_HEADERS,
            'Content-Length': info.size,
            'Content-Type': contentType,
          });
          if (request.method === 'HEAD') {
            response.end();
            return;
          }
          createReadStream(assetPath).pipe(response);
        } catch {
          response.writeHead(404, SECURITY_HEADERS);
          response.end();
        }
      })().catch(() => {
        if (!response.headersSent) response.writeHead(500, SECURITY_HEADERS);
        response.end();
      });
    };

    const ipv4Server = createServer(handleRequest);
    await listenOnLoopback(ipv4Server, 0, '127.0.0.1');
    const address = ipv4Server.address();
    if (address === null || typeof address === 'string') {
      await closeServer(ipv4Server);
      throw new VaultaError(
        'INTERNAL',
        'Die lokale Vaulta-Oberfläche konnte nicht gestartet werden.',
      );
    }

    const servers = [ipv4Server];
    const ipv6Server = createServer(handleRequest);
    try {
      await listenOnLoopback(ipv6Server, address.port, '::1', true);
      servers.push(ipv6Server);
    } catch (error) {
      if (!isUnavailableIpv6(error)) {
        await closeServer(ipv4Server);
        throw error;
      }
    }

    this.servers = servers;
    this.origin = `http://localhost:${address.port}`;
    return this.origin;
  }

  public async close(): Promise<void> {
    const servers = this.servers;
    this.servers = [];
    this.origin = null;
    await Promise.all(servers.map((server) => closeServer(server)));
  }
}

function listenOnLoopback(
  server: Server,
  port: number,
  host: '127.0.0.1' | '::1',
  ipv6Only = false,
): Promise<void> {
  return new Promise((resolveStart, reject) => {
    const onError = (error: Error): void => reject(error);
    server.once('error', onError);
    server.listen({ port, host, ipv6Only }, () => {
      server.off('error', onError);
      resolveStart();
    });
  });
}

function closeServer(server: Server): Promise<void> {
  if (!server.listening) return Promise.resolve();
  return new Promise((resolveClose) => {
    server.close(() => resolveClose());
    server.closeIdleConnections();
  });
}

function isUnavailableIpv6(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException).code;
  return code === 'EAFNOSUPPORT' || code === 'EADDRNOTAVAIL' || code === 'ENETUNREACH';
}
