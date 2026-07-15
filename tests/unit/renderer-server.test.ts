import { request as httpRequest } from 'node:http';
import { resolve } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { RendererServer } from '../../src/main/renderer-server';

interface ResponseResult {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

describe('RendererServer', () => {
  let server: RendererServer;
  let origin: string;

  beforeEach(async () => {
    server = new RendererServer(resolve(process.cwd(), 'tests', 'fixtures', 'renderer'));
    origin = await server.start();
  });

  afterEach(async () => {
    await server.close();
  });

  it('liefert Renderer-Dateien ausschliesslich mit Sicherheitsheadern aus', async () => {
    const response = await request(origin, '/');
    expect(response.status).toBe(200);
    expect(response.body).toContain('Vaulta Renderer');
    expect(response.headers['content-type']).toBe('text/html; charset=utf-8');
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['content-security-policy']).toContain("default-src 'none'");
    expect(response.headers['content-security-policy']).toContain("frame-src 'self' data: blob:");
    expect(response.headers['permissions-policy']).toContain('camera=()');
  });

  it('unterstuetzt HEAD und liefert bekannte Content-Types', async () => {
    const script = await request(origin, '/app.js');
    const head = await request(origin, '/app.js', 'HEAD');
    expect(script.status).toBe(200);
    expect(script.headers['content-type']).toBe('text/javascript; charset=utf-8');
    expect(head.status).toBe(200);
    expect(head.body).toBe('');
    expect(head.headers['content-length']).toBe(String(Buffer.byteLength(script.body)));
  });

  it('liefert dieselbe localhost-Origin ueber IPv4 und IPv6 aus', async () => {
    const ipv4 = await request(origin, '/', 'GET', undefined, '127.0.0.1');
    const ipv6 = await request(origin, '/', 'GET', undefined, '::1');
    const resolvedLocalhost = await request(origin, '/', 'GET', undefined, 'localhost');
    expect(ipv4.status).toBe(200);
    expect(ipv6.status).toBe(200);
    expect(resolvedLocalhost.status).toBe(200);
    expect(ipv6.body).toBe(ipv4.body);
    expect(resolvedLocalhost.body).toBe(ipv4.body);
  });

  it('blockiert Traversal, versteckte Pfade, fremde Hosts und Schreibmethoden', async () => {
    const traversal = await request(origin, '/%2e%2e/package.json');
    const hidden = await request(origin, '/.env');
    const foreignHost = await request(origin, '/', 'GET', 'evil.example');
    const post = await request(origin, '/', 'POST');
    expect([traversal.status, hidden.status, foreignHost.status, post.status]).toEqual([
      404, 404, 404, 404,
    ]);
  });

  it('ist idempotent startbar und verwendet fuer SPA-Routen index.html', async () => {
    await expect(server.start()).resolves.toBe(origin);
    const response = await request(origin, '/eintraege/123');
    expect(response.status).toBe(200);
    expect(response.body).toContain('Vaulta Renderer');
  });
});

function request(
  origin: string,
  path: string,
  method = 'GET',
  host?: string,
  hostname = '127.0.0.1',
): Promise<ResponseResult> {
  const target = new URL(origin);
  return new Promise((resolveRequest, reject) => {
    const request = httpRequest(
      {
        hostname,
        port: target.port,
        path,
        method,
        agent: false,
        headers: { host: host ?? `localhost:${target.port}` },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.on('end', () => {
          resolveRequest({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    request.on('error', reject);
    request.end();
  });
}
