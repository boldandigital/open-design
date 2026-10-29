// Error-SHAPE contract for the imported-project hidden-path refusal.
//
// The daemon already REFUSES hidden path segments (".ssh", ".aws", ...) inside
// an IMPORTED project (external metadata.baseDir) — that rule lives in
// projects.ts::assertVisibleForImportedProject and is covered by
// tests/security-import-folder-dotfiles.test.ts. This file pins the SHAPE of
// that refusal, NOT the rule:
//
//   before: the guard threw a plain Error, indistinguishable from any internal
//           fault, so the route catch blocks flattened it into
//           `500 INTERNAL_ERROR: "upload failed"`.
//   after:  a typed 403 with code IMPORTED_PROJECT_HIDDEN_PATH, a legible
//           message naming the offending segment, and details that expose
//           neither the imported project's absolute root nor any file content.
//
// The refusal must still ABORT the operation (no partial write) and managed
// projects (no external baseDir) must stay unaffected.

import type http from 'node:http';
import { existsSync, mkdtempSync } from 'node:fs';
import { readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import { startServer } from '../src/server.js';

type ErrorEnvelope = {
  error?: {
    code?: string;
    message?: string;
    details?: { segment?: string; path?: string };
  };
};

describe('imported-project hidden-path refusal: typed 4xx error shape', () => {
  let server: http.Server;
  let baseUrl: string;
  const tempDirs: string[] = [];

  // The daemon server boots the full runtime (DB, plugins, adapters), which
  // takes well over vitest's default 10s hook timeout on this machine. Give it
  // explicit headroom so the suite does not flake on a slow (external SSD) box.
  beforeAll(async () => {
    const started = (await startServer({ port: 0, host: '127.0.0.1', returnServer: true })) as {
      url: string;
      server: http.Server;
    };
    baseUrl = started.url;
    server = started.server;
  }, 120_000);

  afterAll(() => {
    if (!server) return;
    return new Promise<void>((resolve) => server.close(() => resolve()));
  });

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  });

  function makeFolder(): string {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'od-hidden-path-'));
    tempDirs.push(dir);
    return dir;
  }

  async function importFolder(baseDir: string): Promise<{ id: string; baseDir: string }> {
    const resp = await fetch(`${baseUrl}/api/import/folder`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ baseDir, name: 'hidden-path-fixture' }),
    });
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as { project: { id: string; metadata?: { baseDir?: string } } };
    return { id: body.project.id, baseDir: body.project.metadata?.baseDir ?? baseDir };
  }

  async function jsonError(resp: Response): Promise<ErrorEnvelope> {
    return (await resp.json().catch(() => ({}))) as ErrorEnvelope;
  }

  async function writeFileJson(
    projectId: string,
    name: string,
    content: string,
  ): Promise<Response> {
    return fetch(`${baseUrl}/api/projects/${projectId}/files`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, content }),
    });
  }

  // The core bug: a hidden path in an imported project produced an opaque
  // 500 INTERNAL_ERROR. It must be a typed, legible 4xx instead.
  it('POST /api/projects/:id/files refuses a hidden path with a typed 4xx, not 500 INTERNAL_ERROR', async () => {
    const folder = makeFolder();
    await writeFile(path.join(folder, 'index.html'), '<!doctype html>');
    const project = await importFolder(folder);

    const resp = await writeFileJson(project.id, '.ssh/id_rsa', 'pwned');

    expect(resp.status).toBe(403);
    expect(resp.status).not.toBe(500);
    const body = await jsonError(resp);
    expect(body.error?.code).toBe('IMPORTED_PROJECT_HIDDEN_PATH');
    expect(body.error?.code).not.toBe('INTERNAL_ERROR');
    expect(body.error?.message).not.toBe('upload failed');
    expect(body.error?.message).toContain('.ssh');
    expect(body.error?.details?.segment).toBe('.ssh');
  });

  // No information leak: the refusal may name the segment the caller asked
  // for, but never the imported project's absolute root, a directory listing,
  // or file content.
  it('the refusal does not leak the imported project root or file content', async () => {
    const folder = makeFolder();
    await writeFile(path.join(folder, 'index.html'), '<!doctype html>');
    const project = await importFolder(folder);

    const resp = await writeFileJson(project.id, '.ssh/id_rsa', 'SUPER-SECRET-CONTENT');
    const raw = await resp.text();
    const body = JSON.parse(raw) as ErrorEnvelope;

    expect(body.error?.code).toBe('IMPORTED_PROJECT_HIDDEN_PATH');
    expect(raw).not.toContain('SUPER-SECRET-CONTENT');
    expect(raw).not.toContain(project.baseDir);
    expect(raw).not.toContain(folder);
  });

  // The refusal must ABORT, not degrade into a partial write. Neither the
  // requested path nor the sanitized fallback may appear on disk.
  it('the refusal aborts the operation — no partial write lands on disk', async () => {
    const folder = makeFolder();
    await writeFile(path.join(folder, 'index.html'), '<!doctype html>');
    const project = await importFolder(folder);

    const resp = await writeFileJson(project.id, '.ssh/id_rsa', 'pwned');
    expect(resp.status).toBe(403);

    expect(existsSync(path.join(folder, '.ssh'))).toBe(false);
    expect(existsSync(path.join(folder, '.ssh', 'id_rsa'))).toBe(false);
    expect(existsSync(path.join(folder, '_ssh'))).toBe(false);
    expect(existsSync(path.join(folder, '_ssh', 'id_rsa'))).toBe(false);
  });

  // The rule itself must be unchanged: an ordinary path in an imported
  // project still works and still lands in the imported folder.
  it('a normal (non-hidden) path in an imported project still succeeds', async () => {
    const folder = makeFolder();
    await writeFile(path.join(folder, 'index.html'), '<!doctype html>');
    const project = await importFolder(folder);

    const resp = await writeFileJson(project.id, 'notes.md', 'hello');

    expect(resp.status).toBe(200);
    await expect(readFile(path.join(project.baseDir, 'notes.md'), 'utf8')).resolves.toBe('hello');
  });

  // A managed project (no external baseDir) is out of scope for the rule and
  // must stay out of scope for the typed error.
  it('a managed project (no external baseDir) is unaffected', async () => {
    const projectId = `managed-hidden-path-${Date.now()}`;
    const createResp = await fetch(`${baseUrl}/api/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: projectId,
        name: 'managed-hidden-path',
        metadata: { kind: 'prototype' },
        skipDiscoveryBrief: true,
      }),
    });
    expect(createResp.status).toBe(200);

    const resp = await writeFileJson(projectId, '.ssh/id_rsa', 'allowed');
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as { error?: { code?: string } };
    expect(body.error?.code).not.toBe('IMPORTED_PROJECT_HIDDEN_PATH');
  });

  // Every sibling route that funnels through the same guard must answer with
  // the same typed error, not a generic 400/404/500.
  it('GET /api/projects/:id/files/<hidden> returns the typed refusal', async () => {
    const folder = makeFolder();
    await writeFile(path.join(folder, 'index.html'), '<!doctype html>');
    const project = await importFolder(folder);

    const resp = await fetch(`${baseUrl}/api/projects/${project.id}/files/.ssh/id_rsa`);

    expect(resp.status).toBe(403);
    const body = await jsonError(resp);
    expect(body.error?.code).toBe('IMPORTED_PROJECT_HIDDEN_PATH');
    expect(body.error?.details?.segment).toBe('.ssh');
  });

  it('DELETE /api/projects/:id/files/<hidden> returns the typed refusal', async () => {
    const folder = makeFolder();
    await writeFile(path.join(folder, 'index.html'), '<!doctype html>');
    await writeFile(path.join(folder, '.ssh'), 'not a real dir');
    const project = await importFolder(folder);

    const resp = await fetch(`${baseUrl}/api/projects/${project.id}/files/.ssh`, {
      method: 'DELETE',
    });

    expect(resp.status).toBe(403);
    const body = await jsonError(resp);
    expect(body.error?.code).toBe('IMPORTED_PROJECT_HIDDEN_PATH');
    expect(body.error?.details?.segment).toBe('.ssh');
  });

  it('POST /api/projects/:id/folders refuses a hidden folder name with the typed refusal', async () => {
    const folder = makeFolder();
    await writeFile(path.join(folder, 'index.html'), '<!doctype html>');
    const project = await importFolder(folder);

    const resp = await fetch(`${baseUrl}/api/projects/${project.id}/folders`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: '.ssh' }),
    });

    expect(resp.status).toBe(403);
    const body = await jsonError(resp);
    expect(body.error?.code).toBe('IMPORTED_PROJECT_HIDDEN_PATH');
    expect(body.error?.details?.segment).toBe('.ssh');
    expect(existsSync(path.join(folder, '.ssh'))).toBe(false);
  });

  it('DELETE /api/projects/:id/folders refuses a hidden folder path with the typed refusal', async () => {
    const folder = makeFolder();
    await writeFile(path.join(folder, 'index.html'), '<!doctype html>');
    const project = await importFolder(folder);

    const resp = await fetch(`${baseUrl}/api/projects/${project.id}/folders`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: '.ssh' }),
    });

    expect(resp.status).toBe(403);
    const body = await jsonError(resp);
    expect(body.error?.code).toBe('IMPORTED_PROJECT_HIDDEN_PATH');
    expect(body.error?.details?.segment).toBe('.ssh');
  });

  it('POST /api/projects/:id/files/rename refuses a hidden target with the typed refusal', async () => {
    const folder = makeFolder();
    await writeFile(path.join(folder, 'index.html'), '<!doctype html>');
    await writeFile(path.join(folder, 'notes.md'), 'keep');
    const project = await importFolder(folder);

    const resp = await fetch(`${baseUrl}/api/projects/${project.id}/files/rename`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: 'notes.md', to: '.ssh/id_rsa' }),
    });

    expect(resp.status).toBe(403);
    const body = await jsonError(resp);
    expect(body.error?.code).toBe('IMPORTED_PROJECT_HIDDEN_PATH');
    expect(body.error?.details?.segment).toBe('.ssh');
    await expect(readFile(path.join(folder, 'notes.md'), 'utf8')).resolves.toBe('keep');
  });

  // The rule refuses EVERY hidden segment, not just a leading one.
  it('refuses a hidden segment in the middle of a path too', async () => {
    const folder = makeFolder();
    await writeFile(path.join(folder, 'index.html'), '<!doctype html>');
    const project = await importFolder(folder);

    const resp = await writeFileJson(project.id, 'docs/.aws/credentials', 'pwned');

    expect(resp.status).toBe(403);
    const body = await jsonError(resp);
    expect(body.error?.code).toBe('IMPORTED_PROJECT_HIDDEN_PATH');
    expect(body.error?.details?.segment).toBe('.aws');
  });
});
