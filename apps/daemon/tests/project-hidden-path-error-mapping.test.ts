// Per-catch-site mapping for the imported-project hidden-path refusal.
//
// The route layer has several independent catch blocks that can swallow the
// guard's error. Each one must translate it into the same typed 4xx instead of
// the generic `500 INTERNAL_ERROR: "upload failed"`.
//
// This file covers the catch sites that are NOT reachable through the HTTP
// surface (the multipart upload route and the multer error handler sanitize
// every incoming name, so the guard can never fire there) plus the shared
// mapper used by the JSON upload route.

import { describe, expect, it } from 'vitest';
import multer from 'multer';

import {
  IMPORTED_PROJECT_HIDDEN_PATH_STATUS,
  isImportedProjectHiddenPathError,
  sendImportedProjectHiddenPathError,
  sendProjectUploadError,
} from '../src/http/imported-project-hidden-path.js';
import { ImportedProjectHiddenPathError } from '../src/projects.js';
import { sendMulterError } from '../src/server.js';

type Captured = {
  status: number;
  body: {
    error?: { code?: string; message?: string; details?: { segment?: string; path?: string } };
  };
};

function fakeRes(): { res: any; captured: Captured } {
  const captured: Captured = { status: 0, body: {} };
  const res: any = {
    req: { method: 'POST', route: { path: '/api/projects/:id/files' } },
    status(code: number) {
      captured.status = code;
      return res;
    },
    json(body: unknown) {
      captured.body = body as Captured['body'];
      return res;
    },
  };
  return { res, captured };
}

function hiddenPathError(): ImportedProjectHiddenPathError {
  return new ImportedProjectHiddenPathError('.ssh', '.ssh/id_rsa');
}

describe('imported-project hidden-path error mapping', () => {
  it('classifies only the typed hidden-path error', () => {
    expect(isImportedProjectHiddenPathError(hiddenPathError())).toBe(true);
    expect(isImportedProjectHiddenPathError(new Error('hidden path segments are not accessible'))).toBe(
      false,
    );
    expect(isImportedProjectHiddenPathError(undefined)).toBe(false);
    expect(isImportedProjectHiddenPathError('nope')).toBe(false);
  });

  it('maps the typed error to 403 with a legible message and the offending segment', () => {
    const { res, captured } = fakeRes();

    const handled = sendImportedProjectHiddenPathError(res, hiddenPathError());

    expect(handled).toBe(true);
    expect(captured.status).toBe(IMPORTED_PROJECT_HIDDEN_PATH_STATUS);
    expect(captured.status).toBe(403);
    expect(captured.body.error?.code).toBe('IMPORTED_PROJECT_HIDDEN_PATH');
    expect(captured.body.error?.message).toContain('.ssh');
    expect(captured.body.error?.message).not.toBe('upload failed');
    expect(captured.body.error?.details?.segment).toBe('.ssh');
  });

  it('leaves unrelated errors to the caller', () => {
    const { res, captured } = fakeRes();

    const handled = sendImportedProjectHiddenPathError(res, new Error('boom'));

    expect(handled).toBe(false);
    expect(captured.status).toBe(0);
    expect(captured.body).toEqual({});
  });

  // Catch site: POST /api/projects/:id/upload (routes/project/index.ts).
  it('project upload catch site maps the typed error and keeps the generic 500 fallback', () => {
    const hidden = fakeRes();
    sendProjectUploadError(hidden.res, hiddenPathError());
    expect(hidden.captured.status).toBe(403);
    expect(hidden.captured.body.error?.code).toBe('IMPORTED_PROJECT_HIDDEN_PATH');
    expect(hidden.captured.body.error?.message).not.toBe('upload failed');

    const generic = fakeRes();
    sendProjectUploadError(generic.res, new Error('boom'));
    expect(generic.captured.status).toBe(500);
    expect(generic.captured.body.error?.code).toBe('INTERNAL_ERROR');
    expect(generic.captured.body.error?.message).toBe('upload failed');
  });

  // Catch site: sendMulterError (server.ts) — both generic 500 branches.
  it('multer error handler maps the typed error and keeps its other mappings', () => {
    const hidden = fakeRes();
    sendMulterError(hidden.res, hiddenPathError());
    expect(hidden.captured.status).toBe(403);
    expect(hidden.captured.body.error?.code).toBe('IMPORTED_PROJECT_HIDDEN_PATH');
    expect(hidden.captured.body.error?.message).not.toBe('upload failed');

    const tooLarge = fakeRes();
    sendMulterError(tooLarge.res, new multer.MulterError('LIMIT_FILE_SIZE'));
    expect(tooLarge.captured.status).toBe(413);
    expect(tooLarge.captured.body.error?.code).toBe('PAYLOAD_TOO_LARGE');

    const generic = fakeRes();
    sendMulterError(generic.res, new Error('boom'));
    expect(generic.captured.status).toBe(500);
    expect(generic.captured.body.error?.code).toBe('INTERNAL_ERROR');
    expect(generic.captured.body.error?.message).toBe('upload failed');
  });
});
