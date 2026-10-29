import type { ApiErrorCode } from '@open-design/contracts';
import type { Response } from 'express';

import { ImportedProjectHiddenPathError } from '../projects.js';

import { sendApiError } from './api-errors.js';

/**
 * Stable machine-readable code for the imported-project hidden-path refusal.
 * Declared in `packages/contracts` so web/daemon clients share one enum.
 */
export const IMPORTED_PROJECT_HIDDEN_PATH_CODE: ApiErrorCode = 'IMPORTED_PROJECT_HIDDEN_PATH';

/**
 * 403 Forbidden.
 *
 * The request is well-formed — it names a real path inside the project — but
 * that path is deliberately not addressable, because an imported project is a
 * folder OUTSIDE the app's managed data root and hidden segments (`.ssh`,
 * `.aws`, …) there may hold the user's own credentials. It is a policy refusal
 * about the target, not a malformed request (400) and not a missing resource
 * (404): the file may well exist, the daemon just refuses to touch it.
 */
export const IMPORTED_PROJECT_HIDDEN_PATH_STATUS = 403;

export function isImportedProjectHiddenPathError(
  err: unknown,
): err is ImportedProjectHiddenPathError {
  return err instanceof ImportedProjectHiddenPathError;
}

/**
 * Writes the typed 4xx for a hidden-path refusal.
 *
 * Returns `true` when it handled the error (the response has been written) and
 * `false` when the error is something else, so callers can fall through to
 * their own handling. Never swallows the error: the operation still fails.
 */
export function sendImportedProjectHiddenPathError(res: Response, err: unknown): boolean {
  if (!isImportedProjectHiddenPathError(err)) return false;
  sendApiError(
    res,
    IMPORTED_PROJECT_HIDDEN_PATH_STATUS,
    IMPORTED_PROJECT_HIDDEN_PATH_CODE,
    err.message,
    { details: { segment: err.segment } },
  );
  return true;
}

/**
 * Shared handler for the project upload catch blocks.
 *
 * The hidden-path refusal gets its own typed 4xx; everything else keeps the
 * historical generic `500 INTERNAL_ERROR: "upload failed"` so unrelated upload
 * failures do not change shape.
 */
export function sendProjectUploadError(res: Response, err: unknown): void {
  if (sendImportedProjectHiddenPathError(res, err)) return;
  sendApiError(res, 500, 'INTERNAL_ERROR', 'upload failed');
}
