import { Request, Response, NextFunction, RequestHandler } from 'express';

/**
 * Options controlling inbound (request body) decompression.
 */
export interface RequestDecompressionOptions {
  /**
   * When false, any request carrying a non-identity `Content-Encoding`
   * is rejected with 415. When true, supported encodings are allowed
   * through to the body parser, which inflates them.
   */
  enabled: boolean;
  /**
   * Lower-cased list of accepted content encodings (besides `identity`).
   * Only encodings the downstream body parser can safely inflate should
   * be listed here — currently `gzip` and `deflate`.
   */
  allowedEncodings: string[];
}

/**
 * Error codes surfaced by the guard. These mirror the shape produced by the
 * global exception filter so clients see a consistent error envelope, even
 * though this guard runs as raw Express middleware (before Nest filters).
 */
export const REQUEST_DECOMPRESSION_ERROR_CODES = {
  DISABLED: 'REQ_COMPRESSION_DISABLED',
  UNSUPPORTED_ENCODING: 'REQ_COMPRESSION_UNSUPPORTED',
  STACKED_ENCODING: 'REQ_COMPRESSION_STACKED',
} as const;

function parseContentEncoding(header: string | string[] | undefined): string[] {
  if (!header) {
    return [];
  }
  const raw = Array.isArray(header) ? header.join(',') : header;
  return raw
    .split(',')
    .map((token) => token.trim().toLowerCase())
    .filter(Boolean);
}

function reject(
  res: Response,
  req: Request,
  errorCode: string,
  message: string,
): void {
  res.status(415).json({
    success: false,
    statusCode: 415,
    errorCode,
    message,
    timestamp: new Date().toISOString(),
    path: req.originalUrl,
  });
}

/**
 * Builds an Express middleware that gates compressed request bodies.
 *
 * It does NOT inflate the body itself — that is delegated to the battle-tested
 * `body-parser` (`express.json` / `express.urlencoded`) layer, which enforces
 * the configured `limit` against the *decompressed* byte stream and aborts with
 * HTTP 413 once that limit is exceeded. This is the zip-bomb safeguard: a tiny
 * compressed payload that inflates past the limit is rejected mid-stream rather
 * than fully buffered.
 *
 * This guard's job is policy enforcement that the parser does not own:
 *   - reject non-identity encodings when the feature is disabled (415),
 *   - reject encodings the parser cannot safely inflate (415),
 *   - reject stacked encodings (e.g. `gzip, gzip`) that could nest a bomb (415).
 *
 * Requests with no `Content-Encoding` (or `identity`) pass straight through.
 */
export function createRequestDecompressionGuard(
  options: RequestDecompressionOptions,
): RequestHandler {
  const allowed = new Set(
    options.allowedEncodings.map((encoding) => encoding.toLowerCase()),
  );

  return (req: Request, res: Response, next: NextFunction): void => {
    const encodings = parseContentEncoding(req.headers['content-encoding']);
    const nonIdentity = encodings.filter((encoding) => encoding !== 'identity');

    // No compression requested — nothing to guard.
    if (nonIdentity.length === 0) {
      next();
      return;
    }

    if (!options.enabled) {
      reject(
        res,
        req,
        REQUEST_DECOMPRESSION_ERROR_CODES.DISABLED,
        'Compressed request bodies are not supported by this server.',
      );
      return;
    }

    // Stacked encodings (e.g. "gzip, deflate") are a vector for nested zip
    // bombs and are not inflated by the body parser. Reject outright.
    if (nonIdentity.length > 1) {
      reject(
        res,
        req,
        REQUEST_DECOMPRESSION_ERROR_CODES.STACKED_ENCODING,
        'Stacked Content-Encoding is not supported. Send a single encoding.',
      );
      return;
    }

    const unsupported = nonIdentity.filter(
      (encoding) => !allowed.has(encoding),
    );
    if (unsupported.length > 0) {
      reject(
        res,
        req,
        REQUEST_DECOMPRESSION_ERROR_CODES.UNSUPPORTED_ENCODING,
        `Unsupported Content-Encoding: ${unsupported.join(', ')}. ` +
          `Supported encodings: ${[...allowed].join(', ')}.`,
      );
      return;
    }

    next();
  };
}
