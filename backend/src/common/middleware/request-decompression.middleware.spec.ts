import * as express from 'express';
import { Express } from 'express';
import * as zlib from 'zlib';
import * as http from 'http';
import { AddressInfo } from 'net';
import {
  createRequestDecompressionGuard,
  RequestDecompressionOptions,
  REQUEST_DECOMPRESSION_ERROR_CODES,
} from './request-decompression.middleware';

/**
 * Builds a minimal Express app wired exactly like `main.ts`: the decompression
 * guard runs first, followed by the body parsers that perform the actual
 * inflation and enforce the decompressed-size limit.
 */
function buildApp(
  overrides: Partial<RequestDecompressionOptions> = {},
  limit = '1mb',
): Express {
  const options: RequestDecompressionOptions = {
    enabled: true,
    allowedEncodings: ['gzip', 'deflate'],
    ...overrides,
  };

  const app = express();
  app.use(createRequestDecompressionGuard(options));
  app.use(express.json({ limit, inflate: options.enabled }));
  app.post('/echo', (req, res) => {
    res.status(200).json({ received: req.body });
  });
  return app;
}

interface RawResponse {
  status: number;
  body: unknown;
  text: string;
}

/**
 * Sends a raw request body to the app over a real socket. We deliberately
 * bypass supertest/superagent here: superagent treats a Buffer passed to
 * `.send()` as a plain object and JSON-serializes it, which would corrupt the
 * compressed bytes. A raw `http` request guarantees the exact bytes are sent.
 */
function sendRaw(
  app: Express,
  headers: Record<string, string>,
  body: Buffer,
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, () => {
      const { port } = server.address() as AddressInfo;
      const req = http.request(
        {
          host: '127.0.0.1',
          port,
          method: 'POST',
          path: '/echo',
          headers: { 'Content-Length': body.length, ...headers },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('end', () => {
            server.close();
            const text = Buffer.concat(chunks).toString('utf8');
            let parsed: unknown = text;
            try {
              parsed = JSON.parse(text);
            } catch {
              /* leave as text */
            }
            resolve({ status: res.statusCode ?? 0, body: parsed, text });
          });
        },
      );
      req.on('error', (err) => {
        server.close();
        reject(err);
      });
      req.end(body);
    });
  });
}

const JSON_HEADERS = { 'Content-Type': 'application/json' };

describe('createRequestDecompressionGuard', () => {
  describe('uncompressed requests', () => {
    it('passes plain JSON straight through', async () => {
      const app = buildApp();
      const payload = { hello: 'world' };

      const res = await sendRaw(
        app,
        JSON_HEADERS,
        Buffer.from(JSON.stringify(payload)),
      );

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ received: payload });
    });
  });

  describe('supported compressed requests', () => {
    it('accepts and inflates a gzip-encoded body within the limit', async () => {
      const app = buildApp();
      const payload = { items: Array.from({ length: 50 }, (_, i) => i) };
      const compressed = zlib.gzipSync(Buffer.from(JSON.stringify(payload)));

      const res = await sendRaw(
        app,
        { ...JSON_HEADERS, 'Content-Encoding': 'gzip' },
        compressed,
      );

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ received: payload });
    });

    it('accepts and inflates a deflate-encoded body within the limit', async () => {
      const app = buildApp();
      const payload = { message: 'compressed via deflate' };
      const compressed = zlib.deflateSync(Buffer.from(JSON.stringify(payload)));

      const res = await sendRaw(
        app,
        { ...JSON_HEADERS, 'Content-Encoding': 'deflate' },
        compressed,
      );

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ received: payload });
    });
  });

  describe('zip bomb protection', () => {
    it('rejects a gzip body that inflates beyond the limit with HTTP 413', async () => {
      // A small (~few KB) compressed payload that decompresses to ~10MB —
      // far beyond the 1mb limit. The parser must abort with 413.
      const app = buildApp({}, '1mb');
      const huge = 'x'.repeat(10 * 1024 * 1024);
      const compressed = zlib.gzipSync(
        Buffer.from(JSON.stringify({ bomb: huge })),
      );

      // Sanity: the compressed payload itself is tiny.
      expect(compressed.length).toBeLessThan(1024 * 1024);

      const res = await sendRaw(
        app,
        { ...JSON_HEADERS, 'Content-Encoding': 'gzip' },
        compressed,
      );

      expect(res.status).toBe(413);
    });

    it('rejects a deflate body that inflates beyond the limit with HTTP 413', async () => {
      const app = buildApp({}, '1mb');
      const huge = 'y'.repeat(10 * 1024 * 1024);
      const compressed = zlib.deflateSync(
        Buffer.from(JSON.stringify({ bomb: huge })),
      );

      expect(compressed.length).toBeLessThan(1024 * 1024);

      const res = await sendRaw(
        app,
        { ...JSON_HEADERS, 'Content-Encoding': 'deflate' },
        compressed,
      );

      expect(res.status).toBe(413);
    });
  });

  describe('unsupported encodings', () => {
    it('rejects an unsupported Content-Encoding (br) with HTTP 415', async () => {
      const app = buildApp();
      const compressed = zlib.brotliCompressSync(
        Buffer.from(JSON.stringify({ hello: 'brotli' })),
      );

      const res = await sendRaw(
        app,
        { ...JSON_HEADERS, 'Content-Encoding': 'br' },
        compressed,
      );

      expect(res.status).toBe(415);
      expect((res.body as { errorCode: string }).errorCode).toBe(
        REQUEST_DECOMPRESSION_ERROR_CODES.UNSUPPORTED_ENCODING,
      );
    });

    it('rejects stacked Content-Encoding with HTTP 415', async () => {
      const app = buildApp();
      const compressed = zlib.gzipSync(
        zlib.gzipSync(Buffer.from(JSON.stringify({ nested: true }))),
      );

      const res = await sendRaw(
        app,
        { ...JSON_HEADERS, 'Content-Encoding': 'gzip, gzip' },
        compressed,
      );

      expect(res.status).toBe(415);
      expect((res.body as { errorCode: string }).errorCode).toBe(
        REQUEST_DECOMPRESSION_ERROR_CODES.STACKED_ENCODING,
      );
    });

    it('treats an identity Content-Encoding as uncompressed', async () => {
      const app = buildApp();
      const payload = { plain: true };

      const res = await sendRaw(
        app,
        { ...JSON_HEADERS, 'Content-Encoding': 'identity' },
        Buffer.from(JSON.stringify(payload)),
      );

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ received: payload });
    });
  });

  describe('feature disabled', () => {
    it('rejects any compressed body with HTTP 415 when disabled', async () => {
      const app = buildApp({ enabled: false });
      const compressed = zlib.gzipSync(
        Buffer.from(JSON.stringify({ hello: 'world' })),
      );

      const res = await sendRaw(
        app,
        { ...JSON_HEADERS, 'Content-Encoding': 'gzip' },
        compressed,
      );

      expect(res.status).toBe(415);
      expect((res.body as { errorCode: string }).errorCode).toBe(
        REQUEST_DECOMPRESSION_ERROR_CODES.DISABLED,
      );
    });

    it('still accepts uncompressed bodies when disabled', async () => {
      const app = buildApp({ enabled: false });
      const payload = { still: 'works' };

      const res = await sendRaw(
        app,
        JSON_HEADERS,
        Buffer.from(JSON.stringify(payload)),
      );

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ received: payload });
    });
  });
});
