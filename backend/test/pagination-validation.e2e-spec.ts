/**
 * Pagination Validation E2E Tests — issue #1136
 *
 * Verifies that invalid pagination inputs produce consistent, helpful
 * error responses that include:
 *
 *   - The standard validation envelope (success: false, statusCode, message,
 *     errors[], timestamp, path, correlationId).
 *   - For each failed field, an allowed-range-aware constraint message
 *     (e.g., "page must be a positive integer >= 1", "limit must not exceed
 *     the maximum page size of 100; use cursor pagination...").
 *   - For invalid cursors, both a top-level `message` ("Invalid pagination
 *     cursor") and a top-level `hint` describing the expected cursor format.
 *
 * Tests run via three layered paths:
 *   1. class-validator unit checks against PageOptionsDto (no live DB needed).
 *   2. Direct unit test of ValidationExceptionFilter with a synthetic host
 *      mock — no DB or HTTP layer required.
 *   3. HTTP smoke tests against a running NestJS app, gracefully skipping
 *      when no auth or DB is available.
 */
import { validate } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import {
  INestApplication,
  BadRequestException,
  ArgumentsHost,
} from '@nestjs/common';
import { Request, Response } from 'express';
import * as request from 'supertest';
import {
  PageOptionsDto,
  PAGE_VALIDATION_MESSAGES,
  MAX_PAGE_SIZE,
  DEFAULT_PAGE_SIZE,
  MIN_PAGE,
} from '../src/common/dto/page-options.dto';
import {
  decodeCursor,
  encodeCursor,
  CURSOR_FORMAT_HINT,
} from '../src/common/helpers/cursor-pagination.helper';
import { AdminUsersQueryDto } from '../src/modules/admin/dto/admin-users-query.dto';
import { ValidationExceptionFilter } from '../src/common/filters/validation-exception.filter';
import { createTestApp, closeTestApp } from './fixtures/database.helpers';
import {
  buildRegisterPayload,
  HTTP_STATUS,
} from './fixtures/test-factories';

// ---------------------------------------------------------------------------
// 1. Unit tests — class-validator behaviour on PageOptionsDto (no DB)
// ---------------------------------------------------------------------------

describe('PageOptionsDto validation messages (#1136)', () => {
  async function validatePayload(payload: Record<string, unknown>) {
    const dto = plainToInstance(PageOptionsDto, payload, {
      enableImplicitConversion: false,
    });
    return validate(dto as object, { whitelist: true });
  }

  function constraintsFor(
    errors: Awaited<ReturnType<typeof validatePayload>>,
    property: string,
  ) {
    const e = errors.find((x) => x.property === property);
    return e?.constraints ?? {};
  }

  it('accepts a default-valid payload with no errors', async () => {
    const errors = await validatePayload({});
    expect(errors).toHaveLength(0);
  });

  it.each([
    ['page', -1, PAGE_VALIDATION_MESSAGES.pageMin, 'min'],
    ['page', 0, PAGE_VALIDATION_MESSAGES.pageMin, 'min'],
    ['limit', -10, PAGE_VALIDATION_MESSAGES.limitMin, 'min'],
    ['limit', 0, PAGE_VALIDATION_MESSAGES.limitMin, 'min'],
  ])(
    'rejects %s=%s with the documented range-aware min message',
    async (field, value, expectedMessage, constraintKey) => {
      const errors = await validatePayload({ [field]: value });
      const c = constraintsFor(errors, field);
      expect(c[constraintKey]).toBe(expectedMessage);
    },
  );

  it('rejects a limit above MAX_PAGE_SIZE with a message that names the maximum', async () => {
    const errors = await validatePayload({ limit: MAX_PAGE_SIZE + 1 });
    const c = constraintsFor(errors, 'limit');
    expect(c.max).toBe(PAGE_VALIDATION_MESSAGES.limitMax);
    // Friendly hint: message must include the numeric MAX so clients can
    // self-correct without consulting external documentation.
    expect(c.max).toContain(String(MAX_PAGE_SIZE));
    expect(c.max).toMatch(/cursor pagination/i);
  });

  it('accepts limit === MAX_PAGE_SIZE (boundary)', async () => {
    const errors = await validatePayload({ limit: MAX_PAGE_SIZE });
    expect(errors).toHaveLength(0);
  });

  it.each([
    ['page', 1.5, PAGE_VALIDATION_MESSAGES.pageInt, 'isInt'],
    ['limit', 'ten', PAGE_VALIDATION_MESSAGES.limitInt, 'isInt'],
  ])(
    'rejects non-integer %s with the documented isInt message',
    async (field, value, expectedMessage, constraintKey) => {
      const errors = await validatePayload({ [field]: value });
      const c = constraintsFor(errors, field);
      expect(c[constraintKey]).toBe(expectedMessage);
    },
  );

  it('rejects an invalid order enum value with the documented enum message', async () => {
    const errors = await validatePayload({ order: 'RANDOM' });
    const c = constraintsFor(errors, 'order');
    expect(c.isEnum).toBe(PAGE_VALIDATION_MESSAGES.orderEnum);
    // Helpful: message lists valid enum values
    expect(c.isEnum).toMatch(/ASC/);
    expect(c.isEnum).toMatch(/DESC/);
  });

  it('rejects a non-boolean-string includeTotal with the documented message', async () => {
    const errors = await validatePayload({ includeTotal: 'yes' });
    const c = constraintsFor(errors, 'includeTotal');
    expect(c.isBooleanString).toBe(PAGE_VALIDATION_MESSAGES.includeTotalBool);
  });

  it('accepts includeTotal="true" and includeTotal="false"', async () => {
    expect(await validatePayload({ includeTotal: 'true' })).toHaveLength(0);
    expect(await validatePayload({ includeTotal: 'false' })).toHaveLength(0);
  });
});

describe('PageOptionsDto exported bounds (#1136 documentation)', () => {
  it('exposes MIN_PAGE, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE as positive integers', () => {
    expect(MIN_PAGE).toBe(1);
    expect(DEFAULT_PAGE_SIZE).toBe(10);
    expect(MAX_PAGE_SIZE).toBe(100);
    expect(DEFAULT_PAGE_SIZE).toBeLessThanOrEqual(MAX_PAGE_SIZE);
  });
});

// ---------------------------------------------------------------------------
// 2. Unit tests — AdminUsersQueryDto validation messages (no DB)
// ---------------------------------------------------------------------------

describe('AdminUsersQueryDto validation messages (#1136)', () => {
  async function validatePayload(payload: Record<string, unknown>) {
    const dto = plainToInstance(AdminUsersQueryDto, payload, {
      enableImplicitConversion: false,
    });
    return validate(dto as object, { whitelist: true });
  }

  it('rejects negative page with the shared PAGE_VALIDATION_MESSAGES.pageMin text', async () => {
    const errors = await validatePayload({ page: -2 });
    const e = errors.find((x) => x.property === 'page');
    expect(e?.constraints?.min).toBe(PAGE_VALIDATION_MESSAGES.pageMin);
  });

  it('rejects limit > MAX_PAGE_SIZE with the shared PAGE_VALIDATION_MESSAGES.limitMax text', async () => {
    const errors = await validatePayload({ limit: 999 });
    const e = errors.find((x) => x.property === 'limit');
    expect(e?.constraints?.max).toBe(PAGE_VALIDATION_MESSAGES.limitMax);
    expect(e?.constraints?.max).toContain(String(MAX_PAGE_SIZE));
  });
});

// ---------------------------------------------------------------------------
// 3. Unit tests — decodeCursor structured error payload
// ---------------------------------------------------------------------------

describe('decodeCursor structured error payload (#1136)', () => {
  it('round-trips a well-formed cursor correctly', () => {
    const payload = {
      createdAt: '2024-06-15T12:00:00.000Z',
      id: 'uuid-abc-123',
    };
    expect(decodeCursor(encodeCursor(payload))).toEqual(payload);
  });

  function captureBadRequest(fn: () => unknown): BadRequestException {
    try {
      fn();
    } catch (e) {
      expect(e).toBeInstanceOf(BadRequestException);
      return e as BadRequestException;
    }
    throw new Error('expected BadRequestException');
  }

  it('throws BadRequestException with message+hint+field for a non-base64 cursor', () => {
    const err = captureBadRequest(() => decodeCursor('not-base64!!!'));
    const response = err.getResponse() as Record<string, unknown>;

    // Backward-compatibility: the top-level message remains the canonical
    // string that downstream consumers (and existing tests) assert on.
    expect(response.message).toBe('Invalid pagination cursor');

    // New hint + field surfaced for clients (issue #1136).
    expect(response.hint).toBe(CURSOR_FORMAT_HINT);
    expect(response.field).toBe('cursor');
  });

  it('throws with same payload when cursor base64-decodes to a missing-field JSON', () => {
    const bad = Buffer.from(JSON.stringify({ id: 'x' })).toString('base64url');
    const err = captureBadRequest(() => decodeCursor(bad));
    const response = err.getResponse() as Record<string, unknown>;
    expect(response.message).toBe('Invalid pagination cursor');
    expect(response.hint).toBe(CURSOR_FORMAT_HINT);
  });

  it('throws with same payload when cursor contains a non-ISO createdAt', () => {
    const bad = Buffer.from(
      JSON.stringify({ createdAt: 'not-a-date', id: 'x' }),
    ).toString('base64url');
    const err = captureBadRequest(() => decodeCursor(bad));
    const response = err.getResponse() as Record<string, unknown>;
    expect(response.message).toBe('Invalid pagination cursor');
    expect(response.hint).toBe(CURSOR_FORMAT_HINT);
  });

  it('throws with same payload for an empty string', () => {
    const err = captureBadRequest(() => decodeCursor(''));
    expect(err.getResponse()).toMatchObject({
      message: 'Invalid pagination cursor',
      hint: CURSOR_FORMAT_HINT,
      field: 'cursor',
    });
  });
});

// ---------------------------------------------------------------------------
// 4. Direct unit test — ValidationExceptionFilter exposes hint + field
//    in the response body without requiring DB or HTTP layer.
// ---------------------------------------------------------------------------

// Minimal stand-in for the Express Response that captures whatever the
// filter writes via response.status(...).json(...). Avoids spinning up
// the full Nest app so this assertion runs even when no DB is available.
class FakeResponse {
  statusCode = 0;
  body: unknown;
  status(code: number): this {
    this.statusCode = code;
    return this;
  }
  json(payload: unknown): this {
    this.body = payload;
    return this;
  }
}

function makeHost(url: string): ArgumentsHost {
  const response = new FakeResponse();
  const req = { url, method: 'GET', correlationId: 'corr-test-1136' };
  return {
    switchToHttp: () => ({
      getResponse: () => response as unknown as Response,
      getRequest: () => req as unknown as Request,
    }),
  } as unknown as ArgumentsHost;
}

function getBody(host: ArgumentsHost): Record<string, unknown> {
  // Pull the body back out of the FakeResponse the host captured. The
  // filter calls host.switchToHttp().getResponse() internally and mutates
  // the same instance, so a follow-up read returns the captured body.
  return (host.switchToHttp().getResponse() as unknown as FakeResponse)
    .body as Record<string, unknown>;
}

describe('ValidationExceptionFilter exposes hint/field in body (#1136)', () => {
  const filter = new ValidationExceptionFilter();

  it('forwards hint + field from a structured BadRequestException payload', () => {
    const exception = new BadRequestException({
      message: 'Invalid pagination cursor',
      hint: CURSOR_FORMAT_HINT,
      field: 'cursor',
    });
    const host = makeHost('/api/v2/transactions?cursor=bad');
    filter.catch(exception, host);
    const body = getBody(host);
    // Standard envelope preserved
    expect(body.success).toBe(false);
    expect(body.statusCode).toBe(400);
    expect(body.message).toBe('Invalid pagination cursor');
    expect(Array.isArray(body.errors)).toBe(true);
    // New hint + field surfaced
    expect(body.hint).toBe(CURSOR_FORMAT_HINT);
    expect(body.field).toBe('cursor');
  });

  it('omits hint/field keys when the exception payload has none', () => {
    const exception = new BadRequestException('Bad Request');
    const host = makeHost('/api/v2/transactions?page=-1');
    filter.catch(exception, host);
    const body = getBody(host);
    expect(body.hint).toBeUndefined();
    expect(body.field).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 5. HTTP smoke tests — run only when DB + auth are available
// ---------------------------------------------------------------------------

describe('Pagination validation HTTP envelope (#1136)', () => {
  let app: INestApplication;
  let accessToken: string | undefined;

  const testUser = buildRegisterPayload();

  beforeAll(async () => {
    app = await createTestApp();

    try {
      const res = await request(app.getHttpServer())
        .post('/api/v2/auth/register')
        .send(testUser);
      accessToken = res.body?.accessToken;
    } catch {
      // No live DB / auth unavailable → HTTP-level assertions below skip.
    }
  });

  afterAll(async () => {
    await closeTestApp(app);
  });

  function authHeader() {
    return accessToken
      ? { Authorization: `Bearer ${accessToken}` }
      : ({} as Record<string, string>);
  }

  it('malformed cursor returns 400 with message+hint+field on a live endpoint', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v2/transactions')
      .query({ cursor: 'not-a-real-cursor' })
      .set(authHeader());

    // Be tolerant of guard ordering: auth may run before the pipe in which
    // case we get 401 instead of 400.
    expect([HTTP_STATUS.BAD_REQUEST, HTTP_STATUS.UNAUTHORIZED]).toContain(
      res.status,
    );

    if (res.status === HTTP_STATUS.BAD_REQUEST) {
      // Top-level message from the structued PayloadException — surfaced
      // verbatim by the ValidationExceptionFilter.
      expect(res.body.message).toBe('Invalid pagination cursor');
      // New top-level hint and field keys (issue #1136).
      expect(res.body.hint).toBe(CURSOR_FORMAT_HINT);
      expect(res.body.field).toBe('cursor');
      // Standard envelope preserved.
      expect(res.body.success).toBe(false);
      expect(res.body.statusCode).toBe(HTTP_STATUS.BAD_REQUEST);
    }
  });

  it('limit above MAX_PAGE_SIZE returns 400 with the range-aware message', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v2/transactions')
      .query({ limit: MAX_PAGE_SIZE + 1 })
      .set(authHeader());

    expect([HTTP_STATUS.BAD_REQUEST, HTTP_STATUS.UNAUTHORIZED]).toContain(
      res.status,
    );

    if (res.status === HTTP_STATUS.BAD_REQUEST) {
      const hasLimitError =
        JSON.stringify(res.body).includes('limit must not exceed') ||
        JSON.stringify(res.body).includes(String(MAX_PAGE_SIZE));
      expect(hasLimitError).toBe(true);
    }
  });
});
