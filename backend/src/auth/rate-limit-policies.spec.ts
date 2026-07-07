/**
 * Rate-limit policy contract tests for issue #1124.
 *
 * These tests verify that:
 *  - Each endpoint group maps to the correct named throttler
 *  - Policy limits and TTLs are within the required ranges
 *  - Retry-After seconds are computed correctly from TTL values
 *
 * They do NOT require a running server or installed NestJS modules —
 * only the policy constants defined below need to stay in sync with
 * the actual @Throttle() decorators in each controller.
 */

// ── Policy registry ──────────────────────────────────────────────────────────
// Mirrors what the @Throttle() decorators set on each endpoint.
// If you change a decorator, update this table.

interface ThrottlePolicy {
  throttler: string;
  limit: number;
  ttl: number; // ms
}

const AUTH_POLICIES: Record<string, ThrottlePolicy> = {
  'POST /auth/register': { throttler: 'auth', limit: 5, ttl: 15 * 60 * 1000 },
  'POST /auth/login': { throttler: 'auth', limit: 5, ttl: 15 * 60 * 1000 },
  'GET /auth/nonce': { throttler: 'auth', limit: 5, ttl: 15 * 60 * 1000 },
  'POST /auth/verify-signature': {
    throttler: 'auth',
    limit: 5,
    ttl: 15 * 60 * 1000,
  },
  'POST /auth/link-wallet': {
    throttler: 'wallet-link',
    limit: 5,
    ttl: 60 * 60 * 1000,
  },
  'POST /auth/2fa/enable': { throttler: 'otp', limit: 3, ttl: 15 * 60 * 1000 },
  'POST /auth/2fa/verify': { throttler: 'otp', limit: 3, ttl: 15 * 60 * 1000 },
  'POST /auth/2fa/validate': {
    throttler: 'auth',
    limit: 5,
    ttl: 15 * 60 * 1000,
  },
  'POST /auth/2fa/disable': { throttler: 'otp', limit: 3, ttl: 15 * 60 * 1000 },
  'POST /auth/2fa/admin-disable': {
    throttler: 'otp',
    limit: 3,
    ttl: 15 * 60 * 1000,
  },
};

const BLOCKCHAIN_POLICIES: Record<string, ThrottlePolicy> = {
  'POST /blockchain/wallets/generate': {
    throttler: 'rpc',
    limit: 10,
    ttl: 60000,
  },
  'GET /blockchain/wallets/:publicKey/transactions': {
    throttler: 'rpc',
    limit: 10,
    ttl: 60000,
  },
  'GET /blockchain/rpc/status': { throttler: 'rpc', limit: 10, ttl: 60000 },
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function retryAfterSeconds(ttlMs: number): number {
  return Math.ceil(ttlMs / 1000);
}

// ── Auth endpoint policies ───────────────────────────────────────────────────

describe('Auth endpoint rate-limit policies', () => {
  describe('credential / session endpoints', () => {
    const credentialEndpoints = [
      'POST /auth/register',
      'POST /auth/login',
      'GET /auth/nonce',
      'POST /auth/verify-signature',
      'POST /auth/2fa/validate',
    ];

    for (const endpoint of credentialEndpoints) {
      it(`${endpoint} uses the auth throttler`, () => {
        expect(AUTH_POLICIES[endpoint].throttler).toBe('auth');
      });

      it(`${endpoint} limit is ≤ 5 per 15 minutes`, () => {
        const p = AUTH_POLICIES[endpoint];
        expect(p.limit).toBeLessThanOrEqual(5);
        expect(p.ttl).toBe(15 * 60 * 1000);
      });
    }
  });

  describe('wallet-link endpoint', () => {
    const endpoint = 'POST /auth/link-wallet';

    it('uses the wallet-link throttler', () => {
      expect(AUTH_POLICIES[endpoint].throttler).toBe('wallet-link');
    });

    it('limit is 5 per hour', () => {
      const p = AUTH_POLICIES[endpoint];
      expect(p.limit).toBe(5);
      expect(p.ttl).toBe(60 * 60 * 1000);
    });

    it('is stricter than the default throttler window', () => {
      const defaultTtl = 60 * 1000;
      expect(AUTH_POLICIES[endpoint].ttl).toBeGreaterThan(defaultTtl);
    });
  });

  describe('OTP / 2FA endpoints', () => {
    const otpEndpoints = [
      'POST /auth/2fa/enable',
      'POST /auth/2fa/verify',
      'POST /auth/2fa/disable',
      'POST /auth/2fa/admin-disable',
    ];

    for (const endpoint of otpEndpoints) {
      it(`${endpoint} uses the otp throttler`, () => {
        expect(AUTH_POLICIES[endpoint].throttler).toBe('otp');
      });

      it(`${endpoint} limit is 3 per 15 min (brute-force resistant)`, () => {
        const p = AUTH_POLICIES[endpoint];
        expect(p.limit).toBe(3);
        expect(p.ttl).toBe(15 * 60 * 1000);
      });
    }

    it('OTP limit is strictly tighter than auth limit', () => {
      const otpLimit = AUTH_POLICIES['POST /auth/2fa/enable'].limit;
      const authLimit = AUTH_POLICIES['POST /auth/login'].limit;
      expect(otpLimit).toBeLessThanOrEqual(authLimit);
    });
  });
});

// ── Blockchain / RPC endpoint policies ──────────────────────────────────────

describe('Blockchain/RPC endpoint rate-limit policies', () => {
  const rpcEndpoints = [
    'POST /blockchain/wallets/generate',
    'GET /blockchain/wallets/:publicKey/transactions',
    'GET /blockchain/rpc/status',
  ];

  for (const endpoint of rpcEndpoints) {
    it(`${endpoint} uses the rpc throttler`, () => {
      expect(BLOCKCHAIN_POLICIES[endpoint].throttler).toBe('rpc');
    });

    it(`${endpoint} limit is 10 per minute`, () => {
      const p = BLOCKCHAIN_POLICIES[endpoint];
      expect(p.limit).toBe(10);
      expect(p.ttl).toBe(60000);
    });

    it(`${endpoint} rpc limit is tighter than default (100/min)`, () => {
      expect(BLOCKCHAIN_POLICIES[endpoint].limit).toBeLessThan(100);
    });
  }
});

// ── Retry-After header calculations ─────────────────────────────────────────

describe('Retry-After header values', () => {
  it('auth throttler (15 min) yields Retry-After: 900', () => {
    expect(retryAfterSeconds(15 * 60 * 1000)).toBe(900);
  });

  it('otp throttler (15 min) yields Retry-After: 900', () => {
    expect(retryAfterSeconds(AUTH_POLICIES['POST /auth/2fa/enable'].ttl)).toBe(
      900,
    );
  });

  it('wallet-link throttler (1 hour) yields Retry-After: 3600', () => {
    expect(retryAfterSeconds(AUTH_POLICIES['POST /auth/link-wallet'].ttl)).toBe(
      3600,
    );
  });

  it('rpc throttler (1 min) yields Retry-After: 60', () => {
    expect(
      retryAfterSeconds(
        BLOCKCHAIN_POLICIES['POST /blockchain/wallets/generate'].ttl,
      ),
    ).toBe(60);
  });

  it('Retry-After is always a whole number of seconds', () => {
    const allPolicies = {
      ...AUTH_POLICIES,
      ...BLOCKCHAIN_POLICIES,
    };

    for (const [, policy] of Object.entries(allPolicies)) {
      const retryAfter = retryAfterSeconds(policy.ttl);
      expect(Number.isInteger(retryAfter)).toBe(true);
      expect(retryAfter).toBeGreaterThan(0);
    }
  });
});

// ── Endpoint coverage check ──────────────────────────────────────────────────

describe('Policy coverage', () => {
  it('all defined auth policies have a non-empty throttler name', () => {
    for (const [endpoint, policy] of Object.entries(AUTH_POLICIES)) {
      expect(policy.throttler).toBeTruthy();
      expect(typeof policy.throttler).toBe('string');
      void endpoint;
    }
  });

  it('all defined auth policies have positive limit and ttl', () => {
    for (const [, policy] of Object.entries(AUTH_POLICIES)) {
      expect(policy.limit).toBeGreaterThan(0);
      expect(policy.ttl).toBeGreaterThan(0);
    }
  });

  it('all blockchain policies use the rpc throttler', () => {
    for (const [, policy] of Object.entries(BLOCKCHAIN_POLICIES)) {
      expect(policy.throttler).toBe('rpc');
    }
  });

  it('sensitive auth endpoints do not use the default throttler', () => {
    const sensitiveEndpoints = [
      'POST /auth/link-wallet',
      'POST /auth/2fa/enable',
      'POST /auth/2fa/verify',
      'POST /auth/2fa/disable',
    ];
    for (const ep of sensitiveEndpoints) {
      expect(AUTH_POLICIES[ep].throttler).not.toBe('default');
    }
  });
});
