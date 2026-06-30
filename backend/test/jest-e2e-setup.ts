/**
 * Jest E2E Test Setup
 * This file is loaded before e2e tests run (via setupFilesAfterEnv in jest-e2e.json)
 * It sets required environment variables for the test environment
 */

// Set default test environment values
process.env.NODE_ENV = process.env.NODE_ENV || 'test';
process.env.PORT = process.env.PORT || '3001';
process.env.DATABASE_URL =
  process.env.DATABASE_URL ||
  'postgresql://user:pass@localhost:5432/nestera_test';
process.env.JWT_SECRET =
  process.env.JWT_SECRET ||
  'super-secret-key-for-testing-purposes-must-be-long-enough';
process.env.JWT_EXPIRATION = process.env.JWT_EXPIRATION || '24h';

// Stellar network configuration
process.env.STELLAR_NETWORK = process.env.STELLAR_NETWORK || 'testnet';
process.env.STELLAR_PUBLIC_KEY =
  process.env.STELLAR_PUBLIC_KEY ||
  'GBUQWP3BOUZX34ULNQG23RQ6F4BFXEUVS2YB5YKTVQГрафик3XVXVYXSX';
process.env.STELLAR_SECRET_KEY =
  process.env.STELLAR_SECRET_KEY ||
  'SBURFLOJJNGJB5YIEBQXSKCM7I67CFXZ3DXEMXPJYBPMXP4Q7XZWI23';
process.env.HORIZON_URL =
  process.env.HORIZON_URL || 'https://horizon-testnet.stellar.org';
process.env.SOROBAN_RPC_URL =
  process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org';
process.env.CONTRACT_ID =
  process.env.CONTRACT_ID ||
  'CBWHJPY37LHMQJ726PN26YLWWP3CQQ7T7NYJT2KMXNQQPLR7QDNVWZGK';

// Email configuration (mock values for testing)
process.env.MAIL_SERVICE = process.env.MAIL_SERVICE || 'test';
process.env.MAIL_FROM = process.env.MAIL_FROM || 'test@example.com';
process.env.MAIL_HOST = process.env.MAIL_HOST || 'localhost';
process.env.MAIL_PORT = process.env.MAIL_PORT || '1025';
process.env.MAIL_USER = process.env.MAIL_USER || 'test_user';
process.env.MAIL_PASS = process.env.MAIL_PASS || 'test_password';

// Database host fallback (in case DATABASE_URL is not set)
process.env.DB_HOST = process.env.DB_HOST || 'localhost';
process.env.DB_PORT = process.env.DB_PORT || '5432';
process.env.DB_NAME = process.env.DB_NAME || 'nestera_test';
process.env.DB_USER = process.env.DB_USER || 'user';
process.env.DB_PASS = process.env.DB_PASS || 'pass';

// Fallback RPC config
process.env.SOROBAN_RPC_FALLBACK_URLS =
  process.env.SOROBAN_RPC_FALLBACK_URLS || 'https://soroban-testnet.stellar.org';
process.env.HORIZON_FALLBACK_URLS =
  process.env.HORIZON_FALLBACK_URLS || 'https://horizon-testnet.stellar.org';
process.env.STELLAR_EVENT_POLL_INTERVAL =
  process.env.STELLAR_EVENT_POLL_INTERVAL || '60000';

// Redis configuration
process.env.REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

// Webhook secret
process.env.STELLAR_WEBHOOK_SECRET =
  process.env.STELLAR_WEBHOOK_SECRET ||
  'test_webhook_secret_long_enough_minimum_16_chars';

// ── Test Mode ──────────────────────────────────────────────────────────────
// Enable deterministic test mode for all E2E tests.
// This stubs external providers (Stellar RPC, email, storage, KYC, etc.)
// so that tests run reliably without network dependencies.
process.env.TEST_MODE = process.env.TEST_MODE || 'true';
