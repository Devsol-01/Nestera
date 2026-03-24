import * as Joi from 'joi';

export const envValidationSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').required(),

  PORT: Joi.number().port().default(3001).required(),

  // ── Database (URL-based OR host-based, both accepted) ──────────────────────
  // Either DATABASE_URL or DB_HOST is required to establish a DB connection.
  DATABASE_URL: Joi.string().uri().optional(),
  DB_HOST: Joi.string().hostname().optional(),
  DB_PORT: Joi.number().port().default(5432).optional(),
  DB_NAME: Joi.string().optional(),
  DB_USER: Joi.string().optional(),
  DB_PASS: Joi.string().optional(),

  // ── Auth ───────────────────────────────────────────────────────────────────
  JWT_SECRET: Joi.string().min(10).required(),
  JWT_EXPIRATION: Joi.string().required(),

  // ── Soroban / Stellar ──────────────────────────────────────────────────────
  STELLAR_NETWORK: Joi.string().valid('testnet', 'mainnet').default('testnet'),
  SOROBAN_RPC_URL: Joi.string().uri().required(),
  HORIZON_URL: Joi.string().uri().required(),
  CONTRACT_ID: Joi.string().required(),
  STELLAR_WEBHOOK_SECRET: Joi.string().min(16).required(),
  STELLAR_EVENT_POLL_INTERVAL: Joi.number().integer().min(1000).default(10000).optional(),

  // Comma-separated fallback RPC / Horizon endpoints for Soroban Testnet
  SOROBAN_RPC_FALLBACK_URLS: Joi.string().optional(),
  HORIZON_FALLBACK_URLS: Joi.string().optional(),

  // RPC retry / timeout knobs
  RPC_MAX_RETRIES: Joi.number().integer().min(0).default(3).optional(),
  RPC_RETRY_DELAY: Joi.number().integer().min(0).default(1000).optional(),
  RPC_TIMEOUT: Joi.number().integer().min(0).default(10000).optional(),

  // ── Redis (optional) ───────────────────────────────────────────────────────
  REDIS_URL: Joi.string().uri().optional(),

  // ── Mail (SMTP, all optional) ──────────────────────────────────────────────
  MAIL_HOST: Joi.string().optional(),
  MAIL_PORT: Joi.number().port().default(587).optional(),
  MAIL_USER: Joi.string().optional(),
  MAIL_PASS: Joi.string().optional(),
  MAIL_FROM: Joi.string().optional(),
}).or('DATABASE_URL', 'DB_HOST'); // enforce at least one DB connection strategy
