export default () => ({
  port: parseInt(process.env.PORT || '3001', 10),
  database: {
    // URL-based connection (takes precedence when provided)
    url: process.env.DATABASE_URL,
    // Host-based connection (used when DATABASE_URL is absent)
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '5432', 10),
    name: process.env.DB_NAME,
    user: process.env.DB_USER,
    pass: process.env.DB_PASS,
    pool: {
      max: parseInt(
        process.env.DATABASE_POOL_MAX ||
          (process.env.NODE_ENV === 'production' ? '30' : '10'),
        10,
      ),
      min: parseInt(
        process.env.DATABASE_POOL_MIN ||
          (process.env.NODE_ENV === 'production' ? '5' : '2'),
        10,
      ),
      maxCeiling: parseInt(process.env.DATABASE_POOL_MAX_CEILING || '50', 10),
      idleTimeout: parseInt(process.env.DATABASE_IDLE_TIMEOUT || '30000', 10),
      connectionTimeout: parseInt(
        process.env.DATABASE_CONNECTION_TIMEOUT || '2000',
        10,
      ),
      statementTimeout: parseInt(
        process.env.DATABASE_STATEMENT_TIMEOUT || '30000',
        10,
      ),
      queryTimeout: parseInt(process.env.DATABASE_QUERY_TIMEOUT || '30000', 10),
      monitorIntervalMs: parseInt(
        process.env.DATABASE_POOL_MONITOR_INTERVAL || '30000',
        10,
      ),
      scaleUpThreshold: parseInt(
        process.env.DATABASE_POOL_SCALE_UP_THRESHOLD || '80',
        10,
      ),
      scaleDownThreshold: parseInt(
        process.env.DATABASE_POOL_SCALE_DOWN_THRESHOLD || '30',
        10,
      ),
      exhaustionWaitingThreshold: parseInt(
        process.env.DATABASE_POOL_EXHAUSTION_WAITING_THRESHOLD || '1',
        10,
      ),
      leakDetectionThreshold: parseInt(
        process.env.DATABASE_POOL_LEAK_THRESHOLD || '90',
        10,
      ),
      allowExitOnIdle: process.env.DATABASE_POOL_ALLOW_EXIT_ON_IDLE === 'true',
      autoScale: process.env.DATABASE_POOL_AUTO_SCALE !== 'false',
    },
    retry: {
      maxRetries: parseInt(process.env.DB_MAX_RETRIES || '5', 10),
      initialDelayMs: parseInt(process.env.DB_RETRY_INITIAL_DELAY || '500', 10),
      maxDelayMs: parseInt(process.env.DB_RETRY_MAX_DELAY || '30000', 10),
      backoffMultiplier: parseFloat(process.env.DB_RETRY_BACKOFF || '2.0'),
      jitterMs: parseInt(process.env.DB_RETRY_JITTER || '100', 10),
    },
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    expiration: process.env.JWT_EXPIRATION,
  },
  stellar: {
    network: process.env.STELLAR_NETWORK || 'testnet',
    rpcUrl: process.env.SOROBAN_RPC_URL,
    horizonUrl: process.env.HORIZON_URL,
    // Fallback RPC URLs (comma-separated, in priority order)
    rpcFallbackUrls: (process.env.SOROBAN_RPC_FALLBACK_URLS || '')
      .split(',')
      .map((url) => url.trim())
      .filter(Boolean),
    // Fallback Horizon URLs (comma-separated, in priority order)
    horizonFallbackUrls: (process.env.HORIZON_FALLBACK_URLS || '')
      .split(',')
      .map((url) => url.trim())
      .filter(Boolean),
    contractId: process.env.CONTRACT_ID,
    webhookSecret: process.env.STELLAR_WEBHOOK_SECRET,
    eventPollInterval: parseInt(
      process.env.STELLAR_EVENT_POLL_INTERVAL || '10000',
      10,
    ),
    // Retry configuration
    rpcMaxRetries: parseInt(process.env.RPC_MAX_RETRIES || '3', 10),
    rpcRetryDelay: parseInt(process.env.RPC_RETRY_DELAY || '1000', 10),
    rpcTimeout: parseInt(process.env.RPC_TIMEOUT || '10000', 10),
  },
  redis: {
    url: process.env.REDIS_URL,
  },
  jobQueue: {
    defaultAttempts: parseInt(
      process.env.JOB_QUEUE_DEFAULT_ATTEMPTS || '3',
      10,
    ),
    backoffDelay: parseInt(process.env.JOB_QUEUE_BACKOFF_DELAY || '2000', 10),
  },
  mail: {
    host: process.env.MAIL_HOST,
    port: parseInt(process.env.MAIL_PORT || '587', 10),
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
    from: process.env.MAIL_FROM || '"Nestera" <noreply@nestera.io>',
  },
  kyc: {
    providerBaseUrl: process.env.KYC_PROVIDER_BASE_URL,
    providerApiKey: process.env.KYC_PROVIDER_API_KEY,
    piiEncryptionKey: process.env.KYC_PII_ENCRYPTION_KEY,
  },
  backup: {
    s3Bucket: process.env.BACKUP_S3_BUCKET,
    s3Region: process.env.BACKUP_S3_REGION ?? 'us-east-1',
    awsAccessKeyId: process.env.BACKUP_AWS_ACCESS_KEY_ID,
    awsSecretAccessKey: process.env.BACKUP_AWS_SECRET_ACCESS_KEY,
    encryptionKey: process.env.BACKUP_ENCRYPTION_KEY, // 64 hex chars = 32 bytes
    retentionDays: parseInt(process.env.BACKUP_RETENTION_DAYS ?? '30', 10),
    tmpDir: process.env.BACKUP_TMP_DIR ?? '/tmp',
  },
  hospital: {
    endpoints: {
      // Hospital endpoints from environment variables
      // Format: HOSPITAL_<ID>_ENDPOINT
      ...(process.env.HOSPITAL_1_ENDPOINT && {
        'hospital-1': process.env.HOSPITAL_1_ENDPOINT,
      }),
      ...(process.env.HOSPITAL_2_ENDPOINT && {
        'hospital-2': process.env.HOSPITAL_2_ENDPOINT,
      }),
      ...(process.env.HOSPITAL_3_ENDPOINT && {
        'hospital-3': process.env.HOSPITAL_3_ENDPOINT,
      }),
    },
    maxRetries: parseInt(process.env.HOSPITAL_MAX_RETRIES || '3', 10),
    retryDelay: parseInt(process.env.HOSPITAL_RETRY_DELAY || '1000', 10),
    requestTimeout: parseInt(
      process.env.HOSPITAL_REQUEST_TIMEOUT || '10000',
      10,
    ),
    circuitBreakerThreshold: parseInt(
      process.env.HOSPITAL_CIRCUIT_BREAKER_THRESHOLD || '5',
      10,
    ),
    circuitBreakerTimeout: parseInt(
      process.env.HOSPITAL_CIRCUIT_BREAKER_TIMEOUT || '60000',
      10,
    ),
  },
  cors: {
    enabled: process.env.CORS_ENABLED !== 'false',
    origins: (process.env.CORS_ORIGINS || 'http://localhost:3000')
      .split(',')
      .map((o) => o.trim())
      .filter(Boolean),
    methods: (
      process.env.CORS_METHODS || 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS'
    )
      .split(',')
      .map((m) => m.trim())
      .filter(Boolean),
    allowedHeaders: (
      process.env.CORS_ALLOWED_HEADERS || 'Content-Type,Authorization,Accept'
    )
      .split(',')
      .map((h) => h.trim())
      .filter(Boolean),
    credentials: process.env.CORS_CREDENTIALS === 'true',
    maxAge: parseInt(process.env.CORS_MAX_AGE || '86400', 10),
  },
  balanceSync: {
    cacheTtlSeconds: parseInt(
      process.env.BALANCE_CACHE_TTL_SECONDS || '300',
      10,
    ),
    pollIntervalMs: parseInt(
      process.env.BALANCE_POLL_INTERVAL_MS || '5000',
      10,
    ),
    reconnectInitialDelayMs: parseInt(
      process.env.BALANCE_RECONNECT_INIT_MS || '1000',
      10,
    ),
    reconnectMaxDelayMs: parseInt(
      process.env.BALANCE_RECONNECT_MAX_MS || '60000',
      10,
    ),
    metricsPersistIntervalMs: parseInt(
      process.env.BALANCE_METRICS_PERSIST_MS || '60000',
      10,
    ),
  },
  distributedLock: {
    defaultTtlMs: parseInt(process.env.DISTRIBUTED_LOCK_TTL_MS || '30000', 10),
    renewalIntervalMs: parseInt(
      process.env.DISTRIBUTED_LOCK_RENEWAL_MS || '10000',
      10,
    ),
    indexerTtlMs: parseInt(process.env.INDEXER_LOCK_TTL_MS || '25000', 10),
    replayTtlMs: parseInt(process.env.REPLAY_LOCK_TTL_MS || '120000', 10),
  },
  idempotency: {
    /**
     * Enable the periodic background cleanup job for expired idempotency
     * records.  Redis TTL is normally authoritative, but the cleanup job
     * defends against TTL misconfiguration, Redis eviction policies, and
     * records whose explicit `expiresAt` has passed (see issue #Cleanup).
     */
    cleanupEnabled:
      process.env.IDEMPOTENCY_CLEANUP_ENABLED !== 'false',
    /**
     * Cron expression for the cleanup job.  Default is hourly to keep
     * per-run work bounded; can be tightened in production via env.
     */
    cleanupCronSchedule:
      process.env.IDEMPOTENCY_CLEANUP_CRON || '0 * * * *',
    /**
     * Maximum number of records processed per cleanup run.  Keeps the
     * job bursty-safe even on installations with many in-flight keys.
     */
    cleanupBatchSize: parseInt(
      process.env.IDEMPOTENCY_CLEANUP_BATCH_SIZE || '500',
      10,
    ),
    /**
     * HOW_MANY hint for SCAN — Redis returns up to this many keys in
     * one round-trip but may return more or fewer.  Tune for throughput.
     */
    cleanupScanCount: parseInt(
      process.env.IDEMPOTENCY_CLEANUP_SCAN_COUNT || '200',
      10,
    ),
    /**
     * Lock TTL for the single-instance cleanup guard.  Must exceed
     * expected maximum cleanup duration to avoid mid-run lock loss.
     */
    cleanupLockTtlMs: parseInt(
      process.env.IDEMPOTENCY_CLEANUP_LOCK_TTL_MS || '120000',
      10,
    ),
  },
  blockchainReplay: {
    maxLedgerRange: parseInt(
      process.env.BLOCKCHAIN_REPLAY_MAX_LEDGER_RANGE || '10000',
      10,
    ),
  },
  health: {
    retentionDays: parseInt(process.env.HEALTH_RETENTION_DAYS || '30', 10),
  },
  upload: {
    provider: process.env.STORAGE_PROVIDER || 'local',
    defaultMaxSize: parseInt(
      process.env.UPLOAD_DEFAULT_MAX_SIZE || String(10 * 1024 * 1024),
      10,
    ),
    maxAvatarSize: parseInt(
      process.env.UPLOAD_MAX_AVATAR_SIZE || String(5 * 1024 * 1024),
      10,
    ),
    maxDocumentSize: parseInt(
      process.env.UPLOAD_MAX_DOCUMENT_SIZE || String(10 * 1024 * 1024),
      10,
    ),
    maxBackupRestoreSize: parseInt(
      process.env.UPLOAD_MAX_BACKUP_SIZE || String(1024 * 1024 * 1024),
      10,
    ),
    signedUrlTtlSeconds: parseInt(
      process.env.STORAGE_SIGNED_URL_TTL || '3600',
      10,
    ),
    s3Bucket: process.env.STORAGE_S3_BUCKET,
    s3Region: process.env.STORAGE_S3_REGION ?? 'us-east-1',
    awsAccessKeyId: process.env.STORAGE_AWS_ACCESS_KEY_ID,
    awsSecretAccessKey: process.env.STORAGE_AWS_SECRET_ACCESS_KEY,
    localDir: process.env.STORAGE_LOCAL_DIR || './uploads',
    virusScanningEnabled: process.env.UPLOAD_VIRUS_SCANNING === 'true',
  },
  storageQuota: {
    enabled: process.env.STORAGE_QUOTA_ENABLED !== 'false',
    reservationTtlHours: parseInt(
      process.env.STORAGE_QUOTA_RESERVATION_TTL_HOURS || '4',
      10,
    ),
    cleanupIntervalMinutes: parseInt(
      process.env.STORAGE_QUOTA_CLEANUP_INTERVAL_MINUTES || '15',
      10,
    ),
  },
  adminNotifications: {
    maxPerMinute: parseInt(process.env.ADMIN_NOTIF_MAX_PER_MINUTE || '60', 10),
    maxPerHour: parseInt(process.env.ADMIN_NOTIF_MAX_PER_HOUR || '500', 10),
    dedupWindowMs: parseInt(
      process.env.ADMIN_NOTIF_DEDUP_WINDOW_MS || '300000',
      10,
    ),
    batchSize: parseInt(process.env.ADMIN_NOTIF_BATCH_SIZE || '50', 10),
  },
  eventStream: {
    maxQueueDepth: parseInt(
      process.env.EVENT_STREAM_MAX_QUEUE_DEPTH || '1000',
      10,
    ),
    workerConcurrency: parseInt(
      process.env.EVENT_STREAM_WORKER_CONCURRENCY || '5',
      10,
    ),
    maxIngestionRatePerSecond: parseInt(
      process.env.EVENT_STREAM_MAX_INGEST_RATE || '100',
      10,
    ),
    pausePollIntervalMs: parseInt(
      process.env.EVENT_STREAM_PAUSE_POLL_MS || '30000',
      10,
    ),
  },
  referralFraud: {
    creationRateWindowMs: parseInt(
      process.env.REFERRAL_FRAUD_CREATION_WINDOW_MS || '3600000',
      10,
    ),
    maxCreationAttemptsPerWindow: parseInt(
      process.env.REFERRAL_FRAUD_MAX_CREATION_ATTEMPTS || '20',
      10,
    ),
    similarMetadataWindowMs: parseInt(
      process.env.REFERRAL_FRAUD_SIMILAR_METADATA_WINDOW_MS || '604800000',
      10,
    ),
    similarMetadataThreshold: parseInt(
      process.env.REFERRAL_FRAUD_SIMILAR_METADATA_THRESHOLD || '2',
      10,
    ),
    signupPatternWindowMs: parseInt(
      process.env.REFERRAL_FRAUD_SIGNUP_WINDOW_MS || '86400000',
      10,
    ),
    signupPatternThreshold: parseInt(
      process.env.REFERRAL_FRAUD_SIGNUP_THRESHOLD || '5',
      10,
    ),
    excessiveCreationWindowMs: parseInt(
      process.env.REFERRAL_FRAUD_EXCESSIVE_WINDOW_MS || '86400000',
      10,
    ),
    excessiveCreationThreshold: parseInt(
      process.env.REFERRAL_FRAUD_EXCESSIVE_THRESHOLD || '10',
      10,
    ),
    suspiciousWithdrawalWindowMs: parseInt(
      process.env.REFERRAL_FRAUD_WITHDRAWAL_WINDOW_MS || '3600000',
      10,
    ),
  },
  compression: {
    threshold: parseInt(process.env.COMPRESSION_THRESHOLD || '1024', 10),
    jsonBodyLimit: process.env.JSON_BODY_LIMIT || '1mb',
    urlencodedBodyLimit: process.env.URLENCODED_BODY_LIMIT || '1mb',
  },
  multiTenant: {
    enabled: process.env.MULTI_TENANT_ENABLED === 'true',
    defaultTenantId: process.env.DEFAULT_TENANT_ID || 'default',
    defaultTenantSlug: process.env.DEFAULT_TENANT_SLUG || 'default',
  },
  testMode: {
    enabled: process.env.TEST_MODE === 'true',
    stellarFixtures: process.env.TEST_MODE_STELLAR_FIXTURES,
  },
});
