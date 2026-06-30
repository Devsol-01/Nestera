import {
  StorageProvider,
  StoredFile,
} from '../../modules/storage/providers/storage-provider.interface';

export interface TestStellarFixtures {
  health?: Record<string, unknown>;
  contractRead?: Record<string, unknown>;
  events?: unknown[];
  delegation?: string | null;
  transactions?: unknown[];
  networkPassphrase?: string;
}

export interface CapturedEmail {
  to: string;
  subject: string;
  text?: string;
  template?: string;
  context?: Record<string, unknown>;
  attachments?: { filename: string; content: Buffer }[];
  timestamp: Date;
}

export interface StoredFileRecord {
  key: string;
  buffer: Buffer;
  contentType: string;
  createdAt: Date;
}

export interface ExternalCallStubs {
  [dependency: string]: unknown;
}

export interface TestModeConfig {
  enabled: boolean;
  stellar: TestStellarFixtures;
}

const DEFAULT_STELLAR_FIXTURES: TestStellarFixtures = {
  health: { ok: true },
  contractRead: {},
  events: [],
  delegation: null,
  transactions: [],
  networkPassphrase: 'Test Skeleton Network; June 2018',
};

export const DEFAULT_TEST_MODE_CONFIG: TestModeConfig = {
  enabled: false,
  stellar: { ...DEFAULT_STELLAR_FIXTURES },
};

export class InMemoryStorageProvider implements StorageProvider {
  readonly name = 'in-memory';
  private readonly store = new Map<string, StoredFileRecord>();

  async save(
    buffer: Buffer,
    options: {
      key: string;
      contentType: string;
      ownerId?: string;
      visibility?: 'private' | 'public';
    },
  ): Promise<StoredFile> {
    this.store.set(options.key, {
      key: options.key,
      buffer,
      contentType: options.contentType,
      createdAt: new Date(),
    });
    return {
      key: options.key,
      path: `/uploads/${options.key}`,
      size: buffer.length,
      contentType: options.contentType,
    };
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async exists(key: string): Promise<boolean> {
    return this.store.has(key);
  }

  async getSignedUrl(
    key: string,
    options: {
      operation: 'read' | 'write';
      expiresInSeconds: number;
      ownerId?: string;
    },
  ): Promise<string> {
    return `/test-uploads/${key}`;
  }

  async listAll(): Promise<{ key: string; lastModified: Date }[]> {
    return Array.from(this.store.values()).map((r) => ({
      key: r.key,
      lastModified: r.createdAt,
    }));
  }

  readFile(key: string): Buffer {
    const record = this.store.get(key);
    if (!record) throw new Error(`File not found: ${key}`);
    return record.buffer;
  }

  get allFiles(): StoredFileRecord[] {
    return Array.from(this.store.values());
  }

  clear(): void {
    this.store.clear();
  }
}
