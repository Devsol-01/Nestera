import { Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  CapturedEmail,
  ExternalCallStubs,
  InMemoryStorageProvider,
  StoredFileRecord,
  TestStellarFixtures,
} from './test-mode.types';

@Injectable()
export class TestModeService {
  private readonly logger = new Logger(TestModeService.name);
  private readonly _stellarFixtures: TestStellarFixtures;
  private readonly _sentEmails: CapturedEmail[] = [];
  private readonly _stubs: ExternalCallStubs = {};
  private readonly _storageProvider: InMemoryStorageProvider;

  constructor(@Optional() private readonly configService?: ConfigService) {
    this._storageProvider = new InMemoryStorageProvider();
    this._stellarFixtures = this.loadStellarFixtures();
  }

  private loadStellarFixtures(): TestStellarFixtures {
    const raw = this.configService?.get<string>('testMode.stellarFixtures');
    if (raw) {
      try {
        return JSON.parse(raw) as TestStellarFixtures;
      } catch {
        this.logger.warn(
          'Failed to parse TEST_MODE_STELLAR_FIXTURES, using defaults',
        );
      }
    }
    return {
      health: { ok: true },
      contractRead: {},
      events: [],
      delegation: null,
      transactions: [],
      networkPassphrase: 'Test Skeleton Network; June 2018',
    };
  }

  get isEnabled(): boolean {
    return this.configService?.get<boolean>('testMode.enabled') ?? false;
  }

  get stellarFixtures(): TestStellarFixtures {
    return this._stellarFixtures;
  }

  get sentEmails(): CapturedEmail[] {
    return this._sentEmails;
  }

  get storageProvider(): InMemoryStorageProvider {
    return this._storageProvider;
  }

  get storedFiles(): StoredFileRecord[] {
    return this._storageProvider.allFiles;
  }

  get stubs(): ExternalCallStubs {
    return this._stubs;
  }

  registerStub(dependency: string, response: unknown): void {
    this._stubs[dependency] = response;
  }

  getStub<T = unknown>(dependency: string): T | undefined {
    return this._stubs[dependency] as T | undefined;
  }

  registerStellarFixture(key: keyof TestStellarFixtures, value: unknown): void {
    (this._stellarFixtures as Record<string, unknown>)[key] = value;
  }

  captureEmail(email: Omit<CapturedEmail, 'timestamp'>): void {
    this._sentEmails.push({ ...email, timestamp: new Date() });
    this.logger.debug(
      `Email captured in test mode: to=${email.to}, subject=${email.subject}`,
    );
  }

  getLastEmail(): CapturedEmail | undefined {
    return this._sentEmails[this._sentEmails.length - 1];
  }

  clearSentEmails(): void {
    this._sentEmails.length = 0;
  }

  reset(): void {
    this.clearSentEmails();
    this._storageProvider.clear();
    Object.keys(this._stubs).forEach((key) => delete this._stubs[key]);
    Object.assign(this._stellarFixtures, {
      health: { ok: true },
      contractRead: {},
      events: [],
      delegation: null,
      transactions: [],
    });
  }
}
