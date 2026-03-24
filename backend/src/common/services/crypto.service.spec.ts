import { Test, TestingModule } from '@nestjs/testing';
import { CryptoService } from './crypto.service';

describe('CryptoService', () => {
  let service: CryptoService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [CryptoService],
    }).compile();

    service = module.get<CryptoService>(CryptoService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('hash', () => {
    it('should generate a hashed string', async () => {
      const password = 'securePassword123';
      const hash = await service.hash(password);
      expect(hash).toBeDefined();
      expect(hash).not.toEqual(password);
      expect(hash.length).toBeGreaterThan(0);
    });
  });

  describe('compare', () => {
    it('should return true for a matching password and hash', async () => {
      const password = 'securePassword123';
      const hash = await service.hash(password);
      const isMatch = await service.compare(password, hash);
      expect(isMatch).toBe(true);
    });

    it('should return false for a non-matching password and hash', async () => {
      const password = 'securePassword123';
      const wrongPassword = 'wrongPassword';
      const hash = await service.hash(password);
      const isMatch = await service.compare(wrongPassword, hash);
      expect(isMatch).toBe(false);
    });
  });
});
