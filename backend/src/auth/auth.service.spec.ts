import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UserService } from '../modules/user/user.service';
import { JwtService } from '@nestjs/jwt';
import { ConflictException, UnauthorizedException } from '@nestjs/common';
// import { CACHE_MANAGER } from '@nestjs/cache-manager';
import * as bcrypt from 'bcrypt';

describe('AuthService', () => {
  let service: AuthService;
  let userService: UserService;
  let jwtService: JwtService;
  let cacheManager: any;

  const mockUser = {
    id: 'user-1',
    email: 'test@example.com',
    password: 'hashed-password',
  };

  beforeEach(async () => {
    // const mockCacheManager = {
    //   set: jest.fn(),
    //   get: jest.fn(),
    //   del: jest.fn(),
    // };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UserService,
          useValue: {
            findByEmail: jest.fn(),
            findByPublicKey: jest.fn(),
            create: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn().mockReturnValue('mock-token'),
          },
        },
        // {
        //   provide: CACHE_MANAGER,
        //   useValue: mockCacheManager,
        // },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userService = module.get<UserService>(UserService);
    jwtService = module.get<JwtService>(JwtService);
    // cacheManager = module.get(CACHE_MANAGER);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('register', () => {
    it('should register a new user', async () => {
      const dto = { email: 'new@example.com', password: 'password123' };
      jest.spyOn(userService, 'findByEmail').mockResolvedValue(null);
      jest
        .spyOn(userService, 'create')
        .mockResolvedValue({ id: '1', ...dto, password: 'hashed' } as any);
      jest
        .spyOn(bcrypt, 'hash')
        .mockImplementation(() => Promise.resolve('hashed'));

      const result = await service.register(dto);
      expect(result).toHaveProperty('accessToken');
      expect(userService.create).toHaveBeenCalled();
    });

    it('should throw ConflictException if user exists', async () => {
      jest.spyOn(userService, 'findByEmail').mockResolvedValue(mockUser as any);
      await expect(
        service.register({ email: 'test@example.com', password: 'pw' }),
      ).rejects.toThrow(ConflictException);
    });
  });

  describe('login', () => {
    it('should return access token if credentials valid', async () => {
      const dto = { email: 'test@example.com', password: 'password123' };
      jest.spyOn(userService, 'findByEmail').mockResolvedValue(mockUser as any);
      jest
        .spyOn(bcrypt, 'compare')
        .mockImplementation(() => Promise.resolve(true));

      const result = await service.login(dto);
      expect(result).toEqual({ accessToken: 'mock-token' });
    });

    it('should throw UnauthorizedException if credentials invalid', async () => {
      const dto = { email: 'test@example.com', password: 'wrong' };
      jest.spyOn(userService, 'findByEmail').mockResolvedValue(mockUser as any);
      jest
        .spyOn(bcrypt, 'compare')
        .mockImplementation(() => Promise.resolve(false));

      await expect(service.login(dto)).rejects.toThrow(UnauthorizedException);
    });
  });
});
