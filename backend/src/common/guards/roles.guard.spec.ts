import { Test, TestingModule } from '@nestjs/testing';
import { RolesGuard } from './roles.guard';
import { Reflector } from '@nestjs/core';
import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Role } from '../enums/role.enum';
import { ROLES_KEY } from '../decorators/roles.decorator';

describe('RolesGuard', () => {
  let guard: RolesGuard;
  let reflector: Reflector;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RolesGuard,
        {
          provide: Reflector,
          useValue: {
            getAllAndOverride: jest.fn(),
          },
        },
      ],
    }).compile();

    guard = module.get<RolesGuard>(RolesGuard);
    reflector = module.get<Reflector>(Reflector);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  describe('canActivate', () => {
    let mockContext: ExecutionContext;

    beforeEach(() => {
      mockContext = {
        getHandler: jest.fn(),
        getClass: jest.fn(),
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue({
            user: { role: Role.USER },
          }),
        }),
      } as any;
    });

    it('should allow access when no roles are required', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

      expect(guard.canActivate(mockContext)).toBe(true);
    });

    it('should allow access when user has required role', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([Role.USER]);
      mockContext.switchToHttp().getRequest().user = { role: Role.USER };

      expect(guard.canActivate(mockContext)).toBe(true);
    });

    it('should allow access when user has one of multiple required roles', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([Role.USER, Role.ADMIN]);
      mockContext.switchToHttp().getRequest().user = { role: Role.USER };

      expect(guard.canActivate(mockContext)).toBe(true);
    });

    it('should deny access when user does not have required role', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([Role.ADMIN]);
      mockContext.switchToHttp().getRequest().user = { role: Role.USER };

      expect(() => guard.canActivate(mockContext)).toThrow(ForbiddenException);
    });

    it('should deny access when no user is present in request', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([Role.ADMIN]);
      mockContext.switchToHttp().getRequest().user = null;

      expect(() => guard.canActivate(mockContext)).toThrow(ForbiddenException);
    });

    it('should deny access when user has no role', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([Role.ADMIN]);
      mockContext.switchToHttp().getRequest().user = { };

      expect(() => guard.canActivate(mockContext)).toThrow(ForbiddenException);
    });
  });
});
