import { Reflector } from '@nestjs/core';
import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { RolesGuard } from './roles.guard';
import { Role } from './roles.enum';
import { ROLES_KEY } from './roles.decorator';

// ── helper to build a minimal ExecutionContext mock ───────────────────────────
function buildContext(user: any, requiredRoles: Role[] | undefined): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({ user }),
    }),
    getHandler: () => ({}),
    getClass: () => ({}),
  } as unknown as ExecutionContext;
}

describe('RolesGuard', () => {
  let guard: RolesGuard;
  let reflector: Reflector;

  beforeEach(() => {
    reflector = new Reflector();
    guard = new RolesGuard(reflector);
  });

  const mockReflector = (roles: Role[] | undefined) => {
    jest
      .spyOn(reflector, 'getAllAndOverride')
      .mockReturnValue(roles as any);
  };

  it('allows access when no @Roles decorator is present', () => {
    mockReflector(undefined);
    const ctx = buildContext({ role: Role.USER }, undefined);
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('allows access when required roles array is empty', () => {
    mockReflector([]);
    const ctx = buildContext({ role: Role.USER }, []);
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('throws ForbiddenException when no user is on the request', () => {
    mockReflector([Role.ADMIN]);
    const ctx = buildContext(undefined, [Role.ADMIN]);
    expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);
  });

  it('allows ADMIN to access an ADMIN-only route', () => {
    mockReflector([Role.ADMIN]);
    const ctx = buildContext({ role: Role.ADMIN }, [Role.ADMIN]);
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('denies USER from accessing an ADMIN-only route', () => {
    mockReflector([Role.ADMIN]);
    const ctx = buildContext({ role: Role.USER }, [Role.ADMIN]);
    expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);
  });

  it('allows USER to access a USER-only route', () => {
    mockReflector([Role.USER]);
    const ctx = buildContext({ role: Role.USER }, [Role.USER]);
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('allows both USER and ADMIN on a shared route', () => {
    mockReflector([Role.USER, Role.ADMIN]);

    const userCtx = buildContext({ role: Role.USER }, [Role.USER, Role.ADMIN]);
    expect(guard.canActivate(userCtx)).toBe(true);

    const adminCtx = buildContext({ role: Role.ADMIN }, [Role.USER, Role.ADMIN]);
    expect(guard.canActivate(adminCtx)).toBe(true);
  });
});
