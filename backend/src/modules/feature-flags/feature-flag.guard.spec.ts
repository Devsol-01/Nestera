import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { FeatureFlagGuard } from './guards/feature-flag.guard';
import { FeatureFlagsService } from './feature-flags.service';
import { FEATURE_FLAG_KEY } from './decorators/feature-flag.decorator';

describe('FeatureFlagGuard', () => {
  let guard: FeatureFlagGuard;
  let reflector: Reflector;
  let featureFlagsService: FeatureFlagsService;

  const mockFeatureFlagsService = {
    isEnabled: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    reflector = new Reflector();
    guard = new FeatureFlagGuard(
      reflector,
      mockFeatureFlagsService as unknown as FeatureFlagsService,
    );
    featureFlagsService =
      mockFeatureFlagsService as unknown as FeatureFlagsService;
  });

  const createContext = (user?: {
    id?: string;
    email?: string;
    role?: string;
  }): ExecutionContext =>
    ({
      getHandler: () => ({}),
      getClass: () => ({}),
      switchToHttp: () => ({
        getRequest: () => ({ user }),
      }),
    }) as ExecutionContext;

  it('allows access when no feature flag metadata is set', async () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

    await expect(guard.canActivate(createContext())).resolves.toBe(true);
    expect(featureFlagsService.isEnabled).not.toHaveBeenCalled();
  });

  it('allows access when feature flag is enabled', async () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue('new-dashboard');
    mockFeatureFlagsService.isEnabled.mockResolvedValue(true);

    await expect(
      guard.canActivate(createContext({ id: 'user-1', role: 'ADMIN' })),
    ).resolves.toBe(true);

    expect(reflector.getAllAndOverride).toHaveBeenCalledWith(
      FEATURE_FLAG_KEY,
      expect.any(Array),
    );
    expect(mockFeatureFlagsService.isEnabled).toHaveBeenCalledWith(
      'new-dashboard',
      {
        address: 'user-1',
        segments: ['ADMIN'],
      },
    );
  });

  it('denies access when feature flag is disabled', async () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue('new-dashboard');
    mockFeatureFlagsService.isEnabled.mockResolvedValue(false);

    await expect(
      guard.canActivate(createContext({ email: 'user@example.com' })),
    ).rejects.toThrow(ForbiddenException);
  });
});
