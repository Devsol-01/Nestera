import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { FEATURE_FLAG_KEY } from '../decorators/feature-flag.decorator';
import { FeatureFlagsService } from '../feature-flags.service';

@Injectable()
export class FeatureFlagGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly featureFlagsService: FeatureFlagsService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const flagKey = this.reflector.getAllAndOverride<string>(FEATURE_FLAG_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!flagKey) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user as
      | { id?: string; email?: string; role?: string }
      | undefined;

    const enabled = await this.featureFlagsService.isEnabled(flagKey, {
      address: user?.id ?? user?.email,
      segments: user?.role ? [user.role] : undefined,
    });

    if (!enabled) {
      throw new ForbiddenException(`Feature "${flagKey}" is not enabled`);
    }

    return true;
  }
}
