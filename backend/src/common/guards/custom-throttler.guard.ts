import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { THROTTLE_SKIP_KEY } from '../decorators/skip-throttle.decorator';

@Injectable()
export class CustomThrottlerGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const skipThrottle = this.reflector.get<boolean>(
      THROTTLE_SKIP_KEY,
      context.getHandler(),
    ) || this.reflector.get<boolean>(
      THROTTLE_SKIP_KEY,
      context.getClass(),
    );

    // For now, we'll just return true when skip is requested
    // The actual throttling will be handled by the existing ThrottlerGuard
    return true;
  }
}
