import { Controller, Get, UseGuards, Request } from '@nestjs/common';
import { Roles } from './roles.decorator';
import { RolesGuard } from './roles.guard';
import { Role } from './roles.enum';

/**
 * Simulates the object that a real auth guard (e.g. JwtAuthGuard) would attach
 * to req.user after verifying a token. In production, replace this middleware
 * with your actual JWT / session guard.
 *
 * Usage: pass ?role=ADMIN or ?role=USER in the query string when testing locally.
 */
import { NestMiddleware, Injectable } from '@nestjs/common';
import { Request as ExpressRequest, Response, NextFunction } from 'express';

@Injectable()
export class FakeAuthMiddleware implements NestMiddleware {
  use(
    req: ExpressRequest & { user?: any },
    _res: Response,
    next: NextFunction,
  ) {
    const role = (req.query.role as string)?.toUpperCase() ?? Role.USER;
    req.user = { id: 1, username: 'testuser', role };
    next();
  }
}

// ──────────────────────────────────────────────────────────────────────────────

@UseGuards(RolesGuard) // apply guard to every route in this controller
@Controller('demo')
export class DemoController {
  /** Accessible by any authenticated user (no @Roles restriction) */
  @Get('public')
  publicRoute() {
    return { message: 'Everyone can see this.' };
  }

  /** Only USERs (and ADMINs are not included here intentionally) */
  @Roles(Role.USER)
  @Get('user-only')
  userOnly(@Request() req: any) {
    return { message: `Hello, ${req.user.username}! This is the USER area.` };
  }

  /** Only ADMINs */
  @Roles(Role.ADMIN)
  @Get('admin-only')
  adminOnly(@Request() req: any) {
    return { message: `Hello, ${req.user.username}! This is the ADMIN area.` };
  }

  /** Both USERs and ADMINs are allowed */
  @Roles(Role.USER, Role.ADMIN)
  @Get('shared')
  shared(@Request() req: any) {
    return {
      message: `Hello, ${req.user.username}! Your role is ${req.user.role}.`,
    };
  }
}
