import { SetMetadata } from '@nestjs/common';
import { Role } from './roles.enum';

export const ROLES_KEY = 'roles';

/**
 * Attach required roles to a route handler or controller.
 * Usage: @Roles(Role.ADMIN) or @Roles(Role.ADMIN, Role.USER)
 */
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
