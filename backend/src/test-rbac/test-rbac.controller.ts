import { Controller, Get, UseGuards, Request } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { RolesGuard } from '../common/guards/roles.guard';
import { Role } from '../common/enums/role.enum';

@Controller('test-rbac')
@UseGuards(JwtAuthGuard, RolesGuard)
export class TestRbacController {
  
  @Get('public')
  getPublicEndpoint() {
    return { message: 'This is a public endpoint accessible to anyone' };
  }

  @Get('user')
  @Roles(Role.USER)
  getUserEndpoint(@Request() req) {
    return { 
      message: 'This endpoint requires USER role or higher',
      user: req.user 
    };
  }

  @Get('admin')
  @Roles(Role.ADMIN)
  getAdminEndpoint(@Request() req) {
    return { 
      message: 'This endpoint requires ADMIN role only',
      user: req.user 
    };
  }

  @Get('user-or-admin')
  @Roles(Role.USER, Role.ADMIN)
  getUserOrAdminEndpoint(@Request() req) {
    return { 
      message: 'This endpoint requires USER or ADMIN role',
      user: req.user 
    };
  }
}
