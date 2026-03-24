import { Test, TestingModule } from '@nestjs/testing';
import { TestRbacController } from './test-rbac.controller';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';

describe('TestRbacController', () => {
  let controller: TestRbacController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [TestRbacController],
      providers: [
        {
          provide: JwtAuthGuard,
          useValue: {
            canActivate: jest.fn(() => true),
          },
        },
        {
          provide: RolesGuard,
          useValue: {
            canActivate: jest.fn(() => true),
          },
        },
      ],
    }).compile();

    controller = module.get<TestRbacController>(TestRbacController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getPublicEndpoint', () => {
    it('should return public message', () => {
      const result = controller.getPublicEndpoint();
      expect(result).toEqual({
        message: 'This is a public endpoint accessible to anyone'
      });
    });
  });

  describe('getUserEndpoint', () => {
    it('should return user message', () => {
      const mockRequest = { user: { role: 'USER', id: '1' } };
      const result = controller.getUserEndpoint(mockRequest);
      expect(result).toEqual({
        message: 'This endpoint requires USER role or higher',
        user: mockRequest.user
      });
    });
  });

  describe('getAdminEndpoint', () => {
    it('should return admin message', () => {
      const mockRequest = { user: { role: 'ADMIN', id: '1' } };
      const result = controller.getAdminEndpoint(mockRequest);
      expect(result).toEqual({
        message: 'This endpoint requires ADMIN role only',
        user: mockRequest.user
      });
    });
  });

  describe('getUserOrAdminEndpoint', () => {
    it('should return user or admin message', () => {
      const mockRequest = { user: { role: 'USER', id: '1' } };
      const result = controller.getUserOrAdminEndpoint(mockRequest);
      expect(result).toEqual({
        message: 'This endpoint requires USER or ADMIN role',
        user: mockRequest.user
      });
    });
  });
});
