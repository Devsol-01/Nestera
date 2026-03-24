import { Module } from '@nestjs/common';
import { TestRbacController } from './test-rbac.controller';

@Module({
  controllers: [TestRbacController],
})
export class TestRbacModule {}
