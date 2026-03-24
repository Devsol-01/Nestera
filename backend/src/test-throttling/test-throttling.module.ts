import { Module } from '@nestjs/common';
import { TestThrottlingController } from './test-throttling.controller';

@Module({
  controllers: [TestThrottlingController],
})
export class TestThrottlingModule {}
