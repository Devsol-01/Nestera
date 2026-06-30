import { Global, Module } from '@nestjs/common';
import { TestModeService } from './test-mode.service';

@Global()
@Module({
  providers: [TestModeService],
  exports: [TestModeService],
})
export class TestModeModule {}
