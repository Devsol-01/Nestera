import { Module } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { cacheConfig } from './cache.config';

@Module({
  imports: [
    CacheModule.registerAsync(cacheConfig),
  ],
  providers: [],
  exports: [],
})
export class RedisCacheModule {}
