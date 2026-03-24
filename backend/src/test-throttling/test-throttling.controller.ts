import { Controller, Get, Post } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
// import { SkipThrottle } from '../common/decorators/skip-throttle.decorator';

@Controller('test-throttling')
export class TestThrottlingController {
  
  @Get()
  getRateLimitedEndpoint() {
    return { 
      message: 'This endpoint is rate limited (100 requests per minute)',
      timestamp: new Date().toISOString()
    };
  }

  @Get('skip')
  @SkipThrottle()
  getUnlimitedEndpoint() {
    return { 
      message: 'This endpoint skips rate limiting',
      timestamp: new Date().toISOString()
    };
  }

  @Post('webhook')
  @SkipThrottle()
  handleWebhook() {
    return { 
      message: 'Webhook endpoint with no rate limiting',
      timestamp: new Date().toISOString()
    };
  }

  @Get('burst')
  getBurstEndpoint() {
    return { 
      message: 'Test burst requests - this should be rate limited',
      timestamp: new Date().toISOString()
    };
  }
}
