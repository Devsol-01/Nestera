import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { DemoController, FakeAuthMiddleware } from './demo.controller';

@Module({
  controllers: [DemoController],
  providers: [],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // In a real app, swap FakeAuthMiddleware for your JwtAuthGuard / passport strategy
    consumer.apply(FakeAuthMiddleware).forRoutes(DemoController);
  }
}
