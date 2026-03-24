import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable Helmet for security headers
  app.use(helmet());

  // Configure CORS
  const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];
  const isProduction = process.env.NODE_ENV === 'production';

  app.enableCors({
    origin: isProduction ? allowedOrigins : '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);

  console.log(`Application is running on: http://localhost:${port}`);
  console.log(`Environment: ${process.env.NODE_ENV}`);
  console.log(
    `CORS enabled for: ${isProduction ? allowedOrigins.join(', ') : 'all origins (development)'}`,
  );
}

bootstrap();
