import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('example')
  getExample() {
    return {
      message: 'This is an example response',
      items: ['item1', 'item2', 'item3'],
    };
  }
}
