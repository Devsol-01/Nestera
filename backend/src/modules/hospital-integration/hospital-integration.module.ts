import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule } from '@nestjs/config';
import { HospitalIntegrationService } from './hospital-integration.service';
import { HospitalIntegrationController } from './hospital-integration.controller';

@Module({
    imports: [
        HttpModule.register({
            timeout: 10000,
            maxRedirects: 5,
        }),
        ConfigModule,
    ],
    controllers: [HospitalIntegrationController],
    providers: [HospitalIntegrationService],
    exports: [HospitalIntegrationService],
})
export class HospitalIntegrationModule { }
