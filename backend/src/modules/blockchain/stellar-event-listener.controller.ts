import { Controller, Get, Post, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { StellarEventListenerService } from './stellar-event-listener.service';

@ApiTags('stellar-events')
@Controller('stellar-events')
export class StellarEventListenerController {
    constructor(
        private readonly eventListenerService: StellarEventListenerService,
    ) { }

    @Get('status')
    @ApiOperation({ summary: 'Get event listener status' })
    @ApiResponse({ status: 200, description: 'Event listener status' })
    getStatus() {
        return this.eventListenerService.getStatus();
    }

    @Post('sync')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Manually trigger event synchronization' })
    @ApiResponse({ status: 200, description: 'Sync completed' })
    @ApiResponse({ status: 500, description: 'Sync failed' })
    async triggerSync() {
        const result = await this.eventListenerService.triggerManualSync();
        return {
            message: 'Manual sync completed',
            ...result,
        };
    }

    @Post('start')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Start event listener' })
    @ApiResponse({ status: 200, description: 'Listener started' })
    async startListener() {
        await this.eventListenerService.startListening();
        return { message: 'Event listener started' };
    }

    @Post('stop')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Stop event listener' })
    @ApiResponse({ status: 200, description: 'Listener stopped' })
    stopListener() {
        this.eventListenerService.stopListening();
        return { message: 'Event listener stopped' };
    }
}
