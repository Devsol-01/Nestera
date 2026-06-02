import { Controller, Get } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { CurrencyService } from './currency.service';

@ApiTags('Currencies')
@Controller('currencies')
export class CurrencyController {
  constructor(private readonly currencyService: CurrencyService) {}

  @Get()
  @ApiOperation({
    summary: 'List supported currencies and validation/conversion metadata',
  })
  listSupportedCurrencies() {
    return this.currencyService.listSupportedCurrencies();
  }
}
