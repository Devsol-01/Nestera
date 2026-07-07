import { Test, TestingModule } from '@nestjs/testing';
import { MetricsService } from './metrics.service';

describe('MetricsService', () => {
  let service: MetricsService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [MetricsService],
    }).compile();

    service = module.get<MetricsService>(MetricsService);
    service.clearMetrics();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should increment counter', () => {
    service.incrementCounter('test_counter', 1);
    const metrics = service.getMetrics('test_counter');
    expect(metrics.length).toBe(1);
    expect(metrics[0].value).toBe(1);
  });

  it('should record histogram', () => {
    service.recordHistogram('test_histogram', 100);
    const histogram = service.getHistogram('test_histogram');
    expect(histogram.length).toBe(1);
    expect(histogram[0].value).toBe(100);
  });

  it('should calculate percentiles', () => {
    for (let i = 1; i <= 100; i++) {
      service.recordHistogram('test_percentile', i);
    }
    const percentiles = service.calculatePercentiles(
      'test_percentile',
      [50, 95, 99],
    );
    expect(percentiles[50]).toBe(50);
    expect(percentiles[95]).toBe(95);
    expect(percentiles[99]).toBe(99);
  });

  it('should calculate rate', () => {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 3600000);

    for (let i = 0; i < 60; i++) {
      service.incrementCounter('test_rate', 1);
    }

    const rate = service.calculateRate('test_rate', {
      start: oneHourAgo,
      end: new Date(Date.now() + 1000),
    });
    expect(rate).toBeGreaterThan(0);
  });

  it('should calculate error rate', () => {
    const start = new Date(Date.now() - 3600000);

    service.incrementCounter('http_requests_total', 90, {
      endpoint: '/api/test',
      status: 'success',
    });
    service.incrementCounter('http_requests_total', 10, {
      endpoint: '/api/test',
      status: 'error',
    });

    const errorRate = service.getErrorRate('/api/test', {
      start,
      end: new Date(Date.now() + 1000),
    });
    expect(errorRate).toBe(10); // 10 errors out of 100 requests = 10%
  });
});
