import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Logger } from '@nestjs/common';
import { ReportProcessor } from './report.processor';
import { ScheduledReportService } from '../../reports/scheduled-report.service';
import { ReportSchedule } from '../../reports/entities/report-schedule.entity';
import {
  ReportType,
  ReportFormat,
  ReportScheduleFrequency,
} from '../../reports/entities/report-schedule.entity';

describe('ReportProcessor', () => {
  let processor: ReportProcessor;
  const scheduledReportService = {
    generateAndArchive: jest.fn(),
  };
  const scheduleRepository = {
    findOne: jest.fn(),
    update: jest.fn(),
  };

  function mockJob(data: Record<string, any>, overrides: Record<string, any> = {}) {
    return {
      id: overrides.id ?? 'job-1',
      data,
      attemptsMade: overrides.attemptsMade ?? 0,
      opts: { attempts: 3, ...overrides.opts },
    } as any;
  }

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ReportProcessor,
        {
          provide: ScheduledReportService,
          useValue: scheduledReportService,
        },
        {
          provide: getRepositoryToken(ReportSchedule),
          useValue: scheduleRepository,
        },
      ],
    }).compile();

    processor = module.get<ReportProcessor>(ReportProcessor);
  });

  it('generates scheduled report when scheduleId is present', async () => {
    const schedule = {
      id: 'sched-1',
      userId: 'user-1',
      reportType: ReportType.DAILY_SUMMARY,
      format: ReportFormat.PDF,
      frequency: ReportScheduleFrequency.DAILY,
    };
    scheduleRepository.findOne.mockResolvedValue(schedule);
    scheduledReportService.generateAndArchive.mockResolvedValue({
      id: 'archive-1',
    });

    const result = await processor.process(mockJob({
      scheduleId: 'sched-1',
      reportType: ReportType.DAILY_SUMMARY,
      userId: 'user-1',
      params: {},
    }));

    expect(scheduledReportService.generateAndArchive).toHaveBeenCalledWith(
      schedule,
    );
    expect(scheduleRepository.update).toHaveBeenCalledWith(
      'sched-1',
      expect.objectContaining({ lastError: null }),
    );
    expect(result.archiveId).toBe('archive-1');
  });

  describe('correlationId', () => {
    it('accepts correlationId in job data without breaking processing', async () => {
      const schedule = {
        id: 'sched-corr',
        userId: 'user-1',
        reportType: ReportType.DAILY_SUMMARY,
        format: ReportFormat.PDF,
        frequency: ReportScheduleFrequency.DAILY,
      };
      scheduleRepository.findOne.mockResolvedValue(schedule);
      scheduledReportService.generateAndArchive.mockResolvedValue({
        id: 'archive-corr',
      });

      const result = await processor.process(mockJob({
        scheduleId: 'sched-corr',
        reportType: ReportType.DAILY_SUMMARY,
        userId: 'user-1',
        params: {},
        correlationId: 'test-corr-report-001',
      }));

      expect(scheduledReportService.generateAndArchive).toHaveBeenCalled();
      expect(result.archiveId).toBe('archive-corr');
      expect(result).toHaveProperty('processed', true);
    });

    it('includes correlationId prefix in debug log message', async () => {
      const schedule = {
        id: 'sched-corr-debug',
        userId: 'user-1',
        reportType: ReportType.DAILY_SUMMARY,
        format: ReportFormat.PDF,
        frequency: ReportScheduleFrequency.DAILY,
      };
      scheduleRepository.findOne.mockResolvedValue(schedule);
      scheduledReportService.generateAndArchive.mockResolvedValue({
        id: 'archive-corr-debug',
      });

      const loggerDebugSpy = jest.spyOn(Logger.prototype, 'debug').mockImplementation();
      const correlationId = 'test-corr-debug-002';

      await processor.process(mockJob({
        scheduleId: 'sched-corr-debug',
        reportType: ReportType.DAILY_SUMMARY,
        userId: 'user-1',
        params: {},
        correlationId,
      }));

      expect(loggerDebugSpy).toHaveBeenCalledWith(
        expect.stringContaining(`[${correlationId}]`),
      );

      loggerDebugSpy.mockRestore();
    });

    it('omits bracket prefix when correlationId is absent', async () => {
      const schedule = {
        id: 'sched-no-corr',
        userId: 'user-1',
        reportType: ReportType.DAILY_SUMMARY,
        format: ReportFormat.PDF,
        frequency: ReportScheduleFrequency.DAILY,
      };
      scheduleRepository.findOne.mockResolvedValue(schedule);
      scheduledReportService.generateAndArchive.mockResolvedValue({
        id: 'archive-no-corr',
      });

      const loggerDebugSpy = jest.spyOn(Logger.prototype, 'debug').mockImplementation();

      await processor.process(mockJob({
        scheduleId: 'sched-no-corr',
        reportType: ReportType.DAILY_SUMMARY,
        userId: 'user-1',
        params: {},
      }));

      expect(loggerDebugSpy).toHaveBeenCalledWith(
        expect.not.stringContaining('[undefined]'),
      );

      loggerDebugSpy.mockRestore();
    });
  });
});
