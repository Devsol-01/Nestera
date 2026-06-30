import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { QUEUE_NAMES } from '../job-queue.constants';
import { DisputeEvidence, EvidenceProcessingStatus } from '../../disputes/entities/dispute-evidence.entity';
import { DisputeEvidenceJobData } from '../job-queue.service';

@Processor(QUEUE_NAMES.DISPUTE_EVIDENCE)
export class DisputeEvidenceProcessor extends WorkerHost {
  private readonly logger = new Logger(DisputeEvidenceProcessor.name);

  constructor(
    @InjectRepository(DisputeEvidence)
    private readonly evidenceRepository: Repository<DisputeEvidence>,
  ) {
    super();
  }

  async process(job: Job<DisputeEvidenceJobData>): Promise<any> {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    const { evidenceId, disputeId, storagePath, mimeType, originalFilename } =
      job.data;

    this.logger.log(
      `${correlationPrefix}Processing evidence job ${job.id} — evidenceId=${evidenceId} disputeId=${disputeId} (attempt ${job.attemptsMade + 1})`,
    );

    // Mark as PROCESSING
    await this.evidenceRepository.update(evidenceId, {
      processingStatus: EvidenceProcessingStatus.PROCESSING,
    });

    try {
      const metadata = await this.processFile({
        storagePath,
        mimeType,
        originalFilename,
      });

      // Mark as COMPLETED and store metadata
      await this.evidenceRepository.update(evidenceId, {
        processingStatus: EvidenceProcessingStatus.COMPLETED,
        processingMetadata: metadata,
        processingError: null,
      });

      this.logger.log(
        `${correlationPrefix}Evidence job ${job.id} completed — evidenceId=${evidenceId}`,
      );

      return { evidenceId, disputeId, status: 'completed', metadata };
    } catch (error) {
      const errMsg = (error as Error).message;
      this.logger.error(
        `${correlationPrefix}Evidence job ${job.id} processing failed — evidenceId=${evidenceId}: ${errMsg}`,
      );

      // Persist failure reason; the @OnWorkerEvent('failed') hook handles
      // final exhaustion marking after all retries are spent.
      await this.evidenceRepository.update(evidenceId, {
        processingStatus: EvidenceProcessingStatus.FAILED,
        processingError: errMsg,
      });

      // Re-throw so BullMQ can apply retry/backoff
      throw error;
    }
  }

  /**
   * Performs actual file processing steps:
   *  - File-type normalisation (ensure PDF/JPEG are well-formed)
   *  - Basic metadata extraction (size, page count for PDFs)
   *  - Placeholder for OCR integration
   *
   * Extend this method with real OCR/normalisation libraries as needed.
   */
  private async processFile(params: {
    storagePath: string;
    mimeType: string;
    originalFilename: string;
  }): Promise<Record<string, any>> {
    const { mimeType, originalFilename, storagePath } = params;

    const metadata: Record<string, any> = {
      processedAt: new Date().toISOString(),
      mimeType,
      originalFilename,
      storagePath,
    };

    if (mimeType === 'application/pdf') {
      // TODO: integrate a real PDF parser (e.g. pdf-parse) to extract page count,
      //       run OCR via Tesseract or a cloud provider, etc.
      metadata['fileType'] = 'pdf';
      metadata['ocrStatus'] = 'skipped'; // replace with actual OCR result
    } else if (mimeType.startsWith('image/')) {
      // TODO: integrate sharp or Jimp for image normalisation (resize, strip EXIF).
      metadata['fileType'] = 'image';
      metadata['normalised'] = false; // replace with actual normalisation result
    } else {
      metadata['fileType'] = 'other';
    }

    return metadata;
  }

  @OnWorkerEvent('failed')
  async onFailed(job: Job<DisputeEvidenceJobData>, error: Error) {
    const { evidenceId, disputeId, correlationId } = job.data;
    const correlationPrefix = correlationId ? `[${correlationId}] ` : '';
    const attemptsExhausted = job.attemptsMade >= (job.opts.attempts ?? 3);

    this.logger.error(
      `${correlationPrefix}Evidence job ${job.id} failed (attempt ${job.attemptsMade}/${job.opts.attempts ?? 3}) — evidenceId=${evidenceId} disputeId=${disputeId}: ${error.message}`,
    );

    if (attemptsExhausted) {
      this.logger.error(
        `${correlationPrefix}Evidence job ${job.id} exhausted retries — moved to dead-letter queue. evidenceId=${evidenceId}`,
      );

      // Ensure the DB reflects final failure state
      await this.evidenceRepository.update(evidenceId, {
        processingStatus: EvidenceProcessingStatus.FAILED,
        processingError: `Exhausted retries: ${error.message}`,
      });
    }
  }

  @OnWorkerEvent('completed')
  onCompleted(job: Job<DisputeEvidenceJobData>) {
    const correlationPrefix = job.data.correlationId ? `[${job.data.correlationId}] ` : '';
    this.logger.debug(
      `${correlationPrefix}Evidence job ${job.id} worker event: completed — evidenceId=${job.data.evidenceId}`,
    );
  }
}
