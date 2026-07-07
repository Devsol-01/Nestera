import { HttpStatus } from '@nestjs/common';
import { ErrorCode } from '../enums/error-code.enum';
import {
  ResourceNotFoundException,
  ResourceNotYetAvailableException,
  ResourcePendingIndexingException,
  ResourceSyncInProgressException,
} from './domain.exception';

describe('Domain Exceptions', () => {
  describe('ResourceNotFoundException', () => {
    it('should create exception with resource name only', () => {
      const exception = new ResourceNotFoundException('Claim');
      expect(exception.errorCode).toBe(ErrorCode.NOT_FOUND);
      expect(exception.getStatus()).toBe(HttpStatus.NOT_FOUND);
      expect(exception.message).toBe('Claim not found');
    });

    it('should create exception with resource name and id', () => {
      const exception = new ResourceNotFoundException('Claim', '123');
      expect(exception.errorCode).toBe(ErrorCode.NOT_FOUND);
      expect(exception.getStatus()).toBe(HttpStatus.NOT_FOUND);
      expect(exception.message).toBe("Claim '123' not found");
    });
  });

  describe('ResourceNotYetAvailableException', () => {
    it('should create exception with resource name only', () => {
      const exception = new ResourceNotYetAvailableException('Transaction');
      expect(exception.errorCode).toBe(ErrorCode.RESOURCE_NOT_YET_AVAILABLE);
      expect(exception.getStatus()).toBe(HttpStatus.ACCEPTED);
      expect(exception.message).toBe('Transaction is being processed and will be available shortly');
      expect(exception.details?.retryAfterSeconds).toBeUndefined();
    });

    it('should create exception with resource name and id', () => {
      const exception = new ResourceNotYetAvailableException('Transaction', 'tx-123');
      expect(exception.errorCode).toBe(ErrorCode.RESOURCE_NOT_YET_AVAILABLE);
      expect(exception.getStatus()).toBe(HttpStatus.ACCEPTED);
      expect(exception.message).toBe("Transaction 'tx-123' is being processed and will be available shortly");
    });

    it('should include retryAfterSeconds in details', () => {
      const exception = new ResourceNotYetAvailableException('Transaction', 'tx-123', 30);
      expect(exception.details?.retryAfterSeconds).toBe(30);
    });

    it('should include additional details', () => {
      const exception = new ResourceNotYetAvailableException('Transaction', 'tx-123', 30, {
        estimatedAvailability: '2024-01-01T00:00:00Z',
      });
      expect(exception.details?.retryAfterSeconds).toBe(30);
      expect((exception.details as any)?.estimatedAvailability).toBe('2024-01-01T00:00:00Z');
    });
  });

  describe('ResourcePendingIndexingException', () => {
    it('should create exception with resource name only', () => {
      const exception = new ResourcePendingIndexingException('SavingsProduct');
      expect(exception.errorCode).toBe(ErrorCode.RESOURCE_PENDING_INDEXING);
      expect(exception.getStatus()).toBe(HttpStatus.ACCEPTED);
      expect(exception.message).toBe('SavingsProduct is pending blockchain indexing');
    });

    it('should create exception with resource name and id', () => {
      const exception = new ResourcePendingIndexingException('SavingsProduct', 'prod-123');
      expect(exception.errorCode).toBe(ErrorCode.RESOURCE_PENDING_INDEXING);
      expect(exception.getStatus()).toBe(HttpStatus.ACCEPTED);
      expect(exception.message).toBe("SavingsProduct 'prod-123' is pending blockchain indexing");
    });

    it('should include retryAfterSeconds in details', () => {
      const exception = new ResourcePendingIndexingException('SavingsProduct', 'prod-123', 45);
      expect(exception.details?.retryAfterSeconds).toBe(45);
    });
  });

  describe('ResourceSyncInProgressException', () => {
    it('should create exception with resource name only', () => {
      const exception = new ResourceSyncInProgressException('Proposal');
      expect(exception.errorCode).toBe(ErrorCode.RESOURCE_SYNC_IN_PROGRESS);
      expect(exception.getStatus()).toBe(HttpStatus.CONFLICT);
      expect(exception.message).toBe('Proposal sync is in progress');
    });

    it('should create exception with resource name and id', () => {
      const exception = new ResourceSyncInProgressException('Proposal', 'prop-456');
      expect(exception.errorCode).toBe(ErrorCode.RESOURCE_SYNC_IN_PROGRESS);
      expect(exception.getStatus()).toBe(HttpStatus.CONFLICT);
      expect(exception.message).toBe("Proposal 'prop-456' sync is in progress");
    });

    it('should include retryAfterSeconds in details', () => {
      const exception = new ResourceSyncInProgressException('Proposal', 'prop-456', 60);
      expect(exception.details?.retryAfterSeconds).toBe(60);
    });
  });
});
