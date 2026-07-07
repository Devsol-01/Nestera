import {
  Injectable,
  Logger,
  NotFoundException,
  BadRequestException,
  Optional,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import axios from 'axios';
import { Repository } from 'typeorm';
import { User } from '../user/entities/user.entity';
import { PiiEncryptionService } from '../../common/services/pii-encryption.service';
import { KycComplianceReport } from './entities/kyc-compliance-report.entity';
import {
  KycProvider,
  KycVerification,
  KycVerificationStatus,
} from './entities/kyc-verification.entity';
import { InitiateKycDto } from './dto/initiate-kyc.dto';
import { KycWebhookDto } from './dto/kyc-webhook.dto';
import { TestModeService } from '../../common/test-mode/test-mode.service';

@Injectable()
export class KycService {
  private readonly logger = new Logger(KycService.name);

  constructor(
    @InjectRepository(KycVerification)
    private readonly verificationRepository: Repository<KycVerification>,
    @InjectRepository(KycComplianceReport)
    private readonly reportRepository: Repository<KycComplianceReport>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configService: ConfigService,
    private readonly piiEncryptionService: PiiEncryptionService,
    @Optional() private readonly testModeService?: TestModeService,
  ) {}

  async initiateVerification(userId: string, dto: InitiateKycDto) {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const providerResponse = await this.createProviderCheck(user, dto);

    const verification = this.verificationRepository.create({
      userId,
      provider: dto.provider,
      providerReference: providerResponse.providerReference,
      status: KycVerificationStatus.PENDING,
      encryptedPii: this.piiEncryptionService.encrypt({
        idNumber: dto.idNumber ?? null,
        documentType: dto.documentType ?? null,
        email: user.email,
      }),
      encryptedProviderResponse: this.piiEncryptionService.encrypt(
        providerResponse.raw,
      ),
    });

    const saved = await this.verificationRepository.save(verification);
    await this.userRepository.update(userId, {
      kycStatus: 'PENDING',
    });

    return {
      verificationId: saved.id,
      providerReference: saved.providerReference,
      provider: saved.provider,
      status: saved.status,
      verificationUrl: providerResponse.verificationUrl,
    };
  }

  async handleWebhook(dto: KycWebhookDto, rawPayload: unknown) {
    const verification = await this.verificationRepository.findOne({
      where: { providerReference: dto.providerReference },
    });

    if (!verification) {
      throw new NotFoundException('KYC verification not found');
    }

    const status = this.normalizeStatus(dto.status);

    verification.status = status;
    verification.failureReason = dto.reason || null;
    verification.encryptedWebhookPayload =
      this.piiEncryptionService.encrypt(rawPayload);

    if (
      status === KycVerificationStatus.APPROVED ||
      status === KycVerificationStatus.REJECTED
    ) {
      verification.completedAt = new Date();
    }

    await this.verificationRepository.save(verification);

    const isApproved = status === KycVerificationStatus.APPROVED;
    await this.userRepository.update(verification.userId, {
      kycStatus: isApproved
        ? 'APPROVED'
        : status === KycVerificationStatus.REJECTED
          ? 'REJECTED'
          : 'PENDING',
      kycRejectionReason: isApproved ? undefined : dto.reason || undefined,
      tier: isApproved ? 'VERIFIED' : 'FREE',
    });

    return { ok: true };
  }

  async getComplianceReport(regulator: string, period: string) {
    const rows = await this.verificationRepository.find({
      where: {},
      order: { createdAt: 'DESC' },
      take: 1000,
    });

    const summary = {
      totalChecks: rows.length,
      approved: rows.filter((r) => r.status === KycVerificationStatus.APPROVED)
        .length,
      rejected: rows.filter((r) => r.status === KycVerificationStatus.REJECTED)
        .length,
      pending: rows.filter((r) => r.status === KycVerificationStatus.PENDING)
        .length,
    };

    const payload = {
      regulator,
      period,
      generatedAt: new Date().toISOString(),
      verifications: rows.map((row) => ({
        id: row.id,
        userId: row.userId,
        provider: row.provider,
        providerReference: row.providerReference,
        status: row.status,
        completedAt: row.completedAt,
        createdAt: row.createdAt,
      })),
    };

    const report = this.reportRepository.create({
      regulator,
      period,
      status: 'FINAL',
      summary,
      payload,
    });

    const saved = await this.reportRepository.save(report);
    return {
      id: saved.id,
      regulator: saved.regulator,
      period: saved.period,
      status: saved.status,
      summary: saved.summary,
      generatedAt: saved.generatedAt,
    };
  }

  async listUserVerifications(userId: string) {
    return this.verificationRepository.find({
      where: { userId },
      order: { createdAt: 'DESC' },
    });
  }

  private normalizeStatus(status: KycVerificationStatus) {
    if (
      status !== KycVerificationStatus.APPROVED &&
      status !== KycVerificationStatus.REJECTED &&
      status !== KycVerificationStatus.PENDING
    ) {
      throw new BadRequestException('Invalid KYC status');
    }

    return status;
  }

  private async createProviderCheck(user: User, dto: InitiateKycDto) {
    if (this.testModeService?.isEnabled) {
      const providerReference = `test_${dto.provider.toLowerCase()}_${Date.now()}`;
      return {
        providerReference,
        verificationUrl: `https://test-mode.kyc/session/${providerReference}`,
        raw: { testMode: true, provider: dto.provider, userEmail: user.email },
      };
    }

    const baseUrl = this.configService.get<string>('KYC_PROVIDER_BASE_URL');
    const apiKey = this.configService.get<string>('KYC_PROVIDER_API_KEY');

    const providerReference = `${dto.provider.toLowerCase()}_${Date.now()}_${Math.floor(Math.random() * 1000)}`;

    if (!baseUrl || !apiKey) {
      this.logger.warn(
        'KYC provider configuration missing. Falling back to simulated provider response.',
      );
      return {
        providerReference,
        verificationUrl: `https://kyc.example.com/session/${providerReference}`,
        raw: {
          simulated: true,
          userEmail: user.email,
          provider: dto.provider,
        },
      };
    }

    try {
      const response = await axios.post(
        `${baseUrl}/verifications`,
        {
          applicant: {
            userId: user.id,
            email: user.email,
            name: user.name,
          },
          provider: dto.provider,
        },
        {
          timeout: 10000,
          headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
        },
      );

      return {
        providerReference: response.data?.id || providerReference,
        verificationUrl:
          response.data?.verificationUrl ||
          `https://kyc.example.com/session/${providerReference}`,
        raw: response.data,
      };
    } catch (error) {
      this.logger.error(
        'Provider API call failed, using resilient simulated response',
      );
      return {
        providerReference,
        verificationUrl: `https://kyc.example.com/session/${providerReference}`,
        raw: {
          simulated: true,
          providerError: true,
          provider: dto.provider,
        },
      };
    }
  }
}
