import {
  IsOptional,
  IsBoolean,
  IsEnum,
  IsString,
  Matches,
} from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';
import {
  DigestFrequency,
  ProfileVisibility,
  ThemePreference,
  DateFormatPreference,
  PreferredContactChannel,
} from '../entities/notification-preference.entity';

export class UpdateUserPreferenceDto {
  // Channel preferences
  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  emailNotifications?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  inAppNotifications?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  pushNotifications?: boolean;

  @ApiPropertyOptional({ example: false })
  @IsOptional()
  @IsBoolean()
  smsNotifications?: boolean;

  @ApiPropertyOptional({ enum: PreferredContactChannel, example: PreferredContactChannel.EMAIL })
  @IsOptional()
  @IsEnum(PreferredContactChannel)
  preferredContactChannel?: PreferredContactChannel;

  // Notification type preferences
  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  depositNotifications?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  withdrawalNotifications?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  goalNotifications?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  governanceNotifications?: boolean;

  @ApiPropertyOptional({ example: false })
  @IsOptional()
  @IsBoolean()
  marketingNotifications?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  sweepNotifications?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  claimNotifications?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  yieldNotifications?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  milestoneNotifications?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  newsletterSubscribed?: boolean;

  // Privacy preferences
  @ApiPropertyOptional({ enum: ProfileVisibility, example: ProfileVisibility.FRIENDS })
  @IsOptional()
  @IsEnum(ProfileVisibility)
  profileVisibility?: ProfileVisibility;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  dataSharingEnabled?: boolean;

  @ApiPropertyOptional({ example: false })
  @IsOptional()
  @IsBoolean()
  personalizedAds?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  locationSharing?: boolean;

  // Display preferences
  @ApiPropertyOptional({ enum: ThemePreference, example: ThemePreference.LIGHT })
  @IsOptional()
  @IsEnum(ThemePreference)
  theme?: ThemePreference;

  @ApiPropertyOptional({ example: 'en' })
  @IsOptional()
  @IsString()
  @Matches(/^[a-z]{2}(-[A-Z]{2})?$/, {
    message: 'language must be a valid locale code',
  })
  language?: string;

  @ApiPropertyOptional({ example: 'USD' })
  @IsOptional()
  @IsString()
  @Matches(/^[A-Z]{3}$/, {
    message: 'currency must be a 3-letter ISO code',
  })
  currency?: string;

  @ApiPropertyOptional({ enum: DateFormatPreference, example:DateFormatPreference.MM_DD_YYYY })
  @IsOptional()
  @IsEnum(DateFormatPreference)
  dateFormat?: DateFormatPreference;

  @ApiPropertyOptional({ example: false })
  @IsOptional()
  @IsBoolean()
  compactLayout?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  displayBalancesInFiat?: boolean;

  // Quiet hours
  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  quietHoursEnabled?: boolean;

  @ApiPropertyOptional({ example: '22:00' })
  @IsOptional()
  @IsString()
  @Matches(/^([01]\d|2[0-3]):[0-5]\d$/, {
    message: 'quietHoursStart must be HH:MM',
  })
  quietHoursStart?: string;

  @ApiPropertyOptional({ example: '08:00' })
  @IsOptional()
  @IsString()
  @Matches(/^([01]\d|2[0-3]):[0-5]\d$/, {
    message: 'quietHoursEnd must be HH:MM',
  })
  quietHoursEnd?: string;

  @ApiPropertyOptional({ example: 'America/New_York' })
  @IsOptional()
  @IsString()
  timezone?: string;

  // Digest frequency
  @ApiPropertyOptional({ enum: DigestFrequency, example: DigestFrequency.DAILY })
  @IsOptional()
  @IsEnum(DigestFrequency)
  digestFrequency?: DigestFrequency;
}
