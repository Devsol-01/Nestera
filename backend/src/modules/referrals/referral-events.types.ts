export const REFERRAL_COMPLETED_EVENT = 'referral.completed' as const;

export type ReferralCompletedEventName = typeof REFERRAL_COMPLETED_EVENT;

export interface ReferralCompletedEventPayloadV1 {
  eventType: ReferralCompletedEventName;
  schemaVersion: 1;
  referralId: string;
  referrerId: string;
  refereeId: string;
  campaignId?: string | null;
  completedAt?: string;
}

export type ReferralCompletedEventPayloadV0 = Omit<
  ReferralCompletedEventPayloadV1,
  'eventType' | 'schemaVersion'
>;

export type ReferralCompletedEventPayload =
  | ReferralCompletedEventPayloadV1
  | ReferralCompletedEventPayloadV0;

export function isReferralCompletedEventV1(
  payload: unknown,
): payload is ReferralCompletedEventPayloadV1 {
  return (
    typeof payload === 'object' &&
    payload !== null &&
    (payload as any).eventType === REFERRAL_COMPLETED_EVENT &&
    (payload as any).schemaVersion === 1
  );
}

export function normalizeReferralCompletedEvent(
  payload: ReferralCompletedEventPayload,
): ReferralCompletedEventPayloadV1 {
  if (isReferralCompletedEventV1(payload)) {
    return payload;
  }

  return {
    eventType: REFERRAL_COMPLETED_EVENT,
    schemaVersion: 1,
    referralId: (payload as any).referralId,
    referrerId: (payload as any).referrerId,
    refereeId: (payload as any).refereeId,
    campaignId: (payload as any).campaignId ?? null,
  };
}
