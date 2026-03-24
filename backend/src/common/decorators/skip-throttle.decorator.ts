import { SetMetadata } from '@nestjs/common';

export const THROTTLE_SKIP_KEY = 'throttle:skip';
export const SkipThrottle = () => SetMetadata(THROTTLE_SKIP_KEY, true);
