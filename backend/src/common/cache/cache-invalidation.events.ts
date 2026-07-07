export class CacheInvalidationEvent {
  constructor(
    public readonly key: string,
    public readonly tags?: string[],
    public readonly pattern?: string,
    public readonly triggerEvent: string = 'Manual Request',
  ) {}
}

export class CacheInvalidationByTagEvent {
  constructor(
    public readonly tag: string,
    public readonly triggerEvent: string = 'Manual Request',
  ) {}
}

export class CacheInvalidationByPatternEvent {
  constructor(
    public readonly pattern: string,
    public readonly triggerEvent: string = 'Manual Request',
  ) {}
}
