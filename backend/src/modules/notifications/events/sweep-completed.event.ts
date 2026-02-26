export class SweepCompletedEvent {
  constructor(
    public readonly userId: string,
    public readonly userEmail: string,
    public readonly userName: string,
    public readonly subscriptionId: string,
    public readonly productName: string,
    public readonly amount: number,
    public readonly txHash?: string,
  ) {}
}
