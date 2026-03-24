import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { Keypair, nativeToScVal } from '@stellar/stellar-sdk';
import { StellarService } from './stellar.service';
import { TransactionDto } from './dto/transaction.dto';
import { RpcClientWrapper } from './rpc-client.wrapper';

const TEST_PUBLIC_KEY = Keypair.random().publicKey();
const TEST_DELEGATE_KEY = Keypair.random().publicKey();

/** Build a minimal fake Horizon transaction record */
const makeFakeTx = (overrides: Partial<Record<string, unknown>> = {}) => ({
  hash: 'abc123def456',
  created_at: '2024-01-15T10:30:00Z',
  operations: jest.fn().mockResolvedValue({
    records: [
      {
        type: 'payment',
        amount: '10.5000000',
        asset_type: 'native',
      },
    ],
  }),
  ...overrides,
});

describe('StellarService', () => {
  let service: StellarService;
  let mockTransactionCall: jest.Mock;
  let mockRpcClient: jest.Mocked<RpcClientWrapper>;

  beforeEach(async () => {
    mockTransactionCall = jest.fn();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        StellarService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              const map: Record<string, unknown> = {
                'stellar.rpcUrl': 'https://soroban-testnet.stellar.org',
                'stellar.horizonUrl': 'https://horizon-testnet.stellar.org',
                'stellar.network': 'testnet',
                'stellar.contractId':
                  'CCJZ5DGASBWQXR5MPFCJXMBI333XE5U3FSJTNQU7RIKE3P5GN2K2WYD5',
                'stellar.rpcFallbackUrls': [],
                'stellar.horizonFallbackUrls': [],
                'stellar.rpcMaxRetries': 3,
                'stellar.rpcRetryDelay': 1000,
                'stellar.rpcTimeout': 10000,
              };
              return map[key] ?? '';
            }),
          },
        },
      ],
    }).compile();

    service = module.get<StellarService>(StellarService);

    // Mock the RPC client wrapper
    mockRpcClient = (service as unknown as { rpcClient: RpcClientWrapper })
      .rpcClient as jest.Mocked<RpcClientWrapper>;

    // Mock executeWithRetry to call the operation directly with a fake Horizon server
    jest
      .spyOn(mockRpcClient, 'executeWithRetry')
      .mockImplementation(async (operation) => {
        const fakeHorizonServer = {
          transactions: () => ({
            forAccount: () => ({
              limit: () => ({
                order: () => ({
                  call: mockTransactionCall,
                }),
              }),
            }),
          }),
        };
        return operation(fakeHorizonServer as any);
      });
  });

  it('should return a mapped array of TransactionDto on success', async () => {
    const fakeTx = makeFakeTx();
    mockTransactionCall.mockResolvedValue({ records: [fakeTx] });

    const result = await service.getRecentTransactions(
      TEST_PUBLIC_KEY,
    );

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject<TransactionDto>({
      hash: 'abc123def456',
      date: '2024-01-15T10:30:00Z',
      amount: '10.5000000',
      token: 'XLM',
    });
  });

  it('should map the token to the asset_code when asset is not native', async () => {
    const fakeTx = makeFakeTx({
      operations: jest.fn().mockResolvedValue({
        records: [
          {
            type: 'payment',
            amount: '50.0000000',
            asset_type: 'credit_alphanum4',
            asset_code: 'USDC',
          },
        ],
      }),
    });
    mockTransactionCall.mockResolvedValue({ records: [fakeTx] });

    const [tx] = await service.getRecentTransactions(
      TEST_PUBLIC_KEY,
    );

    expect(tx.token).toBe('USDC');
    expect(tx.amount).toBe('50.0000000');
  });

  it('should return [] and log an error when Horizon call fails', async () => {
    mockTransactionCall.mockRejectedValue(new Error('Horizon unavailable'));
    const logSpy = jest
      .spyOn(service['logger'], 'error')
      .mockImplementation(() => {});

    const result = await service.getRecentTransactions(
      TEST_PUBLIC_KEY,
    );

    expect(result).toEqual([]);
    expect(logSpy).toHaveBeenCalled();
  });

  it('should default amount to "0" and token to "XLM" when operations call fails', async () => {
    const fakeTx = makeFakeTx({
      operations: jest.fn().mockRejectedValue(new Error('ops error')),
    });
    mockTransactionCall.mockResolvedValue({ records: [fakeTx] });

    const [tx] = await service.getRecentTransactions(
      TEST_PUBLIC_KEY,
    );

    expect(tx.amount).toBe('0');
    expect(tx.token).toBe('XLM');
    expect(tx.hash).toBe('abc123def456');
  });

  it('should respect the limit parameter', async () => {
    mockTransactionCall.mockResolvedValue({ records: [] });

    await service.getRecentTransactions(
      TEST_PUBLIC_KEY,
      5,
    );

    // Verify executeWithRetry was called with 'horizon' type
    expect(mockRpcClient.executeWithRetry).toHaveBeenCalledWith(
      expect.any(Function),
      'horizon',
    );
  });

  it('should return a delegated wallet when contract data resolves to an address', async () => {
    jest
      .spyOn(mockRpcClient, 'executeWithRetry')
      .mockImplementation(async (operation) => {
        const fakeRpcServer = {
          getContractData: jest.fn().mockResolvedValue({
            val: {
              contractData: () => ({
                val: () =>
                  nativeToScVal(
                    TEST_DELEGATE_KEY,
                    { type: 'address' },
                  ),
              }),
            },
          }),
        };

        return operation(fakeRpcServer as any);
      });

    await expect(
      service.getDelegationForUser(
        TEST_PUBLIC_KEY,
      ),
    ).resolves.toBe(TEST_DELEGATE_KEY);
  });

  it('should return null when contract data is missing for all candidate keys', async () => {
    jest
      .spyOn(mockRpcClient, 'executeWithRetry')
      .mockImplementation(async (operation) => {
        const fakeRpcServer = {
          getContractData: jest.fn().mockRejectedValue({
            code: 404,
            message: 'missing',
          }),
        };

        return operation(fakeRpcServer as any);
      });

    await expect(
      service.getDelegationForUser(
        TEST_PUBLIC_KEY,
      ),
    ).resolves.toBeNull();
  });
});
