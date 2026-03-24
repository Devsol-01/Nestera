import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  Asset,
  Horizon,
  Keypair,
  Networks,
  rpc,
  scValToNative,
  Transaction,
  nativeToScVal,
  xdr,
} from '@stellar/stellar-sdk';
import { TransactionDto } from './dto/transaction.dto';
import { RpcClientWrapper, RpcEndpoint } from './rpc-client.wrapper';

const DELEGATION_STORAGE_KEYS = [
  'delegate',
  'delegation',
  'Delegate',
  'Delegation',
] as const;

@Injectable()
export class StellarService implements OnModuleInit {
  private readonly logger = new Logger(StellarService.name);
  private rpcClient: RpcClientWrapper;

  constructor(private configService: ConfigService) {
    // Build RPC endpoints array
    const rpcEndpoints: RpcEndpoint[] = [];
    const primaryRpcUrl = this.configService.get<string>('stellar.rpcUrl');
    if (primaryRpcUrl) {
      rpcEndpoints.push({ url: primaryRpcUrl, priority: 0, type: 'rpc' });
    }

    const fallbackRpcUrls =
      this.configService.get<string[]>('stellar.rpcFallbackUrls') || [];
    fallbackRpcUrls.forEach((url, index) => {
      if (url) {
        rpcEndpoints.push({ url, priority: index + 1, type: 'rpc' });
      }
    });

    // Build Horizon endpoints array
    const horizonEndpoints: RpcEndpoint[] = [];
    const primaryHorizonUrl =
      this.configService.get<string>('stellar.horizonUrl');
    if (primaryHorizonUrl) {
      horizonEndpoints.push({
        url: primaryHorizonUrl,
        priority: 0,
        type: 'horizon',
      });
    }

    const fallbackHorizonUrls =
      this.configService.get<string[]>('stellar.horizonFallbackUrls') || [];
    fallbackHorizonUrls.forEach((url, index) => {
      if (url) {
        horizonEndpoints.push({ url, priority: index + 1, type: 'horizon' });
      }
    });

    // Initialize RPC client wrapper with retry configuration
    this.rpcClient = new RpcClientWrapper(
      rpcEndpoints,
      horizonEndpoints,
      {
        maxRetries: this.configService.get<number>('stellar.rpcMaxRetries') || 3,
        retryDelay: this.configService.get<number>('stellar.rpcRetryDelay') || 1000,
        timeoutMs: this.configService.get<number>('stellar.rpcTimeout') || 10000,
      },
    );
  }

  onModuleInit() {
    this.logger.log('Stellar Service Initialized');
    const network = this.configService.get<string>('stellar.network');
    this.logger.log(`Target Network: ${network}`);

    // Log configured endpoints
    const status = this.rpcClient.getEndpointsStatus();
    this.logger.log(
      `Configured ${status.rpc.endpoints.length} RPC endpoint(s) and ${status.horizon.endpoints.length} Horizon endpoint(s)`,
    );
  }

  getRpcServer() {
    return this.rpcClient.getCurrentRpcServer();
  }

  getHorizonServer() {
    return this.rpcClient.getCurrentHorizonServer();
  }

  /**
   * Get status of all configured RPC endpoints
   */
  getEndpointsStatus() {
    return this.rpcClient.getEndpointsStatus();
  }

  getNetworkPassphrase(): string {
    const network = this.configService.get<string>('stellar.network');
    return network === 'mainnet' ? Networks.PUBLIC : Networks.TESTNET;
  }

  async getHealth() {
    try {
      return await this.rpcClient.executeWithRetry(
        async (client) => {
          return await (client as rpc.Server).getHealth();
        },
        'rpc',
      );
    } catch (error) {
      this.logger.error('Failed to get Stellar RPC health', error);
      throw error;
    }
  }

  // Placeholder for Soroban contract interaction
  async queryContract(contractId: string, method: string) {
    // Implementation for querying smart contracts
    this.logger.log(`Querying contract ${contractId}, method ${method}`);
    // return this.rpcServer.simulateTransaction(...)
    return Promise.resolve();
  }

  async getDelegationForUser(publicKey: string): Promise<string | null> {
    const contractId = this.configService.get<string>('stellar.contractId');
    if (!contractId || !publicKey) {
      return null;
    }

    try {
      return await this.rpcClient.executeWithRetry(
        async (client) => {
          const rpcServer = client as rpc.Server;

          for (const storageKeyName of DELEGATION_STORAGE_KEYS) {
            const storageKey = nativeToScVal([storageKeyName, publicKey], {
              type: ['symbol', 'address'],
            });

            try {
              const entry = await rpcServer.getContractData(
                contractId,
                storageKey,
                rpc.Durability.Persistent,
              );

              const rawValue = entry.val.contractData().val();
              const delegate = this.normalizeDelegationValue(
                scValToNative(rawValue),
              );

              if (delegate) {
                return delegate;
              }

              if (delegate === null) {
                return null;
              }
            } catch (error) {
              if (this.isContractDataMissing(error)) {
                continue;
              }

              throw error;
            }
          }

          return null;
        },
        'rpc',
      );
    } catch (error) {
      this.logger.error(
        `Failed to fetch delegation for ${publicKey}: ${(error as Error).message}`,
        error,
      );
      return null;
    }
  }

  generateKeypair(): { publicKey: string; secretKey: string } {
    const keypair = Keypair.random();
    return {
      publicKey: keypair.publicKey(),
      secretKey: keypair.secret(),
    };
  }

  /**
   * Fetches recent transactions for a given Stellar public key from the
   * Horizon server and maps them into a sanitized TransactionDto array.
   *
   * @param publicKey - The Stellar G... public key of the account
   * @param limit     - Maximum number of transactions to return (default 10)
   * @returns         Array of sanitized TransactionDto objects
   */
  async getRecentTransactions(
    publicKey: string,
    limit = 10,
  ): Promise<TransactionDto[]> {
    try {
      return await this.rpcClient.executeWithRetry(
        async (client) => {
          const horizonServer = client as Horizon.Server;
          const response = await horizonServer
            .transactions()
            .forAccount(publicKey)
            .limit(limit)
            .order('desc')
            .call();

          const transactions = response.records;

          const results = await Promise.all(
            transactions.map(async (tx) => {
              // Default token / amount in case operations cannot be fetched
              let token = 'XLM';
              let amount = '0';

              try {
                const opsResponse = await tx.operations();
                const ops = opsResponse.records;

                if (ops.length > 0) {
                  const op = ops[0] as unknown as Record<string, unknown>;

                  // Extract amount — present on payment, path_payment, etc.
                  if (typeof op['amount'] === 'string') {
                    amount = op['amount'] as string;
                  }

                  // Determine the asset / token type
                  if (
                    op['asset_type'] === 'native' ||
                    op['asset'] instanceof Asset
                  ) {
                    token = 'XLM';
                  } else if (
                    typeof op['asset_code'] === 'string' &&
                    op['asset_code']
                  ) {
                    token = op['asset_code'] as string;
                  } else if (op['buying_asset_code']) {
                    token = op['buying_asset_code'] as string;
                  } else if (op['selling_asset_code']) {
                    token = op['selling_asset_code'] as string;
                  }
                }
              } catch (opError) {
                this.logger.warn(
                  `Could not fetch operations for tx ${tx.hash}: ${(opError as Error).message}`,
                );
              }

              return {
                date: tx.created_at,
                amount,
                token,
                hash: tx.hash,
              } satisfies TransactionDto;
            }),
          );

          return results;
        },
        'horizon',
      );
    } catch (error) {
      this.logger.error(
        `Failed to fetch transactions for ${publicKey}: ${(error as Error).message}`,
        error,
      );
      return [];
    }
  }

  private normalizeDelegationValue(value: unknown): string | null {
    if (value === undefined || value === null || value === false) {
      return null;
    }

    if (typeof value === 'string' && value.trim().length > 0) {
      return value;
    }

    return null;
  }

  private isContractDataMissing(error: unknown): boolean {
    return (
      typeof error === 'object' &&
      error !== null &&
      'code' in error &&
      error.code === 404
    );
  }
}
