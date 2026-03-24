import { Test, TestingModule } from '@nestjs/testing';
import { GovernanceService } from './governance.service';
import { UserService } from '../user/user.service';
import { StellarService } from '../blockchain/stellar.service';

describe('GovernanceService', () => {
  let service: GovernanceService;
  let userService: { findById: jest.Mock };
  let stellarService: { getDelegationForUser: jest.Mock };

  beforeEach(async () => {
    userService = {
      findById: jest.fn(),
    };

    stellarService = {
      getDelegationForUser: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        GovernanceService,
        {
          provide: UserService,
          useValue: userService,
        },
        {
          provide: StellarService,
          useValue: stellarService,
        },
      ],
    }).compile();

    service = module.get<GovernanceService>(GovernanceService);
  });

  it('returns null when the user has no linked wallet', async () => {
    userService.findById.mockResolvedValue({ id: 'user-1', publicKey: null });

    await expect(service.getUserDelegation('user-1')).resolves.toEqual({
      delegate: null,
    });
    expect(stellarService.getDelegationForUser).not.toHaveBeenCalled();
  });

  it('returns null when no delegation exists on-chain', async () => {
    userService.findById.mockResolvedValue({
      id: 'user-1',
      publicKey: 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN',
    });
    stellarService.getDelegationForUser.mockResolvedValue(null);

    await expect(service.getUserDelegation('user-1')).resolves.toEqual({
      delegate: null,
    });
  });

  it('returns the delegated wallet address when present', async () => {
    userService.findById.mockResolvedValue({
      id: 'user-1',
      publicKey: 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN',
    });
    stellarService.getDelegationForUser.mockResolvedValue(
      'GB7TAYQB6A6E7MCCKRUYJ4JYK2YTHJOTD4A5Q65XAH2EJQ2F6J67P5ST',
    );

    await expect(service.getUserDelegation('user-1')).resolves.toEqual({
      delegate: 'GB7TAYQB6A6E7MCCKRUYJ4JYK2YTHJOTD4A5Q65XAH2EJQ2F6J67P5ST',
    });
  });
});
