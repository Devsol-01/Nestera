# Governance Weight / Token Integration

## Overview
This implementation provides voting power calculation for users based on their lifetime deposited funds in the Nestera savings protocol.

## Voting Weight Source
**Current Implementation:** Total deposited funds (lifetime_deposited)

The voting power is calculated from the `lifetime_deposited` field in the user's rewards data, which tracks the cumulative amount a user has deposited across all savings plans.

### Why Lifetime Deposits?
- **Fair representation**: Users who have contributed more to the protocol have proportionally more influence
- **Sybil resistance**: Prevents vote manipulation through multiple accounts
- **Already tracked**: Leverages existing rewards infrastructure
- **Simple & transparent**: Easy to understand and verify

## Functions

### `get_voting_power(user: Address) -> u128`
Returns the voting power for a given user address.

**Parameters:**
- `user`: The address of the user

**Returns:**
- `u128`: The voting power (equal to lifetime deposited amount)

**Example:**
```rust
let power = contract.get_voting_power(&user_address);
// power = 1500 if user has deposited 1500 tokens total
```

### `cast_vote(user: Address, proposal_id: u64, support: bool) -> Result<(), SavingsError>`
Casts a weighted vote on a proposal.

**Parameters:**
- `user`: The address of the voter (requires authentication)
- `proposal_id`: The ID of the proposal to vote on
- `support`: `true` for yes, `false` for no

**Returns:**
- `Ok(())` on success
- `Err(SavingsError::InsufficientBalance)` if user has no voting power

**Events Emitted:**
- `vote`: Contains (user, proposal_id, support, weight)

## Vote Scaling
Votes are automatically scaled by the user's voting power:
- User with 1000 deposited = 1000 voting power
- User with 5000 deposited = 5000 voting power
- User with 0 deposited = 0 voting power (cannot vote)

## Future Enhancements
The current implementation provides a foundation for:
1. **Reward points weighting**: Alternative voting power based on earned points
2. **Staked governance token**: Dedicated governance token for voting
3. **Proposal storage**: Full proposal lifecycle management
4. **Vote tallying**: Automated vote counting and execution
5. **Delegation**: Allow users to delegate voting power
6. **Quadratic voting**: Non-linear voting power calculation

## Testing
Run governance tests:
```bash
cd contracts
cargo test governance_tests
```

All tests verify:
- ✅ New users have zero voting power
- ✅ Voting power increases with deposits
- ✅ Voting power accumulates across multiple deposits
- ✅ Votes require non-zero voting power
- ✅ Votes succeed when user has voting power

## Integration
The governance module integrates seamlessly with:
- **Rewards system**: Uses existing `lifetime_deposited` tracking
- **User management**: Works with existing user initialization
- **Event system**: Emits vote events for off-chain tracking
- **Error handling**: Uses standard `SavingsError` types

## Contract Build Status
✅ Contract builds successfully
✅ All tests pass
✅ No breaking changes to existing functionality
