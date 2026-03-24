/// Returns all proposal IDs the user has voted on
pub fn get_user_voted_proposals(env: &Env, user: Address) -> Vec<u64> {
    let mut voted: Vec<u64> = Vec::new(env);
    let all = list_proposals(env);
    for pid in all.iter() {
        let key = GovernanceKey::VoterRecord(pid.clone(), user.clone());
        if env.storage().persistent().has(&key) {
            voted.push_back(pid.clone());
        }
    }
    voted
}

/// Returns all active (non-executed, within voting period) proposal IDs
pub fn get_active_proposals(env: &Env) -> Vec<u64> {
    let now = env.ledger().timestamp();
    let mut active: Vec<u64> = Vec::new(env);
    let all = list_proposals(env);
    for pid in all.iter() {
        if let Some(p) = get_proposal(env, pid.clone()) {
            if !p.executed && now >= p.start_time && now <= p.end_time {
                active.push_back(pid.clone());
            }
        }
    }
    active
}

/// Returns vote counts for a proposal
pub fn get_proposal_votes(env: &Env, proposal_id: u64) -> (u128, u128, u128) {
    if let Some(p) = get_proposal(env, proposal_id) {
        (p.for_votes, p.against_votes, p.abstain_votes)
    } else {
        (0, 0, 0)
    }
}
use crate::errors::SavingsError;
use crate::governance_events::*;
use crate::rewards::storage::get_user_rewards;
use crate::storage_types::DataKey;
use soroban_sdk::{contracttype, Address, Env, String, Vec};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionProposal {
    pub id: u64,
    pub creator: Address,
    pub description: String,
    pub start_time: u64,
    pub end_time: u64,
    pub executed: bool,
    pub for_votes: u128,
    pub against_votes: u128,
    pub abstain_votes: u128,
    pub action: ProposalAction,
    pub queued_time: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub id: u64,
    pub creator: Address,
    pub description: String,
    pub start_time: u64,
    pub end_time: u64,
    pub executed: bool,
    pub for_votes: u128,
    pub against_votes: u128,
    pub abstain_votes: u128,
    pub queued_time: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VotingConfig {
    pub quorum: u32,
    pub voting_period: u64,
    pub timelock_duration: u64,
    pub proposal_threshold: u128,
    pub max_voting_power: u128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernanceKey {
    Proposal(u64),
    ActionProposal(u64),
    NextProposalId,
    VotingConfig,
    AllProposals,
    GovernanceActive,
    VoterRecord(u64, Address),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalAction {
    SetFlexiRate(i128),
    SetGoalRate(i128),
    SetGroupRate(i128),
    SetLockRate(u64, i128),
    PauseContract,
    UnpauseContract,
}

/// Calculates voting power for a user based on their lifetime deposited funds
pub fn get_voting_power(env: &Env, user: &Address) -> u128 {
    let rewards = get_user_rewards(env, user.clone());
    rewards.lifetime_deposited.max(0) as u128
}

/// Creates a new governance proposal
pub fn create_proposal(
    env: &Env,
    creator: Address,
    description: String,
) -> Result<u64, SavingsError> {
    creator.require_auth();

    let config = get_voting_config(env)?;
    let proposal_id = get_next_proposal_id(env);
    let now = env.ledger().timestamp();

    let proposal = Proposal {
        id: proposal_id,
        creator: creator.clone(),
        description: description.clone(),
        start_time: now,
        end_time: now + config.voting_period,
        executed: false,
        for_votes: 0,
        against_votes: 0,
        abstain_votes: 0,
        queued_time: 0,
    };

    env.storage()
        .persistent()
        .set(&GovernanceKey::Proposal(proposal_id), &proposal);

    let mut all_proposals: Vec<u64> = env
        .storage()
        .persistent()
        .get(&GovernanceKey::AllProposals)
        .unwrap_or(Vec::new(env));
    all_proposals.push_back(proposal_id);
    env.storage()
        .persistent()
        .set(&GovernanceKey::AllProposals, &all_proposals);

    env.storage()
        .persistent()
        .set(&GovernanceKey::NextProposalId, &(proposal_id + 1));

    // Emit event
    emit_proposal_created(env, proposal_id, creator, description);

    Ok(proposal_id)
}

/// Creates a governance proposal with an action
pub fn create_action_proposal(
    env: &Env,
    creator: Address,
    description: String,
    action: ProposalAction,
) -> Result<u64, SavingsError> {
    creator.require_auth();

    let config = get_voting_config(env)?;
    if get_voting_power(env, &creator) < config.proposal_threshold {
        return Err(SavingsError::InsufficientBalance);
    }

    let proposal_id = get_next_proposal_id(env);
    let now = env.ledger().timestamp();

    let proposal = ActionProposal {
        id: proposal_id,
        creator: creator.clone(),
        description: description.clone(),
        start_time: now,
        end_time: now + config.voting_period,
        executed: false,
        for_votes: 0,
        against_votes: 0,
        abstain_votes: 0,
        action,
        queued_time: 0,
    };

    env.storage()
        .persistent()
        .set(&GovernanceKey::ActionProposal(proposal_id), &proposal);

    let mut all_proposals: Vec<u64> = env
        .storage()
        .persistent()
        .get(&GovernanceKey::AllProposals)
        .unwrap_or(Vec::new(env));
    all_proposals.push_back(proposal_id);
    env.storage()
        .persistent()
        .set(&GovernanceKey::AllProposals, &all_proposals);

    env.storage()
        .persistent()
        .set(&GovernanceKey::NextProposalId, &(proposal_id + 1));

    // Emit event
    emit_proposal_created(env, proposal_id, creator, description);

    Ok(proposal_id)
}

/// Gets an action proposal by ID
pub fn get_action_proposal(env: &Env, proposal_id: u64) -> Option<ActionProposal> {
    env.storage()
        .persistent()
        .get(&GovernanceKey::ActionProposal(proposal_id))
}

/// Gets a proposal by ID
pub fn get_proposal(env: &Env, proposal_id: u64) -> Option<Proposal> {
    env.storage()
        .persistent()
        .get(&GovernanceKey::Proposal(proposal_id))
}

/// Lists all proposal IDs
pub fn list_proposals(env: &Env) -> Vec<u64> {
    env.storage()
        .persistent()
        .get(&GovernanceKey::AllProposals)
        .unwrap_or(Vec::new(env))
}

/// Gets the voting configuration
pub fn get_voting_config(env: &Env) -> Result<VotingConfig, SavingsError> {
    env.storage()
        .persistent()
        .get(&GovernanceKey::VotingConfig)
        .ok_or(SavingsError::InternalError)
}

/// Initializes voting configuration (admin only)
pub fn init_voting_config(
    env: &Env,
    admin: Address,
    config: VotingConfig,
) -> Result<(), SavingsError> {
    admin.require_auth();

    let stored_admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(SavingsError::Unauthorized)?;

    if admin != stored_admin {
        return Err(SavingsError::Unauthorized);
    }

    if env.storage().persistent().has(&GovernanceKey::VotingConfig) {
        return Err(SavingsError::ConfigAlreadyInitialized);
    }

    if config.voting_period == 0 || config.timelock_duration == 0 || config.max_voting_power == 0 {
        return Err(SavingsError::InvalidAmount);
    }

    env.storage()
        .persistent()
        .set(&GovernanceKey::VotingConfig, &config);
    env.storage()
        .persistent()
        .set(&GovernanceKey::NextProposalId, &1u64);

    Ok(())
}

fn get_next_proposal_id(env: &Env) -> u64 {
    env.storage()
        .persistent()
        .get(&GovernanceKey::NextProposalId)
        .unwrap_or(1)
}

/// Casts a weighted vote on a proposal
pub fn vote(
    env: &Env,
    proposal_id: u64,
    vote_type: u32,
    voter: Address,
) -> Result<(), SavingsError> {
    voter.require_auth();

    // Validate vote_type: 1=for, 2=against, 3=abstain
    if !(1..=3).contains(&vote_type) {
        return Err(SavingsError::InvalidAmount);
    }

    let weight = get_voting_power(env, &voter);
    if weight == 0 {
        return Err(SavingsError::InsufficientBalance);
    }

    let config = get_voting_config(env)?;
    let capped_weight = weight.min(config.max_voting_power);

    let voter_key = GovernanceKey::VoterRecord(proposal_id, voter.clone());
    if env.storage().persistent().has(&voter_key) {
        return Err(SavingsError::DuplicatePlanId);
    }

    let now = env.ledger().timestamp();

    // Regular proposal
    if let Some(mut proposal) = get_proposal(env, proposal_id) {
        if now < proposal.start_time || now > proposal.end_time {
            return Err(SavingsError::TooLate);
        }

        match vote_type {
            1 => {
                proposal.for_votes = proposal
                    .for_votes
                    .checked_add(capped_weight)
                    .ok_or(SavingsError::Overflow)?
            }
            2 => {
                proposal.against_votes = proposal
                    .against_votes
                    .checked_add(capped_weight)
                    .ok_or(SavingsError::Overflow)?
            }
            3 => {
                proposal.abstain_votes = proposal
                    .abstain_votes
                    .checked_add(capped_weight)
                    .ok_or(SavingsError::Overflow)?
            }
            _ => return Err(SavingsError::InvalidAmount),
        }

        env.storage()
            .persistent()
            .set(&GovernanceKey::Proposal(proposal_id), &proposal);
        env.storage().persistent().set(&voter_key, &true);

        emit_vote_cast(env, proposal_id, voter, vote_type, weight);

        return Ok(());
    }

    // Action proposal
    if let Some(mut proposal) = get_action_proposal(env, proposal_id) {
        if now < proposal.start_time || now > proposal.end_time {
            return Err(SavingsError::TooLate);
        }

        match vote_type {
            1 => {
                proposal.for_votes = proposal
                    .for_votes
                    .checked_add(capped_weight)
                    .ok_or(SavingsError::Overflow)?
            }
            2 => {
                proposal.against_votes = proposal
                    .against_votes
                    .checked_add(capped_weight)
                    .ok_or(SavingsError::Overflow)?
            }
            3 => {
                proposal.abstain_votes = proposal
                    .abstain_votes
                    .checked_add(capped_weight)
                    .ok_or(SavingsError::Overflow)?
            }
            _ => return Err(SavingsError::InvalidAmount),
        }

        env.storage()
            .persistent()
            .set(&GovernanceKey::ActionProposal(proposal_id), &proposal);
        env.storage().persistent().set(&voter_key, &true);

        emit_vote_cast(env, proposal_id, voter, vote_type, weight);

        return Ok(());
    }

    Err(SavingsError::PlanNotFound)
}

/// Checks if a user has already voted on a proposal
pub fn has_voted(env: &Env, proposal_id: u64, voter: &Address) -> bool {
    let voter_key = GovernanceKey::VoterRecord(proposal_id, voter.clone());
    env.storage().persistent().has(&voter_key)
}

/// Queues a proposal for execution after timelock
pub fn queue_proposal(env: &Env, proposal_id: u64) -> Result<(), SavingsError> {
    let now = env.ledger().timestamp();

    if let Some(mut proposal) = get_proposal(env, proposal_id) {
        if now <= proposal.end_time {
            return Err(SavingsError::TooEarly);
        }

        if proposal.queued_time > 0 {
            return Err(SavingsError::DuplicatePlanId);
        }

        if proposal.executed {
            return Err(SavingsError::PlanCompleted);
        }

        if proposal.for_votes <= proposal.against_votes {
            return Err(SavingsError::InsufficientBalance);
        }

        proposal.queued_time = now;
        env.storage()
            .persistent()
            .set(&GovernanceKey::Proposal(proposal_id), &proposal);

        emit_proposal_queued(env, proposal_id, now);

        return Ok(());
    }

    if let Some(mut proposal) = get_action_proposal(env, proposal_id) {
        if now <= proposal.end_time {
            return Err(SavingsError::TooEarly);
        }

        if proposal.queued_time > 0 {
            return Err(SavingsError::DuplicatePlanId);
        }

        if proposal.executed {
            return Err(SavingsError::PlanCompleted);
        }

        if proposal.for_votes <= proposal.against_votes {
            return Err(SavingsError::InsufficientBalance);
        }

        proposal.queued_time = now;
        env.storage()
            .persistent()
            .set(&GovernanceKey::ActionProposal(proposal_id), &proposal);

        emit_proposal_queued(env, proposal_id, now);

        return Ok(());
    }

    Err(SavingsError::PlanNotFound)
}

/// Executes a queued proposal after timelock period
pub fn execute_proposal(env: &Env, proposal_id: u64) -> Result<(), SavingsError> {
    let now = env.ledger().timestamp();
    let config = get_voting_config(env)?;

    if let Some(mut proposal) = get_action_proposal(env, proposal_id) {
        if proposal.queued_time == 0 {
            return Err(SavingsError::TooEarly);
        }

        if proposal.executed {
            return Err(SavingsError::PlanCompleted);
        }

        let execution_time = proposal
            .queued_time
            .checked_add(config.timelock_duration)
            .ok_or(SavingsError::Overflow)?;

        if now < execution_time {
            return Err(SavingsError::TooEarly);
        }

        proposal.executed = true;
        env.storage()
            .persistent()
            .set(&GovernanceKey::ActionProposal(proposal_id), &proposal);

        execute_action(env, &proposal.action)?;

        emit_proposal_executed(env, proposal_id, now);

        return Ok(());
    }

    if let Some(mut proposal) = get_proposal(env, proposal_id) {
        if proposal.queued_time == 0 {
            return Err(SavingsError::TooEarly);
        }

        if proposal.executed {
            return Err(SavingsError::PlanCompleted);
        }

        let execution_time = proposal
            .queued_time
            .checked_add(config.timelock_duration)
            .ok_or(SavingsError::Overflow)?;

        if now < execution_time {
            return Err(SavingsError::TooEarly);
        }

        proposal.executed = true;
        env.storage()
            .persistent()
            .set(&GovernanceKey::Proposal(proposal_id), &proposal);

        emit_proposal_executed(env, proposal_id, now);

        return Ok(());
    }

    Err(SavingsError::PlanNotFound)
}

/// Executes a proposal action
fn execute_action(env: &Env, action: &ProposalAction) -> Result<(), SavingsError> {
    match action {
        ProposalAction::SetFlexiRate(rate) => {
            if *rate < 0 {
                return Err(SavingsError::InvalidInterestRate);
            }
            env.storage().instance().set(&DataKey::FlexiRate, rate);
            Ok(())
        }
        ProposalAction::SetGoalRate(rate) => {
            if *rate < 0 {
                return Err(SavingsError::InvalidInterestRate);
            }
            env.storage().instance().set(&DataKey::GoalRate, rate);
            Ok(())
        }
        ProposalAction::SetGroupRate(rate) => {
            if *rate < 0 {
                return Err(SavingsError::InvalidInterestRate);
            }
            env.storage().instance().set(&DataKey::GroupRate, rate);
            Ok(())
        }
        ProposalAction::SetLockRate(duration, rate) => {
            if *rate < 0 {
                return Err(SavingsError::InvalidInterestRate);
            }
            env.storage()
                .instance()
                .set(&DataKey::LockRate(*duration), rate);
            Ok(())
        }
        ProposalAction::PauseContract => {
            env.storage().persistent().set(&DataKey::Paused, &true);
            crate::ttl::extend_config_ttl(env, &DataKey::Paused);
            Ok(())
        }
        ProposalAction::UnpauseContract => {
            env.storage().persistent().set(&DataKey::Paused, &false);
            crate::ttl::extend_config_ttl(env, &DataKey::Paused);
            Ok(())
        }
    }
}

/// Cancels a proposal (creator or admin only)
pub fn cancel_proposal(env: &Env, proposal_id: u64, caller: Address) -> Result<(), SavingsError> {
    caller.require_auth();

    // Try regular proposal
    if let Some(mut proposal) = get_proposal(env, proposal_id) {
        if proposal.creator != caller {
            return Err(SavingsError::Unauthorized);
        }

        if proposal.executed || proposal.queued_time > 0 {
            return Err(SavingsError::TooLate);
        }

        // Mark as canceled (you may want a separate canceled field later)
        proposal.executed = true;
        env.storage()
            .persistent()
            .set(&GovernanceKey::Proposal(proposal_id), &proposal);

        emit_proposal_canceled(env, proposal_id, env.ledger().timestamp());

        return Ok(());
    }

    // Try action proposal
    if let Some(mut proposal) = get_action_proposal(env, proposal_id) {
        if proposal.creator != caller {
            return Err(SavingsError::Unauthorized);
        }

        if proposal.executed || proposal.queued_time > 0 {
            return Err(SavingsError::TooLate);
        }

        proposal.executed = true;
        env.storage()
            .persistent()
            .set(&GovernanceKey::ActionProposal(proposal_id), &proposal);

        emit_proposal_canceled(env, proposal_id, env.ledger().timestamp());

        return Ok(());
    }

    Err(SavingsError::PlanNotFound)
}

/// Checks if governance is active
pub fn is_governance_active(env: &Env) -> bool {
    env.storage()
        .persistent()
        .get(&GovernanceKey::GovernanceActive)
        .unwrap_or(false)
}

/// Activates governance (admin only, one-time)
pub fn activate_governance(env: &Env, admin: Address) -> Result<(), SavingsError> {
    admin.require_auth();

    let stored_admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(SavingsError::Unauthorized)?;

    if admin != stored_admin {
        return Err(SavingsError::Unauthorized);
    }

    env.storage()
        .persistent()
        .set(&GovernanceKey::GovernanceActive, &true);

    Ok(())
}

/// Validates caller is admin or governance is active
pub fn validate_admin_or_governance(env: &Env, caller: &Address) -> Result<bool, SavingsError> {
    if is_governance_active(env) {
        return Ok(true);
    }

    let stored_admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(SavingsError::Unauthorized)?;

    if caller == &stored_admin {
        Ok(false)
    } else {
        Err(SavingsError::Unauthorized)
    }
}
