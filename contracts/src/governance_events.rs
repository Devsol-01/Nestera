use soroban_sdk::{contracttype, symbol_short, Address, Env, String};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalCreated {
    pub proposal_id: u64,
    pub creator: Address,
    pub description: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteCast {
    pub proposal_id: u64,
    pub voter: Address,
    pub vote_type: u32,
    pub weight: u128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalQueued {
    pub proposal_id: u64,
    pub queued_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalExecuted {
    pub proposal_id: u64,
    pub executed_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalCanceled {
    pub proposal_id: u64,
    pub canceled_at: u64,
}

pub fn emit_proposal_created(env: &Env, proposal_id: u64, creator: Address, description: String) {
    let event = ProposalCreated {
        proposal_id,
        creator: creator.clone(),
        description,
    };

    env.events().publish(
        (symbol_short!("gov"), symbol_short!("created"), creator),
        event,
    );
}

pub fn emit_vote_cast(env: &Env, proposal_id: u64, voter: Address, vote_type: u32, weight: u128) {
    let event = VoteCast {
        proposal_id,
        voter: voter.clone(),
        vote_type,
        weight,
    };

    env.events()
        .publish((symbol_short!("gov"), symbol_short!("voted"), voter), event);
}

pub fn emit_proposal_queued(env: &Env, proposal_id: u64, queued_at: u64) {
    let event = ProposalQueued {
        proposal_id,
        queued_at,
    };
    env.events()
        .publish((symbol_short!("gov"), symbol_short!("queued")), event);
}

pub fn emit_proposal_executed(env: &Env, proposal_id: u64, executed_at: u64) {
    let event = ProposalExecuted {
        proposal_id,
        executed_at,
    };
    env.events()
        .publish((symbol_short!("gov"), symbol_short!("executed")), event);
}

pub fn emit_proposal_canceled(env: &Env, proposal_id: u64, canceled_at: u64) {
    let event = ProposalCanceled {
        proposal_id,
        canceled_at,
    };
    env.events()
        .publish((symbol_short!("gov"), symbol_short!("canceled")), event);
}
