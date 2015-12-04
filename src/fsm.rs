use std::collections::{LinkedList};
use network::{IdentityRequest, IdentityResponse, PeerRequest,
              SignatureRequest, SignatureResponse, BlocksRequest,
              BlockManifest};
use address::InstAddress;
use hashchain::Action;
use signature::RecovSignature;

pub struct FSM {
    states: LinkedList<FSMState>,
}

#[derive(Debug, Clone)]
pub enum FSMState {
    RespondToIdentReq(IdentityRequest),
    ProcessIdentResp(IdentityResponse),
    RequestPeer(InstAddress),
    HandlePeerReq(PeerRequest),
    QueueNewBlock(Vec<Action>),
    HandleSigReq(SignatureRequest),
    HandleSigResp(SignatureResponse),
    AddSignatureToProcessingBlock(InstAddress, RecovSignature),
    HandleBlocksReq(BlocksRequest),
    HandleBlockManifest(BlockManifest),
    SyncNodeTableToDisk,
    SyncHashchainToDisk,
    SyncReplicaToDisk(InstAddress),
    IdleForMilliseconds(u32),
}

impl FSM {
    pub fn new() -> FSM {
        FSM {
            states: LinkedList::new()
        }
    }

    pub fn push_state(&mut self, state: FSMState) {
        self.states.push_back(state);
    }

    pub fn pop_state(&mut self) -> Option<FSMState> {
        self.states.pop_front()
    }
}
