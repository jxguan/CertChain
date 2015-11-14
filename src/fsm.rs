use std::collections::{LinkedList};
use network::{IdentityRequest, IdentityResponse, PeerRequest};
use address::InstAddress;

pub struct FSM {
    states: LinkedList<FSMState>,
}

pub enum FSMState {
    RespondToIdentReq(IdentityRequest),
    ProcessIdentResp(IdentityResponse),
    RequestPeer(InstAddress),
    HandlePeerReq(PeerRequest),
    ApprovePeerRequest(InstAddress),
    SyncNodeTableToDisk,
    SyncHashchainToDisk
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
