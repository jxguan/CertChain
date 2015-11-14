use hash::DoubleSha256Hash;
use address::InstAddress;
use serde::{ser, de};
use std::collections::vec_deque::VecDeque;
use time;
use std::sync::{Arc, RwLock};
use fsm::FSM;

pub type DocumentId = DoubleSha256Hash;

#[derive(Clone, Debug)]
pub enum DocumentType {
    Diploma,
    Transcript
}

impl ser::Serialize for DocumentType {
    fn serialize<S: ser::Serializer>(&self, s: &mut S)
        -> Result<(), S::Error> {
        s.visit_str(&format!("{:?}", self)[..])
    }
}

impl de::Deserialize for DocumentType {
    fn deserialize<D: de::Deserializer>(d: &mut D)
            -> Result<DocumentType, D::Error> {
        d.visit_str(DocumentTypeVisitor)
    }
}

struct DocumentTypeVisitor;

impl de::Visitor for DocumentTypeVisitor {
    type Value = DocumentType;

    fn visit_str<E: de::Error>(&mut self, value: &str)
            -> Result<DocumentType, E> {
        match value {
            "Diploma" => Ok(DocumentType::Diploma),
            "Transcript" => Ok(DocumentType::Transcript),
            _ => Err(de::Error::syntax(&format!(
                        "The visited string {} could not be deserialized \
                        into a DocumentType.", value)[..]))
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Action {
    Certify(DocumentId, DocumentType, String),
    AddPeer(InstAddress, String, u16)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DocumentSummary {
    doc_id: DocumentId,
    doc_type: DocumentType,
    student_id: String,
    cert_timestamp: Option<i64>,
    rev_timestamp: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct Block {
    timestamp: i64,
    actions: Vec<Action>,
}

#[derive(Serialize, Deserialize)]
pub struct Hashchain {
    finalized_blocks: Vec<Block>,
    queued_blocks: VecDeque<Block>,
}

impl DocumentSummary {
    fn new(block: &Block, action: Action) -> DocumentSummary {
        match action {
            Action::Certify(doc_id, doc_type, student_id) => {
                DocumentSummary {
                    doc_id: doc_id,
                    doc_type: doc_type,
                    student_id: student_id,
                    cert_timestamp: Some(block.timestamp),
                    rev_timestamp: None
                }
            },
            Action::AddPeer(_, _, _) => {
                panic!("Cannot create DocumentSummary from AddPeer;
                        action; calling code needs to prevent this.")
            }
        }
    }
}

impl Hashchain {
    pub fn new() -> Hashchain {
        Hashchain {
            finalized_blocks: Vec::new(),
            queued_blocks: VecDeque::new(),
        }
    }

    pub fn queue_new_block(&mut self, actions: Vec<Action>) {
        let block = Block::new(actions);
        self.queued_blocks.push_back(block);
    }

    pub fn process_queue(&mut self) -> bool {
        let mut blocks_processed = false;
        match self.queued_blocks.pop_front() {
            Some(block) => {
                if block.is_valid() {
                    info!("HCHAIN: Finalizing queued block.");
                    self.finalized_blocks.push(block);
                    blocks_processed = true;
                } else {
                    info!("HCHAIN: Re-queueing block.");
                    self.queued_blocks.push_front(block);
                }
            },
            None => ()
        };
        blocks_processed
    }

    pub fn get_certifications(&self,
                optional_student_id: Option<&str>) -> Vec<DocumentSummary> {
        let mut summaries = Vec::new();
        for block in self.finalized_blocks.iter() {
            for action in block.actions.iter() {
                match *action {
                    Action::Certify(_, _, ref sid) => {
                        match optional_student_id {
                            Some(id) => {
                                if id == sid {
                                    summaries.push(
                                        DocumentSummary::new(&block, action.clone()))
                                }
                            }, None => summaries.push(
                                            DocumentSummary::new(&block, action.clone()))
                        };
                    },
                    Action::AddPeer(_, _, _) => {
                        continue;
                    }
                }
            }
        }
        summaries
    }
}

impl Block {
    fn new(actions: Vec<Action>) -> Block {
        Block {
            timestamp: time::get_time().sec,
            actions: actions
        }
    }

    /// TODO: Fill this in.
    fn is_valid(&self) -> bool {
        true
    }
}
