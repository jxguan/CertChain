use hash::DoubleSha256Hash;
use serde::ser;
use std::collections::vec_deque::VecDeque;
use time;

pub type DocumentId = DoubleSha256Hash;

#[derive(Deserialize, Clone, Debug)]
pub enum DocumentType {
    Diploma,
    Transcript
}

impl ser::Serialize for DocumentType {
    fn serialize<S: ser::Serializer>(&self, s: &mut S)
        -> Result<(), S::Error> {
        s.visit_str(&format!("{:?}", self)[..]);
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Action {
    Certify(DocumentId, DocumentType, String),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DocumentSummary {
    doc_id: DocumentId,
    doc_type: DocumentType,
    student_id: String,
    cert_timestamp: Option<i64>,
    rev_timestamp: Option<i64>,
}

pub struct Block {
    timestamp: i64,
    actions: Vec<Action>,
}

pub struct Hashchain {
    finalized_blocks: Vec<Block>,
    queued_blocks: VecDeque<Block>
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

    pub fn process_queue(&mut self) {
        match self.queued_blocks.pop_front() {
            Some(block) => {
                if block.is_valid() {
                    info!("HCHAIN: Finalizing queued block.");
                    self.finalized_blocks.push(block);
                } else {
                    info!("HCHAIN: Re-queueing block.");
                    self.queued_blocks.push_front(block);
                }
            },
            None => ()
        }
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
