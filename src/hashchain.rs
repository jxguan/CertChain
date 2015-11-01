use hash::DoubleSha256Hash;
use serde::ser;

pub type DocumentId = DoubleSha256Hash;

#[derive(Deserialize, Clone, Debug)]
pub enum DocumentType {
    Diploma,
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

pub struct Block {
    actions: Vec<Action>,
}

pub struct Hashchain {
    blocks: Vec<Block>,
}

impl Hashchain {
    pub fn new() -> Hashchain {
        Hashchain {
            blocks: Vec::new(),
        }
    }

    pub fn create_block(&mut self, actions: Vec<Action>) {
        let block = Block::new(actions);
        self.blocks.push(block);
    }

    pub fn get_certifications(&self) -> Vec<Action> {
        let mut certifications = Vec::new();
        for block in self.blocks.iter() {
            for action in block.actions.iter() {
                match *action {
                    Action::Certify(_, _, _) => {
                        certifications.push(action.clone())
                    }
                }
            }
        }
        certifications
    }
}

impl Block {
    fn new(actions: Vec<Action>) -> Block {
        Block {
            actions: actions
        }
    }
}
