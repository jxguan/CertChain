use hash::DoubleSha256Hash;

pub type DocumentId = DoubleSha256Hash;

pub enum Action {
    Certify(DocumentId),
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

    pub fn get_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        for block in self.blocks.iter() {
            for action in block.actions.iter() {
                match *action {
                    Action::Certify(id) => ids.push(format!("{:?}", id))
                }
            }
        }
        ids
    }
}

impl Block {
    fn new(actions: Vec<Action>) -> Block {
        Block {
            actions: actions
        }
    }
}
