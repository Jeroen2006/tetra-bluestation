use tetra_core::{AieRequest, BitBuffer, SsiType, TdmaTime, TetraAddress};

const DEFRAG_BUF_INITIAL_LEN: usize = 512;

#[derive(Debug, PartialEq)]
pub enum DefragBufferState {
    Inactive,
    Active,
    Complete,
}

pub struct DefragBuffer {
    pub state: DefragBufferState,
    pub addr: TetraAddress,
    pub t_first: TdmaTime,
    pub t_last: TdmaTime,
    pub num_frags: usize,
    /// Key-free ciphering policy inherited by all fragments of this TM-SDU.
    /// The exact TDMA time is deliberately resolved again per fragment.
    pub aie_request: Option<AieRequest>,
    pub buffer: BitBuffer,
}

impl DefragBuffer {
    pub fn new() -> Self {
        Self {
            state: DefragBufferState::Inactive,
            addr: TetraAddress {
                ssi: 0,
                ssi_type: SsiType::Issi,
            },
            t_first: TdmaTime::default(),
            t_last: TdmaTime::default(),
            num_frags: 0,
            aie_request: None,
            buffer: BitBuffer::new_autoexpand(DEFRAG_BUF_INITIAL_LEN),
        }
    }

    pub fn reset(&mut self) {
        self.state = DefragBufferState::Inactive;
        self.addr = TetraAddress {
            ssi: 0,
            ssi_type: SsiType::Issi,
        };
        self.t_first = TdmaTime::default();
        self.t_last = TdmaTime::default();
        self.num_frags = 0;
        self.aie_request = None;
        self.buffer = BitBuffer::new_autoexpand(DEFRAG_BUF_INITIAL_LEN);
    }
}
