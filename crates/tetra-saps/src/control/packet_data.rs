#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketBearerControl {
    Open {
        bearer_id: u64,
        generation: u64,
        timeslot_bitmap: u8,
    },
    Resize {
        bearer_id: u64,
        generation: u64,
        timeslot_bitmap: u8,
    },
    Drain {
        bearer_id: u64,
        generation: u64,
    },
    Attach {
        bearer_id: u64,
        generation: u64,
        issi: u32,
        event_label: u16,
    },
    Detach {
        bearer_id: u64,
        generation: u64,
        event_label: u16,
    },
    Close {
        bearer_id: u64,
        generation: u64,
        forced: bool,
    },
}
