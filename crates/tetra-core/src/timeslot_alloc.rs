#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeslotOwner {
    Brew,
    Cmce,
    PacketData,
    CommonControl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeslotAllocErr {
    InvalidTimeslot(u8),
    InUse {
        ts: u8,
        owner: TimeslotOwner,
    },
    NotAllocated {
        ts: u8,
    },
    OwnerMismatch {
        ts: u8,
        owner: TimeslotOwner,
        actual: TimeslotOwner,
    },
}

#[derive(Debug, Clone)]
pub struct TimeslotAllocator {
    // Index 0 = TS2, 1 = TS3, 2 = TS4
    owners: [Option<TimeslotOwner>; 3],
    packet_preemption_requested: bool,
    common_control_pending: [bool; 3],
}

impl Default for TimeslotAllocator {
    fn default() -> Self {
        Self {
            owners: [None, None, None],
            packet_preemption_requested: false,
            common_control_pending: [false; 3],
        }
    }
}

impl TimeslotAllocator {
    fn idx(ts: u8) -> Result<usize, TimeslotAllocErr> {
        if (2..=4).contains(&ts) {
            Ok((ts - 2) as usize)
        } else {
            Err(TimeslotAllocErr::InvalidTimeslot(ts))
        }
    }

    pub fn set_common_control_target(&mut self, count: u8) {
        self.common_control_pending = std::array::from_fn(|index| index < usize::from(count.min(2)));
    }

    pub fn allocate_any(&mut self, owner: TimeslotOwner) -> Option<u8> {
        for (i, slot) in self.owners.iter_mut().enumerate() {
            if slot.is_none() && !self.common_control_pending[i] {
                *slot = Some(owner);
                return Some(i as u8 + 2);
            }
        }
        if owner == TimeslotOwner::Cmce && self.owners.contains(&Some(TimeslotOwner::PacketData)) {
            self.packet_preemption_requested = true;
        }
        None
    }

    pub fn take_packet_preemption_request(&mut self) -> bool {
        std::mem::take(&mut self.packet_preemption_requested)
    }

    /// Ask the packet-data owner to drain a bearer because queued CMCE voice
    /// needs capacity. The owner performs the over-air deassignment before
    /// releasing any slot.
    pub fn request_packet_preemption(&mut self) -> bool {
        if self.owners.contains(&Some(TimeslotOwner::PacketData)) {
            self.packet_preemption_requested = true;
            true
        } else {
            false
        }
    }

    pub fn packet_slots(&self) -> Vec<u8> {
        self.owners
            .iter()
            .enumerate()
            .filter_map(|(index, owner)| (*owner == Some(TimeslotOwner::PacketData)).then_some(index as u8 + 2))
            .collect()
    }

    pub fn reserve(&mut self, owner: TimeslotOwner, ts: u8) -> Result<(), TimeslotAllocErr> {
        let idx = Self::idx(ts)?;
        match self.owners[idx] {
            None if !self.common_control_pending[idx] || owner == TimeslotOwner::CommonControl => {
                self.owners[idx] = Some(owner);
                Ok(())
            }
            Some(existing) => Err(TimeslotAllocErr::InUse { ts, owner: existing }),
            None => Err(TimeslotAllocErr::InUse { ts, owner: TimeslotOwner::CommonControl }),
        }
    }

    pub fn release(&mut self, owner: TimeslotOwner, ts: u8) -> Result<(), TimeslotAllocErr> {
        let idx = Self::idx(ts)?;
        match self.owners[idx] {
            None => Err(TimeslotAllocErr::NotAllocated { ts }),
            Some(existing) if existing != owner => Err(TimeslotAllocErr::OwnerMismatch {
                ts,
                owner,
                actual: existing,
            }),
            Some(_) => {
                self.owners[idx] = None;
                Ok(())
            }
        }
    }

    pub fn owner(&self, ts: u8) -> Option<TimeslotOwner> {
        Self::idx(ts).ok().and_then(|idx| self.owners[idx])
    }

    pub fn is_free(&self, ts: u8) -> bool {
        Self::idx(ts).is_ok_and(|idx| self.owners[idx].is_none() && !self.common_control_pending[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_scch_waits_for_occupant_and_fences_new_allocations() {
        let mut allocator = TimeslotAllocator::default();
        allocator.reserve(TimeslotOwner::Cmce, 2).unwrap();
        allocator.set_common_control_target(2);
        assert_eq!(allocator.owner(2), Some(TimeslotOwner::Cmce));
        assert!(allocator.reserve(TimeslotOwner::CommonControl, 2).is_err());
        assert_eq!(allocator.allocate_any(TimeslotOwner::PacketData), Some(4));
        assert!(allocator.reserve(TimeslotOwner::PacketData, 3).is_err());
        allocator.release(TimeslotOwner::Cmce, 2).unwrap();
        assert!(!allocator.is_free(2));
        allocator.reserve(TimeslotOwner::CommonControl, 2).unwrap();
        allocator.set_common_control_target(0);
        assert!(!allocator.is_free(2));
        allocator.release(TimeslotOwner::CommonControl, 2).unwrap();
        assert!(allocator.is_free(2)); assert!(allocator.is_free(3));
    }

    #[test]
    fn voice_requests_preemption_only_when_packet_data_blocks_capacity() {
        let mut allocator = TimeslotAllocator::default();
        allocator.reserve(TimeslotOwner::PacketData, 2).unwrap();
        allocator.reserve(TimeslotOwner::Brew, 3).unwrap();

        assert_eq!(allocator.allocate_any(TimeslotOwner::Cmce), Some(4));
        assert!(!allocator.take_packet_preemption_request());

        assert_eq!(allocator.allocate_any(TimeslotOwner::Cmce), None);
        assert!(allocator.take_packet_preemption_request());
        assert!(!allocator.take_packet_preemption_request());
        assert_eq!(allocator.owner(2), Some(TimeslotOwner::PacketData));
    }

    #[test]
    fn non_voice_capacity_requests_never_preempt_packet_data() {
        let mut allocator = TimeslotAllocator::default();
        for timeslot in 2..=4 {
            allocator.reserve(TimeslotOwner::PacketData, timeslot).unwrap();
        }

        assert_eq!(allocator.allocate_any(TimeslotOwner::Brew), None);
        assert!(!allocator.take_packet_preemption_request());
    }

    #[test]
    fn queued_voice_can_request_packet_preemption_before_allocation() {
        let mut allocator = TimeslotAllocator::default();
        allocator.reserve(TimeslotOwner::PacketData, 2).unwrap();

        assert!(allocator.request_packet_preemption());
        assert!(allocator.take_packet_preemption_request());
        assert_eq!(allocator.owner(2), Some(TimeslotOwner::PacketData));
    }
}
