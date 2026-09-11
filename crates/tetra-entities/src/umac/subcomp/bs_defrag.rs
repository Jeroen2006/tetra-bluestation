use std::collections::HashMap;

use tetra_core::{AieRequest, BitBuffer, TdmaTime, TetraAddress};

use crate::umac::subcomp::defrag::{DefragBuffer, DefragBufferState};

const DEFRAG_BUF_MAX_LEN: usize = 4096;
const DEFRAG_TS_BEFORE_TIMEOUT: i32 = 10 * 4; // TODO check documentation. 10 frames.

/// Defragmenter suitable for BS use
/// Maintains a set of DefragBuffers per originating timeslot, indexed by SSI.
///
/// A fragmented PDU may continue in any of the equivalent timeslots that make
/// up a multislot PDCH (TTR 001-05 section 6.10). Therefore lookups are by SSI
/// across all timeslots; the array only records where the first fragment was
/// received. An MS cannot interleave two fragmented MAC SDUs.
pub struct BsDefrag {
    pub buffers: [HashMap<u32, DefragBuffer>; 4],
}

impl BsDefrag {
    pub fn new() -> Self {
        Self {
            buffers: [HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new()],
        }
    }

    pub fn reset(&mut self) {
        for map in &mut self.buffers {
            map.clear();
        }
    }

    pub fn age_buffers(&mut self, t: TdmaTime) {
        for map in &mut self.buffers {
            for buffer in map.values_mut() {
                if buffer.state != DefragBufferState::Inactive && t.diff(buffer.t_last) > DEFRAG_TS_BEFORE_TIMEOUT {
                    tracing::info!("defrag_buffer for {} timed out", buffer.t_last.t);
                    buffer.reset();
                }
            }
        }
    }

    fn active_buffer_slot(&self, ssi: u32, t: TdmaTime) -> Option<usize> {
        let current_ts = (t.t - 1) as usize;
        if self.buffers[current_ts]
            .get(&ssi)
            .is_some_and(|buffer| buffer.state == DefragBufferState::Active)
        {
            return Some(current_ts);
        }

        self.buffers
            .iter()
            .enumerate()
            .filter_map(|(ts, buffers)| {
                let buffer = buffers.get(&ssi)?;
                (buffer.state == DefragBufferState::Active).then_some((ts, t.diff(buffer.t_last)))
            })
            // Prefer the most recent fragment. The fallback for a negative
            // difference only matters around a TDMA wrap or reordered input.
            .min_by_key(|(_, age)| if *age >= 0 { *age } else { i32::MAX })
            .map(|(ts, _)| ts)
    }

    fn append_fragment(&mut self, bitbuffer: &mut BitBuffer, ssi: u32, t: TdmaTime, origin_ts: usize) -> bool {
        let buf = match self.buffers[origin_ts].get_mut(&ssi) {
            Some(buffer) => buffer,
            None => return false,
        };

        if buf.state != DefragBufferState::Active {
            return false;
        }

        if buf.buffer.get_len() + bitbuffer.get_len_remaining() > DEFRAG_BUF_MAX_LEN {
            tracing::warn!("defrag_buffer originating on ts {} ssi {} would exceed max len", origin_ts + 1, ssi);
            buf.reset();
            return false;
        }

        buf.t_last = t;
        buf.num_frags += 1;
        buf.buffer.copy_bits(bitbuffer, bitbuffer.get_len_remaining());

        tracing::debug!(
            "defrag_buffer originating on ts {} continued on ts {} ssi: {}, t: {}-{}, frags: {}: {}",
            origin_ts + 1,
            t.t,
            ssi,
            buf.t_first,
            buf.t_last,
            buf.num_frags,
            buf.buffer.dump_bin()
        );
        true
    }

    /// Inserts a first fragment into a fragbuffer.
    pub fn insert_first(&mut self, bitbuffer: &mut BitBuffer, t: TdmaTime, addr: TetraAddress, aie_request: Option<AieRequest>) {
        let ts = (t.t - 1) as usize;
        let ssi = addr.ssi;
        // A new first fragment supersedes any incomplete PDU from this MS,
        // including one that began on another slot of a multislot PDCH.
        let mut reusable = None;
        for (origin_ts, buffers) in self.buffers.iter_mut().enumerate() {
            if let Some(mut old) = buffers.remove(&ssi) {
                if old.state == DefragBufferState::Active {
                    tracing::warn!(
                        "new first fragment replaced active defrag_buffer originating on ts {} for ssi {}",
                        origin_ts + 1,
                        ssi
                    );
                }
                old.reset();
                reusable.get_or_insert(old);
            }
        }
        let mut buf = reusable.unwrap_or_else(DefragBuffer::new);

        // Initialize target buffer
        buf.state = DefragBufferState::Active;
        buf.addr = addr;
        buf.t_first = t;
        buf.t_last = t;
        buf.num_frags = 1;
        buf.aie_request = aie_request;

        // Copy the bitbuffer data from pos to end into our fragbuffer
        buf.buffer.copy_bits(bitbuffer, bitbuffer.get_len_remaining());

        tracing::debug!(
            "defrag_buffer for ts {} ssi: {}, t: {}-{}, frags: {}: {}",
            t.t,
            buf.addr.ssi,
            buf.t_first,
            buf.t_last,
            buf.num_frags,
            buf.buffer.dump_bin()
        );

        self.buffers[ts].insert(ssi, buf);
    }

    pub fn insert_next(&mut self, bitbuffer: &mut BitBuffer, ssi: u32, t: TdmaTime) {
        let Some(origin_ts) = self.active_buffer_slot(ssi, t) else {
            tracing::warn!("active defrag_buffer for current ts {} ssi {} not found", t.t, ssi);
            return;
        };
        self.append_fragment(bitbuffer, ssi, t, origin_ts);
    }

    /// Inserts the last fragment into a DefragBuffer, and returns the completed object
    pub fn insert_last(&mut self, bitbuffer: &mut BitBuffer, ssi: u32, t: TdmaTime) -> Option<DefragBuffer> {
        let Some(origin_ts) = self.active_buffer_slot(ssi, t) else {
            tracing::warn!("active defrag_buffer for current ts {} ssi {} not found", t.t, ssi);
            return None;
        };
        if !self.append_fragment(bitbuffer, ssi, t, origin_ts) {
            return None;
        }

        let mut buf = match self.buffers[origin_ts].remove(&ssi) {
            Some(b) => b,
            None => {
                tracing::warn!("defrag_buffer originating on ts {} ssi {} not found", origin_ts + 1, ssi);
                return None;
            }
        };

        // Update state to complete and return
        buf.state = DefragBufferState::Complete;
        buf.buffer.set_raw_pos(0);
        Some(buf)
    }

    /// Retrieves the key-free AIE policy associated with a DefragBuffer.
    pub fn get_aie_request(&self, ssi: u32, t: TdmaTime) -> Option<AieRequest> {
        let origin_ts = self.active_buffer_slot(ssi, t)?;
        self.buffers[origin_ts].get(&ssi)?.aie_request
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tetra_core::{address::SsiType, bitbuffer::BitBuffer, debug};

    #[test]
    fn test_3_chunks() {
        debug::setup_logging_verbose();

        let ssi = 1234;
        let mut buf1 = BitBuffer::from_bitstr("000");
        let t1 = TdmaTime::default().add_timeslots(2); // UL time 0
        let mut buf2 = BitBuffer::from_bitstr("111");
        let t2 = t1.add_timeslots(4);
        let mut buf3 = BitBuffer::from_bitstr("0011");
        let t3 = t2.add_timeslots(4);

        let mut defragger = BsDefrag::new();
        let addr = TetraAddress {
            ssi,
            ssi_type: SsiType::Issi,
        };
        defragger.insert_first(&mut buf1, t1, addr, None);
        defragger.insert_next(&mut buf2, ssi, t2);
        let out = defragger.insert_last(&mut buf3, ssi, t3).unwrap();
        assert_eq!(out.buffer.to_bitstr(), "0001110011");
        assert_eq!(out.buffer.get_pos(), 0);
    }

    #[test]
    fn fragmented_pdu_can_span_multislot_pdch_timeslots() {
        let ssi = 77480;
        let t1 = TdmaTime::default().add_timeslots(2);
        let t2 = t1.add_timeslots(1);
        let t3 = t2.add_timeslots(1);
        assert_ne!(t1.t, t2.t);
        assert_ne!(t2.t, t3.t);

        let mut first = BitBuffer::from_bitstr("000");
        let mut next = BitBuffer::from_bitstr("111");
        let mut last = BitBuffer::from_bitstr("0011");
        let mut defragger = BsDefrag::new();
        defragger.insert_first(&mut first, t1, TetraAddress::issi(ssi), None);
        defragger.insert_next(&mut next, ssi, t2);
        let out = defragger.insert_last(&mut last, ssi, t3).unwrap();

        assert_eq!(out.buffer.to_bitstr(), "0001110011");
        assert_eq!(out.t_first, t1);
        assert_eq!(out.t_last, t3);
        assert_eq!(out.num_frags, 3);
        assert!(defragger.buffers.iter().all(|buffers| !buffers.contains_key(&ssi)));
    }
}
