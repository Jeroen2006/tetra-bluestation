//! Native SwMI TMD user-plane bridge.
//!
//! It does not own a socket: [`super::SwmiWorker`] remains the only network
//! thread.  This entity converts the existing UMAC TMD boundary to typed SwMI
//! voice-frame messages and therefore keeps radio scheduling independent from
//! WSS latency.

use std::collections::HashMap;

use tetra_core::{Sap, TdmaTime, tetra_entities::TetraEntity};
use tetra_saps::{SapMsg, SapMsgInner, control::call_control::CallControl, tmd::TmdCircuitDataReq};
use tetra_swmi_protocol::SwmiMessage;

use crate::{MessageQueue, TetraEntityTrait};

use super::SwmiMediaEndpoint;

#[derive(Clone, Copy)]
struct ActiveVoiceCall {
    call_id: u16,
    source_itsi: u32,
    gssi: u32,
}

/// Bridge voice on active centrally-authorized calls.  A mapping is created
/// solely by CMCE floor decisions, never from raw TMD traffic.
pub struct SwmiMediaEntity {
    endpoint: SwmiMediaEndpoint,
    calls_by_ts: HashMap<u8, ActiveVoiceCall>,
}

impl SwmiMediaEntity {
    pub fn new(endpoint: SwmiMediaEndpoint) -> Self {
        Self {
            endpoint,
            calls_by_ts: HashMap::new(),
        }
    }

    fn handle_ul_voice(&mut self, ts: u8, data: Vec<u8>) {
        let Some(call) = self.calls_by_ts.get(&ts).copied() else { return };
        if !self.endpoint.is_online() {
            return;
        }
        let length_bits = if data.len() == 274 {
            274
        } else {
            (data.len() * 8).min(u16::MAX as usize) as u16
        };
        if self
            .endpoint
            .submit(SwmiMessage::VoiceFrame {
                call_id: call.call_id as u64,
                source_itsi: call.source_itsi as u64,
                gssi: call.gssi,
                length_bits,
                data,
            })
            .is_err()
        {
            tracing::debug!(
                ts,
                call_id = call.call_id,
                "SwMI voice frame dropped because worker queue is unavailable"
            );
        }
    }

    fn handle_dl_voice(&mut self, queue: &mut MessageQueue, call_id: u64, gssi: u32, data: Vec<u8>) {
        let Some((&ts, _)) = self
            .calls_by_ts
            .iter()
            .find(|(_, call)| call.call_id as u64 == call_id && call.gssi == gssi)
        else {
            tracing::trace!(call_id, gssi, "SwMI voice frame received before local call allocation");
            return;
        };
        let Some(data) = dl_payload(data) else {
            tracing::warn!(call_id, gssi, "SwMI voice frame has unsupported TMD length");
            return;
        };
        queue.push_back(SapMsg {
            sap: Sap::TmdSap,
            src: TetraEntity::Swmi,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmdCircuitDataReq(TmdCircuitDataReq { ts, data }),
        });
    }
}

/// UMAC supplies either 274 one-bit values or its already packed 35-octet
/// speech payload.  Preserve packed data and pack bit vectors MSB first.
fn dl_payload(data: Vec<u8>) -> Option<Vec<u8>> {
    match data.len() {
        35 => Some(data),
        36 => Some(data[1..].to_vec()), // tolerate an STE-framed peer
        274 => {
            let mut packed = Vec::with_capacity(35);
            for chunk in data.chunks(8) {
                let mut byte = 0u8;
                for (bit, value) in chunk.iter().enumerate() {
                    byte |= (value & 1) << (7 - bit);
                }
                packed.push(byte);
            }
            Some(packed)
        }
        _ => None,
    }
}

impl TetraEntityTrait for SwmiMediaEntity {
    fn entity(&self) -> TetraEntity {
        TetraEntity::Swmi
    }

    fn set_config(&mut self, _config: tetra_config::bluestation::SharedConfig) {}

    fn tick_start(&mut self, queue: &mut MessageQueue, _ts: TdmaTime) {
        while let Some(message) = self.endpoint.try_recv() {
            if let SwmiMessage::VoiceFrame { call_id, gssi, data, .. } = message {
                self.handle_dl_voice(queue, call_id, gssi, data);
            }
        }
    }

    fn rx_prim(&mut self, _queue: &mut MessageQueue, message: SapMsg) {
        match message.msg {
            SapMsgInner::TmdCircuitDataInd(prim) => self.handle_ul_voice(prim.ts, prim.data),
            SapMsgInner::CmceCallControl(CallControl::FloorGranted {
                call_id,
                source_issi,
                dest_gssi,
                ts,
            }) => {
                self.calls_by_ts.insert(
                    ts,
                    ActiveVoiceCall {
                        call_id,
                        source_itsi: source_issi,
                        gssi: dest_gssi,
                    },
                );
            }
            SapMsgInner::CmceCallControl(CallControl::FloorReleased { call_id, ts })
            | SapMsgInner::CmceCallControl(CallControl::CallEnded { call_id, ts }) => {
                if self.calls_by_ts.get(&ts).is_some_and(|call| call.call_id == call_id) {
                    self.calls_by_ts.remove(&ts);
                }
            }
            _ => {}
        }
    }
}
