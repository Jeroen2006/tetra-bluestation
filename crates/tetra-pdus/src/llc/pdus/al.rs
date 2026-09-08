//! Original acknowledged advanced-link PDUs used by the TIP packet profile.

use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

use crate::llc::enums::llc_pdu_type::LlcPduType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlSetup {
    pub acknowledged: bool,
    pub link_number: u8,
    pub maximum_sdu: u8,
    pub connection_width: bool,
    pub asymmetric: bool,
    pub uplink_slots: Option<u8>,
    pub downlink_slots: Option<u8>,
    pub throughput: u8,
    pub window_size: u8,
    pub sdu_retransmissions: u8,
    pub segment_retransmissions: u8,
    pub report: u8,
}

impl AlSetup {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        expect_type(buffer, LlcPduType::AlSetup)?;
        let acknowledged = buffer.read_field(1, "advanced_link_service")? != 0;
        let link_number = buffer.read_field(2, "advanced_link_number")? as u8;
        let maximum_sdu = buffer.read_field(3, "maximum_tl_sdu")? as u8;
        let connection_width = buffer.read_field(1, "connection_width")? != 0;
        let asymmetric = buffer.read_field(1, "advanced_link_symmetry")? != 0;
        let uplink_slots = connection_width
            .then(|| buffer.read_field(2, "uplink_timeslots").map(|value| value as u8 + 1))
            .transpose()?;
        let downlink_slots = (connection_width && asymmetric)
            .then(|| buffer.read_field(2, "downlink_timeslots").map(|value| value as u8 + 1))
            .transpose()?;
        let throughput = buffer.read_field(3, "data_transfer_throughput")? as u8;
        let window_size = buffer.read_field(2, "tl_sdu_window")? as u8;
        let sdu_retransmissions = buffer.read_field(3, "tl_sdu_retransmissions")? as u8;
        let segment_retransmissions = buffer.read_field(4, "segment_retransmissions")? as u8;
        let report = buffer.read_field(3, "setup_report")? as u8;
        if !acknowledged || link_number > 3 || maximum_sdu > 7 || window_size == 0 {
            return Err(PduParseErr::NotImplemented {
                field: Some("non-TIP original advanced link"),
            });
        }
        Ok(Self {
            acknowledged,
            link_number,
            maximum_sdu,
            connection_width,
            asymmetric,
            uplink_slots,
            downlink_slots,
            throughput,
            window_size,
            sdu_retransmissions,
            segment_retransmissions,
            report,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if !self.acknowledged
            || self.link_number > 3
            || self.maximum_sdu > 7
            || self.throughput > 7
            || !(1..=3).contains(&self.window_size)
            || self.sdu_retransmissions > 7
            || self.segment_retransmissions > 15
            || self.report > 7
            || self.connection_width != self.uplink_slots.is_some()
            || self.asymmetric != self.downlink_slots.is_some()
        {
            return Err(PduParseErr::Inconsistency {
                field: "al_setup",
                reason: "invalid original advanced-link profile",
            });
        }
        buffer.write_bits(LlcPduType::AlSetup.into_raw(), 4);
        buffer.write_bit(1);
        buffer.write_bits(self.link_number.into(), 2);
        buffer.write_bits(self.maximum_sdu.into(), 3);
        buffer.write_bit(self.connection_width as u8);
        buffer.write_bit(self.asymmetric as u8);
        if let Some(slots) = self.uplink_slots {
            write_slots(buffer, slots, "uplink_timeslots")?;
        }
        if let Some(slots) = self.downlink_slots {
            write_slots(buffer, slots, "downlink_timeslots")?;
        }
        buffer.write_bits(self.throughput.into(), 3);
        buffer.write_bits(self.window_size.into(), 2);
        buffer.write_bits(self.sdu_retransmissions.into(), 3);
        buffer.write_bits(self.segment_retransmissions.into(), 4);
        buffer.write_bits(self.report.into(), 3);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlDataHeader {
    pub final_segment: bool,
    pub acknowledgement_requested: bool,
    pub ns: u8,
    pub segment: u8,
}

impl AlDataHeader {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        expect_type(buffer, LlcPduType::AlDataAlFinal)?;
        Ok(Self {
            final_segment: buffer.read_field(1, "final")? != 0,
            acknowledgement_requested: buffer.read_field(1, "acknowledgement_request")? != 0,
            ns: buffer.read_field(3, "ns")? as u8,
            segment: buffer.read_field(8, "segment_sequence")? as u8,
        })
    }

    pub fn to_bitbuf(self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if self.ns > 7 {
            return Err(PduParseErr::InvalidValue {
                field: "ns",
                value: self.ns.into(),
            });
        }
        buffer.write_bits(LlcPduType::AlDataAlFinal.into_raw(), 4);
        buffer.write_bit(self.final_segment as u8);
        buffer.write_bit(self.acknowledgement_requested as u8);
        buffer.write_bits(self.ns.into(), 3);
        buffer.write_bits(self.segment.into(), 8);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlAck {
    pub receiver_ready: bool,
    pub nr: u8,
    pub acknowledgement_length: u8,
    pub first_missing_segment: Option<u8>,
    pub acknowledgement_bitmap: Vec<bool>,
}

impl AlAck {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        expect_type(buffer, LlcPduType::AlAckAlRnr)?;
        let receiver_ready = buffer.read_field(1, "flow_control")? != 0;
        let nr = buffer.read_field(3, "nr")? as u8;
        let acknowledgement_length = buffer.read_field(6, "acknowledgement_length")? as u8;
        let first_missing_segment = if (1..=62).contains(&acknowledgement_length) {
            Some(buffer.read_field(8, "first_missing_segment")? as u8)
        } else {
            None
        };
        let mut acknowledgement_bitmap = Vec::new();
        if acknowledgement_length > 1 && acknowledgement_length < 63 {
            let bitmap = acknowledgement_length as usize - 1;
            if buffer.get_len_remaining() < bitmap {
                return Err(PduParseErr::BufferEnded {
                    field: Some("acknowledgement_bitmap"),
                });
            }
            for _ in 0..bitmap {
                acknowledgement_bitmap.push(
                    buffer.read_bit().ok_or(PduParseErr::BufferEnded {
                        field: Some("acknowledgement_bitmap"),
                    })? != 0,
                );
            }
        }
        Ok(Self {
            receiver_ready,
            nr,
            acknowledgement_length,
            first_missing_segment,
            acknowledgement_bitmap,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if self.nr > 7
            || self.acknowledgement_length > 63
            || ((1..=62).contains(&self.acknowledgement_length) != self.first_missing_segment.is_some())
            || self.acknowledgement_bitmap.len() != self.acknowledgement_length.saturating_sub(1) as usize
        {
            return Err(PduParseErr::Inconsistency {
                field: "al_ack",
                reason: "invalid acknowledgement block",
            });
        }
        buffer.write_bits(LlcPduType::AlAckAlRnr.into_raw(), 4);
        buffer.write_bit(self.receiver_ready as u8);
        buffer.write_bits(self.nr.into(), 3);
        buffer.write_bits(self.acknowledgement_length.into(), 6);
        if let Some(segment) = self.first_missing_segment {
            buffer.write_bits(segment.into(), 8);
            for received in &self.acknowledgement_bitmap {
                buffer.write_bit(*received as u8);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlReconnect {
    pub acknowledged: bool,
    pub link_number: u8,
    /// 0 propose, 1 reject, 2 accept.
    pub report: u8,
}

impl AlReconnect {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        expect_type(buffer, LlcPduType::AlReconnect)?;
        let value = Self {
            acknowledged: buffer.read_field(1, "advanced_link_service")? != 0,
            link_number: buffer.read_field(2, "advanced_link_number")? as u8,
            report: buffer.read_field(2, "reconnect_report")? as u8,
        };
        if !value.acknowledged || value.link_number > 3 || value.report > 2 {
            return Err(PduParseErr::NotImplemented {
                field: Some("unsupported advanced-link reconnect profile"),
            });
        }
        Ok(value)
    }

    pub fn to_bitbuf(self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if !self.acknowledged || self.link_number > 3 || self.report > 2 {
            return Err(PduParseErr::Inconsistency {
                field: "al_reconnect",
                reason: "invalid acknowledged advanced-link reconnect",
            });
        }
        buffer.write_bits(LlcPduType::AlReconnect.into_raw(), 4);
        buffer.write_bit(1);
        buffer.write_bits(self.link_number.into(), 2);
        buffer.write_bits(self.report.into(), 2);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlDisconnect {
    pub acknowledged: bool,
    pub link_number: u8,
    pub report: u8,
}

impl AlDisconnect {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        expect_type(buffer, LlcPduType::AlDisc)?;
        Ok(Self {
            acknowledged: buffer.read_field(1, "advanced_link_service")? != 0,
            link_number: buffer.read_field(2, "advanced_link_number")? as u8,
            report: buffer.read_field(3, "disconnect_report")? as u8,
        })
    }

    pub fn to_bitbuf(self, buffer: &mut BitBuffer) {
        buffer.write_bits(LlcPduType::AlDisc.into_raw(), 4);
        buffer.write_bit(self.acknowledged as u8);
        buffer.write_bits(self.link_number.into(), 2);
        buffer.write_bits(self.report.into(), 3);
    }
}

fn expect_type(buffer: &mut BitBuffer, expected: LlcPduType) -> Result<(), PduParseErr> {
    let found = buffer.read_field(4, "llc_pdu_type")?;
    if found != expected.into_raw() {
        return Err(PduParseErr::InvalidPduType {
            expected: expected.into_raw(),
            found,
        });
    }
    Ok(())
}

fn write_slots(buffer: &mut BitBuffer, slots: u8, field: &'static str) -> Result<(), PduParseErr> {
    if !(1..=4).contains(&slots) {
        return Err(PduParseErr::InvalidValue {
            field,
            value: slots.into(),
        });
    }
    buffer.write_bits((slots - 1).into(), 2);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_setup_round_trip() {
        let setup = AlSetup {
            acknowledged: true,
            link_number: 0,
            maximum_sdu: 6,
            connection_width: true,
            asymmetric: false,
            uplink_slots: Some(3),
            downlink_slots: None,
            throughput: 4,
            window_size: 2,
            sdu_retransmissions: 3,
            segment_retransmissions: 5,
            report: 0,
        };
        let mut bits = BitBuffer::new_autoexpand(32);
        setup.to_bitbuf(&mut bits).unwrap();
        bits.seek(0);
        assert_eq!(AlSetup::from_bitbuf(&mut bits).unwrap(), setup);
        assert_eq!(bits.get_len_remaining(), 0);
    }

    #[test]
    fn whole_sdu_ack_has_no_segment_fields() {
        let ack = AlAck {
            receiver_ready: true,
            nr: 5,
            acknowledgement_length: 0,
            first_missing_segment: None,
            acknowledgement_bitmap: Vec::new(),
        };
        let mut bits = BitBuffer::new_autoexpand(16);
        ack.to_bitbuf(&mut bits).unwrap();
        assert_eq!(bits.get_len_written(), 14);
        bits.seek(0);
        assert_eq!(AlAck::from_bitbuf(&mut bits).unwrap(), ack);
    }
}
