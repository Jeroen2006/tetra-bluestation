use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SndcpResourceRequest {
    pub asymmetric_connection: bool,
    pub data_transfer_throughput: u8,
    pub uplink_or_symmetric_timeslots: u8,
    pub downlink_timeslots: Option<u8>,
    pub full_phase_modulation_capability: u8,
    pub reserved: u8,
}

impl SndcpResourceRequest {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let asymmetric_connection = buffer.read_field(1, "connection_symmetry")? != 0;
        let data_transfer_throughput = buffer.read_field(3, "data_transfer_throughput")? as u8;
        let uplink_or_symmetric_timeslots = buffer.read_field(2, "uplink_or_symmetric_timeslots")? as u8;
        let downlink_timeslots = if asymmetric_connection {
            Some(buffer.read_field(2, "downlink_timeslots")? as u8)
        } else {
            None
        };
        let full_phase_modulation_capability = buffer.read_field(2, "full_phase_modulation_capability")? as u8;
        let reserved = buffer.read_field(2, "reserved")? as u8;

        Ok(Self {
            asymmetric_connection,
            data_transfer_throughput,
            uplink_or_symmetric_timeslots,
            downlink_timeslots,
            full_phase_modulation_capability,
            reserved,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        self.validate()?;

        buffer.write_bit(self.asymmetric_connection as u8);
        buffer.write_bits(self.data_transfer_throughput as u64, 3);
        buffer.write_bits(self.uplink_or_symmetric_timeslots as u64, 2);
        if let Some(downlink_timeslots) = self.downlink_timeslots {
            buffer.write_bits(downlink_timeslots as u64, 2);
        }
        buffer.write_bits(self.full_phase_modulation_capability as u64, 2);
        buffer.write_bits(self.reserved as u64, 2);

        Ok(())
    }

    fn validate(&self) -> Result<(), PduParseErr> {
        if self.asymmetric_connection != self.downlink_timeslots.is_some() {
            return Err(PduParseErr::Inconsistency {
                field: "downlink_timeslots",
                reason: "downlink timeslots are present only for asymmetric resource requests",
            });
        }
        if self.data_transfer_throughput > 7 {
            return Err(PduParseErr::InvalidValue {
                field: "data_transfer_throughput",
                value: self.data_transfer_throughput as u64,
            });
        }
        if self.uplink_or_symmetric_timeslots > 3 {
            return Err(PduParseErr::InvalidValue {
                field: "uplink_or_symmetric_timeslots",
                value: self.uplink_or_symmetric_timeslots as u64,
            });
        }
        if let Some(downlink_timeslots) = self.downlink_timeslots {
            if downlink_timeslots > 3 {
                return Err(PduParseErr::InvalidValue {
                    field: "downlink_timeslots",
                    value: downlink_timeslots as u64,
                });
            }
        }
        if self.full_phase_modulation_capability > 3 {
            return Err(PduParseErr::InvalidValue {
                field: "full_phase_modulation_capability",
                value: self.full_phase_modulation_capability as u64,
            });
        }
        if self.reserved > 3 {
            return Err(PduParseErr::InvalidValue {
                field: "reserved",
                value: self.reserved as u64,
            });
        }
        if self.data_transfer_throughput == 0b110
            && (self.asymmetric_connection || self.uplink_or_symmetric_timeslots != self.full_phase_modulation_capability)
        {
            return Err(PduParseErr::Inconsistency {
                field: "data_transfer_throughput",
                reason: "unspecified phase modulation resource requires symmetric request and matching capability",
            });
        }
        Ok(())
    }
}
