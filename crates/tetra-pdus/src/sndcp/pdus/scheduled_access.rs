use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SndcpScheduledAccess {
    pub schedule_repetition_period_slots: u16,
    pub schedule_timing_error: u8,
    pub pdu_sizes_octets: Vec<u16>,
}

fn validate_schedule_repetition_period(value: u16) -> Result<(), PduParseErr> {
    if (4..=706).contains(&value) {
        Ok(())
    } else {
        Err(PduParseErr::InvalidValue {
            field: "schedule_repetition_period",
            value: value as u64,
        })
    }
}

fn validate_schedule_timing_error(value: u8) -> Result<(), PduParseErr> {
    if value <= 7 {
        Ok(())
    } else {
        Err(PduParseErr::InvalidValue {
            field: "schedule_timing_error",
            value: value as u64,
        })
    }
}

fn validate_scheduled_pdu_size(value: u16) -> Result<(), PduParseErr> {
    if (1..=2002).contains(&value) {
        Ok(())
    } else {
        Err(PduParseErr::InvalidValue {
            field: "scheduled_pdu_size_octets",
            value: value as u64,
        })
    }
}

impl SndcpScheduledAccess {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let schedule_repetition_period_slots = buffer.read_field(10, "schedule_repetition_period")? as u16;
        validate_schedule_repetition_period(schedule_repetition_period_slots)?;

        let schedule_timing_error = buffer.read_field(3, "schedule_timing_error")? as u8;
        validate_schedule_timing_error(schedule_timing_error)?;

        let count = buffer.read_field(3, "scheduled_pdu_count")? as usize;
        if !(1..=7).contains(&count) {
            return Err(PduParseErr::InvalidValue {
                field: "scheduled_pdu_count",
                value: count as u64,
            });
        }

        let mut pdu_sizes_octets = Vec::with_capacity(count);
        for _ in 0..count {
            let size = buffer.read_field(12, "scheduled_pdu_size_octets")? as u16;
            validate_scheduled_pdu_size(size)?;
            pdu_sizes_octets.push(size);
        }

        Ok(Self {
            schedule_repetition_period_slots,
            schedule_timing_error,
            pdu_sizes_octets,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_schedule_repetition_period(self.schedule_repetition_period_slots)?;
        validate_schedule_timing_error(self.schedule_timing_error)?;
        if !(1..=7).contains(&self.pdu_sizes_octets.len()) {
            return Err(PduParseErr::InvalidValue {
                field: "scheduled_pdu_count",
                value: self.pdu_sizes_octets.len() as u64,
            });
        }

        buffer.write_bits(self.schedule_repetition_period_slots as u64, 10);
        buffer.write_bits(self.schedule_timing_error as u64, 3);
        buffer.write_bits(self.pdu_sizes_octets.len() as u64, 3);
        for size in &self.pdu_sizes_octets {
            validate_scheduled_pdu_size(*size)?;
            buffer.write_bits(*size as u64, 12);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SndcpQosSchedule {
    pub scheduled_access_information_included: bool,
    pub scheduled_access: Option<SndcpScheduledAccess>,
}

impl SndcpQosSchedule {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let scheduled_access_information_included = buffer.read_field(1, "scheduled_access_information_included")? != 0;
        let scheduled_access = if scheduled_access_information_included {
            Some(SndcpScheduledAccess::from_bitbuf(buffer)?)
        } else {
            None
        };
        Ok(Self {
            scheduled_access_information_included,
            scheduled_access,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if self.scheduled_access_information_included != self.scheduled_access.is_some() {
            return Err(PduParseErr::Inconsistency {
                field: "scheduled_access",
                reason: "scheduled access presence must match scheduled access information included",
            });
        }
        buffer.write_bit(self.scheduled_access_information_included as u8);
        if let Some(scheduled_access) = &self.scheduled_access {
            scheduled_access.to_bitbuf(buffer)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SndcpQosScheduleRequest {
    pub background_class_request_any_data_class: bool,
    pub scheduled_access: SndcpQosSchedule,
}

fn skip_bits(buffer: &mut BitBuffer, bits: usize, field: &'static str) -> Result<(), PduParseErr> {
    buffer.read_bits(bits).ok_or(PduParseErr::BufferEnded { field: Some(field) })?;
    Ok(())
}

fn skip_qos_filter(buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    skip_bits(buffer, 2, "qos_filter_operation")?;
    let qos_filter_type = buffer.read_field(4, "qos_filter_type")? as u8;
    match qos_filter_type {
        0 => {}
        1..=3 => skip_bits(buffer, 16, "qos_filter_port")?,
        4..=6 => {
            skip_bits(buffer, 16, "qos_filter_port_low")?;
            skip_bits(buffer, 16, "qos_filter_port_high")?;
        }
        7 => skip_bits(buffer, 16, "qos_filter_diffserv")?,
        8..=11 => skip_bits(buffer, 16, "qos_filter_reserved")?,
        12..=15 => {
            skip_bits(buffer, 16, "qos_filter_reserved")?;
            skip_bits(buffer, 16, "qos_filter_reserved")?;
        }
        _ => {
            return Err(PduParseErr::InvalidValue {
                field: "qos_filter_type",
                value: qos_filter_type as u64,
            });
        }
    }
    Ok(())
}

impl SndcpQosScheduleRequest {
    pub fn from_raw_qos_bits(len_bits: usize, data: &[u8]) -> Result<Self, PduParseErr> {
        if data.len() * 8 < len_bits {
            return Err(PduParseErr::InconsistentLength {
                expected: len_bits.div_ceil(8),
                found: data.len(),
            });
        }

        let mut buffer = BitBuffer::from_bytes(data);
        buffer.set_raw_end(len_bits);

        let background_class_request_any_data_class = buffer.read_field(1, "background_class_request")? != 0;
        if !background_class_request_any_data_class {
            return Ok(Self {
                background_class_request_any_data_class,
                scheduled_access: SndcpQosSchedule {
                    scheduled_access_information_included: false,
                    scheduled_access: None,
                },
            });
        }

        skip_bits(&mut buffer, 4, "context_ready_timer")?;
        let asymmetrical_qos = buffer.read_field(1, "asymmetrical_qos")? != 0;
        skip_bits(&mut buffer, 20, "qos_set_uplink_or_common")?;
        if asymmetrical_qos {
            skip_bits(&mut buffer, 20, "qos_set_downlink")?;
        }

        let qos_filter_included = buffer.read_field(1, "qos_filter_included")? != 0;
        if qos_filter_included {
            skip_qos_filter(&mut buffer)?;
        }

        let scheduled_access = SndcpQosSchedule::from_bitbuf(&mut buffer)?;

        if buffer.get_len_remaining() > 0 {
            let additional_qos_a_included = buffer.read_field(1, "additional_qos_a_included")? != 0;
            if additional_qos_a_included {
                skip_bits(&mut buffer, 16, "additional_qos_a")?;
            }
        }

        if buffer.get_len_remaining() > 0 {
            let additional_qos_b_included = buffer.read_field(1, "additional_qos_b_included")? != 0;
            if additional_qos_b_included {
                skip_bits(&mut buffer, 16, "additional_qos_b")?;
            }
        }

        Ok(Self {
            background_class_request_any_data_class,
            scheduled_access,
        })
    }

    pub fn scheduled_access_requested(&self) -> bool {
        self.scheduled_access.scheduled_access_information_included
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduled_access_layout() {
        let scheduled = SndcpScheduledAccess {
            schedule_repetition_period_slots: 4,
            schedule_timing_error: 2,
            pdu_sizes_octets: vec![31, 296],
        };

        let mut encoded = BitBuffer::new_autoexpand(48);
        scheduled.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "0000000100010010000000011111000100101000");

        encoded.seek(0);
        let decoded = SndcpScheduledAccess::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, scheduled);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn qos_schedule_included_layout() {
        let schedule = SndcpQosSchedule {
            scheduled_access_information_included: true,
            scheduled_access: Some(SndcpScheduledAccess {
                schedule_repetition_period_slots: 4,
                schedule_timing_error: 0,
                pdu_sizes_octets: vec![31],
            }),
        };

        let mut encoded = BitBuffer::new_autoexpand(40);
        schedule.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "10000000100000001000000011111");

        encoded.seek(0);
        let decoded = SndcpQosSchedule::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, schedule);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn qos_schedule_request_detects_absent_schedule_for_background_class() {
        let data = [0u8; 1];

        let decoded = SndcpQosScheduleRequest::from_raw_qos_bits(1, &data).unwrap();

        assert!(!decoded.background_class_request_any_data_class);
        assert!(!decoded.scheduled_access_requested());
    }

    #[test]
    fn qos_schedule_request_detects_included_schedule() {
        let scheduled = SndcpScheduledAccess {
            schedule_repetition_period_slots: 8,
            schedule_timing_error: 1,
            pdu_sizes_octets: vec![64],
        };
        let mut encoded = BitBuffer::new_autoexpand(96);
        encoded.write_bit(1); // any data class
        encoded.write_bits(0, 4); // CONTEXT_READY tracks READY
        encoded.write_bit(0); // symmetrical QoS
        encoded.write_bits(0, 20); // common QoS set
        encoded.write_bit(0); // no QoS filter
        SndcpQosSchedule {
            scheduled_access_information_included: true,
            scheduled_access: Some(scheduled),
        }
        .to_bitbuf(&mut encoded)
        .unwrap();
        encoded.write_bit(0); // no additional QoS A
        encoded.write_bit(0); // no additional QoS B

        let len_bits = encoded.get_len_written();
        let data = encoded.into_bytes();
        let decoded = SndcpQosScheduleRequest::from_raw_qos_bits(len_bits, &data).unwrap();

        assert!(decoded.background_class_request_any_data_class);
        assert!(decoded.scheduled_access_requested());
    }
}
