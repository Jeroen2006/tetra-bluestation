//! SC2/TMO CK change PDUs from EN 300 392-7 annex A.4.
//!
//! The key-change PDU family also covers CCK, GCK and DMO subset forms.  This
//! codec deliberately accepts only the SCK/TMO form needed to enter or rotate
//! SC2.  Unsupported forms fail closed instead of being decoded as SC2.

use tetra_core::{BitBuffer, PduParseErr, expect_pdu_type};

use crate::mm::enums::mm_pdu_type_dl::MmPduTypeDl;
use crate::mm::enums::mm_pdu_type_ul::MmPduTypeUl;

const SCK_KEY_CHANGE_TYPE: u8 = 0;
const TIME_ABSOLUTE_IV: u8 = 0;
const TIME_NETWORK: u8 = 1;
const TIME_IMMEDIATE: u8 = 2;
const TIME_CURRENTLY_IN_USE: u8 = 3;

/// Active SCK identity in D-CK CHANGE DEMAND/U-CK CHANGE RESULT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SckChangeData {
    pub sck_number: u8,
    pub version_number: u16,
}

/// Point at which the announced SCK becomes valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CkChangeTime {
    AbsoluteIv {
        slot_number: u8,
        frame_number: u8,
        multiframe_number: u8,
        hyperframe_number: u16,
    },
    NetworkTime(u64),
    Immediate,
    CurrentlyInUse,
}

/// D-CK CHANGE DEMAND, restricted to the SC2 SCK/TMO form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DCkChangeDemand {
    pub acknowledgement_required: bool,
    /// 0 = no change; 2 = transition to SC2. Other values are rejected by
    /// this SC2-focused codec.
    pub change_of_security_class: u8,
    pub scks: Vec<SckChangeData>,
    pub time: CkChangeTime,
}

/// U-CK CHANGE RESULT, restricted to the SC2 SCK/TMO form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UCkChangeResult {
    pub change_of_security_class: u8,
    pub selected_scks: Vec<SckChangeData>,
}

impl DCkChangeDemand {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, MmPduTypeDl::DCkChangeDemand)?;
        let acknowledgement_required = buffer.read_field(1, "acknowledgement_flag")? != 0;
        let change_of_security_class = buffer.read_field(2, "change_of_security_class")? as u8;
        validate_sc2_class(change_of_security_class)?;
        expect_sck_tmo(buffer)?;
        let scks = read_sck_changes(buffer)?;
        let time = read_time(buffer)?;
        Ok(Self {
            acknowledgement_required,
            change_of_security_class,
            scks,
            time,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_sc2_class(self.change_of_security_class)?;
        validate_scks(&self.scks)?;
        buffer.write_bits(MmPduTypeDl::DCkChangeDemand.into_raw(), 4);
        buffer.write_bits(self.acknowledgement_required as u64, 1);
        buffer.write_bits(u64::from(self.change_of_security_class), 2);
        buffer.write_bits(u64::from(SCK_KEY_CHANGE_TYPE), 3);
        buffer.write_bit(0); // SCK use: TMO
        buffer.write_bits(self.scks.len() as u64, 4);
        for sck in &self.scks {
            write_sck_change(sck, buffer)?;
        }
        write_time(&self.time, buffer)
    }
}

impl UCkChangeResult {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, MmPduTypeUl::UCkChangeResult)?;
        let change_of_security_class = buffer.read_field(2, "change_of_security_class")? as u8;
        validate_sc2_class(change_of_security_class)?;
        expect_sck_tmo(buffer)?;
        Ok(Self {
            change_of_security_class,
            selected_scks: read_sck_changes(buffer)?,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_sc2_class(self.change_of_security_class)?;
        validate_scks(&self.selected_scks)?;
        buffer.write_bits(MmPduTypeUl::UCkChangeResult.into_raw(), 4);
        buffer.write_bits(u64::from(self.change_of_security_class), 2);
        buffer.write_bits(u64::from(SCK_KEY_CHANGE_TYPE), 3);
        buffer.write_bit(0); // SCK use: TMO
        buffer.write_bits(self.selected_scks.len() as u64, 4);
        for sck in &self.selected_scks {
            write_sck_change(sck, buffer)?;
        }
        Ok(())
    }
}

fn validate_sc2_class(value: u8) -> Result<(), PduParseErr> {
    if value == 0 || value == 2 {
        Ok(())
    } else {
        Err(PduParseErr::NotImplemented {
            field: Some("change_of_security_class_non_sc2"),
        })
    }
}

fn expect_sck_tmo(buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    let key_change_type = buffer.read_field(3, "key_change_type")? as u8;
    if key_change_type != SCK_KEY_CHANGE_TYPE {
        return Err(PduParseErr::NotImplemented {
            field: Some("key_change_type_non_sck"),
        });
    }
    if buffer.read_field(1, "sck_use")? != 0 {
        return Err(PduParseErr::NotImplemented {
            field: Some("sck_use_dmo"),
        });
    }
    Ok(())
}

fn read_sck_changes(buffer: &mut BitBuffer) -> Result<Vec<SckChangeData>, PduParseErr> {
    let count = buffer.read_field(4, "number_of_scks_changed")? as usize;
    if count == 0 {
        return Err(PduParseErr::NotImplemented {
            field: Some("sck_subset_change"),
        });
    }
    (0..count)
        .map(|_| {
            Ok(SckChangeData {
                sck_number: buffer.read_field(5, "sck_number")? as u8,
                version_number: buffer.read_field(16, "sck_version_number")? as u16,
            })
        })
        .collect()
}

fn validate_scks(scks: &[SckChangeData]) -> Result<(), PduParseErr> {
    if scks.is_empty() || scks.len() > 15 {
        return Err(PduParseErr::InvalidValue {
            field: "number_of_scks_changed",
            value: scks.len() as u64,
        });
    }
    for sck in scks {
        if sck.sck_number > 31 {
            return Err(PduParseErr::InvalidValue {
                field: "sck_number",
                value: u64::from(sck.sck_number),
            });
        }
    }
    Ok(())
}

fn write_sck_change(value: &SckChangeData, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    if value.sck_number > 31 {
        return Err(PduParseErr::InvalidValue {
            field: "sck_number",
            value: u64::from(value.sck_number),
        });
    }
    buffer.write_bits(u64::from(value.sck_number), 5);
    buffer.write_bits(u64::from(value.version_number), 16);
    Ok(())
}

fn read_time(buffer: &mut BitBuffer) -> Result<CkChangeTime, PduParseErr> {
    match buffer.read_field(2, "time_type")? as u8 {
        TIME_ABSOLUTE_IV => Ok(CkChangeTime::AbsoluteIv {
            slot_number: buffer.read_field(2, "slot_number")? as u8,
            frame_number: buffer.read_field(5, "frame_number")? as u8,
            multiframe_number: buffer.read_field(6, "multiframe_number")? as u8,
            hyperframe_number: buffer.read_field(16, "hyperframe_number")? as u16,
        }),
        TIME_NETWORK => Ok(CkChangeTime::NetworkTime(buffer.read_field(48, "network_time")?)),
        TIME_IMMEDIATE => Ok(CkChangeTime::Immediate),
        TIME_CURRENTLY_IN_USE => Ok(CkChangeTime::CurrentlyInUse),
        _ => unreachable!(),
    }
}

fn write_time(value: &CkChangeTime, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    match value {
        CkChangeTime::AbsoluteIv {
            slot_number,
            frame_number,
            multiframe_number,
            hyperframe_number,
        } => {
            if *slot_number > 3 || *frame_number > 31 || *multiframe_number > 63 {
                return Err(PduParseErr::InvalidValue {
                    field: "absolute_iv_component",
                    value: 0,
                });
            }
            buffer.write_bits(u64::from(TIME_ABSOLUTE_IV), 2);
            buffer.write_bits(u64::from(*slot_number), 2);
            buffer.write_bits(u64::from(*frame_number), 5);
            buffer.write_bits(u64::from(*multiframe_number), 6);
            buffer.write_bits(u64::from(*hyperframe_number), 16);
        }
        CkChangeTime::NetworkTime(value) => {
            if *value >= (1_u64 << 48) {
                return Err(PduParseErr::InvalidValue {
                    field: "network_time",
                    value: *value,
                });
            }
            buffer.write_bits(u64::from(TIME_NETWORK), 2);
            buffer.write_bits(*value, 48);
        }
        CkChangeTime::Immediate => buffer.write_bits(u64::from(TIME_IMMEDIATE), 2),
        CkChangeTime::CurrentlyInUse => buffer.write_bits(u64::from(TIME_CURRENTLY_IN_USE), 2),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sc2_demand_and_result_roundtrip() {
        let demand = DCkChangeDemand {
            acknowledgement_required: false,
            change_of_security_class: 2,
            scks: vec![SckChangeData {
                sck_number: 7,
                version_number: 3,
            }],
            time: CkChangeTime::AbsoluteIv {
                slot_number: 1,
                frame_number: 2,
                multiframe_number: 3,
                hyperframe_number: 4,
            },
        };
        let mut buffer = BitBuffer::new_autoexpand(96);
        demand.to_bitbuf(&mut buffer).expect("serialize demand");
        buffer.seek(0);
        assert_eq!(DCkChangeDemand::from_bitbuf(&mut buffer).expect("parse demand"), demand);
        assert_eq!(buffer.get_len_remaining(), 0);

        let result = UCkChangeResult {
            change_of_security_class: 2,
            selected_scks: demand.scks,
        };
        result.to_bitbuf(&mut buffer).expect("serialize result");
        buffer.seek(0);
        assert_eq!(UCkChangeResult::from_bitbuf(&mut buffer).expect("parse result"), result);
        assert_eq!(buffer.get_len_remaining(), 0);
    }
}
