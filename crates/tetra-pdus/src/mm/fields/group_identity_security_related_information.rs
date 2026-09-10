use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

/// TTR 001-11 table 14. One type-4 payload can associate up to thirty GSSIs
/// with a 16-bit GCKN. CCK-default groups omit this complete security element;
/// the upper half of the 17-bit select field is reserved by this profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupIdentitySecurityRelatedInformation {
    pub associations: Vec<GroupGckAssociation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupGckAssociation {
    pub gssi: u32,
    pub selection: GckSelectNumber,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GckSelectNumber {
    Selected(u16),
}

impl GckSelectNumber {
    fn from_raw(value: u64) -> Result<Self, PduParseErr> {
        match value {
            0..=0xffff => Ok(Self::Selected(value as u16)),
            _ => Err(PduParseErr::InvalidValue {
                field: "gck_select_number",
                value,
            }),
        }
    }

    fn into_raw(self) -> u64 {
        match self {
            Self::Selected(gckn) => u64::from(gckn),
        }
    }
}

impl GroupIdentitySecurityRelatedInformation {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let count = buffer.read_field(5, "number_of_groups")? as usize;
        if count == 0 || count > 30 {
            return Err(PduParseErr::InvalidValue {
                field: "number_of_groups",
                value: count as u64,
            });
        }
        let mut groups = Vec::with_capacity(count);
        for _ in 0..count {
            groups.push(buffer.read_field(24, "gssi")? as u32);
        }
        if buffer.read_field(1, "gck_association")? != 1 {
            return Err(PduParseErr::InvalidValue {
                field: "gck_association",
                value: 0,
            });
        }
        let selection = GckSelectNumber::from_raw(buffer.read_field(17, "gck_select_number")?)?;
        if buffer.read_field(1, "sck_association")? != 0 {
            return Err(PduParseErr::InvalidValue {
                field: "sck_association",
                value: 1,
            });
        }
        let associations = groups.into_iter().map(|gssi| GroupGckAssociation { gssi, selection }).collect();
        Ok(Self { associations })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if self.associations.is_empty() || self.associations.len() > 30 {
            return Err(PduParseErr::InvalidValue {
                field: "number_of_groups",
                value: self.associations.len() as u64,
            });
        }
        let selection = self.associations[0].selection;
        if self.associations.iter().any(|a| a.selection != selection) {
            return Err(PduParseErr::InvalidValue {
                field: "mixed_gck_associations",
                value: self.associations.len() as u64,
            });
        }
        buffer.write_bits(self.associations.len() as u64, 5);
        for association in &self.associations {
            if association.gssi == 0 || association.gssi > 0x00ff_ffff {
                return Err(PduParseErr::InvalidValue {
                    field: "gssi",
                    value: u64::from(association.gssi),
                });
            }
            buffer.write_bits(u64::from(association.gssi), 24);
        }
        // EN 300 392-7 table 4.11: all GSSIs precede their shared key association.
        buffer.write_bit(1);
        buffer.write_bits(selection.into_raw(), 17);
        buffer.write_bit(0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_groups_follow_table_4_11_bit_order() {
        let vector = concat!(
            "00010",
            "000000000000000011001100",
            "000000000000011111010100",
            "1",
            "00000000000000001",
            "0"
        );
        let expected = GroupIdentitySecurityRelatedInformation {
            associations: vec![
                GroupGckAssociation {
                    gssi: 204,
                    selection: GckSelectNumber::Selected(1),
                },
                GroupGckAssociation {
                    gssi: 2004,
                    selection: GckSelectNumber::Selected(1),
                },
            ],
        };
        let mut input = BitBuffer::from_bitstr(vector);
        assert_eq!(GroupIdentitySecurityRelatedInformation::from_bitbuf(&mut input).unwrap(), expected);
        let mut output = BitBuffer::new_autoexpand(80);
        expected.to_bitbuf(&mut output).unwrap();
        assert_eq!(output.to_bitstr(), vector);
    }
    #[test]
    fn roundtrip_twenty_scanned_groups() {
        let value = GroupIdentitySecurityRelatedInformation {
            associations: (1..=20)
                .map(|gssi| GroupGckAssociation {
                    gssi,
                    selection: GckSelectNumber::Selected(1),
                })
                .collect(),
        };
        let mut bits = BitBuffer::new_autoexpand(128);
        value.to_bitbuf(&mut bits).unwrap();
        bits.seek(0);
        assert_eq!(GroupIdentitySecurityRelatedInformation::from_bitbuf(&mut bits).unwrap(), value);
    }

    #[test]
    fn reserved_seventeenth_select_bit_is_rejected() {
        let mut bits = BitBuffer::from_bitstr(concat!(
            "00001",                    // one group
            "000001101001001100101101", // GSSI 430893
            "1",                        // association supplied
            "10000000000000000",        // reserved by TTR table 14
            "0"                         // no SCK association
        ));
        assert!(GroupIdentitySecurityRelatedInformation::from_bitbuf(&mut bits).is_err());
    }
}
