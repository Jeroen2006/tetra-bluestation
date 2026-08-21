use crate::mm::enums::mm_pdu_type_ul::MmPduTypeUl;
use crate::mm::enums::type34_elem_id_ul::MmType34ElemIdUl;
use tetra_core::{expect_pdu_type, pdu_parse_error::PduParseErr, typed_pdu_fields::typed, BitBuffer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UAuthentication {
    pub subtype: u8,
    pub response_1: Option<[u8; 4]>,
    pub mutual: bool,
    pub rand_2: Option<[u8; 10]>,
    pub authentication_result: Option<bool>,
}

impl UAuthentication {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, MmPduTypeUl::UAuthentication)?;
        let subtype = buffer.read_field(2, "authentication_subtype")? as u8;
        // A.8.6: 00 = DEMAND, 01 = RESPONSE, 10 = RESULT, 11 = REJECT.
        // The previous implementation treated 10 as RESPONSE, so a
        // standards-compliant U-AUTHENTICATION RESPONSE was discarded by
        // MmBs before it could be forwarded to the SwMI.
        let response_1 = if subtype == 1 {
            let mut value = [0; 4];
            for byte in &mut value {
                *byte = buffer.read_field(8, "response_1")? as u8;
            }
            Some(value)
        } else if subtype == 0 || subtype == 2 {
            None
        } else {
            return Err(PduParseErr::InvalidValue {
                field: "authentication_subtype",
                value: subtype as u64,
            });
        };
        let (response_1, mutual, rand_2, authentication_result) = if subtype == 0 {
            let mut value = [0; 10];
            for byte in &mut value {
                *byte = buffer.read_field(8, "rand_2")? as u8;
            }
            // U-AUTHENTICATION DEMAND also has the optional Type-3
            // proprietary tail.  The normal form carries O=0.
            if buffer.get_len_remaining() > 0 {
                let obit = buffer.read_field(1, "proprietary_obit")?;
                if obit != 0 {
                    return Err(PduParseErr::NotImplemented {
                        field: Some("proprietary"),
                    });
                }
            }
            (None, true, Some(value), None)
        } else if subtype == 1 {
            let mutual = buffer.read_field(1, "mutual")? != 0;
            // RAND2 is the conditional fixed Type-1 field in U-AUTH RESPONSE.
            // The optional Type-3 proprietary tail follows it, hence the
            // terminal's mutual response is 4+2+32+1+80+O = 120 bits.
            let rand_2 = if mutual {
                let mut value = [0; 10];
                for byte in &mut value {
                    *byte = buffer.read_field(8, "rand_2")? as u8;
                }
                Some(value)
            } else {
                None
            };
            if buffer.get_len_remaining() > 0 {
                let obit = buffer.read_field(1, "proprietary_obit")?;
                if obit != 0 {
                    return Err(PduParseErr::NotImplemented {
                        field: Some("proprietary"),
                    });
                }
            }
            (response_1, mutual, rand_2, None)
        } else if subtype == 2 {
            let result = buffer.read_field(1, "authentication_result")? != 0;
            let mutual = buffer.read_field(1, "mutual")? != 0;
            let response_1 = if buffer.get_len_remaining() > 0 {
                let obit = buffer.read_field(1, "proprietary_obit")? != 0;
                if obit {
                    let field = typed::parse_type3_generic(true, buffer, MmType34ElemIdUl::Proprietary)?;
                    let Some(field) = field else {
                        return Err(PduParseErr::InvalidValue {
                            field: "authentication_result_proprietary_id",
                            value: 0,
                        });
                    };
                    if field.len != 32 {
                        return Err(PduParseErr::InvalidValue {
                            field: "authentication_result_response_1_length",
                            value: field.len as u64,
                        });
                    }
                    Some((field.data as u32).to_be_bytes())
                } else {
                    None
                }
            } else {
                None
            };
            (response_1, mutual, None, Some(result))
        } else {
            return Err(PduParseErr::InvalidValue {
                field: "authentication_subtype",
                value: subtype as u64,
            });
        };
        Ok(Self {
            response_1,
            subtype,
            mutual,
            rand_2,
            authentication_result,
        })
    }
}
