use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnData {
    pub nsapi: u8,
    pub pcomp: u8,
    pub dcomp: u8,
    pub n_pdu_len_bits: usize,
    pub n_pdu: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnUnitdata {
    pub nsapi: u8,
    pub pcomp: u8,
    pub dcomp: u8,
    pub n_pdu_len_bits: usize,
    pub n_pdu: Vec<u8>,
}

fn validate_header(nsapi: u8, pcomp: u8, dcomp: u8) -> Result<(), PduParseErr> {
    if !(1..=14).contains(&nsapi) {
        return Err(PduParseErr::InvalidValue {
            field: "nsapi",
            value: nsapi as u64,
        });
    }
    if pcomp > 15 {
        return Err(PduParseErr::InvalidValue {
            field: "pcomp",
            value: pcomp as u64,
        });
    }
    if dcomp > 15 {
        return Err(PduParseErr::InvalidValue {
            field: "dcomp",
            value: dcomp as u64,
        });
    }
    Ok(())
}

fn read_n_pdu(buffer: &mut BitBuffer, field: &'static str) -> Result<(usize, Vec<u8>), PduParseErr> {
    let len_bits = buffer.get_len_remaining();
    let mut data = vec![0; len_bits.div_ceil(8)];
    buffer
        .read_bits_into_slice(len_bits, &mut data)
        .ok_or(PduParseErr::BufferEnded { field: Some(field) })?;
    Ok((len_bits, data))
}

fn write_n_pdu(buffer: &mut BitBuffer, len_bits: usize, data: &[u8]) -> Result<(), PduParseErr> {
    if data.len() * 8 < len_bits {
        return Err(PduParseErr::InconsistentLength {
            expected: len_bits.div_ceil(8),
            found: data.len(),
        });
    }

    let mut src = BitBuffer::from_bytes(data);
    buffer.copy_bits(&mut src, len_bits);
    Ok(())
}

impl SnData {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::Data)?;

        let nsapi = buffer.read_field(4, "nsapi")? as u8;
        let pcomp = buffer.read_field(4, "pcomp")? as u8;
        let dcomp = buffer.read_field(4, "dcomp")? as u8;
        let (n_pdu_len_bits, n_pdu) = read_n_pdu(buffer, "n_pdu")?;

        Ok(SnData {
            nsapi,
            pcomp,
            dcomp,
            n_pdu_len_bits,
            n_pdu,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_header(self.nsapi, self.pcomp, self.dcomp)?;

        buffer.write_bits(SnPduType::Data.into_raw(), 4);
        buffer.write_bits(self.nsapi as u64, 4);
        buffer.write_bits(self.pcomp as u64, 4);
        buffer.write_bits(self.dcomp as u64, 4);
        write_n_pdu(buffer, self.n_pdu_len_bits, &self.n_pdu)
    }
}

impl SnUnitdata {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::Unitdata)?;

        let nsapi = buffer.read_field(4, "nsapi")? as u8;
        let pcomp = buffer.read_field(4, "pcomp")? as u8;
        let dcomp = buffer.read_field(4, "dcomp")? as u8;
        let (n_pdu_len_bits, n_pdu) = read_n_pdu(buffer, "n_pdu")?;

        Ok(SnUnitdata {
            nsapi,
            pcomp,
            dcomp,
            n_pdu_len_bits,
            n_pdu,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_header(self.nsapi, self.pcomp, self.dcomp)?;

        buffer.write_bits(SnPduType::Unitdata.into_raw(), 4);
        buffer.write_bits(self.nsapi as u64, 4);
        buffer.write_bits(self.pcomp as u64, 4);
        buffer.write_bits(self.dcomp as u64, 4);
        write_n_pdu(buffer, self.n_pdu_len_bits, &self.n_pdu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sn_unitdata_layout_has_no_trailing_obit() {
        let pdu = SnUnitdata {
            nsapi: 1,
            pcomp: 0,
            dcomp: 0,
            n_pdu_len_bits: 8,
            n_pdu: vec![0xcc],
        };

        let mut encoded = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut encoded).unwrap();

        assert_eq!(encoded.to_bitstr(), "010000010000000011001100");

        encoded.seek(0);
        let decoded = SnUnitdata::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn sn_data_layout_has_no_trailing_obit() {
        let pdu = SnData {
            nsapi: 1,
            pcomp: 0,
            dcomp: 0,
            n_pdu_len_bits: 8,
            n_pdu: vec![0xcc],
        };

        let mut encoded = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut encoded).unwrap();

        assert_eq!(encoded.to_bitstr(), "010100010000000011001100");

        encoded.seek(0);
        let decoded = SnData::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }
}
