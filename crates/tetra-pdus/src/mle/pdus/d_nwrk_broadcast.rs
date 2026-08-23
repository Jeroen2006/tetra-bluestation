use core::fmt;

use tetra_core::typed_pdu_fields::*;
use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::mle::enums::mle_pdu_type_dl::MlePduTypeDl;
use crate::mle::fields::neighbour_cell_information_for_ca::NeighbourCellInformationForCa;

/// Representation of the D-NWRK-BROADCAST PDU (Clause 18.4.1.4.1).
/// Upon receipt from the SwMI, the message shall inform the MS-MLE about parameters for the CA serving cell and parameters for one or more CA neighbour cells.
/// Response expected: -
/// Response to: -/U-PREPARE/U-PREPARE-DA

// note 1: This element shall not be used by a DA MS.
// note 2: If present, the element shall indicate how many “Neighbour cell information for CA” elements follow. If not present, no neighbour cell information shall follow.
// note 3: The element definition is contained in clause 18.5 which gives the type and length for each sub-element which is included in this element. The element shall be present as many times as indicated by the “number of CA neighbour cells” element. There shall be no P-bit preceding each “neighbour cell information for CA” element which is carried by this PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNwrkBroadcast {
    /// Type1, 16 bits, See note 1,
    pub cell_re_select_parameters: u16,
    /// Type1, 2 bits, See note 1,
    pub cell_load_ca: u8,
    /// Type2, 48 bits, TETRA network time
    pub tetra_network_time: Option<u64>,
    /// Type2, 3 bits, See note 2,
    pub neighbour_cell_information_for_ca: Vec<NeighbourCellInformationForCa>,
}

impl DNwrkBroadcast {
    /// Parse from BitBuffer
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(3, "pdu_type")?;
        expect_pdu_type!(pdu_type, MlePduTypeDl::DNwrkBroadcast)?;

        // Type1
        let cell_re_select_parameters = buffer.read_field(16, "cell_re_select_parameters")? as u16;
        // Type1
        let cell_load_ca = buffer.read_field(2, "cell_load_ca")? as u8;

        // obit designates presence of any further type2 fields
        let obit = delimiters::read_obit(buffer)?;

        // Type2
        let tetra_network_time = typed::parse_type2_generic(obit, buffer, 48, "tetra_network_time")?;
        // Type2
        let number_of_ca_neighbour_cells = typed::parse_type2_generic(obit, buffer, 3, "number_of_ca_neighbour_cells")?;

        // Conditional
        let neighbour_cell_information_for_ca = match number_of_ca_neighbour_cells {
            Some(count) => (0..count)
                .map(|_| NeighbourCellInformationForCa::from_bitbuf(buffer))
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };

        // MLE PDUs do not use M-bits (Annex E.2.1) — no trailing delimiter to read

        Ok(DNwrkBroadcast {
            cell_re_select_parameters,
            cell_load_ca,
            tetra_network_time,
            neighbour_cell_information_for_ca,
        })
    }

    /// Serialize this PDU into the given BitBuffer.
    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        // PDU Type
        buffer.write_bits(MlePduTypeDl::DNwrkBroadcast.into_raw(), 3);
        // Type1
        buffer.write_bits(self.cell_re_select_parameters as u64, 16);
        // Type1
        buffer.write_bits(self.cell_load_ca as u64, 2);

        if self.neighbour_cell_information_for_ca.len() > 7 {
            return Err(PduParseErr::InvalidValue {
                field: "number_of_ca_neighbour_cells",
                value: self.neighbour_cell_information_for_ca.len() as u64,
            });
        }
        // Check if any optional field present and place o-bit
        let has_neighbours = !self.neighbour_cell_information_for_ca.is_empty();
        let obit = self.tetra_network_time.is_some() || has_neighbours;
        delimiters::write_obit(buffer, obit as u8);
        if !obit {
            return Ok(());
        }

        // Type2
        typed::write_type2_generic(obit, buffer, self.tetra_network_time, 48);

        // Type2
        typed::write_type2_generic(
            obit,
            buffer,
            has_neighbours.then_some(self.neighbour_cell_information_for_ca.len() as u64),
            3,
        );

        // Conditional
        for neighbour in &self.neighbour_cell_information_for_ca {
            neighbour.to_bitbuf(buffer)?;
        }
        // MLE PDUs do not use M-bits (Annex E.2.1) — PDU ends after last Type 2 element
        Ok(())
    }
}

impl fmt::Display for DNwrkBroadcast {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNwrkBroadcast {{ cell_re_select_parameters: {:?} cell_load_ca: {:?} tetra_network_time: {:?} neighbour_cell_information_for_ca: {:?} }}",
            self.cell_re_select_parameters, self.cell_load_ca, self.tetra_network_time, self.neighbour_cell_information_for_ca,
        )
    }
}

#[cfg(test)]
mod tests {
    use tetra_core::BitBuffer;

    use super::*;

    #[test]
    fn roundtrips_network_time_and_ca_neighbour() {
        let pdu = DNwrkBroadcast {
            cell_re_select_parameters: 0x1234,
            cell_load_ca: 2,
            tetra_network_time: Some(0x12_3456_789a_bc),
            neighbour_cell_information_for_ca: vec![NeighbourCellInformationForCa {
                cell_identifier_ca: 1,
                cell_reselection_types_supported: 2,
                synchronized: true,
                cell_load_ca: 0,
                main_carrier_number: 777,
                main_carrier_number_extension: None,
                mcc: Some(204),
                mnc: Some(16),
                location_area: Some(101),
                ms_txpwr_max_cell: None,
                rxlev_access_min: None,
                subscriber_class: None,
                bs_service_details: None,
                timeshare_security_parameters: None,
                tdma_frame_offset: Some(4),
            }],
        };
        let mut encoded = BitBuffer::new_autoexpand(160);
        pdu.to_bitbuf(&mut encoded).expect("serialize D-NWRK-BROADCAST");
        encoded.seek(0);
        assert_eq!(DNwrkBroadcast::from_bitbuf(&mut encoded).expect("parse D-NWRK-BROADCAST"), pdu);
    }
}
