use tetra_core::{
    BitBuffer,
    pdu_parse_error::PduParseErr,
    typed_pdu_fields::{delimiters, typed},
};

use super::bs_service_details::BsServiceDetails;

/// Neighbour cell information for CA (TS 100 392-2, table 18.64).
///
/// This is deliberately a typed element rather than an opaque bit blob: a
/// mobile station inherits omitted optional fields from its serving cell, so a
/// SwMI must be able to express every differing value accurately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighbourCellInformationForCa {
    pub cell_identifier_ca: u8,
    pub cell_reselection_types_supported: u8,
    pub synchronized: bool,
    pub cell_load_ca: u8,
    pub main_carrier_number: u16,
    pub main_carrier_number_extension: Option<u16>,
    pub mcc: Option<u16>,
    pub mnc: Option<u16>,
    pub location_area: Option<u16>,
    pub ms_txpwr_max_cell: Option<u8>,
    pub rxlev_access_min: Option<u8>,
    pub subscriber_class: Option<u16>,
    pub bs_service_details: Option<BsServiceDetails>,
    pub timeshare_security_parameters: Option<u8>,
    pub tdma_frame_offset: Option<u8>,
}

impl NeighbourCellInformationForCa {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let cell_identifier_ca = buffer.read_field(5, "cell_identifier_ca")? as u8;
        let cell_reselection_types_supported = buffer.read_field(2, "cell_reselection_types_supported")? as u8;
        let synchronized = buffer.read_field(1, "neighbour_cell_synchronized")? != 0;
        let cell_load_ca = buffer.read_field(2, "neighbour_cell_load_ca")? as u8;
        let main_carrier_number = buffer.read_field(12, "neighbour_main_carrier_number")? as u16;

        let obit = delimiters::read_obit(buffer)?;
        let main_carrier_number_extension =
            typed::parse_type2_generic(obit, buffer, 10, "main_carrier_number_extension")?.map(|value| value as u16);
        let mcc = typed::parse_type2_generic(obit, buffer, 10, "neighbour_mcc")?.map(|value| value as u16);
        let mnc = typed::parse_type2_generic(obit, buffer, 14, "neighbour_mnc")?.map(|value| value as u16);
        let location_area = typed::parse_type2_generic(obit, buffer, 14, "neighbour_location_area")?.map(|value| value as u16);
        let ms_txpwr_max_cell = typed::parse_type2_generic(obit, buffer, 3, "neighbour_ms_txpwr_max_cell")?.map(|value| value as u8);
        let rxlev_access_min = typed::parse_type2_generic(obit, buffer, 4, "neighbour_rxlev_access_min")?.map(|value| value as u8);
        let subscriber_class = typed::parse_type2_generic(obit, buffer, 16, "neighbour_subscriber_class")?.map(|value| value as u16);
        let bs_service_details = typed::parse_type2_struct(obit, buffer, BsServiceDetails::from_bitbuf)?;
        let timeshare_security_parameters =
            typed::parse_type2_generic(obit, buffer, 5, "timeshare_security_parameters")?.map(|value| value as u8);
        let tdma_frame_offset = typed::parse_type2_generic(obit, buffer, 6, "tdma_frame_offset")?.map(|value| value as u8);

        Ok(Self {
            cell_identifier_ca,
            cell_reselection_types_supported,
            synchronized,
            cell_load_ca,
            main_carrier_number,
            main_carrier_number_extension,
            mcc,
            mnc,
            location_area,
            ms_txpwr_max_cell,
            rxlev_access_min,
            subscriber_class,
            bs_service_details,
            timeshare_security_parameters,
            tdma_frame_offset,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if self.cell_identifier_ca > 31
            || self.cell_reselection_types_supported > 3
            || self.cell_load_ca > 3
            || self.main_carrier_number > 0x0fff
        {
            return Err(PduParseErr::InvalidValue {
                field: "neighbour_cell_information_for_ca",
                value: self.cell_identifier_ca as u64,
            });
        }
        buffer.write_bits(self.cell_identifier_ca as u64, 5);
        buffer.write_bits(self.cell_reselection_types_supported as u64, 2);
        buffer.write_bits(self.synchronized as u64, 1);
        buffer.write_bits(self.cell_load_ca as u64, 2);
        buffer.write_bits(self.main_carrier_number as u64, 12);

        let obit = self.main_carrier_number_extension.is_some()
            || self.mcc.is_some()
            || self.mnc.is_some()
            || self.location_area.is_some()
            || self.ms_txpwr_max_cell.is_some()
            || self.rxlev_access_min.is_some()
            || self.subscriber_class.is_some()
            || self.bs_service_details.is_some()
            || self.timeshare_security_parameters.is_some()
            || self.tdma_frame_offset.is_some();
        delimiters::write_obit(buffer, obit as u8);
        if !obit {
            return Ok(());
        }
        typed::write_type2_generic(obit, buffer, self.main_carrier_number_extension.map(u64::from), 10);
        typed::write_type2_generic(obit, buffer, self.mcc.map(u64::from), 10);
        typed::write_type2_generic(obit, buffer, self.mnc.map(u64::from), 14);
        typed::write_type2_generic(obit, buffer, self.location_area.map(u64::from), 14);
        typed::write_type2_generic(obit, buffer, self.ms_txpwr_max_cell.map(u64::from), 3);
        typed::write_type2_generic(obit, buffer, self.rxlev_access_min.map(u64::from), 4);
        typed::write_type2_generic(obit, buffer, self.subscriber_class.map(u64::from), 16);
        typed::write_type2_struct(obit, buffer, &self.bs_service_details, |details, out| {
            details.to_bitbuf(out);
            Ok(())
        })?;
        typed::write_type2_generic(obit, buffer, self.timeshare_security_parameters.map(u64::from), 5);
        typed::write_type2_generic(obit, buffer, self.tdma_frame_offset.map(u64::from), 6);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_complete_ca_neighbour_information() {
        let neighbour = NeighbourCellInformationForCa {
            cell_identifier_ca: 7,
            // Forward registration supported; expedited reselection not
            // recommended, so an MS can use announced Type 1/2 reselection.
            cell_reselection_types_supported: 2,
            synchronized: true,
            cell_load_ca: 1,
            main_carrier_number: 2047,
            main_carrier_number_extension: Some(3),
            mcc: Some(204),
            mnc: Some(16),
            location_area: Some(101),
            ms_txpwr_max_cell: Some(5),
            rxlev_access_min: Some(9),
            subscriber_class: Some(0x55aa),
            bs_service_details: Some(BsServiceDetails {
                registration: true,
                deregistration: true,
                priority_cell: false,
                no_minimum_mode: false,
                migration: false,
                system_wide_services: true,
                voice_service: true,
                circuit_mode_data_service: false,
                sndcp_service: false,
                aie_service: false,
                advanced_link: true,
            }),
            timeshare_security_parameters: Some(17),
            tdma_frame_offset: Some(23),
        };
        let mut encoded = BitBuffer::new_autoexpand(160);
        neighbour.to_bitbuf(&mut encoded).expect("serialize CA neighbour information");
        encoded.seek(0);
        assert_eq!(
            NeighbourCellInformationForCa::from_bitbuf(&mut encoded).expect("parse CA neighbour information"),
            neighbour
        );
    }
}
