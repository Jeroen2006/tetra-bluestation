use std::collections::HashSet;

use tetra_config::bluestation::{CfgNetworkBroadcast, RuntimeNetworkBroadcast, SharedConfig};
use tetra_core::{BitBuffer, Sap, SsiType, TetraAddress, tetra_entities::TetraEntity};
use tetra_pdus::mle::{
    enums::mle_protocol_discriminator::MleProtocolDiscriminator,
    fields::{bs_service_details::BsServiceDetails, neighbour_cell_information_for_ca::NeighbourCellInformationForCa},
    pdus::d_nwrk_broadcast::DNwrkBroadcast,
};
use tetra_saps::{SapMsg, SapMsgInner, tla::TlaTlUnitdataReqBl};
use tetra_swmi_protocol::{NeighbourCell, NeighbourCellSnapshot};

use crate::{MessageQueue, mle::components::network_time};

/// Produces the CA D-NWRK-BROADCAST carousel. The SwMI owns the neighbour
/// directory; the BS owns local time and reselection settings.
pub struct MleBroadcast {
    config: SharedConfig,
    snapshot_version: u64,
    neighbours: Vec<NeighbourCell>,
    next_batch: usize,
}

impl MleBroadcast {
    pub fn new(config: SharedConfig) -> Self {
        Self {
            config,
            snapshot_version: 0,
            neighbours: Vec::new(),
            next_batch: 0,
        }
    }

    pub fn replace_neighbours(&mut self, snapshot: NeighbourCellSnapshot) {
        if snapshot.directory_version < self.snapshot_version {
            tracing::debug!(
                current = self.snapshot_version,
                received = snapshot.directory_version,
                "ignoring stale neighbour directory snapshot"
            );
            return;
        }
        self.snapshot_version = snapshot.directory_version;
        self.neighbours = snapshot.neighbours;
        self.next_batch = 0;
        tracing::info!(
            directory_version = self.snapshot_version,
            neighbours = self.neighbours.len(),
            "SwMI neighbour directory applied"
        );
    }

    /// Resolve a CA cell identifier from U-PREPARE in this serving cell's
    /// most recently received directory snapshot.
    pub fn neighbour_station_id(&self, cell_identifier_ca: u8) -> Option<&str> {
        self.neighbours
            .iter()
            .find(|neighbour| neighbour.cell_identifier_ca == cell_identifier_ca)
            .map(|neighbour| neighbour.station_id.as_str())
    }

    pub fn apply_runtime_update(&mut self, neighbours: Vec<String>, broadcast: CfgNetworkBroadcast) -> Result<u64, &'static str> {
        if neighbours.len() > 31 || neighbours.iter().any(|id| id.trim().is_empty()) {
            return Err("neighbour IDs must be non-empty and contain at most 31 entries");
        }
        let unique: HashSet<_> = neighbours.iter().collect();
        if unique.len() != neighbours.len() {
            return Err("neighbour IDs must be unique");
        }
        if broadcast.cell_load_ca > 3 {
            return Err("cell_load_ca must be 0-3");
        }
        if broadcast.time_enabled {
            let Some(timezone) = &broadcast.timezone else {
                return Err("timezone is required while time broadcasting is enabled");
            };
            if timezone.parse::<chrono_tz::Tz>().is_err() {
                return Err("timezone must be a valid IANA timezone");
            }
        }

        let mut state = self.config.state_write();
        let version = state.network_broadcast.version.saturating_add(1);
        state.network_broadcast = RuntimeNetworkBroadcast {
            version,
            neighbours: tetra_config::bluestation::CfgNeighbourCells { ids: neighbours },
            broadcast,
        };
        Ok(version)
    }

    pub fn send_broadcast(&mut self, queue: &mut MessageQueue) {
        let runtime = self.config.state_read().network_broadcast.clone();
        let batch = self.next_neighbour_batch();
        let network_time = if runtime.broadcast.time_enabled {
            runtime
                .broadcast
                .timezone
                .as_deref()
                .and_then(network_time::encode_tetra_network_time)
        } else {
            None
        };

        let pdu = DNwrkBroadcast {
            cell_re_select_parameters: runtime.broadcast.cell_reselect_parameters,
            cell_load_ca: runtime.broadcast.cell_load_ca,
            tetra_network_time: network_time,
            neighbour_cell_information_for_ca: batch.iter().map(neighbour_to_air).collect(),
        };

        let mut pdu_buf = BitBuffer::new_autoexpand(256);
        if let Err(error) = pdu.to_bitbuf(&mut pdu_buf) {
            tracing::warn!(error = ?error, "failed to serialize D-NWRK-BROADCAST");
            return;
        }
        let pdu_len = pdu_buf.get_pos();
        pdu_buf.seek(0);

        let mut tl_sdu = BitBuffer::new_autoexpand(3 + pdu_len);
        tl_sdu.write_bits(MleProtocolDiscriminator::Mle.into_raw(), 3);
        tl_sdu.copy_bits(&mut pdu_buf, pdu_len);
        tl_sdu.seek(0);

        queue.push_back(SapMsg {
            sap: Sap::TlaSap,
            src: TetraEntity::Mle,
            dest: TetraEntity::Llc,
            msg: SapMsgInner::TlaTlUnitdataReqBl(TlaTlUnitdataReqBl {
                main_address: TetraAddress {
                    ssi: 0xFFFFFF,
                    ssi_type: SsiType::Gssi,
                },
                link_id: 0,
                endpoint_id: 0,
                tl_sdu,
                stealing_permission: false,
                subscriber_class: 0,
                fcs_flag: false,
                air_interface_encryption: None,
                packet_data_flag: false,
                n_tlsdu_repeats: 0,
                data_class_info: None,
                req_handle: 0,
                chan_alloc: None,
                associated_channel: None,
                tx_reporter: None,
            }),
        });
        tracing::debug!(
            directory_version = self.snapshot_version,
            neighbours = batch.len(),
            time = network_time.is_some(),
            "D-NWRK-BROADCAST queued"
        );
    }

    fn next_neighbour_batch(&mut self) -> Vec<NeighbourCell> {
        if self.neighbours.is_empty() {
            return Vec::new();
        }
        let batches = self.neighbours.len().div_ceil(7);
        let index = self.next_batch % batches;
        self.next_batch = (index + 1) % batches;
        let start = index * 7;
        self.neighbours[start..self.neighbours.len().min(start + 7)].to_vec()
    }
}

fn neighbour_to_air(neighbour: &NeighbourCell) -> NeighbourCellInformationForCa {
    let report = &neighbour.report;
    let flags = report.service_flags;
    NeighbourCellInformationForCa {
        cell_identifier_ca: neighbour.cell_identifier_ca,
        // 10: forward registration supported, expedited reselection not recommended.
        cell_reselection_types_supported: 0b10,
        synchronized: report.synchronized,
        cell_load_ca: report.cell_load_ca,
        main_carrier_number: report.main_carrier,
        main_carrier_number_extension: None,
        mcc: Some(report.cell.mcc),
        mnc: Some(report.cell.mnc),
        location_area: Some(report.cell.location_area),
        ms_txpwr_max_cell: Some(report.ms_txpwr_max_cell),
        rxlev_access_min: Some(report.rxlev_access_min),
        subscriber_class: Some(report.subscriber_class),
        bs_service_details: Some(BsServiceDetails {
            registration: flags & (1 << 0) != 0,
            deregistration: flags & (1 << 1) != 0,
            priority_cell: flags & (1 << 2) != 0,
            no_minimum_mode: flags & (1 << 3) != 0,
            migration: flags & (1 << 4) != 0,
            system_wide_services: flags & (1 << 5) != 0,
            voice_service: flags & (1 << 6) != 0,
            circuit_mode_data_service: flags & (1 << 7) != 0,
            sndcp_service: flags & (1 << 8) != 0,
            aie_service: flags & (1 << 9) != 0,
            advanced_link: flags & (1 << 10) != 0,
        }),
        timeshare_security_parameters: None,
        tdma_frame_offset: report.synchronized.then_some(report.tdma_frame_offset),
    }
}
