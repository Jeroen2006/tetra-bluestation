//! Native BlueStation client for the central SwMI.
//!
//! This module intentionally has no legacy protocol naming.  It owns the
//! connection, handshake, heartbeat and serving-cell SYSINFO reporting.  MM
//! and CMCE authority routing will be attached to this client in the next
//! slice.

use std::{
    fs::File,
    io::BufReader,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Instant,
};

use crossbeam_channel::{Receiver, Sender, TryRecvError, TrySendError};

use tetra_config::bluestation::{CfgSwmi, RuntimeAieConfig, RuntimeNetworkBroadcast, RuntimeSc2Aie, RuntimeSc2Binding, RuntimeSc2RolloverEvent, RuntimeSc2TeaAlgorithm, SharedConfig};
use tetra_swmi_protocol::{
    CellConfig, NeighbourCellSnapshot, Sc2RolloverStatus, Sc2TeaAlgorithm, SwmiMessage, SystemInfoReport, WEBSOCKET_CONTROL_SUBPROTOCOL,
};

use crate::network::transports::{
    NetworkTransport,
    websocket::{WebSocketTransport, WebSocketTransportConfig},
};

pub mod entity;

fn runtime_aie_config(cell: &CellConfig) -> Result<RuntimeAieConfig, &'static str> {
    if !cell.aie.enabled {
        return Ok(RuntimeAieConfig {
            enabled: false,
            sc1_allowed: cell.aie.sc1_allowed,
            sc2: None,
            rollover: None,
        });
    }
    let Some(sc2) = cell.aie.sc2 else {
        return Err("active SwMI AIE configuration is missing SC2 settings");
    };
    let Some(key) = sc2.key else {
        return Err("active SwMI SC2 configuration is missing SCK material");
    };
    Ok(RuntimeAieConfig {
        enabled: true,
        sc1_allowed: cell.aie.sc1_allowed,
        sc2: Some(RuntimeSc2Aie::new(
            match sc2.algorithm {
                Sc2TeaAlgorithm::Tea1 => RuntimeSc2TeaAlgorithm::Tea1,
                Sc2TeaAlgorithm::Tea3 => RuntimeSc2TeaAlgorithm::Tea3,
            },
            sc2.sckn,
            sc2.sck_vn,
            key,
        )),
        rollover: None,
    })
}

pub fn build_websocket_transport(config: &CfgSwmi) -> Result<WebSocketTransport, String> {
    let custom_root_certs = load_swmi_ca_certificate(config)?;
    Ok(WebSocketTransport::new(WebSocketTransportConfig {
        host: config.host.clone(),
        port: config.port,
        use_tls: config.tls,
        custom_root_certs,
        basic_auth_credentials: None,
        digest_auth_credentials: Some((config.username.clone(), config.password.clone())),
        endpoint_path: "/swmi/".to_owned(),
        subprotocol: Some(WEBSOCKET_CONTROL_SUBPROTOCOL.to_owned()),
        user_agent: format!("BlueStation/{}", tetra_core::STACK_VERSION),
        extra_headers: Vec::new(),
        heartbeat_interval: config.heartbeat_interval,
        heartbeat_timeout: config.heartbeat_timeout,
    }))
}

fn load_swmi_ca_certificate(config: &CfgSwmi) -> Result<Option<Vec<rustls::pki_types::CertificateDer<'static>>>, String> {
    let Some(path) = &config.ca_certificate else {
        return Ok(None);
    };
    let file = File::open(path).map_err(|error| format!("open {path:?}: {error}"))?;
    let mut reader = BufReader::new(file);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("parse PEM certificate {path:?}: {error}"))?;
    if certificates.is_empty() {
        return Err(format!("PEM certificate {path:?} contains no certificates"));
    }
    Ok(Some(certificates))
}

/// MM's non-blocking end of the SwMI link. It is deliberately owned by the
/// radio/router thread; the WSS transport lives exclusively in `SwmiWorker`.
pub struct SwmiMmEndpoint {
    outgoing: Sender<SwmiMessage>,
    incoming: Receiver<SwmiMessage>,
    online: Arc<AtomicBool>,
}

impl SwmiMmEndpoint {
    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }

    pub fn submit(&self, message: SwmiMessage) -> Result<(), SwmiMessage> {
        self.outgoing.try_send(message).map_err(|error| match error {
            TrySendError::Full(message) | TrySendError::Disconnected(message) => message,
        })
    }

    pub fn try_recv(&self) -> Option<SwmiMessage> {
        match self.incoming.try_recv() {
            Ok(message) => Some(message),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    }
}

pub struct SwmiWorkerEndpoint {
    outgoing: Receiver<SwmiMessage>,
    mm_incoming: Sender<SwmiMessage>,
    cmce_incoming: Sender<SwmiMessage>,
    mle_incoming: Sender<NeighbourCellSnapshot>,
    media_incoming: Sender<SwmiMessage>,
    online: Arc<AtomicBool>,
}

/// MLE's non-blocking view of the centrally resolved neighbour directory.
/// It is separate from MM/CMCE because the MLE owns D-NWRK-BROADCAST.
pub struct SwmiMleEndpoint {
    incoming: Receiver<NeighbourCellSnapshot>,
}

impl SwmiMleEndpoint {
    pub fn try_recv(&self) -> Option<NeighbourCellSnapshot> {
        self.incoming.try_recv().ok()
    }
}

/// User-plane endpoint owned by the radio/router thread.  The WSS worker is
/// the only networking owner; this endpoint is intentionally non-blocking so
/// a congested SwMI link can never stall TDMA processing.
pub struct SwmiMediaEndpoint {
    outgoing: Sender<SwmiMessage>,
    incoming: Receiver<SwmiMessage>,
    online: Arc<AtomicBool>,
}

impl SwmiMediaEndpoint {
    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }
    pub fn submit(&self, message: SwmiMessage) -> Result<(), SwmiMessage> {
        self.outgoing.try_send(message).map_err(|error| match error {
            TrySendError::Full(message) | TrySendError::Disconnected(message) => message,
        })
    }
    pub fn try_recv(&self) -> Option<SwmiMessage> {
        match self.incoming.try_recv() {
            Ok(message) => Some(message),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    }
}

/// CMCE's independent non-blocking endpoint.  MM and CMCE never compete for
/// the same receiver, while both submit requests through the worker's single
/// ordered WSS egress queue.
#[derive(Clone)]
pub struct SwmiCmceEndpoint {
    outgoing: Sender<SwmiMessage>,
    incoming: Receiver<SwmiMessage>,
    online: Arc<AtomicBool>,
}

impl SwmiCmceEndpoint {
    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }

    pub fn submit(&self, message: SwmiMessage) -> Result<(), SwmiMessage> {
        self.outgoing.try_send(message).map_err(|error| match error {
            TrySendError::Full(message) | TrySendError::Disconnected(message) => message,
        })
    }

    pub fn try_recv(&self) -> Option<SwmiMessage> {
        match self.incoming.try_recv() {
            Ok(message) => Some(message),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    }
}

/// Build the two thread-safe ends before entities are constructed. This keeps
/// the transport worker separate from MM and makes LST selection instantaneous.
pub fn channel() -> (
    SwmiWorkerEndpoint,
    SwmiMmEndpoint,
    SwmiCmceEndpoint,
    SwmiMleEndpoint,
    SwmiMediaEndpoint,
) {
    let (outgoing_tx, outgoing_rx) = crossbeam_channel::unbounded();
    let (mm_incoming_tx, mm_incoming_rx) = crossbeam_channel::unbounded();
    let (cmce_incoming_tx, cmce_incoming_rx) = crossbeam_channel::unbounded();
    let (mle_incoming_tx, mle_incoming_rx) = crossbeam_channel::unbounded();
    let (media_incoming_tx, media_incoming_rx) = crossbeam_channel::unbounded();
    let online = Arc::new(AtomicBool::new(false));
    (
        SwmiWorkerEndpoint {
            outgoing: outgoing_rx,
            mm_incoming: mm_incoming_tx,
            cmce_incoming: cmce_incoming_tx,
            mle_incoming: mle_incoming_tx,
            media_incoming: media_incoming_tx,
            online: online.clone(),
        },
        SwmiMmEndpoint {
            outgoing: outgoing_tx.clone(),
            incoming: mm_incoming_rx,
            online: online.clone(),
        },
        SwmiCmceEndpoint {
            outgoing: outgoing_tx.clone(),
            incoming: cmce_incoming_rx,
            online: online.clone(),
        },
        SwmiMleEndpoint { incoming: mle_incoming_rx },
        SwmiMediaEndpoint {
            outgoing: outgoing_tx,
            incoming: media_incoming_rx,
            online,
        },
    )
}

pub fn start(config: SharedConfig, endpoint: SwmiWorkerEndpoint) -> Option<thread::JoinHandle<()>> {
    let swmi = config.config().swmi.clone()?;
    let profile = LocalRadioProfile::from_config(&config);
    let transport = match build_websocket_transport(&swmi) {
        Ok(transport) => transport,
        Err(error) => {
            tracing::error!(error = %error, "SwMI worker not started: invalid TLS trust configuration");
            return None;
        }
    };
    Some(thread::spawn(move || {
        SwmiWorker::new(config, swmi, profile, transport, endpoint).run()
    }))
}

#[derive(Debug, Clone)]
struct LocalRadioProfile {
    main_carrier: u16,
    frequency_band: u8,
    frequency_offset_hz: i16,
    duplex_spacing_id: u8,
    reverse_operation: bool,
    colour_code: u8,
    system_code: u8,
    service_flags: u16,
    ms_txpwr_max_cell: u8,
    rxlev_access_min: u8,
    subscriber_class: u16,
    tdma_synchronized: bool,
    tdma_frame_offset: u8,
}

impl LocalRadioProfile {
    const SYSTEM_WIDE_SERVICES_FLAG: u16 = 1 << 5;
    const AIE_SERVICE_FLAG: u16 = 1 << 9;

    fn from_config(config: &SharedConfig) -> Self {
        let cfg = config.config();
        let cell = &cfg.cell;
        let service_flags = u16::from(cell.registration)
            | (u16::from(cell.deregistration) << 1)
            | (u16::from(cell.priority_cell) << 2)
            | (u16::from(cell.no_minimum_mode) << 3)
            | (u16::from(cell.migration) << 4)
            | (u16::from(cell.system_wide_services) << 5)
            | (u16::from(cell.voice_service) << 6)
            | (u16::from(cell.circuit_mode_data_service) << 7)
            | (u16::from(cell.sndcp_service) << 8)
            | (u16::from(cell.aie_service) << 9)
            | (u16::from(cell.advanced_link) << 10);
        Self {
            main_carrier: cell.main_carrier,
            frequency_band: cell.freq_band,
            frequency_offset_hz: cell.freq_offset_hz,
            duplex_spacing_id: cell.duplex_spacing_id,
            reverse_operation: cell.reverse_operation,
            colour_code: cell.colour_code,
            system_code: cell.system_code,
            service_flags,
            ms_txpwr_max_cell: cell.ms_txpwr_max_cell,
            rxlev_access_min: cell.rxlev_access_min,
            subscriber_class: cell.subscriber_class,
            tdma_synchronized: cell.tdma_synchronized,
            tdma_frame_offset: cell.tdma_frame_offset,
        }
    }

    /// The service details advertised for a neighbour must agree with the
    /// serving cell's effective state.  In particular, a BS with a configured
    /// SwMI uses the live connection state for `system_wide_services`, rather
    /// than the local fallback configuration value.
    fn effective_service_flags(&self, network_connected: bool, aie_enabled: bool) -> u16 {
        // AIE is an SwMI-owned runtime policy. Do not reuse the static local
        // cell setting here, otherwise a neighbour snapshot can advertise an
        // active SC2 cell with its Air Interface Encryption Service bit clear.
        (self.service_flags & !(Self::SYSTEM_WIDE_SERVICES_FLAG | Self::AIE_SERVICE_FLAG))
            | (u16::from(network_connected) << 5)
            | (u16::from(aie_enabled) << 9)
    }

    fn report(&self, cell: CellConfig, runtime: &RuntimeNetworkBroadcast, network_connected: bool) -> SystemInfoReport {
        SystemInfoReport {
            report_version: cell.config_version,
            cell,
            main_carrier: self.main_carrier,
            frequency_band: self.frequency_band,
            frequency_offset_hz: self.frequency_offset_hz,
            duplex_spacing_id: self.duplex_spacing_id,
            reverse_operation: self.reverse_operation,
            colour_code: self.colour_code,
            system_code: self.system_code,
            service_flags: self.effective_service_flags(network_connected, cell.aie.enabled),
            ms_txpwr_max_cell: self.ms_txpwr_max_cell,
            rxlev_access_min: self.rxlev_access_min,
            subscriber_class: self.subscriber_class,
            cell_load_ca: runtime.broadcast.cell_load_ca,
            neighbour_station_ids: runtime.neighbours.ids.clone(),
            synchronized: self.tdma_synchronized,
            tdma_frame_offset: self.tdma_frame_offset,
        }
    }
}

struct SwmiWorker<T: NetworkTransport> {
    stack_config: SharedConfig,
    config: CfgSwmi,
    profile: LocalRadioProfile,
    transport: T,
    endpoint: SwmiWorkerEndpoint,
    heartbeat_sequence: u64,
    command_sequence: u64,
    current_cell_config: Option<CellConfig>,
    last_advertisement_version: u64,
    recovery_request_id: Option<u64>,
}

impl<T: NetworkTransport> SwmiWorker<T> {
    fn new(stack_config: SharedConfig, config: CfgSwmi, profile: LocalRadioProfile, transport: T, endpoint: SwmiWorkerEndpoint) -> Self {
        Self {
            stack_config,
            config,
            profile,
            transport,
            endpoint,
            heartbeat_sequence: 0,
            command_sequence: 1,
            current_cell_config: None,
            last_advertisement_version: 0,
            recovery_request_id: None,
        }
    }

    fn run(&mut self) {
        loop {
            if let Err(error) = self.transport.connect() {
                self.endpoint.online.store(false, Ordering::Release);
                self.stack_config.state_write().network_connected = false;
                tracing::warn!(error = %error, "SwMI connection failed; retrying");
                thread::sleep(self.config.reconnect_delay);
                continue;
            }
            tracing::info!(host = %self.config.host, "SwMI control connection established");
            self.recovery_request_id = None;
            if !self.send(SwmiMessage::Hello {
                connection_epoch: 0,
                software_version: tetra_core::STACK_VERSION.to_owned(),
            }) {
                self.endpoint.online.store(false, Ordering::Release);
                self.stack_config.state_write().network_connected = false;
                continue;
            }

            let mut last_heartbeat = Instant::now();
            while self.transport.is_connected() {
                for incoming in self.transport.receive_reliable() {
                    match SwmiMessage::decode(&incoming.payload) {
                        Ok(SwmiMessage::CellConfig { command_id, cell }) => {
                            // A CellConfig also arrives during initial LST
                            // recovery.  Once that recovery is complete,
                            // though, it is a live policy update (for example
                            // an SCK/SCK-VN rotation), not a loss of SwMI
                            // service.  Do not take system-wide services down
                            // for an already-online connection.
                            let was_online = self.endpoint.online.load(Ordering::Acquire);
                            let aie = match runtime_aie_config(&cell) {
                                Ok(aie) => aie,
                                Err(error) => {
                                    tracing::warn!(
                                        config_version = cell.config_version,
                                        error,
                                        "rejecting incomplete SwMI AIE configuration"
                                    );
                                    let _ = self.send(SwmiMessage::Receipt {
                                        command_id,
                                        accepted: false,
                                        code: 2,
                                    });
                                    continue;
                                }
                            };
                            tracing::info!(
                                config_version = cell.config_version,
                                mcc = cell.mcc,
                                mnc = cell.mnc,
                                location_area = cell.location_area,
                                authentication_required = cell.authentication_required,
                                aie_enabled = aie.enabled,
                                sc1_allowed = aie.sc1_allowed,
                                sckn = aie.sc2.as_ref().map(|sc2| sc2.sckn),
                                sck_vn = aie.sc2.as_ref().map(|sc2| sc2.sck_vn),
                                algorithm = ?aie.sc2.as_ref().map(|sc2| sc2.algorithm),
                                "SwMI cell configuration received"
                            );
                            // The central SwMI is authoritative for the serving
                            // cell policy.  UMAC reads this mutable value and
                            // updates the broadcast Extended Services field.
                            {
                                let mut state = self.stack_config.state_write();
                                state.authentication_required = cell.authentication_required;
                                state.aie = aie;
                                // A changed SCKN/SCK-VN may not leave an old
                                // per-terminal/call binding usable. The SCK
                                // itself remains only in `state.aie`.
                                let current_sc2 = if state.aie.enabled { state.aie.sc2.clone() } else { None };
                                state.aie_sessions.retain_current_key(current_sc2.as_ref());
                                if !was_online {
                                    state.network_connected = false;
                                }
                            }
                            self.current_cell_config = Some(cell);
                            let accepted = self.report_current_advertisement();
                            let _ = self.send(SwmiMessage::Receipt {
                                command_id,
                                accepted,
                                code: if accepted { 0 } else { 1 },
                            });
                            if !was_online {
                                // This session remains in LST until the SwMI
                                // has reconciled the local subscriber snapshot.
                                self.endpoint.online.store(false, Ordering::Release);
                                self.stack_config.state_write().network_connected = false;
                            }
                        }
                        Ok(SwmiMessage::Sc2RolloverPrepare {
                            command_id,
                            rollover_id,
                            active,
                            future,
                            activation_network_time,
                        }) => {
                            let result = (|| {
                                let broadcast_ready = {
                                    let state = self.stack_config.state_read();
                                    state.network_broadcast.broadcast.time_enabled
                                        && state.network_broadcast.broadcast.timezone.is_some()
                                };
                                if !broadcast_ready {
                                    return Err("TETRA Network Time broadcast is not configured");
                                }
                                let key = future.key.ok_or("rollover future SCK is missing")?;
                                let algorithm = match future.algorithm {
                                    Sc2TeaAlgorithm::Tea1 => RuntimeSc2TeaAlgorithm::Tea1,
                                    Sc2TeaAlgorithm::Tea3 => RuntimeSc2TeaAlgorithm::Tea3,
                                };
                                let active_algorithm = match active.algorithm {
                                    Sc2TeaAlgorithm::Tea1 => tetra_core::AieAlgorithm::Tea1,
                                    Sc2TeaAlgorithm::Tea3 => tetra_core::AieAlgorithm::Tea3,
                                };
                                let binding = RuntimeSc2Binding {
                                    key: tetra_core::Sc2KeyIdentifier::new(active_algorithm, active.sckn, active.sck_vn)
                                        .ok_or("invalid rollover active identity")?,
                                };
                                self.stack_config
                                    .state_write()
                                    .aie
                                    .stage_rollover(
                                        rollover_id,
                                        binding,
                                        RuntimeSc2Aie::new(algorithm, future.sckn, future.sck_vn, key),
                                        activation_network_time,
                                    )
                            })();
                            let (accepted, detail) = match result {
                                Ok(()) => (true, None),
                                Err(error) => {
                                    tracing::warn!(command_id, rollover_id, error, "rejecting SC2 rollover prepare");
                                    (false, Some(error.to_owned()))
                                }
                            };
                            let already_activated = accepted
                                && self
                                    .stack_config
                                    .state_read()
                                    .aie
                                    .rollover_is_activated(rollover_id);
                            let local_network_time = self
                                .stack_config
                                .state_read()
                                .network_broadcast
                                .broadcast
                                .timezone
                                .as_deref()
                                .and_then(crate::mle::components::network_time::encode_tetra_network_time);
                            let _ = self.send(SwmiMessage::Receipt {
                                command_id,
                                accepted,
                                code: if accepted { 0 } else { 2 },
                            });
                            let _ = self.send(SwmiMessage::Sc2RolloverStatus {
                                command_id,
                                rollover_id,
                                status: if !accepted {
                                    Sc2RolloverStatus::Rejected
                                } else if already_activated {
                                    Sc2RolloverStatus::Activated
                                } else {
                                    Sc2RolloverStatus::Prepared
                                },
                                local_cutover_network_time: local_network_time,
                                detail,
                            });
                            if accepted
                                && self
                                    .endpoint
                                    .mm_incoming
                                    .send(SwmiMessage::Sc2RolloverPrepare {
                                        command_id,
                                        rollover_id,
                                        active,
                                        future,
                                        activation_network_time,
                                    })
                                    .is_err()
                            {
                                tracing::warn!(rollover_id, "SwMI MM endpoint closed; cannot announce SC2 rollover on air");
                            }
                        }
                        Ok(SwmiMessage::Sc2RolloverCancel { command_id, rollover_id }) => {
                            let cancelled = self
                                .stack_config
                                .state_write()
                                .aie
                                .cancel_staged_rollover(rollover_id);
                            let _ = self.send(SwmiMessage::Receipt {
                                command_id,
                                accepted: cancelled,
                                code: if cancelled { 0 } else { 2 },
                            });
                            if cancelled {
                                tracing::info!(rollover_id, "cancelled staged SC2 rollover");
                            } else {
                                tracing::warn!(rollover_id, "cannot cancel unknown or already active SC2 rollover");
                            }
                        }
                        Ok(SwmiMessage::Receipt {
                            command_id,
                            accepted,
                            code,
                        }) => tracing::debug!(command_id, accepted, code, "SwMI command receipt"),
                        Ok(
                            message @ (SwmiMessage::RegistrationDecision { .. }
                            | SwmiMessage::AttachmentDecision { .. }
                            | SwmiMessage::EnergyEconomyDecision { .. }
                            | SwmiMessage::EnergyEconomyRebaseRequest { .. }
                            | SwmiMessage::SubscriberStateSync { .. }
                            | SwmiMessage::LstRecoveryRequest { .. }
                            | SwmiMessage::DeregistrationNotice { .. }
                            | SwmiMessage::AuthenticationChallenge { .. }
                            | SwmiMessage::AuthenticationResponseDemand { .. }
                            | SwmiMessage::AuthenticationResult { .. }
                            | SwmiMessage::OtarDownlink { .. }
                            | SwmiMessage::LivelinessCheck { .. }),
                        ) => {
                            if let SwmiMessage::LstRecoveryRequest { command_id } = &message {
                                self.recovery_request_id = Some(*command_id);
                            }
                            if self.endpoint.mm_incoming.send(message).is_err() {
                                tracing::warn!("SwMI MM endpoint closed; dropping central decision");
                            }
                        }
                        Ok(message @ SwmiMessage::LstRecoveryResult { command_id, .. }) => {
                            if self.recovery_request_id != Some(command_id) {
                                tracing::warn!(command_id, expected = ?self.recovery_request_id, "stale LST recovery result ignored");
                                continue;
                            }
                            self.recovery_request_id = None;
                            self.endpoint.online.store(true, Ordering::Release);
                            self.stack_config.state_write().network_connected = true;
                            // The initial advertisement is sent while LST is
                            // active and therefore carries
                            // system_wide_services = 0.  Publish it again now
                            // that this cell is available to the SwMI, so its
                            // neighbour-cell snapshot carries the live value.
                            let _ = self.report_current_advertisement();
                            if self.endpoint.mm_incoming.send(message).is_err() {
                                tracing::warn!("SwMI MM endpoint closed; dropping LST recovery result");
                            }
                        }
                        Ok(SwmiMessage::NeighbourCellSnapshot(snapshot)) => {
                            if self.endpoint.mle_incoming.send(snapshot).is_err() {
                                tracing::warn!("SwMI MLE endpoint closed; dropping neighbour snapshot");
                            }
                        }
                        Ok(
                            message @ (SwmiMessage::GroupCallStart { .. }
                            | SwmiMessage::GroupCallPriorityChanged { .. }
                            | SwmiMessage::FloorPreempted { .. }
                            | SwmiMessage::FloorGranted { .. }
                            | SwmiMessage::FloorReleased { .. }
                            | SwmiMessage::CallDisconnect { .. }
                            | SwmiMessage::CallRelease { .. }
                            | SwmiMessage::CallReject { .. }
                            | SwmiMessage::PrivateCallProceeding { .. }
                            | SwmiMessage::PrivateCallOffer { .. }
                            | SwmiMessage::PrivateCallAlert { .. }
                            | SwmiMessage::PrivateCallReserve { .. }
                            | SwmiMessage::PrivateCallConnected { .. }
                            | SwmiMessage::PrivateCallRestore { .. }
                            | SwmiMessage::PrivateCallEndpointMoved { .. }
                            | SwmiMessage::PrivateCallRelease { .. }
                            | SwmiMessage::PrivateFloorGranted { .. }
                            | SwmiMessage::PrivateFloorReleased { .. }
                            | SwmiMessage::PrivateCallKeepalive { .. }
                            | SwmiMessage::HandoverReserveGroupCall { .. }
                            | SwmiMessage::SdsDeliver { .. }
                            | SwmiMessage::SdsFailure { .. }
                            | SwmiMessage::StatusDeliver { .. }
                            | SwmiMessage::DgnaCommand { .. }),
                        ) => {
                            if self.endpoint.cmce_incoming.send(message).is_err() {
                                tracing::warn!("SwMI CMCE endpoint closed; dropping central call action");
                            }
                        }
                        Ok(message @ (SwmiMessage::VoiceFrame { .. } | SwmiMessage::PrivateVoiceFrame { .. })) => {
                            if self.endpoint.media_incoming.send(message).is_err() {
                                tracing::warn!("SwMI media endpoint closed; dropping voice frame");
                            }
                        }
                        Ok(message) => tracing::debug!(?message, "SwMI message received"),
                        Err(error) => tracing::warn!(error = %error, "invalid SwMI message ignored"),
                    }
                }
                while let Ok(message) = self.endpoint.outgoing.try_recv() {
                    if !self.send(message) {
                        break;
                    }
                }
                let rollover_events: Vec<RuntimeSc2RolloverEvent> = self
                    .stack_config
                    .state_write()
                    .sc2_rollover_events
                    .drain(..)
                    .collect();
                for event in rollover_events {
                    let command_id = self.next_command_id();
                    let _ = self.send(SwmiMessage::Sc2RolloverStatus {
                        command_id,
                        rollover_id: event.rollover_id,
                        status: if event.activated { Sc2RolloverStatus::Activated } else { Sc2RolloverStatus::Failed },
                        local_cutover_network_time: Some(event.local_network_time),
                        detail: None,
                    });
                }
                let advertisement_version = self.stack_config.state_read().network_broadcast.version;
                if self.current_cell_config.is_some() && advertisement_version != self.last_advertisement_version {
                    let _ = self.report_current_advertisement();
                }
                if last_heartbeat.elapsed() >= self.config.heartbeat_interval {
                    self.heartbeat_sequence += 1;
                    if !self.send(SwmiMessage::Heartbeat {
                        connection_epoch: 0,
                        sequence: self.heartbeat_sequence,
                    }) {
                        break;
                    }
                    last_heartbeat = Instant::now();
                }
                thread::sleep(std::time::Duration::from_millis(20));
            }
            tracing::warn!("SwMI control connection lost; entering reconnect loop");
            self.endpoint.online.store(false, Ordering::Release);
            self.stack_config.state_write().network_connected = false;
            thread::sleep(self.config.reconnect_delay);
        }
    }

    fn next_command_id(&mut self) -> u64 {
        let id = self.command_sequence;
        self.command_sequence += 1;
        id
    }
    fn report_current_advertisement(&mut self) -> bool {
        let Some(cell) = self.current_cell_config.clone() else {
            return false;
        };
        let runtime = self.stack_config.state_read().network_broadcast.clone();
        let network_connected = self.stack_config.state_read().network_connected;
        let command_id = self.next_command_id();
        let accepted = self.send(SwmiMessage::SystemInfoReport {
            command_id,
            report: self.profile.report(cell, &runtime, network_connected),
        });
        if accepted {
            self.last_advertisement_version = runtime.version;
        }
        accepted
    }
    fn send(&mut self, message: SwmiMessage) -> bool {
        let bytes = match message.encode() {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(error = %error, "SwMI message encoding failed");
                return false;
            }
        };
        match self.transport.send_reliable(&bytes) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(error = %error, "SwMI send failed");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalRadioProfile, runtime_aie_config};
    use tetra_config::bluestation::RuntimeSc2TeaAlgorithm;
    use tetra_swmi_protocol::{CellAieConfig, CellConfig, Sc2AieConfig, Sc2TeaAlgorithm};

    #[test]
    fn runtime_aie_config_retains_the_tea_algorithm_from_swmi() {
        let runtime = runtime_aie_config(&CellConfig {
            config_version: 1,
            mcc: 204,
            mnc: 2671,
            location_area: 42,
            authentication_required: false,
            aie: CellAieConfig {
                enabled: true,
                sc1_allowed: false,
                sc2: Some(Sc2AieConfig {
                    algorithm: Sc2TeaAlgorithm::Tea3,
                    sckn: 30,
                    sck_vn: 7,
                    key: Some([0x5a; 10]),
                }),
            },
        })
        .expect("valid AIE configuration");

        assert_eq!(runtime.sc2.expect("SC2 settings").algorithm, RuntimeSc2TeaAlgorithm::Tea3);
    }

    #[test]
    fn neighbour_service_flags_follow_the_effective_swmi_connection_state() {
        let profile = LocalRadioProfile {
            // registration, deregistration and voice enabled; local fallback
            // system-wide services disabled.
            service_flags: (1 << 0) | (1 << 1) | (1 << 6),
            main_carrier: 0,
            frequency_band: 0,
            frequency_offset_hz: 0,
            duplex_spacing_id: 0,
            reverse_operation: false,
            colour_code: 0,
            system_code: 0,
            ms_txpwr_max_cell: 0,
            rxlev_access_min: 0,
            subscriber_class: 0,
            tdma_synchronized: false,
            tdma_frame_offset: 0,
        };

        assert_eq!(profile.effective_service_flags(false, false), 0b000_0100_0011);
        assert_eq!(profile.effective_service_flags(true, false), 0b000_0110_0011);
        assert_eq!(profile.effective_service_flags(true, true), 0b100_0110_0011);
    }
}
