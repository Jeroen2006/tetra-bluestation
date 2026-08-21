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

use tetra_config::bluestation::{CfgSwmi, SharedConfig};
use tetra_swmi_protocol::{CellConfig, SwmiMessage, SystemInfoReport, WEBSOCKET_CONTROL_SUBPROTOCOL};

use crate::network::transports::{
    NetworkTransport,
    websocket::{WebSocketTransport, WebSocketTransportConfig},
};

pub mod entity;

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
    media_incoming: Sender<SwmiMessage>,
    online: Arc<AtomicBool>,
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
pub fn channel() -> (SwmiWorkerEndpoint, SwmiMmEndpoint, SwmiCmceEndpoint, SwmiMediaEndpoint) {
    let (outgoing_tx, outgoing_rx) = crossbeam_channel::unbounded();
    let (mm_incoming_tx, mm_incoming_rx) = crossbeam_channel::unbounded();
    let (cmce_incoming_tx, cmce_incoming_rx) = crossbeam_channel::unbounded();
    let (media_incoming_tx, media_incoming_rx) = crossbeam_channel::unbounded();
    let online = Arc::new(AtomicBool::new(false));
    (
        SwmiWorkerEndpoint {
            outgoing: outgoing_rx,
            mm_incoming: mm_incoming_tx,
            cmce_incoming: cmce_incoming_tx,
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
}

impl LocalRadioProfile {
    fn from_config(config: &SharedConfig) -> Self {
        let cfg = config.config();
        let cell = &cfg.cell;
        let service_flags = u16::from(cell.registration)
            | (u16::from(cell.deregistration) << 1)
            | (u16::from(cell.voice_service) << 2)
            | (u16::from(cell.circuit_mode_data_service) << 3)
            | (u16::from(cell.sndcp_service) << 4)
            | (u16::from(cell.aie_service) << 5)
            | (u16::from(cell.advanced_link) << 6);
        Self {
            main_carrier: cell.main_carrier,
            frequency_band: cell.freq_band,
            frequency_offset_hz: cell.freq_offset_hz,
            duplex_spacing_id: cell.duplex_spacing_id,
            reverse_operation: cell.reverse_operation,
            colour_code: cell.colour_code,
            system_code: cell.system_code,
            service_flags,
        }
    }

    fn report(&self, cell: CellConfig) -> SystemInfoReport {
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
            service_flags: self.service_flags,
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
                            tracing::info!(
                                config_version = cell.config_version,
                                mcc = cell.mcc,
                                mnc = cell.mnc,
                                location_area = cell.location_area,
                                authentication_required = cell.authentication_required,
                                "SwMI cell configuration received"
                            );
                            // The central SwMI is authoritative for the serving
                            // cell policy.  UMAC reads this mutable value and
                            // updates the broadcast Extended Services field.
                            self.stack_config.state_write().authentication_required = cell.authentication_required;
                            let report_command_id = self.next_command_id();
                            let accepted = self.send(SwmiMessage::SystemInfoReport {
                                command_id: report_command_id,
                                report: self.profile.report(cell),
                            });
                            let _ = self.send(SwmiMessage::Receipt {
                                command_id,
                                accepted,
                                code: if accepted { 0 } else { 1 },
                            });
                            self.endpoint.online.store(accepted, Ordering::Release);
                            // System-wide services are broadcast by UMAC.  Keep
                            // that radio indication aligned with the *usable*
                            // SwMI session (cell configuration accepted and
                            // SYSINFO report queued), rather than merely with
                            // the presence of a [swmi] configuration section.
                            self.stack_config.state_write().network_connected = accepted;
                        }
                        Ok(SwmiMessage::Receipt {
                            command_id,
                            accepted,
                            code,
                        }) => tracing::debug!(command_id, accepted, code, "SwMI command receipt"),
                        Ok(
                            message @ (SwmiMessage::RegistrationDecision { .. }
                            | SwmiMessage::AttachmentDecision { .. }
                            | SwmiMessage::AuthenticationChallenge { .. }
                            | SwmiMessage::AuthenticationResponseDemand { .. }
                            | SwmiMessage::AuthenticationResult { .. }),
                        ) => {
                            if self.endpoint.mm_incoming.send(message).is_err() {
                                tracing::warn!("SwMI MM endpoint closed; dropping central decision");
                            }
                        }
                        Ok(
                            message @ (SwmiMessage::GroupCallStart { .. }
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
                            | SwmiMessage::PrivateCallRelease { .. }
                            | SwmiMessage::PrivateFloorGranted { .. }
                            | SwmiMessage::PrivateFloorReleased { .. }
                            | SwmiMessage::PrivateCallKeepalive { .. }),
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
