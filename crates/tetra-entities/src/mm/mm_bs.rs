use crate::net_control::ControlEndpoint;
use crate::net_telemetry::channel::TelemetrySink;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::net_swmi::SwmiMmEndpoint;
use crate::{MessageQueue, TetraEntityTrait, net_brew};
use tetra_config::bluestation::{DmMsRouteAddress, DmoCarrierState, SharedConfig};
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::typed_pdu_fields::Type3FieldGeneric;
use tetra_core::{
    AieRequest, AieScope, AieSubject, BitBuffer, Layer2Service, Sap, SsiType, TdmaTime, TetraAddress, TxReporter, TxState, assert_warn,
    unimplemented_log,
};
use tetra_saps::control::brew::{BrewSubscriberAction, MmSubscriberUpdate};
use tetra_saps::control::call_control::CallControl;
use tetra_saps::lmm::{LmmMleSeamlessHandover, LmmMleUnitdataReq};
use tetra_saps::{SapMsg, SapMsgInner};
use tetra_swmi_protocol::{
    AieLocationUpdateDecision, AieObservationEvent, AieObservationState, AttachmentOperation, AttachmentResult, DmGatewayAddress,
    DmGatewayCarrier, EnergyEconomyAssignment, TerminalAieObservation,
    HandoverChannelAllocation, SwmiMessage,
};

use crate::mm::components::client_state::{MmClientMgr, MmClientState};
use crate::mm::components::not_supported::make_ul_mm_pdu_function_not_supported;
use tetra_pdus::mm::enums::energy_saving_mode::EnergySavingMode;
use tetra_pdus::mm::enums::location_update_type::LocationUpdateType;
use tetra_pdus::mm::enums::mm_pdu_type_ul::MmPduTypeUl;
use tetra_pdus::mm::enums::reject_cause::RejectCause;
use tetra_pdus::mm::enums::status_downlink::StatusDownlink;
use tetra_pdus::mm::enums::status_uplink::StatusUplink;
use tetra_pdus::mm::enums::type34_elem_id_dl::MmType34ElemIdDl;
use tetra_pdus::mm::fields::energy_saving_information::EnergySavingInformation;
use tetra_pdus::mm::fields::group_identity_attachment::GroupIdentityAttachment;
use tetra_pdus::mm::fields::group_identity_downlink::GroupIdentityDownlink;
use tetra_pdus::mm::fields::group_identity_location_accept::GroupIdentityLocationAccept;
use tetra_pdus::mm::fields::group_identity_uplink::GroupIdentityUplink;
use tetra_pdus::mm::pdus::ck_change::UCkChangeResult;
use tetra_pdus::mm::pdus::d_attach_detach_group_identity_acknowledgement::DAttachDetachGroupIdentityAcknowledgement;
use tetra_pdus::mm::pdus::d_authentication_demand::DAuthenticationDemand;
use tetra_pdus::mm::pdus::d_authentication_response::DAuthenticationResponse;
use tetra_pdus::mm::pdus::d_authentication_result::DAuthenticationResult;
use tetra_pdus::mm::pdus::d_location_update_accept::DLocationUpdateAccept;
use tetra_pdus::mm::pdus::d_location_update_command::DLocationUpdateCommand;
use tetra_pdus::mm::pdus::d_location_update_reject::DLocationUpdateReject;
use tetra_pdus::mm::pdus::d_mm_status::DMmStatus;
use tetra_pdus::mm::pdus::d_mm_status::DMmStatusGatewayPayload;
use tetra_pdus::mm::pdus::otar::{DOtar, UOtar};
use tetra_pdus::mm::pdus::u_attach_detach_group_identity::UAttachDetachGroupIdentity;
use tetra_pdus::mm::pdus::u_authentication::UAuthentication;
use tetra_pdus::mm::pdus::u_itsi_detach::UItsiDetach;
use tetra_pdus::mm::pdus::u_location_update_demand::ULocationUpdateDemand;
use tetra_pdus::mm::pdus::u_mm_status::UMmStatus;
use tetra_pdus::mm::pdus::u_mm_status::UMmStatusGatewayPayload;

/// ETSI T351 = 10 seconds. TETRA has 18 TDMA frames of four slots per second.
const T351_TIMESLOTS: i32 = 10 * 18 * 4;

/// TTR 001-11 Table 6.2 on-air KSG numbers. These are protocol values, not
/// the ordinal positions of the local TEA enum.
const fn sc2_ksg_number(algorithm: tetra_config::bluestation::RuntimeSc2TeaAlgorithm) -> u8 {
    match algorithm {
        tetra_config::bluestation::RuntimeSc2TeaAlgorithm::Tea1 => 0,
        tetra_config::bluestation::RuntimeSc2TeaAlgorithm::Tea3 => 2,
    }
}

/// Keep only a bounded, metadata-only history.  In particular, neither an
/// OTAR payload nor a sealed key is retained by the key-lifecycle tracker.
const MAX_RECENT_OTAR_DELIVERIES: usize = 64;

/// The response type which completes an OTAR transaction at the application
/// layer.  This is deliberately separate from a basic-link acknowledgement:
/// BL-ACK proves radio delivery, while a U-OTAR result reports provisioning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OtarTerminalResponse {
    CckResult,
    SckResult,
    GckResult,
    GskoResult,
    KeyStatusResponse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OtarDownlinkKind {
    CckProvide,
    CckReject,
    SckProvide,
    SckReject,
    GckProvide,
    GckReject,
    GskoProvide,
    GskoReject,
    KeyStatusDemand,
}

impl OtarDownlinkKind {
    fn from_pdu(pdu: &DOtar) -> Self {
        match pdu {
            DOtar::CckProvide(_) => Self::CckProvide,
            DOtar::CckReject(_) => Self::CckReject,
            DOtar::SckProvide(_) => Self::SckProvide,
            DOtar::SckReject(_) => Self::SckReject,
            DOtar::GckProvide(_) => Self::GckProvide,
            DOtar::GckReject(_) => Self::GckReject,
            DOtar::GskoProvide(_) => Self::GskoProvide,
            DOtar::GskoReject(_) => Self::GskoReject,
            DOtar::KeyStatusDemand(_) => Self::KeyStatusDemand,
        }
    }

    fn expected_response(self) -> Option<OtarTerminalResponse> {
        match self {
            Self::CckProvide => Some(OtarTerminalResponse::CckResult),
            Self::SckProvide => Some(OtarTerminalResponse::SckResult),
            Self::GckProvide => Some(OtarTerminalResponse::GckResult),
            Self::GskoProvide => Some(OtarTerminalResponse::GskoResult),
            Self::KeyStatusDemand => Some(OtarTerminalResponse::KeyStatusResponse),
            Self::CckReject | Self::SckReject | Self::GckReject | Self::GskoReject => None,
        }
    }

    /// TTR 001-11 6.2.17 explicitly permits only the GSKO bootstrap
    /// downlinks clear after an SC2 registration.  All other OTAR requests
    /// need the terminal's active SC2 context (or a non-SC2 policy).
    fn is_clear_gsko_bootstrap(self) -> bool {
        matches!(self, Self::GskoProvide | Self::GskoReject)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OtarDeliveryStatus {
    Queued,
    AirTransmitted,
    LinkAcknowledged,
    AwaitingTerminalResult,
    TerminalResult { success: bool },
    LinkFailed { state: TxState },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompletedOtarDelivery {
    command_id: u64,
    issi: u32,
    kind: OtarDownlinkKind,
    status: OtarDeliveryStatus,
}

/// The only mutable BS-side delivery state for a D-OTAR.  The opaque D-OTAR
/// payload is intentionally not copied here: LLC owns its retransmission
/// buffer and the result tracker contains identifiers only.
#[derive(Debug)]
struct PendingOtarDelivery {
    command_id: u64,
    issi: u32,
    air_handle: u32,
    kind: OtarDownlinkKind,
    expected_response: Option<OtarTerminalResponse>,
    tx_reporter: TxReporter,
    status: OtarDeliveryStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GskoBootstrapStatus {
    Requested,
    Providing {
        command_id: u64,
        version_number: u16,
        cmg_gssi: u32,
    },
    Provisioned {
        version_number: u16,
        cmg_gssi: u32,
    },
    Rejected {
        command_id: u64,
        cmg_gssi: u32,
        reason: u8,
    },
    Failed {
        command_id: u64,
    },
}

/// A CK result is retained as operational metadata only; SCK bytes remain in
/// the AIE provider and are never copied into MM state.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CkChangeResultStatus {
    change_of_security_class: u8,
    selected_sck_count: usize,
}

fn dm_ms_route_address(address: tetra_pdus::mm::fields::dm_ms_address::DmMsAddress) -> DmMsRouteAddress {
    DmMsRouteAddress {
        ssi: address.ssi,
        mcc: address.mcc,
        mnc: address.mnc,
    }
}

fn dmo_carrier_state(carrier: tetra_pdus::mm::fields::dmo_carrier::DmoCarrier) -> DmoCarrierState {
    DmoCarrierState {
        carrier_number: carrier.carrier_number,
        frequency_band: carrier.frequency_band,
        offset: carrier.offset,
        duplex_spacing: carrier.duplex_spacing,
        normal_reverse: carrier.normal_reverse,
    }
}

pub struct MmBs {
    config: SharedConfig,
    telemetry: Option<TelemetrySink>,
    control: Option<ControlEndpoint>,
    client_mgr: MmClientMgr,
    swmi: Option<SwmiMmEndpoint>,
    next_swmi_command_id: u64,
    pending_registrations: HashMap<u64, PendingRegistration>,
    registration_deadlines: HashMap<u64, TdmaTime>,
    pending_attachments: HashMap<u64, PendingAttachment>,
    pending_location_attachments: HashMap<u64, PendingLocationAttachment>,
    pending_energy_economy: HashMap<u64, (u32, u32)>,
    /// SwMI authentication correlation per terminal and air-interface handle.
    /// MLE reuses handle 0 for concurrent registrations, so a handle alone is
    /// not a unique key.
    pending_auth_commands: HashMap<(u32, u32), u64>,
    /// Registration command IDs for which the SwMI has completed successful
    /// authentication.  The final D-LOCATION UPDATE ACCEPT carries the
    /// Authentication Downlink only for these registrations.
    authenticated_registrations: HashSet<u64>,
    /// Recovery request IDs awaiting one canonical SwMI result. These are
    /// session-scoped; a stale result from an older connection is ignored.
    pending_lst_recoveries: HashSet<u64>,
    /// D-OTAR transmissions currently owned by LLC. This is key-free: the
    /// encoded, potentially sealed payload remains solely in LLC's retry
    /// buffer and is never logged by MM.
    pending_otar_deliveries: HashMap<u64, PendingOtarDelivery>,
    /// Bounded radio/application outcomes for diagnostics and future SwMI
    /// lifecycle reporting. The entries contain no payload or key material.
    recent_otar_deliveries: VecDeque<CompletedOtarDelivery>,
    /// Per-terminal GSKO bootstrap state. A GSKO itself is never stored at
    /// the BS; only its version and CMG association are tracked.
    gsko_bootstraps: HashMap<u32, GskoBootstrapStatus>,
    /// Last validated SC2/TMO U-CK CHANGE RESULT per ISSI. Activation policy
    /// remains SwMI-owned; this prevents the BS from silently changing its
    /// advertised SCK merely because it observed an uplink result.
    ck_change_results: HashMap<u32, CkChangeResultStatus>,
    /// A clear D-LOCATION UPDATE ACCEPT can contain the sealed SCK that turns
    /// the terminal into an SC2 peer. Do not enable the BS-side binding at
    /// queue admission: its clear BL-ACK must still be accepted. The receipt
    /// reaches `Transmitted` only after the complete air PDU was sent.
    pending_sc2_activations: HashMap<u32, TxReporter>,
    current_time: TdmaTime,
}

struct PendingRegistration {
    itsi: u32,
    air_handle: u32,
    location_update_type: LocationUpdateType,
    address_extension: Option<u64>,
    energy_saving_information: Option<EnergySavingInformation>,
    has_group_identity_location_demand: bool,
    location_attachment: Option<PendingAttachment>,
    authentication_successful: bool,
    /// SwMI-selected SC2 information for the final D-LOCATION UPDATE ACCEPT.
    /// The Authentication Downlink is opaque at the BS because it can carry a
    /// TAA1-protected SCK provision.
    aie: AieLocationUpdateDecision,
    /// Present only when the MM SDU arrived inside MLE U-PREPARE. The source
    /// cell merely carries the forward-registration exchange; subscriber
    /// state belongs to this target serving cell.
    forward_registration_target_station_id: Option<String>,
}

struct PendingAttachment {
    itsi: u32,
    air_handle: u32,
    replace_all: bool,
    operations: Vec<GroupIdentityUplink>,
}

/// A group operation carried inside U-LOCATION UPDATE DEMAND.  Its result is
/// encoded in D-LOCATION UPDATE ACCEPT, never as a separate D-ATTACH/DETACH
/// acknowledgement.
struct PendingLocationAttachment {
    registration: PendingRegistration,
    attachment: PendingAttachment,
    rua_requested: bool,
}

impl MmBs {
    /// Select an explicit downlink policy while the MM transaction still
    /// knows whether this terminal completed the SC2 bootstrap. Registration
    /// constructors deliberately use `clear`; OTAR uses the stricter helper
    /// below. A terminal without a binding must never be guessed capable of
    /// protected normal OTAR.
    fn downlink_aie_request(&self, issi: u32) -> AieRequest {
        let state = self.config.state_read();
        if state.aie.enabled && state.aie_sessions.terminal(issi).is_some() {
            AieRequest::sc2(AieSubject::Individual { issi }, AieScope::MacResource)
        } else {
            AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource)
        }
    }

    /// Derive D-OTAR protection from the actual OTAR form, rather than using
    /// a blanket clear exception. In SC2-only mode a normal SCK/GCK/CCK
    /// transaction cannot be sent until the terminal has an active context.
    fn otar_downlink_aie_request(&self, issi: u32, kind: OtarDownlinkKind) -> Result<AieRequest, &'static str> {
        let state = self.config.state_read();
        if !state.aie.enabled || kind.is_clear_gsko_bootstrap() {
            return Ok(AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource));
        }
        if state.aie_sessions.terminal(issi).is_some() {
            return Ok(AieRequest::sc2(AieSubject::Individual { issi }, AieScope::MacResource));
        }
        if state.aie.sc1_allowed {
            // This is compatibility policy, not an SC2 bootstrap exception.
            return Ok(AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource));
        }
        Err("SC2-only OTAR downlink has no active terminal cipher context")
    }

    fn remember_otar_outcome(&mut self, delivery: CompletedOtarDelivery) {
        if self.recent_otar_deliveries.len() == MAX_RECENT_OTAR_DELIVERIES {
            self.recent_otar_deliveries.pop_front();
        }
        self.recent_otar_deliveries.push_back(delivery);
    }

    fn complete_otar_delivery(&mut self, command_id: u64, status: OtarDeliveryStatus) {
        let Some(pending) = self.pending_otar_deliveries.remove(&command_id) else {
            return;
        };
        if matches!(status, OtarDeliveryStatus::LinkFailed { .. }) && matches!(pending.kind, OtarDownlinkKind::GskoProvide) {
            self.gsko_bootstraps
                .insert(pending.issi, GskoBootstrapStatus::Failed { command_id });
        }
        self.remember_otar_outcome(CompletedOtarDelivery {
            command_id,
            issi: pending.issi,
            kind: pending.kind,
            status,
        });
    }

    /// Poll only the lower-layer receipt. LLC performs its own ETSI basic-link
    /// retransmissions; MM must not re-enqueue a second D-OTAR with a sealed
    /// key because that would create duplicate provisioning transactions.
    fn update_otar_delivery_statuses(&mut self) {
        let command_ids = self.pending_otar_deliveries.keys().copied().collect::<Vec<_>>();
        for command_id in command_ids {
            let (issi, kind, status_change, complete) = {
                let Some(pending) = self.pending_otar_deliveries.get_mut(&command_id) else {
                    continue;
                };
                let tx_state = pending.tx_reporter.get_state();
                let link_ack_expected = pending.tx_reporter.expects_ack();
                let previous_status = pending.status;
                let mut complete = None;

                match tx_state {
                    TxState::Pending => {}
                    TxState::Discarded | TxState::Lost => {
                        let failed = OtarDeliveryStatus::LinkFailed { state: tx_state };
                        pending.status = failed;
                        complete = Some(failed);
                    }
                    TxState::Transmitted if previous_status == OtarDeliveryStatus::Queued => {
                        pending.status = OtarDeliveryStatus::AirTransmitted;
                        if !link_ack_expected {
                            if pending.expected_response.is_some() {
                                pending.status = OtarDeliveryStatus::AwaitingTerminalResult;
                            } else {
                                complete = Some(OtarDeliveryStatus::AirTransmitted);
                            }
                        }
                    }
                    TxState::Transmitted => {}
                    TxState::Acknowledged
                        if !matches!(
                            previous_status,
                            OtarDeliveryStatus::LinkAcknowledged | OtarDeliveryStatus::AwaitingTerminalResult
                        ) =>
                    {
                        pending.status = OtarDeliveryStatus::LinkAcknowledged;
                        if pending.expected_response.is_some() {
                            pending.status = OtarDeliveryStatus::AwaitingTerminalResult;
                        } else {
                            complete = Some(OtarDeliveryStatus::LinkAcknowledged);
                        }
                    }
                    TxState::Acknowledged => {}
                }

                (
                    pending.issi,
                    pending.kind,
                    (previous_status != pending.status).then_some(pending.status),
                    complete,
                )
            };
            if let Some(status) = status_change {
                tracing::debug!(command_id, issi, ?kind, ?status, "D-OTAR delivery status changed");
            }
            if let Some(status) = complete {
                self.complete_otar_delivery(command_id, status);
            }
        }
    }

    fn complete_otar_terminal_response(&mut self, issi: u32, air_handle: u32, response: OtarTerminalResponse, success: bool) {
        let matching = self
            .pending_otar_deliveries
            .iter()
            .filter_map(|(&command_id, pending)| {
                (pending.issi == issi && pending.air_handle == air_handle && pending.expected_response == Some(response))
                    .then_some(command_id)
            })
            .collect::<Vec<_>>();
        let [command_id] = matching.as_slice() else {
            if matching.len() > 1 {
                tracing::warn!(
                    issi,
                    air_handle,
                    ?response,
                    candidates = matching.len(),
                    "ambiguous U-OTAR result correlation"
                );
            } else {
                tracing::debug!(issi, air_handle, ?response, "U-OTAR result has no pending BS delivery correlation");
            }
            return;
        };
        let command_id = *command_id;
        tracing::debug!(
            command_id,
            issi,
            air_handle,
            ?response,
            success,
            "U-OTAR terminal result correlated"
        );
        if response == OtarTerminalResponse::GskoResult && !success {
            self.gsko_bootstraps.insert(issi, GskoBootstrapStatus::Failed { command_id });
        }
        self.complete_otar_delivery(command_id, OtarDeliveryStatus::TerminalResult { success });
    }

    /// Decode Table A.35. The optional RAND2 is a Type-2 field, so even an
    /// Authentication Uplink that only requests the CK contains two bits:
    /// the request flag followed by the Type-2 presence flag. Do not discard
    /// that normal `10` form as malformed; doing so would suppress the SCK
    /// provision in the following D-LOCATION UPDATE ACCEPT.
    fn authentication_uplink(field: &Type3FieldGeneric) -> Option<(bool, Option<[u8; 10]>)> {
        if field.len != 2 && field.len != 82 {
            return None;
        }
        let mut bits = if field.raw.is_empty() {
            let mut value = BitBuffer::new(field.len);
            value.write_bits(field.data, field.len);
            // `write_bits` advances the cursor. Rewind before decoding the
            // two-bit Authentication Uplink; otherwise a normal `10` CK
            // request is read at end-of-buffer and silently becomes `None`.
            value.seek(0);
            value
        } else {
            let mut value = BitBuffer::from_vec(field.raw.clone());
            value.set_raw_end(field.len);
            value
        };
        let ck_requested = bits.read_field(1, "ck_request_flag").ok()? != 0;
        let random_challenge_present = bits.read_field(1, "rand_2_present").ok()? != 0;
        let rand_2 = random_challenge_present
            .then(|| {
                if field.len != 82 {
                    return None;
                }
                let mut value = [0_u8; 10];
                bits.read_bits_into_slice(80, &mut value).map(|_| value)
            })
            .flatten();
        if !random_challenge_present && field.len != 2 {
            return None;
        }
        Some((ck_requested, rand_2))
    }

    /// Table A.46, SC2 form: KSG(4), security class=0, SCKN(5).
    fn sc2_ciphering_parameters(&self) -> Option<u16> {
        let state = self.config.state_read();
        if !state.aie.enabled {
            return None;
        }
        let sc2 = state.aie.sc2.as_ref()?;
        let ksg = sc2_ksg_number(sc2.algorithm);
        Some((u16::from(ksg) << 6) | u16::from(sc2.sckn))
    }

    fn validate_sc2_location_update(&self, pdu: &ULocationUpdateDemand) -> Result<(), (u8, u16)> {
        let Some(expected) = self.sc2_ciphering_parameters() else {
            return Ok(());
        };
        let state = self.config.state_read();
        if !pdu.cipher_control || pdu.ciphering_parameters.is_none() {
            return if state.aie.sc1_allowed {
                Ok(())
            } else {
                Err((RejectCause::CipheringRequired as u8, expected))
            };
        }
        let provided = pdu.ciphering_parameters.expect("checked present") as u16;
        let expected_ksg = expected >> 6;
        let provided_ksg = provided >> 6;
        if provided_ksg != expected_ksg {
            return Err((RejectCause::IdentifiedCipherKsgNotSupported as u8, expected));
        }
        // Security-class bit must be zero and the SC2 SCKN must agree.
        if (provided & 0x3f) != (expected & 0x3f) {
            return Err((RejectCause::IdentifiedCipherKeyNotAvailable as u8, expected));
        }
        Ok(())
    }

    pub fn new(
        config: SharedConfig,
        telemetry: Option<TelemetrySink>,
        control: Option<ControlEndpoint>,
        swmi: Option<SwmiMmEndpoint>,
    ) -> Self {
        let client_mgr = MmClientMgr::new(telemetry.clone());
        Self {
            config,
            telemetry,
            control,
            client_mgr,
            swmi,
            next_swmi_command_id: 1,
            pending_registrations: HashMap::new(),
            registration_deadlines: HashMap::new(),
            pending_attachments: HashMap::new(),
            pending_location_attachments: HashMap::new(),
            pending_energy_economy: HashMap::new(),
            pending_auth_commands: HashMap::new(),
            authenticated_registrations: HashSet::new(),
            pending_lst_recoveries: HashSet::new(),
            pending_otar_deliveries: HashMap::new(),
            recent_otar_deliveries: VecDeque::new(),
            gsko_bootstraps: HashMap::new(),
            ck_change_results: HashMap::new(),
            pending_sc2_activations: HashMap::new(),
            current_time: TdmaTime::default(),
        }
    }

    fn next_swmi_command_id(&mut self) -> u64 {
        let command_id = self.next_swmi_command_id;
        self.next_swmi_command_id = self.next_swmi_command_id.wrapping_add(1).max(1);
        command_id
    }

    fn report_aie_observation(
        &mut self,
        issi: u32,
        air_handle: u32,
        event: AieObservationEvent,
        state: AieObservationState,
        air_interface_encrypted: Option<bool>,
        cipher_control: Option<bool>,
        ciphering_parameters: Option<u16>,
        ck_requested: Option<bool>,
        success: Option<bool>,
        cause: Option<u16>,
        detail: Option<String>,
    ) {
        if !self.swmi.as_ref().is_some_and(SwmiMmEndpoint::is_online) {
            return;
        }
        let (algorithm, sckn, sck_vn) = {
            let state = self.config.state_read();
            match state.aie.sc2.as_ref() {
                Some(sc2) => (
                    Some(match sc2.algorithm {
                        tetra_config::bluestation::RuntimeSc2TeaAlgorithm::Tea1 => tetra_swmi_protocol::Sc2TeaAlgorithm::Tea1,
                        tetra_config::bluestation::RuntimeSc2TeaAlgorithm::Tea3 => tetra_swmi_protocol::Sc2TeaAlgorithm::Tea3,
                    }),
                    Some(sc2.sckn),
                    Some(sc2.sck_vn),
                ),
                None => (None, None, None),
            }
        };
        let command_id = self.next_swmi_command_id();
        let message = SwmiMessage::TerminalAieObservation(TerminalAieObservation {
            command_id,
            itsi: u64::from(issi),
            air_handle,
            event,
            state,
            air_interface_encrypted,
            cipher_control,
            ciphering_parameters,
            ck_requested,
            algorithm,
            sckn,
            sck_vn,
            success,
            cause,
            detail,
        });
        if self.swmi.as_ref().expect("SwMI online check above").submit(message).is_err() {
            tracing::debug!(command_id, issi, "AIE observation could not be queued to SwMI");
        }
    }

    fn packet_aie_state(air_interface_encrypted: bool) -> AieObservationState {
        if air_interface_encrypted {
            AieObservationState::Sc2
        } else {
            AieObservationState::Clear
        }
    }

    /// A clear MM bootstrap is allowed for a terminal that already has an
    /// active SC2 binding.  Report that terminal's effective security state as
    /// SC2 while retaining `air_interface_encrypted = false` as the raw packet
    /// fact.  This prevents a successful clear bootstrap/authentication from
    /// overwriting the terminal's established SC2 state in the SwMI view.
    fn effective_aie_state(&self, issi: u32, air_interface_encrypted: bool) -> AieObservationState {
        if air_interface_encrypted {
            return AieObservationState::Sc2;
        }
        let state = self.config.state_read();
        if state.aie.enabled && state.aie_sessions.terminal(issi).is_some() {
            AieObservationState::Sc2
        } else {
            AieObservationState::Clear
        }
    }

    fn authentication_correlation_key(issi: u32, air_handle: u32) -> (u32, u32) {
        (issi, air_handle)
    }

    /// The SCK itself remains in the shared AIE key-provider state. MM only
    /// records the key-free identity after a successful SC2 registration.
    fn activate_sc2_terminal(&self, issi: u32) {
        let mut state = self.config.state_write();
        if !state.aie.enabled {
            return;
        }
        let Some(sc2) = state.aie.sc2.clone() else {
            return;
        };
        state.aie_sessions.activate_terminal(issi, &sc2);
    }

    /// Keep an already encrypted location-update exchange encrypted. In
    /// particular this covers D-AUTHENTICATION and D-LOCATION UPDATE ACCEPT
    /// sent after UMAC has decoded an initial SC2 ESI. A clear bootstrap has
    /// no binding yet and therefore remains clear until its accept is sent.
    fn aie_request_for_terminal(&self, issi: u32) -> AieRequest {
        let state = self.config.state_read();
        if state.aie.enabled && state.aie_sessions.terminal(issi).is_some() {
            AieRequest::sc2(AieSubject::Individual { issi }, AieScope::MacResource)
        } else {
            AieRequest::clear(AieSubject::System, AieScope::MacResource)
        }
    }

    fn defer_sc2_activation(&mut self, issi: u32, aie: &AieLocationUpdateDecision, receipt: TxReporter) {
        // Cipher Control announces the cell's selected SC2 parameters, but
        // it does not itself give a previously clear MS an SCK.  Activating
        // the BS binding in that case makes the cell reject the MS's next
        // clear bootstrap retry even though it never received a key.  Only
        // the full Table A.94 CK/SCK provision (228 bits) can transition a
        // clear terminal into SC2 here.  An already ciphered registration
        // already has its binding before this function is reached.
        if aie.authentication_downlink_bit_len == Some(228) {
            self.pending_sc2_activations.insert(issi, receipt);
        }
    }

    /// TTR 001-11 6.2.23.1: following a clear location update the ciphering
    /// state changes after the last D-LOCATION UPDATE ACCEPT repeat is sent,
    /// or on its clear BL-ACK, whichever comes first. `Transmitted` is the
    /// former event in this stack. A dropped/lost clear accept must never
    /// leave an SC2 binding active.
    fn update_sc2_activations(&mut self) {
        let outcomes = self
            .pending_sc2_activations
            .iter()
            .filter_map(|(&issi, receipt)| match receipt.get_state() {
                TxState::Transmitted | TxState::Acknowledged => Some((issi, true, receipt.get_state())),
                TxState::Discarded | TxState::Lost => Some((issi, false, receipt.get_state())),
                TxState::Pending => None,
            })
            .collect::<Vec<_>>();
        for (issi, activate, state) in outcomes {
            self.pending_sc2_activations.remove(&issi);
            if activate {
                self.activate_sc2_terminal(issi);
                self.report_aie_observation(
                    issi,
                    0,
                    AieObservationEvent::TerminalActivation,
                    AieObservationState::Sc2,
                    Some(true),
                    None,
                    None,
                    None,
                    Some(true),
                    None,
                    Some("SC2 terminal binding activated after delivered bootstrap".to_owned()),
                );
                tracing::debug!(issi, ?state, "activated SC2 after clear location-update accept transmission");
            } else {
                tracing::warn!(
                    issi,
                    ?state,
                    "clear location-update accept was not delivered; SC2 activation cancelled"
                );
            }
        }
    }

    /// The ESI startpoint is the activation/monitoring phase. It deliberately
    /// uses the next MCCH slot rather than inventing a separate timer.
    fn energy_economy_assignment(&self, mode: EnergySavingMode) -> EnergyEconomyAssignment {
        if mode == EnergySavingMode::StayAlive {
            return EnergyEconomyAssignment::default();
        }
        let start = self.current_time.add_timeslots(1).forward_to_timeslot(1);
        EnergyEconomyAssignment {
            mode: mode as u8,
            frame_number: Some(start.f),
            multiframe_number: Some(start.m),
        }
    }

    fn energy_economy_for_omitted_request(
        location_update_type: LocationUpdateType,
        current: Option<EnergyEconomyAssignment>,
    ) -> EnergyEconomyAssignment {
        // ETSI TS 100 392-2 14.1.12: for periodic and demand location
        // updating, an omitted Energy Saving Mode means that the previously
        // negotiated mode in the same registered area remains active.
        if matches!(
            location_update_type,
            LocationUpdateType::PeriodicLocationUpdating
                | LocationUpdateType::DemandLocationUpdating
                | LocationUpdateType::DisabledMsUpdating
        ) {
            current.unwrap_or_default()
        } else {
            EnergyEconomyAssignment::default()
        }
    }

    fn current_energy_economy(&self, issi: u32) -> Option<EnergyEconomyAssignment> {
        self.config
            .state_read()
            .subscribers
            .energy_economy(issi)
            .map(|(mode, frame_number, multiframe_number)| EnergyEconomyAssignment {
                mode,
                frame_number,
                multiframe_number,
            })
    }

    fn esi_from_assignment(assignment: EnergyEconomyAssignment) -> EnergySavingInformation {
        EnergySavingInformation {
            energy_saving_mode: EnergySavingMode::try_from(assignment.mode as u64).expect("validated EE mode"),
            frame_number: assignment.frame_number,
            multiframe_number: assignment.multiframe_number,
        }
    }

    fn store_energy_economy(&mut self, issi: u32, assignment: EnergyEconomyAssignment) {
        let mode = EnergySavingMode::try_from(assignment.mode as u64).expect("validated EE mode");
        let _ = self
            .client_mgr
            .set_client_energy_saving(issi, mode, assignment.frame_number, assignment.multiframe_number);
        self.config.state_write().subscribers.set_energy_economy(
            issi,
            assignment.mode,
            assignment.frame_number,
            assignment.multiframe_number,
        );
    }

    fn activate_energy_economy_after_next_control(&self, issi: u32) {
        self.config
            .state_write()
            .subscribers
            .set_energy_economy_activation_pending(issi, true);
    }

    fn emit_subscriber_update(&self, queue: &mut MessageQueue, issi: u32, groups: Vec<u32>, action: BrewSubscriberAction) {
        let class_of_usage = groups
            .iter()
            .map(|gssi| self.client_mgr.client_group_class_of_usage(issi, *gssi).unwrap_or(0))
            .collect::<Vec<_>>();
        // If brew is active, forward subscriber updates to the Brew entity.
        // Register/Deregister must always be sent for brew-routable ISSIs,
        // even when there are no group affiliations yet. The Brew worker
        // decides whether to send REGISTER or REREGISTER based on its own state.
        // Affiliate/Deaffiliate only sent when there are brew-routable groups.
        if net_brew::is_active(&self.config) {
            let brew_groups = groups
                .iter()
                .filter(|gssi| net_brew::is_brew_gssi_routable(&self.config, **gssi))
                .copied()
                .collect::<Vec<u32>>();
            let should_send = match action {
                BrewSubscriberAction::Register | BrewSubscriberAction::Deregister => net_brew::is_brew_issi_routable(&self.config, issi),
                BrewSubscriberAction::Affiliate | BrewSubscriberAction::Deaffiliate => !brew_groups.is_empty(),
                BrewSubscriberAction::ScanningState => false,
            };
            if should_send {
                let brew_update = MmSubscriberUpdate {
                    issi,
                    groups: brew_groups,
                    action,
                    class_of_usage: Vec::new(),
                    scanning_enabled: None,
                };
                let msg = SapMsg {
                    sap: Sap::Control,
                    src: TetraEntity::Mm,
                    dest: TetraEntity::Brew,
                    msg: SapMsgInner::MmSubscriberUpdate(brew_update),
                };
                queue.push_back(msg);
            }
        }

        // Always emit an update to the Cmce entity
        let mm_update = MmSubscriberUpdate {
            issi,
            groups,
            action,
            class_of_usage,
            scanning_enabled: None,
        };
        let msg = SapMsg {
            sap: Sap::Control,
            src: TetraEntity::Mm,
            dest: TetraEntity::Cmce,
            msg: SapMsgInner::MmSubscriberUpdate(mm_update),
        };
        queue.push_back(msg);
    }

    /// Remove a terminal's local serving-cell state.
    ///
    /// This is shared by a locally initiated U-ITSI DETACH and by the SwMI's
    /// authoritative notification that the terminal has re-anchored at
    /// another cell. The latter must not be echoed back to the SwMI: the
    /// central anchor has already moved, and a stale-cell deregistration must
    /// not be allowed to deregister the new serving cell.
    fn remove_local_subscriber(&mut self, queue: &mut MessageQueue, issi: u32) -> bool {
        let Some(client) = self.client_mgr.remove_client(issi) else {
            tracing::debug!(issi, "local subscriber cleanup ignored for unknown client");
            return false;
        };

        {
            let mut state = self.config.state_write();
            state.subscribers.deregister(issi);
            state.aie_sessions.deactivate_terminal(issi);
        }
        let was_gateway = self.config.state_read().dm_gateways.is_active(issi);
        if was_gateway {
            self.config.state_write().dm_gateways.deactivate(issi);
            self.publish_dm_gateway_state(issi, false);
        }
        if !client.groups.is_empty() {
            let groups: Vec<u32> = client.groups.keys().copied().collect();
            self.emit_subscriber_update(queue, issi, groups, BrewSubscriberAction::Deaffiliate);
        }
        self.emit_subscriber_update(queue, issi, Vec::new(), BrewSubscriberAction::Deregister);
        true
    }

    fn rx_u_itsi_detach(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("rx_u_itsi_detach");
        let SapMsgInner::LmmMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };

        let pdu = match UItsiDetach::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing UItsiDetach: {:?} {}", e, prim.sdu.dump_bin());
                return;
            }
        };

        // Check if we can satisfy this request, print unsupported stuff
        if !Self::feature_check_u_itsi_detach(&pdu) {
            tracing::error!("Unsupported critical features in UItsiDetach");
            return;
        }

        let ssi = prim.received_address.ssi;
        if self.swmi.as_ref().is_some_and(SwmiMmEndpoint::is_online) {
            let command_id = self.next_swmi_command_id();
            if self
                .swmi
                .as_ref()
                .expect("SwMI checked above")
                .submit(SwmiMessage::DeregistrationNotice {
                    command_id,
                    itsi: ssi as u64,
                })
                .is_ok()
            {
                tracing::info!(command_id, itsi = ssi, "deregistration forwarded to SwMI");
            } else {
                tracing::warn!(
                    command_id,
                    itsi = ssi,
                    "SwMI deregistration queue unavailable; applying local-site trunking"
                );
            }
        }
        if !self.remove_local_subscriber(queue, ssi) {
            tracing::warn!("Received UItsiDetach for unknown client with SSI: {}", ssi);
        }
    }

    fn rx_u_location_update_demand(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("rx_location_update_demand");
        let SapMsgInner::LmmMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };

        let pdu = match ULocationUpdateDemand::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing ULocationUpdateDemand: {:?} {}", e, prim.sdu.dump_bin());
                return;
            }
        };

        // Migration not supported: ETSI 16.4.1.1 case b) requires identity exchange via
        // D-LOCATION-UPDATE-PROCEEDING which we don't implement. Reject with cause
        // "Migration not supported" (12, Table 16.81) so the MS can act on it.
        if pdu.location_update_type == LocationUpdateType::MigratingLocationUpdating
            || pdu.location_update_type == LocationUpdateType::ServiceRestorationMigratingLocationUpdating
        {
            tracing::warn!(
                "Rejecting migration request from SSI {}: {}",
                prim.received_address.ssi,
                pdu.location_update_type
            );
            Self::send_d_location_update_reject(
                queue,
                prim.received_address.ssi,
                prim.handle,
                pdu.location_update_type,
                pdu.address_extension,
            );
            return;
        }

        // Check if we can satisfy this request, print unsupported stuff
        if !Self::feature_check_u_location_update_demand(&pdu) {
            tracing::error!("Unsupported critical features in ULocationUpdateDemand");
            return;
        }
        if let Err((cause, parameters)) = self.validate_sc2_location_update(&pdu) {
            let air_interface_encrypted = matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }));
            self.report_aie_observation(
                prim.received_address.ssi,
                prim.handle,
                AieObservationEvent::CipheringMismatch,
                Self::packet_aie_state(air_interface_encrypted),
                Some(air_interface_encrypted),
                Some(pdu.cipher_control),
                pdu.ciphering_parameters.map(|value| value as u16),
                None,
                Some(false),
                Some(u16::from(cause)),
                Some("location-update AIE parameters rejected".to_owned()),
            );
            Self::send_d_location_update_reject_with_ciphering_parameters(
                queue,
                prim.received_address.ssi,
                prim.handle,
                pdu.location_update_type,
                pdu.address_extension,
                cause,
                parameters,
            );
            return;
        }

        // In network mode the SwMI owns registration policy. The air handle
        // stays at the BS and is echoed by the SwMI decision, so this router
        // thread never waits on WSS. Group operations are handled after the
        // registration decision; they must never make the registration itself
        // silently fall back to LST.
        let issi = prim.received_address.ssi;
        // ETSI TS 100 392-2 §16.7.1/§16.10.10: the BS may choose a mode and
        // startpoint. Current policy accepts the requested mode and selects
        // the next MCCH phase from the local TDMA clock. For periodic/demand
        // updates, an omitted mode is explicitly a request to retain the
        // existing assignment; it is not a request for StayAlive.
        let energy_economy = match pdu.energy_saving_mode {
            Some(mode) => self.energy_economy_assignment(mode),
            None => Self::energy_economy_for_omitted_request(
                pdu.location_update_type,
                self.current_energy_economy(issi),
            ),
        };
        let esi = (energy_economy.mode != 0).then(|| Self::esi_from_assignment(energy_economy));

        let has_group_identity_location_demand = pdu.group_identity_location_demand.is_some();
        let location_attachment = pdu.group_identity_location_demand.as_ref().and_then(|demand| {
            let operations = demand.group_identity_uplink.clone()?;
            let valid = operations.iter().all(|group| group.gssi.is_some());
            valid.then_some(PendingAttachment {
                itsi: issi,
                air_handle: prim.handle,
                replace_all: demand.group_identity_attach_detach_mode == 1,
                operations,
            })
        });
        if self.swmi.as_ref().is_some_and(SwmiMmEndpoint::is_online) {
            let command_id = self.next_swmi_command_id();
            let (ck_requested, rand_2) = pdu
                .authentication_uplink
                .as_ref()
                .and_then(Self::authentication_uplink)
                .unwrap_or((false, None));
            let authentication = rand_2.map(|rand_2| tetra_swmi_protocol::AuthenticationResponse {
                command_id,
                itsi: issi as u64,
                air_handle: prim.handle,
                response_1: None,
                response_2: None,
                rand_2: Some(rand_2),
                random_seed: None,
                mutual: true,
                authentication_result: None,
            });
            let air_interface_encrypted = matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }));
            let ciphering_parameters = pdu.ciphering_parameters.map(|value| value as u16);
            let request = SwmiMessage::RegistrationAttempt {
                command_id,
                itsi: issi as u64,
                air_handle: prim.handle,
                location_update_type: u64::from(pdu.location_update_type) as u8,
                address_extension: pdu.address_extension,
                forward_registration_target_station_id: prim.forward_registration_target_station_id.clone(),
                energy_economy,
                authentication,
                aie: tetra_swmi_protocol::AieLocationUpdateRequest {
                    // Cipher Control records the requested registration
                    // policy; this separately records the bearer that was
                    // actually used on air. A clear bootstrap may still ask
                    // for ciphering-on, so do not conflate the two.
                    air_interface_encrypted,
                    cipher_control: pdu.cipher_control,
                    ciphering_parameters,
                    ck_requested,
                },
            };
            if self.swmi.as_ref().expect("SwMI checked above").submit(request).is_ok() {
                self.report_aie_observation(
                    issi,
                    prim.handle,
                    AieObservationEvent::Registration,
                    self.effective_aie_state(issi, air_interface_encrypted),
                    Some(air_interface_encrypted),
                    Some(pdu.cipher_control),
                    ciphering_parameters,
                    Some(ck_requested),
                    None,
                    None,
                    None,
                );
                self.config.state_write().subscribers.set_registration_delivery_pending(issi, true);
                self.pending_registrations.insert(
                    command_id,
                    PendingRegistration {
                        itsi: issi,
                        air_handle: prim.handle,
                        location_update_type: pdu.location_update_type,
                        address_extension: pdu.address_extension,
                        energy_saving_information: esi,
                        has_group_identity_location_demand,
                        location_attachment,
                        authentication_successful: false,
                        aie: AieLocationUpdateDecision::default(),
                        forward_registration_target_station_id: prim.forward_registration_target_station_id.clone(),
                    },
                );
                self.registration_deadlines
                    .insert(command_id, self.current_time.add_timeslots(T351_TIMESLOTS));
                // This confirms the CK-request transition without exposing
                // RAND2, the subscriber key, or any sealed key material.
                tracing::info!(
                    command_id,
                    issi,
                    ck_requested,
                    cipher_control = pdu.cipher_control,
                    ciphering_parameters = pdu.ciphering_parameters,
                    "location update forwarded to SwMI"
                );
                return;
            }
            tracing::warn!(command_id, issi, "SwMI request queue unavailable; using local-site trunking");
        }

        // Try to register the client
        let issi = prim.received_address.ssi;
        let handle = prim.handle;
        let is_new = !self.client_mgr.client_is_known(issi);
        if is_new {
            match self.client_mgr.try_register_client(issi, true) {
                Ok(_) => {
                    self.config.state_write().subscribers.register(issi);
                    self.emit_subscriber_update(queue, issi, Vec::new(), BrewSubscriberAction::Register);
                }
                Err(e) => {
                    tracing::warn!("Failed registering roaming MS {}: {:?}", issi, e);
                    // unimplemented_log!("Handle failed registration of roaming MS");
                    return;
                }
            }
        } else if let Err(e) = self.client_mgr.set_client_state(issi, MmClientState::Attached) {
            tracing::warn!("Failed updating roaming MS {}: {:?}", issi, e);
            return;
        }
        self.config.state_write().subscribers.set_registration_delivery_pending(issi, true);

        // Store energy saving mode in client state
        self.store_energy_economy(issi, energy_economy);
        if energy_economy.mode != 0 {
            self.activate_energy_economy_after_next_control(issi);
        }

        // Process optional GroupIdentityLocationDemand field
        let has_groups = pdu.group_identity_location_demand.is_some();
        let gila = if let Some(gild) = pdu.group_identity_location_demand {
            // ETSI Table 16.49 (clause 16.10.17): mode=1 means "detach all currently
            // attached group identities and attach group identities defined in the
            // group identity uplink element."
            if gild.group_identity_attach_detach_mode == 1 {
                let prior_groups: Vec<u32> = self
                    .client_mgr
                    .get_client_by_issi(issi)
                    .map(|client| client.groups.keys().copied().collect())
                    .unwrap_or_default();
                if let Err(e) = self.client_mgr.client_detach_all_groups(issi) {
                    tracing::warn!("Failed detaching all groups for MS {}: {:?}", issi, e);
                } else if !prior_groups.is_empty() {
                    {
                        let mut state = self.config.state_write();
                        for &gssi in &prior_groups {
                            state.subscribers.deaffiliate(issi, gssi);
                        }
                    }
                    self.emit_subscriber_update(queue, issi, prior_groups, BrewSubscriberAction::Deaffiliate);
                }
            }

            // Try to attach to requested groups, then build GroupIdentityLocationAccept element
            let accepted_groups = if let Some(giu) = &gild.group_identity_uplink {
                Some(self.try_attach_detach_groups(queue, issi, &giu))
            } else {
                None
            };
            let gila = GroupIdentityLocationAccept {
                group_identity_accept_reject: 0, // Accept
                group_identity_downlink: accepted_groups,
            };

            Some(gila)
        } else {
            // No GroupIdentityLocationAccept element present
            None
        };

        // Store and log class_of_ms
        if let Some(ref class) = pdu.class_of_ms {
            tracing::info!("MS {} class_of_ms: {}", issi, class);
        }
        let _ = self.client_mgr.set_client_class_of_ms(issi, pdu.class_of_ms);

        // Build D-LOCATION UPDATE ACCEPT pdu
        let pdu_response = DLocationUpdateAccept {
            location_update_accept_type: pdu.location_update_type,
            ssi: Some(issi as u64),
            address_extension: None,
            subscriber_class: None,
            energy_saving_information: esi,
            scch_information_and_distribution_on_18th_frame: None,
            new_registered_area: None,
            security_downlink: None,
            group_identity_location_accept: gila,
            default_group_attachment_lifetime: None,
            authentication_downlink: None,
            group_identity_security_related_information: None,
            cell_type_control: None,
            proprietary: None,
        };

        // Convert pdu to bits
        let pdu_len = 4 + 3 + 24 + 1 + 1 + 1; // Minimal lenght; may expand beyond this. 
        let mut sdu = BitBuffer::new_autoexpand(pdu_len);
        pdu_response.to_bitbuf(&mut sdu).unwrap(); // we want to know when this happens
        sdu.seek(0);
        tracing::debug!("-> {} sdu {}", pdu_response, sdu.dump_bin());

        // Build and submit response prim
        let msg = SapMsg {
            sap: Sap::LmmSap,
            src: TetraEntity::Mm,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                sdu,
                handle: prim.handle,
                address: TetraAddress::issi(issi),
                layer2service: Layer2Service::Acknowledged,
                stealing_permission: false,
                stealing_repeats_flag: false,
                encryption_flag: false,
                aie_request: AieRequest::clear(AieSubject::System, AieScope::MacResource),
                is_null_pdu: false,
                tx_reporter: None,
                seamless_handover: None,
            }),
        };
        queue.push_back(msg);
        // The current stack has no lower-layer delivery callback for this
        // acknowledged MM primitive. Queue admission is therefore the local
        // confirmation point; retries before this point still count as RA load.
        self.config.state_write().subscribers.mark_active(issi);

        // If this is an unknown returning radio (not ITSI attach) that didn't
        // include groups in the registration, force a full group report via
        // D-LOCATION UPDATE COMMAND. Skip if groups were already provided to
        // avoid a redundant clear-and-reattach cycle.
        if is_new && pdu.location_update_type != LocationUpdateType::ItsiAttach && !has_groups {
            tracing::info!("Sending D-LOCATION UPDATE COMMAND to returning MS {} to request group report", issi);
            self.send_d_location_update_command(queue, issi, handle, true);
        }
    }

    fn rx_u_mm_status(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("rx_u_mm_status");
        let SapMsgInner::LmmMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };

        let pdu = match UMmStatus::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing UMmStatus: {:?} {}", e, prim.sdu.dump_bin());
                return;
            }
        };

        let issi = prim.received_address.ssi;
        let handle = prim.handle;

        let mut handled = false;
        match pdu.status_uplink {
            StatusUplink::ChangeOfEnergySavingModeRequest => {
                // Parse energy saving mode from the sub-PDU payload
                let esm = if let Some(dep_info) = pdu.status_uplink_dependent_information {
                    // First 3 bits of the dependent information contain the energy saving mode
                    let dep_len = pdu.status_uplink_dependent_information_len.unwrap_or(0);
                    if dep_len >= 3 {
                        let mode_val = dep_info >> (dep_len - 3);
                        EnergySavingMode::try_from(mode_val).unwrap_or(EnergySavingMode::StayAlive)
                    } else {
                        EnergySavingMode::StayAlive
                    }
                } else {
                    EnergySavingMode::StayAlive
                };

                let assignment = self.energy_economy_assignment(esm);
                tracing::info!(issi, mode = ?esm, ?assignment, "MS requested EE mode change");
                if self.swmi.as_ref().is_some_and(SwmiMmEndpoint::is_online) {
                    let command_id = self.next_swmi_command_id();
                    let request = SwmiMessage::EnergyEconomyUpdate {
                        command_id,
                        itsi: issi as u64,
                        air_handle: handle,
                        energy_economy: assignment,
                    };
                    if self.swmi.as_ref().expect("SwMI checked above").submit(request).is_ok() {
                        self.pending_energy_economy.insert(command_id, (issi, handle));
                        return;
                    }
                    tracing::warn!(command_id, issi, "SwMI EE request queue unavailable; using local-site trunking");
                }
                self.store_energy_economy(issi, assignment);
                if assignment.mode != 0 {
                    self.activate_energy_economy_after_next_control(issi);
                }
                self.send_d_mm_status_energy_saving(queue, issi, handle, Self::esi_from_assignment(assignment));
                handled = true;
            }
            StatusUplink::ChangeOfEnergySavingModeResponse => {
                // MS confirming a BS-initiated change
                let esm = if let Some(dep_info) = pdu.status_uplink_dependent_information {
                    let dep_len = pdu.status_uplink_dependent_information_len.unwrap_or(0);
                    if dep_len >= 3 {
                        let mode_val = dep_info >> (dep_len - 3);
                        EnergySavingMode::try_from(mode_val).unwrap_or(EnergySavingMode::StayAlive)
                    } else {
                        EnergySavingMode::StayAlive
                    }
                } else {
                    EnergySavingMode::StayAlive
                };

                tracing::info!("MS {} energy saving mode change response: {:?}", issi, esm);
                self.store_energy_economy(issi, self.energy_economy_assignment(esm));
                handled = true;
            }
            StatusUplink::ChangeOfScanningState => {
                let enabled = match (pdu.status_uplink_dependent_information, pdu.status_uplink_dependent_information_len) {
                    (Some(value), Some(bits)) if bits > 0 => ((value >> (bits - 1)) & 1) == 0,
                    _ => {
                        tracing::warn!(issi, "U-MM STATUS ChangeOfScanningState without state bit");
                        true
                    }
                };
                if let Err(error) = self.client_mgr.set_client_scanning_enabled(issi, enabled) {
                    tracing::warn!(issi, ?error, "cannot store group scanning state for unknown MS");
                } else {
                    self.config.state_write().subscribers.set_scanning_enabled(issi, enabled);
                }
                if self.swmi.as_ref().is_some_and(|endpoint| endpoint.is_online()) {
                    let command_id = self.next_swmi_command_id();
                    if let Err(error) = self
                        .swmi
                        .as_ref()
                        .expect("SwMI checked above")
                        .submit(SwmiMessage::ScanningStateUpdate {
                            command_id,
                            itsi: issi as u64,
                            scanning_enabled: enabled,
                        })
                    {
                        tracing::warn!(issi, command_id, ?error, "cannot forward group scanning state to SwMI");
                    }
                }
                queue.push_back(SapMsg {
                    sap: Sap::Control,
                    src: TetraEntity::Mm,
                    dest: TetraEntity::Cmce,
                    msg: SapMsgInner::MmSubscriberUpdate(MmSubscriberUpdate {
                        issi,
                        groups: Vec::new(),
                        action: BrewSubscriberAction::ScanningState,
                        class_of_usage: Vec::new(),
                        scanning_enabled: Some(enabled),
                    }),
                });
                tracing::info!(issi, scanning_enabled = enabled, "MS changed group scanning state");
                handled = true;
            }
            StatusUplink::RequestToStartDmGatewayOperation => {
                let Some(UMmStatusGatewayPayload::Start { addresses, dmo_carrier }) = pdu.gateway_payload else {
                    return;
                };
                if !self.config.state_read().subscribers.is_registered(issi) {
                    tracing::warn!(issi, "unregistered terminal requested DM gateway operation");
                    self.send_d_mm_status_gateway(
                        queue,
                        issi,
                        handle,
                        StatusDownlink::RejectionToStartDmGatewayOperation,
                        DMmStatusGatewayPayload::Empty,
                    );
                    return;
                }
                let addresses = addresses.into_iter().map(dm_ms_route_address).collect::<Vec<_>>();
                self.config
                    .state_write()
                    .dm_gateways
                    .activate(issi, dmo_carrier.map(dmo_carrier_state), addresses, self.current_time);
                self.publish_dm_gateway_state(issi, true);
                self.send_d_mm_status_gateway(
                    queue,
                    issi,
                    handle,
                    StatusDownlink::AcceptanceToStartDmGatewayOperation,
                    DMmStatusGatewayPayload::RejectedAddresses(Vec::new()),
                );
                handled = true;
            }
            StatusUplink::RequestToContinuedmGatewayOperation => {
                let Some(UMmStatusGatewayPayload::Continue { dmo_carrier }) = pdu.gateway_payload else {
                    return;
                };
                let retained = self.config.state_read().dm_gateways.is_active(issi);
                if retained {
                    self.config
                        .state_write()
                        .dm_gateways
                        .update_carrier(issi, dmo_carrier.map(dmo_carrier_state), self.current_time);
                    self.publish_dm_gateway_state(issi, true);
                }
                self.send_d_mm_status_gateway(
                    queue,
                    issi,
                    handle,
                    if retained {
                        StatusDownlink::AcceptanceToContinueDmGatewayOperation
                    } else {
                        StatusDownlink::RejectionToContinueDmGatewayOperation
                    },
                    if retained {
                        DMmStatusGatewayPayload::RetainedAddressSet(true)
                    } else {
                        DMmStatusGatewayPayload::Empty
                    },
                );
                handled = true;
            }
            StatusUplink::RequestToStopDmGatewayOperation => {
                self.config.state_write().dm_gateways.deactivate(issi);
                self.publish_dm_gateway_state(issi, false);
                self.send_d_mm_status_gateway(
                    queue,
                    issi,
                    handle,
                    StatusDownlink::AcceptanceToStopDmGatewayOperation,
                    DMmStatusGatewayPayload::Empty,
                );
                handled = true;
            }
            StatusUplink::RequestToAddDmMsAddresses
            | StatusUplink::RequestToRemoveDmMsAddresses
            | StatusUplink::RequestToReplaceDmMsAddresses => {
                let Some(UMmStatusGatewayPayload::Addresses(addresses)) = pdu.gateway_payload else {
                    return;
                };
                let addresses = addresses.into_iter().map(dm_ms_route_address).collect::<Vec<_>>();
                let mut state = self.config.state_write();
                if !state.dm_gateways.is_active(issi) {
                    tracing::warn!(issi, "DM-MS address update from inactive gateway");
                    return;
                }
                match pdu.status_uplink {
                    StatusUplink::RequestToAddDmMsAddresses => state.dm_gateways.add_addresses(issi, addresses, self.current_time),
                    StatusUplink::RequestToRemoveDmMsAddresses => state.dm_gateways.remove_addresses(issi, addresses, self.current_time),
                    StatusUplink::RequestToReplaceDmMsAddresses => state.dm_gateways.replace_addresses(issi, addresses, self.current_time),
                    _ => unreachable!(),
                }
                drop(state);
                self.publish_dm_gateway_state(issi, true);
                self.send_d_mm_status_gateway(
                    queue,
                    issi,
                    handle,
                    StatusDownlink::AcceptanceOfDmMsAddresses,
                    DMmStatusGatewayPayload::RejectedAddresses(Vec::new()),
                );
                handled = true;
            }
            StatusUplink::AcceptanceToRemovalOfDmMsAddresses
            | StatusUplink::AcceptanceToChangeRegistrationLabel
            | StatusUplink::AcceptanceToStopDmGatewayOperation => {
                self.config.state_write().dm_gateways.touch(issi, self.current_time);
                handled = true;
            }
            StatusUplink::DualWatchModeRequest
            | StatusUplink::TerminatingDualWatchModeRequest
            | StatusUplink::ChangeOfDualWatchModeResponse
            | StatusUplink::StartOfDirectModeOperation
            | StatusUplink::MsFrequencyBandsInformation => {
                unimplemented_log!("{:?}", pdu.status_uplink)
            }
            _ => {
                assert_warn!(false, "Unrecognized UMmStatus type {:?}", pdu.status_uplink);
            }
        }

        if !handled {
            // A fairly untested, best-effort way of sending a PDU not supported error back
            // Note that an MS is not required to really do anything with this message.
            let (sapmsg, debug_str) = make_ul_mm_pdu_function_not_supported(
                handle,
                MmPduTypeUl::UMmStatus,
                Some((6, pdu.status_uplink.into())),
                prim.received_address,
                self.downlink_aie_request(issi),
            );
            tracing::debug!("-> {}", debug_str);
            queue.push_back(sapmsg);
        }
    }

    fn rx_u_attach_detach_group_identity(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("rx_u_attach_detach_group_identity");
        let SapMsgInner::LmmMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };

        let issi = prim.received_address.ssi;

        let pdu = match UAttachDetachGroupIdentity::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing UAttachDetachGroupIdentity: {:?} {}", e, prim.sdu.dump_bin());
                return;
            }
        };

        // Check if we can satisfy this request, print unsupported stuff
        if !Self::feature_check_u_attach_detach_group_identity(&pdu) {
            tracing::error!("Unsupported features in UAttachDetachGroupIdentity");
            return;
        }

        let requested_operations = pdu
            .group_identity_uplink
            .as_ref()
            .expect("checked by feature_check")
            .iter()
            .map(|group| {
                Some(AttachmentOperation {
                    gssi: group.gssi?,
                    detach: group.group_identity_detachment_uplink.is_some(),
                    class_of_usage: group.class_of_usage.unwrap_or(0),
                })
            })
            .collect::<Option<Vec<_>>>();
        if let Some(operations) = requested_operations
            && self.swmi.as_ref().is_some_and(SwmiMmEndpoint::is_online)
        {
            let command_id = self.next_swmi_command_id();
            let replace_all = pdu.group_identity_attach_detach_mode;
            let request = SwmiMessage::AttachmentAttempt {
                command_id,
                itsi: issi as u64,
                air_handle: prim.handle,
                replace_all,
                operations,
            };
            if self.swmi.as_ref().expect("SwMI checked above").submit(request).is_ok() {
                self.pending_attachments.insert(
                    command_id,
                    PendingAttachment {
                        itsi: issi,
                        air_handle: prim.handle,
                        replace_all,
                        operations: pdu.group_identity_uplink.clone().expect("checked above"),
                    },
                );
                tracing::info!(command_id, issi, "group attachment forwarded to SwMI");
                return;
            }
            tracing::warn!(command_id, issi, "SwMI attachment queue unavailable; using local-site trunking");
        }

        // If group_identity_attach_detach_mode == 1, we first detach all groups
        if pdu.group_identity_attach_detach_mode == true {
            if !self.client_mgr.client_is_known(issi) {
                // Client unknown (e.g. never registered via location update).
                // Re-register so group attachment can proceed.
                match self.client_mgr.try_register_client(issi, true) {
                    Ok(_) => {
                        self.config.state_write().subscribers.register(issi);
                        self.emit_subscriber_update(queue, issi, Vec::new(), BrewSubscriberAction::Register);
                    }
                    Err(e) => {
                        tracing::warn!("Failed re-registering MS {} on group attach: {:?}", issi, e);
                        return;
                    }
                }
            } else {
                // Client is known — detach all existing groups first
                let prior_groups: Vec<u32> = self
                    .client_mgr
                    .get_client_by_issi(issi)
                    .map(|client| client.groups.keys().copied().collect())
                    .unwrap_or_default();
                match self.client_mgr.client_detach_all_groups(issi) {
                    Ok(_) => {
                        if !prior_groups.is_empty() {
                            {
                                let mut state = self.config.state_write();
                                for &gssi in &prior_groups {
                                    state.subscribers.deaffiliate(issi, gssi);
                                }
                            }
                            self.emit_subscriber_update(queue, issi, prior_groups, BrewSubscriberAction::Deaffiliate);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed detaching all groups for MS {}: {:?}", issi, e);
                        return;
                    }
                }
            }
        }

        // Try to attach to requested groups, and retrieve list of accepted GroupIdentityDownlink elements
        // We can unwrap since we did compat check earlier
        let accepted_gid = self.try_attach_detach_groups(queue, issi, &pdu.group_identity_uplink.unwrap());

        // Build reply PDU
        let pdu_response = DAttachDetachGroupIdentityAcknowledgement {
            group_identity_accept_reject: 0, // Accept
            reserved: false,                 // TODO FIXME Guessed proper value of reserved field
            proprietary: None,
            group_identity_downlink: Some(accepted_gid),
            group_identity_security_related_information: None,
        };

        // Write to PDU
        let mut sdu = BitBuffer::new_autoexpand(32);
        pdu_response.to_bitbuf(&mut sdu).unwrap(); // We want to know when this happens
        sdu.seek(0);
        tracing::debug!("-> {:?} sdu {}", pdu_response, sdu.dump_bin());

        let msg = SapMsg {
            sap: Sap::LmmSap,
            src: TetraEntity::Mm,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                sdu,
                handle: prim.handle,
                address: TetraAddress::issi(issi),
                layer2service: Layer2Service::Acknowledged,
                stealing_permission: false,
                stealing_repeats_flag: false,
                encryption_flag: false,
                aie_request: self.downlink_aie_request(issi),
                is_null_pdu: false,
                tx_reporter: None,
                seamless_handover: None,
            }),
        };
        queue.push_back(msg);
    }

    fn rx_lmm_mle_unitdata_ind(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        // unimplemented_log!("rx_lmm_mle_unitdata_ind for MM component");
        let SapMsgInner::LmmMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };

        let Some(bits) = prim.sdu.peek_bits(4) else {
            tracing::warn!("insufficient bits: {}", prim.sdu.dump_bin());
            return;
        };

        let Ok(pdu_type) = MmPduTypeUl::try_from(bits) else {
            tracing::warn!("invalid pdu type: {} in {}", bits, prim.sdu.dump_bin());
            return;
        };

        // TTR 001-11 clause 6.2.17 permits a deliberately small clear
        // exception set after SC2 activation. Keep that decision at MM,
        // where the actual MM PDU type is known: location update and its
        // authentication exchange remain bootstrap procedures, while OTAR
        // is narrowed further to its permitted result/GSKO variants by
        // `rx_u_otar` below. All ordinary clear MM PDUs fail closed when
        // SC1 fallback is disabled.
        let is_clear_from_bound_sc2_terminal = matches!(prim.air_interface_encryption, Some(AieRequest::Clear { .. }) | None) && {
            let state = self.config.state_read();
            state.aie.enabled && !state.aie.sc1_allowed && state.aie_sessions.terminal(prim.received_address.ssi).is_some()
        };
        if is_clear_from_bound_sc2_terminal
            && !matches!(
                pdu_type,
                MmPduTypeUl::ULocationUpdateDemand | MmPduTypeUl::UAuthentication | MmPduTypeUl::UOtar
            )
        {
            tracing::warn!(
                issi = prim.received_address.ssi,
                ?pdu_type,
                "rejecting unexpected clear post-SC2 MM PDU"
            );
            return;
        }
        if matches!(
            prim.air_interface_encryption,
            Some(AieRequest::Sc2 {
                subject: AieSubject::System,
                ..
            })
        ) && prim.received_address.ssi_type == SsiType::Esi
            && pdu_type != MmPduTypeUl::ULocationUpdateDemand
        {
            tracing::warn!(?pdu_type, "rejecting unbound encrypted SC2 MM PDU outside location update");
            return;
        }

        match pdu_type {
            MmPduTypeUl::UAuthentication => self.rx_u_authentication(queue, message),
            MmPduTypeUl::UItsiDetach => self.rx_u_itsi_detach(queue, message),
            MmPduTypeUl::ULocationUpdateDemand => self.rx_u_location_update_demand(queue, message),
            MmPduTypeUl::UMmStatus => self.rx_u_mm_status(queue, message),
            MmPduTypeUl::UCkChangeResult => self.rx_u_ck_change_result(message),
            MmPduTypeUl::UOtar => self.rx_u_otar(message),
            MmPduTypeUl::UInformationProvide => unimplemented_log!("UInformationProvide"),
            MmPduTypeUl::UAttachDetachGroupIdentity => self.rx_u_attach_detach_group_identity(queue, message),
            MmPduTypeUl::UAttachDetachGroupIdentityAcknowledgement => unimplemented_log!("UAttachDetachGroupIdentityAcknowledgement"),
            MmPduTypeUl::UTeiProvide => unimplemented_log!("UTeiProvide"),
            MmPduTypeUl::UDisableStatus => unimplemented_log!("UDisableStatus"),
            MmPduTypeUl::MmPduFunctionNotSupported => unimplemented_log!("MmPduFunctionNotSupported"),
        };
    }

    /// The BS validates and transports OTAR but never receives key material
    /// from the SwMI.  This keeps TAA1-K, KSO and clear SCK/GSKO state in the
    /// central key provider, while retaining the exact air-interface handle
    /// needed to schedule the response.
    fn rx_u_otar(&mut self, mut message: SapMsg) {
        let SapMsgInner::LmmMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        let pdu = match UOtar::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => pdu,
            Err(error) => {
                tracing::warn!(issi = prim.received_address.ssi, error = ?error, "discarding malformed U-OTAR PDU");
                self.report_aie_observation(
                    prim.received_address.ssi,
                    prim.handle,
                    AieObservationEvent::ProtocolError,
                    Self::packet_aie_state(matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }))),
                    Some(matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }))),
                    None,
                    None,
                    None,
                    Some(false),
                    None,
                    Some("malformed U-OTAR PDU".to_owned()),
                );
                return;
            }
        };
        let subtype = match &pdu {
            UOtar::CckDemand(_) => "cck-demand",
            UOtar::CckResult(_) => "cck-result",
            UOtar::SckDemand(_) => "sck-demand",
            UOtar::SckResult(_) => "sck-result",
            UOtar::GckDemand(_) => "gck-demand",
            UOtar::GckResult(_) => "gck-result",
            UOtar::GskoDemand(_) => "gsko-demand",
            UOtar::GskoResult(_) => "gsko-result",
            UOtar::KeyStatusResponse(_) => "key-status-response",
        };
        let is_clear_from_bound_sc2_terminal = matches!(prim.air_interface_encryption, Some(AieRequest::Clear { .. }) | None) && {
            let state = self.config.state_read();
            state.aie.enabled && !state.aie.sc1_allowed && state.aie_sessions.terminal(prim.received_address.ssi).is_some()
        };
        if is_clear_from_bound_sc2_terminal
            && !matches!(
                pdu,
                UOtar::CckResult(_) | UOtar::SckResult(_) | UOtar::GskoDemand(_) | UOtar::GskoResult(_)
            )
        {
            tracing::warn!(
                issi = prim.received_address.ssi,
                subtype,
                "rejecting clear U-OTAR variant outside SC2 bootstrap allow-list"
            );
            self.report_aie_observation(
                prim.received_address.ssi,
                prim.handle,
                AieObservationEvent::CipheringMismatch,
                AieObservationState::Clear,
                Some(false),
                None,
                None,
                None,
                Some(false),
                Some(1),
                Some("clear U-OTAR rejected while SC2 is required".to_owned()),
            );
            return;
        }
        // Correlate the terminal-level provision/key-status response before
        // forwarding the opaque PDU. A BL-ACK is not considered equivalent to
        // this result: a terminal can acknowledge radio delivery and still
        // reject the sealed key or report a different key status.
        match &pdu {
            UOtar::CckResult(result) => self.complete_otar_terminal_response(
                prim.received_address.ssi,
                prim.handle,
                OtarTerminalResponse::CckResult,
                result.provision_result == 0 && result.future_provision_result.is_none_or(|code| code == 0),
            ),
            UOtar::SckResult(result) => self.complete_otar_terminal_response(
                prim.received_address.ssi,
                prim.handle,
                OtarTerminalResponse::SckResult,
                result.results.iter().all(|entry| entry.provision_result == 0),
            ),
            UOtar::GckResult(result) => self.complete_otar_terminal_response(
                prim.received_address.ssi,
                prim.handle,
                OtarTerminalResponse::GckResult,
                result.results.iter().all(|entry| entry.provision_result == 0),
            ),
            UOtar::GskoDemand(_) => {
                self.gsko_bootstraps
                    .insert(prim.received_address.ssi, GskoBootstrapStatus::Requested);
            }
            UOtar::GskoResult(result) => {
                let success = result.provision_result == 0;
                self.complete_otar_terminal_response(prim.received_address.ssi, prim.handle, OtarTerminalResponse::GskoResult, success);
                if success {
                    self.gsko_bootstraps.insert(
                        prim.received_address.ssi,
                        GskoBootstrapStatus::Provisioned {
                            version_number: result.version_number,
                            cmg_gssi: result.cmg_gssi,
                        },
                    );
                }
            }
            UOtar::KeyStatusResponse(_) => self.complete_otar_terminal_response(
                prim.received_address.ssi,
                prim.handle,
                OtarTerminalResponse::KeyStatusResponse,
                true,
            ),
            UOtar::CckDemand(_) | UOtar::SckDemand(_) | UOtar::GckDemand(_) => {}
        }
        let (event, success, cause) = match &pdu {
            UOtar::KeyStatusResponse(_) => (AieObservationEvent::KeyStatus, Some(true), None),
            UOtar::CckResult(result) => {
                let success = result.provision_result == 0 && result.future_provision_result.is_none_or(|code| code == 0);
                (AieObservationEvent::Otar, Some(success), (!success).then_some(u16::from(result.provision_result)))
            }
            UOtar::SckResult(result) => {
                let cause = result.results.iter().find_map(|entry| (entry.provision_result != 0).then_some(u16::from(entry.provision_result)));
                (AieObservationEvent::Otar, Some(cause.is_none()), cause)
            }
            UOtar::GckResult(result) => {
                let cause = result.results.iter().find_map(|entry| (entry.provision_result != 0).then_some(u16::from(entry.provision_result)));
                (AieObservationEvent::Otar, Some(cause.is_none()), cause)
            }
            UOtar::GskoResult(result) => (AieObservationEvent::Otar, Some(result.provision_result == 0), (!result.provision_result.eq(&0)).then_some(u16::from(result.provision_result))),
            UOtar::CckDemand(_) | UOtar::SckDemand(_) | UOtar::GckDemand(_) | UOtar::GskoDemand(_) => (AieObservationEvent::Otar, None, None),
        };
        self.report_aie_observation(
            prim.received_address.ssi,
            prim.handle,
            event,
            self.effective_aie_state(prim.received_address.ssi, matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }))),
            Some(matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }))),
            None,
            None,
            None,
            success,
            cause,
            Some(format!("U-OTAR {subtype}")),
        );
        let mut wire = BitBuffer::new_autoexpand(64);
        if let Err(error) = pdu.to_bitbuf(&mut wire) {
            tracing::warn!(issi = prim.received_address.ssi, error = ?error, "cannot reencode validated U-OTAR PDU");
            return;
        }
        let payload_bit_len = match u16::try_from(wire.get_len()) {
            Ok(value) => value,
            Err(_) => {
                tracing::warn!(issi = prim.received_address.ssi, "U-OTAR PDU exceeds SwMI transport limit");
                return;
            }
        };
        let command_id = self.next_swmi_command_id();
        let Some(endpoint) = self.swmi.as_ref().filter(|endpoint| endpoint.is_online()) else {
            tracing::warn!(issi = prim.received_address.ssi, "discarding U-OTAR PDU while SwMI is unavailable");
            return;
        };
        let request = SwmiMessage::OtarUplink {
            command_id,
            itsi: prim.received_address.ssi as u64,
            air_handle: prim.handle,
            payload_bit_len,
            payload: wire.into_bytes(),
        };
        if endpoint.submit(request).is_err() {
            tracing::warn!(command_id, issi = prim.received_address.ssi, "SwMI OTAR queue unavailable");
            return;
        }
        // Keep PDU logs metadata-only: the payload may contain sealed keys.
        tracing::debug!(command_id, issi = prim.received_address.ssi, subtype, "U-OTAR forwarded to SwMI");
    }

    fn rx_u_ck_change_result(&mut self, mut message: SapMsg) {
        let SapMsgInner::LmmMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        let result = match UCkChangeResult::from_bitbuf(&mut prim.sdu) {
            Ok(result) => result,
            Err(error) => {
                tracing::warn!(issi = prim.received_address.ssi, error = ?error, "discarding malformed U-CK CHANGE RESULT");
                self.report_aie_observation(
                    prim.received_address.ssi,
                    prim.handle,
                    AieObservationEvent::ProtocolError,
                    Self::packet_aie_state(matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }))),
                    Some(matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }))),
                    None,
                    None,
                    None,
                    Some(false),
                    None,
                    Some("malformed U-CK CHANGE RESULT".to_owned()),
                );
                return;
            }
        };
        let selected_sck_count = result.selected_scks.len();
        self.ck_change_results.insert(
            prim.received_address.ssi,
            CkChangeResultStatus {
                change_of_security_class: result.change_of_security_class,
                selected_sck_count,
            },
        );
        // This result does not activate a key locally. The SwMI alone decides
        // the activation time and distributes the corresponding cell config.
        tracing::debug!(
            issi = prim.received_address.ssi,
            change_of_security_class = result.change_of_security_class,
            selected_sck_count,
            "validated U-CK CHANGE RESULT"
        );
        self.report_aie_observation(
            prim.received_address.ssi,
            prim.handle,
            AieObservationEvent::CkChange,
            self.effective_aie_state(prim.received_address.ssi, matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }))),
            Some(matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }))),
            None,
            None,
            None,
            Some(true),
            None,
            Some(format!("validated U-CK CHANGE RESULT with {selected_sck_count} selected SCK(s)")),
        );
    }

    fn rx_u_authentication(&mut self, _queue: &mut MessageQueue, mut message: SapMsg) {
        let SapMsgInner::LmmMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        let pdu = match UAuthentication::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => pdu,
            Err(error) => {
                // Keep the raw SDU in the log.  This is especially useful for
                // distinguishing a terminal that ignores D-AUTHENTICATION
                // DEMAND from one that answers with a malformed/unsupported
                // subtype or Type-3 RAND2 element.
                tracing::warn!(
                    error = ?error,
                    sdu = %prim.sdu.dump_bin(),
                    "invalid U-AUTHENTICATION"
                );
                self.report_aie_observation(
                    prim.received_address.ssi,
                    prim.handle,
                    AieObservationEvent::ProtocolError,
                    Self::packet_aie_state(matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }))),
                    Some(matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }))),
                    None,
                    None,
                    None,
                    Some(false),
                    None,
                    Some("invalid U-AUTHENTICATION".to_owned()),
                );
                return;
            }
        };
        let command_id = self
            .pending_auth_commands
            .get(&Self::authentication_correlation_key(prim.received_address.ssi, prim.handle))
            .copied()
            .unwrap_or_else(|| self.next_swmi_command_id());
        let Some(swmi) = self.swmi.as_ref() else {
            return;
        };
        let _ = swmi.submit(SwmiMessage::AuthenticationResponse(tetra_swmi_protocol::AuthenticationResponse {
            command_id,
            itsi: prim.received_address.ssi as u64,
            air_handle: prim.handle,
            response_1: pdu.response_1,
            response_2: None,
            rand_2: pdu.rand_2,
            random_seed: None,
            mutual: pdu.mutual,
            authentication_result: pdu.authentication_result,
        }));
        if let Some(authentication_result) = pdu.authentication_result {
            if authentication_result {
                self.authenticated_registrations.insert(command_id);
            } else {
                self.authenticated_registrations.remove(&command_id);
            }
            tracing::info!(
                command_id,
                itsi = prim.received_address.ssi,
                authentication_result,
                mutual = pdu.mutual,
                "U-AUTHENTICATION RESULT forwarded to SwMI"
            );
            self.report_aie_observation(
                prim.received_address.ssi,
                prim.handle,
                AieObservationEvent::Authentication,
                self.effective_aie_state(prim.received_address.ssi, matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }))),
                Some(matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }))),
                None,
                None,
                None,
                Some(authentication_result),
                (!authentication_result).then_some(1),
                Some(if authentication_result { "terminal authentication accepted" } else { "terminal authentication rejected" }.to_owned()),
            );
        } else {
            tracing::info!(
                command_id,
                itsi = prim.received_address.ssi,
                mutual = pdu.mutual,
                "U-AUTHENTICATION RESPONSE forwarded to SwMI"
            );
            self.report_aie_observation(
                prim.received_address.ssi,
                prim.handle,
                AieObservationEvent::Authentication,
                self.effective_aie_state(prim.received_address.ssi, matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }))),
                Some(matches!(prim.air_interface_encryption, Some(AieRequest::Sc2 { .. }))),
                None,
                None,
                None,
                None,
                None,
                Some("terminal authentication response received".to_owned()),
            );
        }
    }

    fn try_attach_detach_groups(
        &mut self,
        queue: &mut MessageQueue,
        issi: u32,
        giu_vec: &Vec<GroupIdentityUplink>,
    ) -> Vec<GroupIdentityDownlink> {
        let mut accepted_groups = Vec::new();
        let mut aff_groups = Vec::new();
        let mut deaff_groups = Vec::new();

        for giu in giu_vec.iter() {
            if giu.gssi.is_none() || giu.vgssi.is_some() || giu.address_extension.is_some() {
                unimplemented_log!("Only support GroupIdentityUplink with address_type 0");
                continue;
            }

            let gssi = giu.gssi.unwrap(); // can't fail
            let is_detach = giu.group_identity_detachment_uplink.is_some();

            if is_detach {
                match self.client_mgr.client_group_attach(issi, gssi, false) {
                    Ok(changed) => {
                        if changed {
                            self.config.state_write().subscribers.deaffiliate(issi, gssi);
                            deaff_groups.push(gssi);
                        }
                        let gid = GroupIdentityDownlink {
                            group_identity_attachment: None,
                            group_identity_detachment_uplink: giu.group_identity_detachment_uplink,
                            gssi: Some(gssi),
                            address_extension: None,
                            vgssi: None,
                        };
                        accepted_groups.push(gid);
                    }
                    Err(e) => {
                        tracing::warn!("Failed detaching MS {} from group {}: {:?}", issi, gssi, e);
                    }
                }
            } else {
                match self
                    .client_mgr
                    .client_group_attach_with_class_of_usage(issi, gssi, true, giu.class_of_usage.unwrap_or(0))
                {
                    Ok(changed) => {
                        if changed {
                            self.config.state_write().subscribers.affiliate(issi, gssi);
                            aff_groups.push(gssi);
                        }
                        // We have added the client to this group. Add an entry to the downlink response
                        let gid = GroupIdentityDownlink {
                            group_identity_attachment: Some(GroupIdentityAttachment {
                                group_identity_attachment_lifetime: 1, // re-attach after ITSI attach (ETSI default per clause 16.4.2)
                                class_of_usage: giu.class_of_usage.unwrap_or(0),
                            }),
                            group_identity_detachment_uplink: None,
                            gssi: Some(gssi),
                            address_extension: None,
                            vgssi: None,
                        };
                        accepted_groups.push(gid);
                    }
                    Err(e) => {
                        tracing::warn!("Failed attaching MS {} to group {}: {:?}", issi, gssi, e);
                    }
                }
            }
        }

        if !aff_groups.is_empty() {
            self.emit_subscriber_update(queue, issi, aff_groups, BrewSubscriberAction::Affiliate);
        }
        if !deaff_groups.is_empty() {
            self.emit_subscriber_update(queue, issi, deaff_groups, BrewSubscriberAction::Deaffiliate);
        }

        accepted_groups
    }

    fn apply_swmi_registration_decision(
        &mut self,
        queue: &mut MessageQueue,
        command_id: u64,
        itsi: u64,
        air_handle: u32,
        accepted: bool,
        cause: u16,
        energy_economy: EnergyEconomyAssignment,
        rua_requested: bool,
        handover_allocation: Option<HandoverChannelAllocation>,
        aie: AieLocationUpdateDecision,
    ) {
        let Some(pending) = self.pending_registrations.get(&command_id) else {
            tracing::warn!(command_id, itsi, "received SwMI registration decision without pending air request");
            return;
        };
        self.registration_deadlines.remove(&command_id);
        if pending.itsi as u64 != itsi || pending.air_handle != air_handle {
            tracing::warn!(
                command_id,
                expected_itsi = pending.itsi,
                itsi,
                expected_air_handle = pending.air_handle,
                air_handle,
                "discarding mismatched SwMI registration decision"
            );
            return;
        }
        // Keep a pending registration intact unless the decision correlates
        // with it. A delayed or malformed SwMI response must not make the
        // legitimate terminal impossible to complete later.
        let mut pending = self
            .pending_registrations
            .remove(&command_id)
            .expect("pending registration was checked above");
        pending.aie = aie;
        pending.authentication_successful = self.authenticated_registrations.remove(&command_id);
        let auth_key = Self::authentication_correlation_key(pending.itsi, pending.air_handle);
        if self
            .pending_auth_commands
            .get(&auth_key)
            .is_some_and(|current_command_id| *current_command_id == command_id)
        {
            self.pending_auth_commands.remove(&auth_key);
        }
        if !accepted {
            self.config
                .state_write()
                .subscribers
                .set_registration_delivery_pending(pending.itsi, false);
            tracing::info!(command_id, itsi, cause, "SwMI rejected location update");
            if let Some(parameters) = pending.aie.ciphering_parameters {
                Self::send_d_location_update_reject_with_ciphering_parameters(
                    queue,
                    pending.itsi,
                    pending.air_handle,
                    pending.location_update_type,
                    pending.address_extension,
                    cause as u8,
                    parameters,
                );
            } else {
                Self::send_d_location_update_reject_with_cause(
                    queue,
                    pending.itsi,
                    pending.air_handle,
                    pending.location_update_type,
                    pending.address_extension,
                    cause as u8,
                );
            }
            return;
        }

        // The SwMI decision is authoritative. This also ensures a roaming
        // target uses the exact phase that the serving SwMI record carries.
        pending.energy_saving_information = (energy_economy.mode != 0).then(|| Self::esi_from_assignment(energy_economy));

        if pending.forward_registration_target_station_id.is_some() {
            // The SwMI has already moved the central serving-cell anchor and
            // pushed the authoritative subscriber state to the target BS. Do
            // not create a duplicate local client at the old cell merely
            // because it transported the U-PREPARE exchange.
            self.config
                .state_write()
                .subscribers
                .set_registration_delivery_pending(pending.itsi, false);
            let seamless_handover = handover_allocation.map(|allocation| LmmMleSeamlessHandover {
                carrier: allocation.carrier,
                timeslots: std::array::from_fn(|index| allocation.timeslot_bitmap & (1 << index) != 0),
                usage: allocation.usage,
            });
            let _ = Self::send_d_location_update_accept_with_handover(
                queue,
                pending.itsi,
                pending.air_handle,
                pending.location_update_type,
                pending.energy_saving_information,
                pending.authentication_successful,
                &pending.aie,
                self.aie_request_for_terminal(pending.itsi),
                pending.has_group_identity_location_demand.then_some(GroupIdentityLocationAccept {
                    group_identity_accept_reject: 0,
                    group_identity_downlink: None,
                }),
                seamless_handover,
                rua_requested,
            );
            tracing::info!(command_id, itsi, target = ?pending.forward_registration_target_station_id, type_one = handover_allocation.is_some(), "forward registration accepted; response will be wrapped in D-NEW-CELL");
            return;
        }

        let is_new = !self.client_mgr.client_is_known(pending.itsi);
        if is_new {
            if let Err(error) = self.client_mgr.try_register_client(pending.itsi, true) {
                tracing::warn!(
                    command_id,
                    itsi,
                    ?error,
                    "SwMI accepted registration but local client state could not be created"
                );
                Self::send_d_location_update_reject_with_cause(
                    queue,
                    pending.itsi,
                    pending.air_handle,
                    pending.location_update_type,
                    pending.address_extension,
                    RejectCause::NetworkFailure as u8,
                );
                return;
            }
            self.config.state_write().subscribers.register(pending.itsi);
            self.emit_subscriber_update(queue, pending.itsi, Vec::new(), BrewSubscriberAction::Register);
        } else if let Err(error) = self.client_mgr.set_client_state(pending.itsi, MmClientState::Attached) {
            tracing::warn!(
                command_id,
                itsi,
                ?error,
                "SwMI accepted registration but local client state could not be updated"
            );
            Self::send_d_location_update_reject_with_cause(
                queue,
                pending.itsi,
                pending.air_handle,
                pending.location_update_type,
                pending.address_extension,
                RejectCause::NetworkFailure as u8,
            );
            return;
        }
        self.config
            .state_write()
            .subscribers
            .set_registration_delivery_pending(pending.itsi, true);
        self.store_energy_economy(pending.itsi, energy_economy);
        if energy_economy.mode != 0 {
            self.activate_energy_economy_after_next_control(pending.itsi);
        }

        // A location update can atomically contain group attachment changes.
        // The SwMI must decide those as well, but the resulting elements belong
        // in D-LOCATION UPDATE ACCEPT.  Retain the air request until the
        // attachment decision arrives instead of sending a second MM response.
        if let Some(attachment) = pending.location_attachment.take() {
            let operations = attachment
                .operations
                .iter()
                .map(|group| AttachmentOperation {
                    gssi: group.gssi.expect("validated before SwMI registration"),
                    detach: group.group_identity_detachment_uplink.is_some(),
                    class_of_usage: group.class_of_usage.unwrap_or(0),
                })
                .collect();
            if self.swmi.as_ref().is_some_and(SwmiMmEndpoint::is_online) {
                let attachment_command_id = self.next_swmi_command_id();
                let request = SwmiMessage::AttachmentAttempt {
                    command_id: attachment_command_id,
                    itsi,
                    air_handle: pending.air_handle,
                    replace_all: attachment.replace_all,
                    operations,
                };
                if self.swmi.as_ref().expect("SwMI checked above").submit(request).is_ok() {
                    self.pending_location_attachments.insert(
                        attachment_command_id,
                        PendingLocationAttachment {
                            registration: pending,
                            attachment,
                            rua_requested,
                        },
                    );
                    tracing::info!(
                        registration_command_id = command_id,
                        attachment_command_id,
                        itsi,
                        "location-update group attachment forwarded to SwMI"
                    );
                    return;
                }
            }
            tracing::warn!(
                command_id,
                itsi,
                "SwMI unavailable while deciding location-update group attachment; using local-site trunking"
            );
            let local_results = Self::local_attachment_results(&attachment);
            let (had_rejection, groups) = self.apply_swmi_attachment_state(queue, command_id, itsi, false, &attachment, local_results);
            let receipt = Self::send_d_location_update_accept_with_handover(
                queue,
                pending.itsi,
                pending.air_handle,
                pending.location_update_type,
                pending.energy_saving_information,
                pending.authentication_successful,
                &pending.aie,
                self.aie_request_for_terminal(pending.itsi),
                Some(GroupIdentityLocationAccept {
                    group_identity_accept_reject: u8::from(had_rejection),
                    group_identity_downlink: Some(groups),
                }),
                None,
                rua_requested,
            );
            self.config.state_write().subscribers.mark_active(pending.itsi);
            self.defer_sc2_activation(pending.itsi, &pending.aie, receipt);
            return;
        }
        let receipt = Self::send_d_location_update_accept_with_handover(
            queue,
            pending.itsi,
            pending.air_handle,
            pending.location_update_type,
            pending.energy_saving_information,
            pending.authentication_successful,
            &pending.aie,
            self.aie_request_for_terminal(pending.itsi),
            pending.has_group_identity_location_demand.then_some(GroupIdentityLocationAccept {
                group_identity_accept_reject: 0,
                group_identity_downlink: None,
            }),
            None,
            rua_requested,
        );
        self.config.state_write().subscribers.mark_active(pending.itsi);
        self.defer_sc2_activation(pending.itsi, &pending.aie, receipt);
        tracing::info!(
            command_id,
            itsi,
            authentication_successful = pending.authentication_successful,
            "SwMI location update accepted; awaiting/processing group attachment"
        );
    }

    fn apply_swmi_attachment_decision(
        &mut self,
        queue: &mut MessageQueue,
        command_id: u64,
        itsi: u64,
        air_handle: u32,
        has_rejection: bool,
        results: Vec<AttachmentResult>,
    ) {
        let Some(pending) = self.pending_attachments.remove(&command_id) else {
            tracing::warn!(command_id, itsi, "received SwMI attachment decision without pending air request");
            return;
        };
        if pending.itsi as u64 != itsi || pending.air_handle != air_handle || pending.operations.len() != results.len() {
            tracing::warn!(
                command_id,
                expected_itsi = pending.itsi,
                itsi,
                "discarding mismatched SwMI attachment decision"
            );
            return;
        }

        let (had_rejection, accepted_downlink) =
            self.apply_swmi_attachment_state(queue, command_id, itsi, has_rejection, &pending, results);
        self.send_d_attachment_acknowledgement(queue, pending.itsi, pending.air_handle, had_rejection, accepted_downlink);
        tracing::info!(
            command_id,
            itsi,
            rejected = had_rejection,
            "SwMI attachment decision sent on air interface"
        );
    }

    /// Restore affiliations received from the SwMI after a successful roam.
    /// This deliberately emits only internal MM->CMCE state changes: the MS
    /// has already completed its location update and must not receive a
    /// synthetic D-ATTACH/DETACH acknowledgement for state it did not just
    /// request over the air.
    fn apply_swmi_subscriber_state_sync(
        &mut self,
        queue: &mut MessageQueue,
        itsi: u64,
        groups: Vec<AttachmentOperation>,
        scanning_enabled: bool,
        energy_economy: EnergyEconomyAssignment,
    ) {
        let Ok(issi) = u32::try_from(itsi) else {
            tracing::warn!(itsi, "discarding roaming state with invalid ISSI");
            return;
        };
        if !self.client_mgr.client_is_known(issi) {
            if let Err(error) = self.client_mgr.try_register_client(issi, true) {
                tracing::warn!(issi, ?error, "unable to create target-cell subscriber state for roaming MS");
                return;
            }
            self.config.state_write().subscribers.register(issi);
            self.emit_subscriber_update(queue, issi, Vec::new(), BrewSubscriberAction::Register);
        }
        // This arrives before call replay during roaming, so UMAC has the
        // target-cell monitoring phase before it queues any MCCH setup.
        self.store_energy_economy(issi, energy_economy);
        let old_groups = self
            .client_mgr
            .get_client_by_issi(issi)
            .map(|client| client.groups.keys().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        if !old_groups.is_empty() {
            let _ = self.client_mgr.client_detach_all_groups(issi);
            {
                let mut state = self.config.state_write();
                for gssi in &old_groups {
                    state.subscribers.deaffiliate(issi, *gssi);
                }
            }
            self.emit_subscriber_update(queue, issi, old_groups, BrewSubscriberAction::Deaffiliate);
        }

        let mut restored = Vec::new();
        for group in groups.into_iter().filter(|group| !group.detach) {
            match self
                .client_mgr
                .client_group_attach_with_class_of_usage(issi, group.gssi, true, group.class_of_usage)
            {
                Ok(_) => {
                    self.config.state_write().subscribers.affiliate(issi, group.gssi);
                    restored.push(group.gssi);
                }
                Err(error) => tracing::warn!(issi, gssi = group.gssi, ?error, "unable to restore roaming affiliation"),
            }
        }
        let restored_count = restored.len();
        if !restored.is_empty() {
            self.emit_subscriber_update(queue, issi, restored, BrewSubscriberAction::Affiliate);
        }
        if self.client_mgr.set_client_scanning_enabled(issi, scanning_enabled).is_ok() {
            self.config.state_write().subscribers.set_scanning_enabled(issi, scanning_enabled);
            let update = MmSubscriberUpdate {
                issi,
                groups: Vec::new(),
                action: BrewSubscriberAction::ScanningState,
                class_of_usage: Vec::new(),
                scanning_enabled: Some(scanning_enabled),
            };
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Mm,
                dest: TetraEntity::Cmce,
                msg: SapMsgInner::MmSubscriberUpdate(update),
            });
        }
        tracing::info!(
            issi,
            groups = restored_count,
            scanning_enabled,
            ?energy_economy,
            "restored roaming group-scanning state from SwMI"
        );
    }

    fn apply_swmi_attachment_state(
        &mut self,
        queue: &mut MessageQueue,
        command_id: u64,
        itsi: u64,
        has_rejection: bool,
        pending: &PendingAttachment,
        results: Vec<AttachmentResult>,
    ) -> (bool, Vec<GroupIdentityDownlink>) {
        let accepted_attachment = results.iter().any(|result| result.accepted && !result.operation.detach);
        let mut had_rejection = has_rejection;
        if pending.replace_all && accepted_attachment {
            let prior_groups = self
                .client_mgr
                .get_client_by_issi(pending.itsi)
                .map(|client| client.groups.keys().copied().collect::<Vec<_>>())
                .unwrap_or_default();
            if self.client_mgr.client_detach_all_groups(pending.itsi).is_ok() && !prior_groups.is_empty() {
                {
                    let mut state = self.config.state_write();
                    for gssi in &prior_groups {
                        state.subscribers.deaffiliate(pending.itsi, *gssi);
                    }
                }
                self.emit_subscriber_update(queue, pending.itsi, prior_groups, BrewSubscriberAction::Deaffiliate);
            }
        }

        let mut accepted_downlink = Vec::new();
        let mut affiliated = Vec::new();
        let mut deaffiliated = Vec::new();
        for (result, original) in results.into_iter().zip(&pending.operations) {
            if !result.accepted {
                had_rejection = true;
                // TS 100 392-2 §16.8.2 requires every rejected MS-initiated
                // attachment to be named in a Group Identity Detachment
                // Downlink element.  Omitting it makes an MS treat the group
                // as accepted (or leaves its UI state stale), even though the
                // aggregate accept/reject bit is set.
                //
                // Cause 1 is the SwMI's "unknown group" policy outcome and
                // maps to detachment-downlink value 00.  The remaining policy
                // failures deliberately use the same safe, non-attaching
                // reason until richer per-policy air causes are modelled.
                accepted_downlink.push(GroupIdentityDownlink {
                    group_identity_attachment: None,
                    group_identity_detachment_uplink: Some(0),
                    gssi: Some(result.operation.gssi),
                    address_extension: None,
                    vgssi: None,
                });
                continue;
            }
            let gssi = result.operation.gssi;
            let detach = result.operation.detach;
            match self
                .client_mgr
                .client_group_attach_with_class_of_usage(pending.itsi, gssi, !detach, result.operation.class_of_usage)
            {
                Ok(changed) => {
                    if changed {
                        if detach {
                            self.config.state_write().subscribers.deaffiliate(pending.itsi, gssi);
                            deaffiliated.push(gssi);
                        } else {
                            self.config.state_write().subscribers.affiliate(pending.itsi, gssi);
                            affiliated.push(gssi);
                        }
                    }
                    accepted_downlink.push(GroupIdentityDownlink {
                        group_identity_attachment: (!detach).then_some(GroupIdentityAttachment {
                            group_identity_attachment_lifetime: 1,
                            class_of_usage: result.operation.class_of_usage,
                        }),
                        group_identity_detachment_uplink: detach.then_some(original.group_identity_detachment_uplink.unwrap_or(0)),
                        gssi: Some(gssi),
                        address_extension: None,
                        vgssi: None,
                    });
                }
                Err(error) => {
                    had_rejection = true;
                    tracing::warn!(
                        command_id,
                        itsi,
                        gssi,
                        ?error,
                        "SwMI accepted attachment but BS local state update failed"
                    );
                }
            }
        }
        if !affiliated.is_empty() {
            self.emit_subscriber_update(queue, pending.itsi, affiliated, BrewSubscriberAction::Affiliate);
        }
        if !deaffiliated.is_empty() {
            self.emit_subscriber_update(queue, pending.itsi, deaffiliated, BrewSubscriberAction::Deaffiliate);
        }
        (had_rejection, accepted_downlink)
    }

    fn local_attachment_results(pending: &PendingAttachment) -> Vec<AttachmentResult> {
        pending
            .operations
            .iter()
            .map(|group| AttachmentResult {
                operation: AttachmentOperation {
                    gssi: group.gssi.expect("validated before attachment decision"),
                    detach: group.group_identity_detachment_uplink.is_some(),
                    class_of_usage: group.class_of_usage.unwrap_or(0),
                },
                accepted: true,
                cause: 0,
            })
            .collect()
    }

    fn apply_swmi_location_attachment_decision(
        &mut self,
        queue: &mut MessageQueue,
        command_id: u64,
        itsi: u64,
        air_handle: u32,
        has_rejection: bool,
        results: Vec<AttachmentResult>,
    ) {
        let Some(pending) = self.pending_location_attachments.remove(&command_id) else {
            tracing::warn!(
                command_id,
                itsi,
                "received SwMI location attachment decision without pending air request"
            );
            return;
        };
        if pending.registration.itsi as u64 != itsi
            || pending.registration.air_handle != air_handle
            || pending.attachment.operations.len() != results.len()
        {
            tracing::warn!(
                command_id,
                expected_itsi = pending.registration.itsi,
                itsi,
                "discarding mismatched SwMI location attachment decision"
            );
            return;
        }
        let (had_rejection, groups) =
            self.apply_swmi_attachment_state(queue, command_id, itsi, has_rejection, &pending.attachment, results);
        let registration = pending.registration;
        let receipt = Self::send_d_location_update_accept_with_handover(
            queue,
            registration.itsi,
            registration.air_handle,
            registration.location_update_type,
            registration.energy_saving_information,
            registration.authentication_successful,
            &registration.aie,
            self.aie_request_for_terminal(registration.itsi),
            Some(GroupIdentityLocationAccept {
                group_identity_accept_reject: u8::from(had_rejection),
                group_identity_downlink: Some(groups),
            }),
            None,
            pending.rua_requested,
        );
        self.config.state_write().subscribers.mark_active(registration.itsi);
        self.defer_sc2_activation(registration.itsi, &registration.aie, receipt);
        tracing::info!(
            command_id,
            itsi,
            rejected = had_rejection,
            authentication_downlink = registration.authentication_successful,
            "SwMI location update and group attachment accepted on air interface"
        );
    }

    fn send_d_attachment_acknowledgement(
        &self,
        queue: &mut MessageQueue,
        issi: u32,
        handle: u32,
        has_rejection: bool,
        groups: Vec<GroupIdentityDownlink>,
    ) {
        let pdu = DAttachDetachGroupIdentityAcknowledgement {
            group_identity_accept_reject: u8::from(has_rejection),
            reserved: false,
            proprietary: None,
            group_identity_downlink: Some(groups),
            group_identity_security_related_information: None,
        };
        let mut sdu = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut sdu).expect("serialize SwMI D-ATTACH/DETACH acknowledgement");
        sdu.seek(0);
        queue.push_back(SapMsg {
            sap: Sap::LmmSap,
            src: TetraEntity::Mm,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                sdu,
                handle,
                address: TetraAddress::issi(issi),
                layer2service: Layer2Service::Acknowledged,
                stealing_permission: false,
                stealing_repeats_flag: false,
                encryption_flag: false,
                // A standalone group attachment is normal post-registration
                // signalling.  Unlike a location-update bootstrap response,
                // it must retain the terminal's active SC2 context.
                aie_request: self.downlink_aie_request(issi),
                is_null_pdu: false,
                tx_reporter: None,
                seamless_handover: None,
            }),
        });
    }

    fn send_d_location_update_accept(
        queue: &mut MessageQueue,
        issi: u32,
        handle: u32,
        location_update_type: LocationUpdateType,
        energy_saving_information: Option<EnergySavingInformation>,
        authentication_successful: bool,
        group_identity_location_accept: Option<GroupIdentityLocationAccept>,
    ) {
        let _ = Self::send_d_location_update_accept_with_handover(
            queue,
            issi,
            handle,
            location_update_type,
            energy_saving_information,
            authentication_successful,
            &AieLocationUpdateDecision::default(),
            AieRequest::clear(AieSubject::System, AieScope::MacResource),
            group_identity_location_accept,
            None,
            false,
        );
    }

    fn send_d_location_update_accept_with_handover(
        queue: &mut MessageQueue,
        issi: u32,
        handle: u32,
        location_update_type: LocationUpdateType,
        energy_saving_information: Option<EnergySavingInformation>,
        authentication_successful: bool,
        aie: &AieLocationUpdateDecision,
        aie_request: AieRequest,
        group_identity_location_accept: Option<GroupIdentityLocationAccept>,
        seamless_handover: Option<LmmMleSeamlessHandover>,
        rua_requested: bool,
    ) -> TxReporter {
        let pdu = DLocationUpdateAccept {
            location_update_accept_type: location_update_type,
            ssi: Some(issi as u64),
            address_extension: None,
            subscriber_class: None,
            energy_saving_information,
            scch_information_and_distribution_on_18th_frame: None,
            new_registered_area: None,
            security_downlink: None,
            group_identity_location_accept,
            default_group_attachment_lifetime: None,
            authentication_downlink: aie
                .authentication_downlink_bit_len
                .map(|len| {
                    let first = aie
                        .authentication_downlink
                        .get(..8)
                        .and_then(|bytes| bytes.try_into().ok())
                        .map(u64::from_be_bytes)
                        .unwrap_or_default();
                    Type3FieldGeneric {
                        field_id: MmType34ElemIdDl::AuthenticationDownlink.into(),
                        len: usize::from(len),
                        data: first,
                        raw: aie.authentication_downlink.clone(),
                    }
                })
                .or_else(|| {
                    authentication_successful.then(|| Type3FieldGeneric {
                        field_id: MmType34ElemIdDl::AuthenticationDownlink.into(),
                        // Authentication Downlink has three mandatory bits:
                        // authentication result, TEI request, and CK provisioning.
                        // Accept the authentication without requesting a TEI or
                        // provisioning a cipher key.
                        len: 3,
                        data: 0b100,
                        raw: Vec::new(),
                    })
                }),
            group_identity_security_related_information: None,
            cell_type_control: None,
            proprietary: rua_requested.then(|| Type3FieldGeneric {
                field_id: MmType34ElemIdDl::Proprietary.into(),
                // TTR 001-17 table 1: TETRA MoU (0x01), RUA requested (0x2),
                // assignment requested with alpha-tag RUI (0b100).
                len: 15,
                data: (1 << 7) | (2 << 3) | 4,
                raw: Vec::new(),
            }),
        };
        let mut sdu = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut sdu).expect("serialize SwMI D-LOCATION UPDATE ACCEPT");
        sdu.seek(0);
        tracing::debug!(
            issi,
            authentication_downlink = aie.authentication_downlink_bit_len.is_some() || authentication_successful,
            "sending D-LOCATION UPDATE ACCEPT"
        );
        let tx_reporter = TxReporter::new();
        queue.push_back(SapMsg {
            sap: Sap::LmmSap,
            src: TetraEntity::Mm,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                sdu,
                handle,
                address: TetraAddress::issi(issi),
                layer2service: Layer2Service::Acknowledged,
                stealing_permission: false,
                stealing_repeats_flag: false,
                encryption_flag: false,
                aie_request,
                is_null_pdu: false,
                tx_reporter: Some(tx_reporter.clone()),
                seamless_handover,
            }),
        });
        tx_reporter
    }

    /// Sends a D-LOCATION UPDATE COMMAND. Recovery paths can request a full
    /// group report; SwMI liveliness checks deliberately do not disturb it.
    fn send_d_location_update_command(&self, queue: &mut MessageQueue, issi: u32, handle: u32, group_identity_report: bool) {
        let ciphering_parameters = self.sc2_ciphering_parameters();
        let pdu = DLocationUpdateCommand {
            group_identity_report,
            cipher_control: ciphering_parameters.is_some(),
            ciphering_parameters: ciphering_parameters.map(u64::from),
            address_extension: None,
            cell_type_control: None,
            proprietary: None,
        };

        let mut sdu = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut sdu).unwrap();
        sdu.seek(0);
        tracing::debug!("-> DLocationUpdateCommand sdu {}", sdu.dump_bin());

        let msg = SapMsg {
            sap: Sap::LmmSap,
            src: TetraEntity::Mm,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                sdu,
                handle,
                address: TetraAddress::issi(issi),
                layer2service: Layer2Service::Acknowledged,
                stealing_permission: false,
                stealing_repeats_flag: false,
                encryption_flag: false,
                aie_request: AieRequest::clear(AieSubject::System, AieScope::MacResource),
                is_null_pdu: false,
                tx_reporter: None,
                seamless_handover: None,
            }),
        };
        queue.push_back(msg);
    }

    /// Sends a D-LOCATION UPDATE REJECT PDU (ETSI clause 16.9.2.9)
    fn send_d_location_update_reject(
        queue: &mut MessageQueue,
        issi: u32,
        handle: u32,
        location_update_type: LocationUpdateType,
        address_extension: Option<u64>,
    ) {
        Self::send_d_location_update_reject_with_cause(
            queue,
            issi,
            handle,
            location_update_type,
            address_extension,
            RejectCause::MigrationNotSupported as u8,
        );
    }

    fn send_d_location_update_reject_with_cause(
        queue: &mut MessageQueue,
        issi: u32,
        handle: u32,
        location_update_type: LocationUpdateType,
        address_extension: Option<u64>,
        reject_cause: u8,
    ) {
        let pdu = DLocationUpdateReject {
            location_update_type,
            reject_cause,
            cipher_control: false,
            ciphering_parameters: None,
            // Echo back MNI if present, required for case b) per ETSI 16.4.1.1
            address_extension,
            cell_type_control: None,
            proprietary: None,
        };

        let mut sdu = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut sdu).unwrap();
        sdu.seek(0);
        tracing::debug!("-> {} sdu {}", pdu, sdu.dump_bin());

        let msg = SapMsg {
            sap: Sap::LmmSap,
            src: TetraEntity::Mm,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                sdu,
                handle,
                address: TetraAddress::issi(issi),
                layer2service: Layer2Service::Acknowledged,
                stealing_permission: false,
                stealing_repeats_flag: false,
                encryption_flag: false,
                aie_request: AieRequest::clear(AieSubject::System, AieScope::MacResource),
                is_null_pdu: false,
                tx_reporter: None,
                seamless_handover: None,
            }),
        };
        queue.push_back(msg);
    }

    /// A class-2 negotiation failure must advertise the SwMI-selected
    /// KSG/SCKN (Table A.46) so the MS can re-register with the accepted
    /// parameters.  This is intentionally clear bootstrap signalling.
    fn send_d_location_update_reject_with_ciphering_parameters(
        queue: &mut MessageQueue,
        issi: u32,
        handle: u32,
        location_update_type: LocationUpdateType,
        address_extension: Option<u64>,
        reject_cause: u8,
        ciphering_parameters: u16,
    ) {
        let pdu = DLocationUpdateReject {
            location_update_type,
            reject_cause,
            cipher_control: true,
            ciphering_parameters: Some(u64::from(ciphering_parameters)),
            address_extension,
            cell_type_control: None,
            proprietary: None,
        };
        let mut sdu = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut sdu).expect("serialize SC2 D-LOCATION UPDATE REJECT");
        sdu.seek(0);
        queue.push_back(SapMsg {
            sap: Sap::LmmSap,
            src: TetraEntity::Mm,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                sdu,
                handle,
                address: TetraAddress::issi(issi),
                layer2service: Layer2Service::Acknowledged,
                stealing_permission: false,
                stealing_repeats_flag: false,
                encryption_flag: false,
                aie_request: AieRequest::clear(AieSubject::System, AieScope::MacResource),
                is_null_pdu: false,
                tx_reporter: None,
                seamless_handover: None,
            }),
        });
        tracing::info!(issi, reject_cause, ciphering_parameters, "sent SC2 registration negotiation reject");
    }

    /// Sends a D-MM-STATUS with ChangeOfEnergySavingModeResponse
    fn send_d_mm_status_energy_saving(&self, queue: &mut MessageQueue, issi: u32, handle: u32, esi: EnergySavingInformation) {
        let pdu = DMmStatus {
            status_downlink: StatusDownlink::ChangeOfEnergySavingModeResponse,
            energy_saving_information: Some(esi),
            gateway_payload: None,
            proprietary: None,
        };

        let mut sdu = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut sdu).unwrap();
        sdu.seek(0);
        tracing::debug!("-> {} sdu {}", pdu, sdu.dump_bin());

        let msg = SapMsg {
            sap: Sap::LmmSap,
            src: TetraEntity::Mm,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                sdu,
                handle,
                address: TetraAddress::issi(issi),
                layer2service: Layer2Service::Acknowledged,
                stealing_permission: false,
                stealing_repeats_flag: false,
                encryption_flag: false,
                aie_request: self.downlink_aie_request(issi),
                is_null_pdu: false,
                tx_reporter: None,
                seamless_handover: None,
            }),
        };
        queue.push_back(msg);
    }

    fn send_d_mm_status_gateway(
        &self,
        queue: &mut MessageQueue,
        issi: u32,
        handle: u32,
        status_downlink: StatusDownlink,
        gateway_payload: DMmStatusGatewayPayload,
    ) {
        let pdu = DMmStatus {
            status_downlink,
            energy_saving_information: None,
            gateway_payload: Some(gateway_payload),
            proprietary: None,
        };
        let mut sdu = BitBuffer::new_autoexpand(128);
        if let Err(error) = pdu.to_bitbuf(&mut sdu) {
            tracing::warn!(?error, issi, "cannot encode D-MM STATUS gateway response");
            return;
        }
        sdu.seek(0);
        queue.push_back(SapMsg {
            sap: Sap::LmmSap,
            src: TetraEntity::Mm,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                sdu,
                handle,
                address: TetraAddress::issi(issi),
                layer2service: Layer2Service::Acknowledged,
                stealing_permission: false,
                stealing_repeats_flag: false,
                encryption_flag: false,
                aie_request: self.downlink_aie_request(issi),
                is_null_pdu: false,
                tx_reporter: None,
                seamless_handover: None,
            }),
        });
    }

    fn publish_dm_gateway_state(&mut self, gateway_issi: u32, active: bool) {
        if !self.swmi.as_ref().is_some_and(|endpoint| endpoint.is_online()) {
            return;
        }
        let state = self.config.state_read();
        let session = state.dm_gateways.session(gateway_issi);
        let (dmo_carrier, dm_ms_addresses) = session
            .map(|session| {
                let carrier = session.dmo_carrier.map(|carrier| DmGatewayCarrier {
                    carrier_number: carrier.carrier_number,
                    frequency_band: carrier.frequency_band,
                    offset: carrier.offset,
                    duplex_spacing: carrier.duplex_spacing,
                    normal_reverse: carrier.normal_reverse,
                });
                let addresses = session
                    .dm_ms_addresses
                    .iter()
                    .map(|address| DmGatewayAddress {
                        ssi: address.ssi,
                        mcc: address.mcc,
                        mnc: address.mnc,
                    })
                    .collect();
                (carrier, addresses)
            })
            .unwrap_or((None, Vec::new()));
        drop(state);
        let command_id = self.next_swmi_command_id();
        if let Err(error) = self
            .swmi
            .as_ref()
            .expect("SwMI checked above")
            .submit(SwmiMessage::DmGatewayStateUpdate {
                command_id,
                gateway_issi: gateway_issi as u64,
                active,
                dmo_carrier,
                dm_ms_addresses,
            })
        {
            tracing::warn!(?error, gateway_issi, "cannot publish DM gateway state to SwMI");
        }
    }

    fn feature_check_u_itsi_detach(pdu: &UItsiDetach) -> bool {
        let supported = true;
        if pdu.address_extension.is_some() {
            unimplemented_log!("Unsupported address_extension present");
        };
        if pdu.proprietary.is_some() {
            unimplemented_log!("Unsupported proprietary present");
        };
        supported
    }

    fn feature_check_u_location_update_demand(pdu: &ULocationUpdateDemand) -> bool {
        let mut supported = true;
        if pdu.location_update_type == LocationUpdateType::MigratingLocationUpdating
            || pdu.location_update_type == LocationUpdateType::DisabledMsUpdating
        {
            unimplemented_log!("Unsupported {}", pdu.location_update_type);
            supported = false;
        }
        if pdu.request_to_append_la == true {
            unimplemented_log!("Unsupported request_to_append_la == true");
            supported = false;
        }
        // Cipher control and its ten-bit parameters are handled by the SC2
        // negotiation path before the registration reaches the SwMI.
        if pdu.la_information.is_some() {
            unimplemented_log!("Unsupported la_information present");
        }
        if pdu.ssi.is_some() {
            unimplemented_log!("Unsupported ssi present");
        }
        if pdu.address_extension.is_some() {
            unimplemented_log!("Unsupported address_extension present");
        }
        if pdu.group_report_response.is_some() {
            unimplemented_log!("Unsupported group_report_response present");
        }
        if pdu.authentication_uplink.is_some() {
            tracing::debug!("authentication_uplink is handled by the SwMI authentication state machine");
        }
        if pdu.extended_capabilities.is_some() {
            unimplemented_log!("Unsupported extended_capabilities present");
        }
        if pdu.proprietary.is_some() {
            unimplemented_log!("Unsupported proprietary present");
        }

        supported
    }

    /// Check for unsupported features in U-ATTACH/DETACH GROUP IDENTITY
    /// Returns false if a critical feature is missing
    fn feature_check_u_attach_detach_group_identity(pdu: &UAttachDetachGroupIdentity) -> bool {
        let mut supported = true;
        if pdu.group_identity_report == true {
            unimplemented_log!("Unsupported group_identity_report == true");
        }
        if pdu.group_identity_uplink.is_none() {
            unimplemented_log!("Missing group_identity_uplink");
            supported = false;
        }
        if pdu.group_report_response.is_some() {
            unimplemented_log!("Unsupported group_report_response present");
        }
        if pdu.proprietary.is_some() {
            unimplemented_log!("Unsupported proprietary present");
        }

        supported
    }
}

impl TetraEntityTrait for MmBs {
    fn entity(&self) -> TetraEntity {
        TetraEntity::Mm
    }

    fn set_config(&mut self, config: SharedConfig) {
        self.config = config;
    }

    fn tick_start(&mut self, queue: &mut MessageQueue, ts: TdmaTime) {
        self.current_time = ts;
        self.update_sc2_activations();
        self.update_otar_delivery_statuses();
        let timed_out: Vec<u64> = self
            .registration_deadlines
            .iter()
            .filter_map(|(&command_id, deadline)| (deadline.age(ts) >= 0).then_some(command_id))
            .collect();
        for command_id in timed_out {
            self.registration_deadlines.remove(&command_id);
            if let Some(pending) = self.pending_registrations.remove(&command_id) {
                self.config
                    .state_write()
                    .subscribers
                    .set_registration_delivery_pending(pending.itsi, false);
                tracing::warn!(command_id, issi = pending.itsi, "location update timed out at T351");
                Self::send_d_location_update_reject_with_cause(
                    queue,
                    pending.itsi,
                    pending.air_handle,
                    pending.location_update_type,
                    pending.address_extension,
                    RejectCause::NetworkFailure as u8,
                );
            }
        }
        while let Some(message) = self.swmi.as_ref().and_then(SwmiMmEndpoint::try_recv) {
            match message {
                SwmiMessage::LivelinessCheck { itsi } => {
                    let Ok(issi) = u32::try_from(itsi) else {
                        tracing::warn!(itsi, "discarding liveliness check with invalid ISSI");
                        continue;
                    };
                    if !self.config.state_read().subscribers.is_registered(issi) {
                        tracing::debug!(issi, "ignoring liveliness check for unknown local terminal");
                        continue;
                    }
                    queue.push_back(SapMsg {
                        sap: Sap::Control,
                        src: TetraEntity::Mm,
                        dest: TetraEntity::Cmce,
                        msg: SapMsgInner::CmceCallControl(CallControl::LivelinessCheckRequest { itsi: issi }),
                    });
                    tracing::debug!(issi, "queued SwMI liveliness check for CMCE call-state gating");
                }
                SwmiMessage::RegistrationDecision {
                    command_id,
                    itsi,
                    air_handle,
                    location_update_type: _,
                    accepted,
                    cause,
                    energy_economy,
                    rua_requested,
                    handover_allocation,
                    aie,
                } => self.apply_swmi_registration_decision(
                    queue,
                    command_id,
                    itsi,
                    air_handle,
                    accepted,
                    cause,
                    energy_economy,
                    rua_requested,
                    handover_allocation,
                    aie,
                ),
                SwmiMessage::AuthenticationChallenge {
                    command_id,
                    itsi,
                    air_handle,
                    rand_1,
                    random_seed,
                    mutual,
                } => {
                    self.pending_auth_commands
                        .insert(Self::authentication_correlation_key(itsi as u32, air_handle), command_id);
                    let pdu = DAuthenticationDemand { rand_1, random_seed };
                    let mut sdu = BitBuffer::new_autoexpand(24);
                    pdu.to_bitbuf(&mut sdu).unwrap();
                    sdu.seek(0);
                    queue.push_back(SapMsg {
                        sap: Sap::LmmSap,
                        src: TetraEntity::Mm,
                        dest: TetraEntity::Mle,
                        msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                            sdu,
                            handle: air_handle,
                            address: TetraAddress::issi(itsi as u32),
                            layer2service: Layer2Service::Acknowledged,
                            stealing_permission: false,
                            stealing_repeats_flag: false,
                            encryption_flag: false,
                            aie_request: self.aie_request_for_terminal(itsi as u32),
                            is_null_pdu: false,
                            tx_reporter: None,
                            seamless_handover: None,
                        }),
                    });
                    tracing::debug!(command_id, itsi, mutual, "sent D-AUTHENTICATION DEMAND");
                }
                SwmiMessage::AuthenticationResult {
                    command_id,
                    itsi,
                    air_handle,
                    success,
                    response_2,
                } => {
                    if success {
                        self.authenticated_registrations.insert(command_id);
                    } else {
                        self.authenticated_registrations.remove(&command_id);
                    }
                    let pdu = DAuthenticationResult {
                        success,
                        mutual: response_2.is_some(),
                        response_2,
                    };
                    let mut sdu = BitBuffer::new_autoexpand(16);
                    if pdu.to_bitbuf(&mut sdu).is_ok() {
                        sdu.seek(0);
                        queue.push_back(SapMsg {
                            sap: Sap::LmmSap,
                            src: TetraEntity::Mm,
                            dest: TetraEntity::Mle,
                            msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                                sdu,
                                handle: air_handle,
                                address: TetraAddress::issi(itsi as u32),
                                layer2service: Layer2Service::Acknowledged,
                                stealing_permission: false,
                                stealing_repeats_flag: false,
                                encryption_flag: false,
                                aie_request: self.aie_request_for_terminal(itsi as u32),
                                is_null_pdu: false,
                                tx_reporter: None,
                                seamless_handover: None,
                            }),
                        });
                    }
                    if !success {
                        Self::send_d_location_update_reject_with_cause(
                            queue,
                            itsi as u32,
                            air_handle,
                            LocationUpdateType::ItsiAttach,
                            None,
                            RejectCause::AuthenticationFailure as u8,
                        );
                    }
                    tracing::debug!(command_id, itsi, response_2 = ?response_2, "received D-AUTHENTICATION RESULT");
                }
                SwmiMessage::AuthenticationResponseDemand {
                    command_id,
                    itsi,
                    air_handle,
                    random_seed,
                    response_2,
                    mutual,
                    rand_1,
                } => {
                    let pdu = DAuthenticationResponse {
                        random_seed,
                        response_2,
                        mutual,
                        rand_1,
                    };
                    let mut sdu = BitBuffer::new_autoexpand(24);
                    if pdu.to_bitbuf(&mut sdu).is_ok() {
                        sdu.seek(0);
                        queue.push_back(SapMsg {
                            sap: Sap::LmmSap,
                            src: TetraEntity::Mm,
                            dest: TetraEntity::Mle,
                            msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                                sdu,
                                handle: air_handle,
                                address: TetraAddress::issi(itsi as u32),
                                layer2service: Layer2Service::Acknowledged,
                                stealing_permission: false,
                                stealing_repeats_flag: false,
                                encryption_flag: false,
                                aie_request: self.aie_request_for_terminal(itsi as u32),
                                is_null_pdu: false,
                                tx_reporter: None,
                                seamless_handover: None,
                            }),
                        });
                    }
                    self.pending_auth_commands
                        .insert(Self::authentication_correlation_key(itsi as u32, air_handle), command_id);
                }
                SwmiMessage::OtarDownlink {
                    command_id,
                    itsi,
                    air_handle,
                    address_ssi,
                    acknowledged,
                    payload_bit_len,
                    payload,
                } => {
                    let Ok(issi) = u32::try_from(itsi) else {
                        tracing::warn!(command_id, itsi, "discarding OTAR downlink with invalid ISSI");
                        continue;
                    };
                    if address_ssi != issi {
                        tracing::warn!(
                            command_id,
                            itsi,
                            address_ssi,
                            "discarding OTAR downlink with mismatched terminal address"
                        );
                        continue;
                    }
                    if usize::from(payload_bit_len) > payload.len().saturating_mul(8) {
                        tracing::warn!(command_id, issi, "discarding OTAR downlink with invalid bit length");
                        continue;
                    }
                    let mut sdu = BitBuffer::from_vec(payload);
                    sdu.set_raw_end(usize::from(payload_bit_len));
                    let mut check = BitBuffer::from_bitbuffer(&sdu);
                    let pdu = match DOtar::from_bitbuf(&mut check) {
                        Ok(pdu) => pdu,
                        Err(error) => {
                            tracing::warn!(command_id, issi, error = ?error, "discarding malformed SwMI D-OTAR PDU");
                            continue;
                        }
                    };
                    let kind = OtarDownlinkKind::from_pdu(&pdu);
                    let aie_request = match self.otar_downlink_aie_request(issi, kind) {
                        Ok(request) => request,
                        Err(reason) => {
                            tracing::warn!(command_id, issi, ?kind, reason, "rejecting unsafe clear D-OTAR in SC2-only mode");
                            continue;
                        }
                    };
                    if !acknowledged {
                        // MLE's MM route currently supports acknowledged
                        // basic-link service only. Rejecting this explicitly
                        // is safer than reaching its assertion and claiming a
                        // delivery status we cannot observe.
                        tracing::warn!(command_id, issi, ?kind, "cannot schedule unacknowledged D-OTAR on the MM route");
                        continue;
                    }
                    match &pdu {
                        DOtar::GskoProvide(provide) => {
                            self.gsko_bootstraps.insert(
                                issi,
                                GskoBootstrapStatus::Providing {
                                    command_id,
                                    version_number: provide.version_number,
                                    cmg_gssi: provide.cmg_gssi,
                                },
                            );
                        }
                        DOtar::GskoReject(reject) => {
                            self.gsko_bootstraps.insert(
                                issi,
                                GskoBootstrapStatus::Rejected {
                                    command_id,
                                    cmg_gssi: reject.cmg_gssi,
                                    reason: reject.reject_reason,
                                },
                            );
                        }
                        _ => {}
                    }
                    let tx_reporter = TxReporter::new();
                    self.pending_otar_deliveries.insert(
                        command_id,
                        PendingOtarDelivery {
                            command_id,
                            issi,
                            air_handle,
                            kind,
                            expected_response: kind.expected_response(),
                            tx_reporter: tx_reporter.clone(),
                            status: OtarDeliveryStatus::Queued,
                        },
                    );
                    sdu.seek(0);
                    queue.push_back(SapMsg {
                        sap: Sap::LmmSap,
                        src: TetraEntity::Mm,
                        dest: TetraEntity::Mle,
                        msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                            sdu,
                            handle: air_handle,
                            address: TetraAddress::issi(address_ssi),
                            layer2service: Layer2Service::Acknowledged,
                            stealing_permission: false,
                            stealing_repeats_flag: false,
                            encryption_flag: false,
                            aie_request,
                            is_null_pdu: false,
                            tx_reporter: Some(tx_reporter),
                            seamless_handover: None,
                        }),
                    });
                    tracing::debug!(
                        command_id,
                        issi,
                        address_ssi,
                        acknowledged,
                        ?kind,
                        encrypted = aie_request.is_encrypted(),
                        "scheduled SwMI D-OTAR PDU"
                    );
                }
                SwmiMessage::AttachmentDecision {
                    command_id,
                    itsi,
                    air_handle,
                    has_rejection,
                    results,
                } => {
                    if self.pending_location_attachments.contains_key(&command_id) {
                        self.apply_swmi_location_attachment_decision(queue, command_id, itsi, air_handle, has_rejection, results);
                    } else {
                        self.apply_swmi_attachment_decision(queue, command_id, itsi, air_handle, has_rejection, results);
                    }
                }
                SwmiMessage::SubscriberStateSync {
                    itsi,
                    groups,
                    scanning_enabled,
                    energy_economy,
                } => self.apply_swmi_subscriber_state_sync(queue, itsi, groups, scanning_enabled, energy_economy),
                SwmiMessage::LstRecoveryRequest { command_id } => {
                    if !self.pending_lst_recoveries.insert(command_id) {
                        tracing::warn!(command_id, "duplicate LST recovery request ignored");
                        continue;
                    }
                    let rua_state = self.config.state_read().subscribers.clone();
                    let subscribers = self.client_mgr.lst_recovery_snapshot(|issi| rua_state.rua_assignment_state(issi));
                    let subscriber_count = subscribers.len();
                    let Some(endpoint) = self.swmi.as_ref() else {
                        self.pending_lst_recoveries.remove(&command_id);
                        continue;
                    };
                    if let Err(error) = endpoint.submit(SwmiMessage::LstRecoverySnapshot { command_id, subscribers }) {
                        self.pending_lst_recoveries.remove(&command_id);
                        tracing::warn!(command_id, ?error, "cannot submit LST recovery snapshot to SwMI");
                    } else {
                        tracing::info!(command_id, subscriber_count, "uploaded LST subscriber recovery snapshot to SwMI");
                    }
                }
                SwmiMessage::LstRecoveryResult {
                    command_id,
                    accepted,
                    rejected,
                } => {
                    if !self.pending_lst_recoveries.remove(&command_id) {
                        tracing::warn!(command_id, "stale LST recovery result ignored");
                        continue;
                    }
                    let accepted_count = accepted.len();
                    let rejected_count = rejected.len();
                    for subscriber in accepted {
                        let requested_rua_reassignment = subscriber.rua_assigned == Some(false)
                            && u32::try_from(subscriber.itsi)
                                .ok()
                                .and_then(|issi| self.config.state_read().subscribers.rua_assignment_state(issi))
                                == Some(true);
                        self.apply_swmi_subscriber_state_sync(
                            queue,
                            subscriber.itsi,
                            subscriber.groups,
                            subscriber.scanning_enabled,
                            subscriber.energy_economy,
                        );
                        if requested_rua_reassignment {
                            let issi = subscriber.itsi as u32;
                            // TTR 001-17 figure 5: a D-LOCATION UPDATE COMMAND
                            // causes U-LOCATION UPDATE DEMAND, whose accept can
                            // carry the alpha-tag RUA assignment request.
                            self.config.state_write().subscribers.set_rua_assignment_state(issi, None);
                            self.send_d_location_update_command(queue, issi, 0, true);
                            tracing::info!(issi, command_id, "requested fresh RUA registration after LST mismatch");
                        }
                    }
                    for rejection in rejected {
                        let Ok(issi) = u32::try_from(rejection.itsi) else {
                            tracing::warn!(itsi = rejection.itsi, "invalid ISSI in LST recovery rejection");
                            continue;
                        };
                        if self.remove_local_subscriber(queue, issi) {
                            tracing::warn!(
                                command_id,
                                issi,
                                cause = rejection.cause,
                                "SwMI rejected LST subscriber recovery; removed local state"
                            );
                        }
                    }
                    tracing::info!(
                        command_id,
                        accepted_count,
                        rejected_count,
                        "applied canonical LST recovery result from SwMI"
                    );
                }
                // Command id zero is reserved for the SwMI-to-old-serving-BS
                // direction. It is deliberately not a normal U-ITSI DETACH:
                // the SwMI has already moved the authoritative registration
                // anchor, so only local MM/CMCE state must be discarded.
                SwmiMessage::DeregistrationNotice { command_id: 0, itsi } => {
                    let Ok(issi) = u32::try_from(itsi) else {
                        tracing::warn!(itsi, "discarding old-serving-cell cleanup with invalid ISSI");
                        continue;
                    };
                    if self.remove_local_subscriber(queue, issi) {
                        tracing::info!(issi, "discarded stale old-serving-cell subscriber state after roam");
                    }
                }
                SwmiMessage::DeregistrationNotice { command_id, itsi } => {
                    tracing::warn!(command_id, itsi, "unexpected nonzero deregistration notice from SwMI");
                }
                SwmiMessage::EnergyEconomyDecision {
                    command_id,
                    itsi,
                    air_handle,
                    accepted,
                    energy_economy,
                } => {
                    let Some((expected_issi, expected_handle)) = self.pending_energy_economy.remove(&command_id) else {
                        tracing::warn!(command_id, itsi, "EE decision without pending request");
                        continue;
                    };
                    if expected_issi != itsi as u32 || expected_handle != air_handle {
                        tracing::warn!(command_id, itsi, "discarding mismatched EE decision");
                        continue;
                    }
                    if accepted {
                        self.store_energy_economy(expected_issi, energy_economy);
                        if energy_economy.mode != 0 {
                            self.activate_energy_economy_after_next_control(expected_issi);
                        }
                        self.send_d_mm_status_energy_saving(
                            queue,
                            expected_issi,
                            expected_handle,
                            Self::esi_from_assignment(energy_economy),
                        );
                    } else {
                        tracing::warn!(command_id, itsi, "SwMI rejected EE mode change");
                    }
                }
                SwmiMessage::EnergyEconomyRebaseRequest { request_id, itsi, mode } => {
                    let Ok(issi) = u32::try_from(itsi) else {
                        tracing::warn!(request_id, itsi, "discarding EE rebase request with invalid ISSI");
                        continue;
                    };
                    let Ok(mode) = EnergySavingMode::try_from(mode as u64) else {
                        tracing::warn!(request_id, itsi, "discarding EE rebase request with invalid mode");
                        continue;
                    };
                    let assignment = self.energy_economy_assignment(mode);
                    if assignment.mode == 0 {
                        tracing::warn!(request_id, issi, "unexpected StayAlive EE rebase request");
                        continue;
                    }
                    if let Some(endpoint) = self.swmi.as_ref() {
                        if let Err(error) = endpoint.submit(SwmiMessage::EnergyEconomyRebaseResult {
                            request_id,
                            itsi,
                            energy_economy: assignment,
                        }) {
                            tracing::warn!(request_id, issi, ?error, "cannot return target-BS EE rebase result");
                        }
                    }
                }
                message => tracing::warn!(?message, "unexpected non-MM SwMI message on MM endpoint"),
            }
        }
        // A decision that was in flight when the SwMI link failed becomes an
        // LST decision. This preserves service locally instead of leaving a
        // terminal indefinitely waiting for an acknowledged response.
        if self.swmi.as_ref().is_some_and(|endpoint| !endpoint.is_online()) {
            let recover: Vec<(u64, u32, u32)> = self
                .pending_registrations
                .iter()
                .map(|(command_id, pending)| (*command_id, pending.itsi, pending.air_handle))
                .collect();
            for (command_id, itsi, air_handle) in recover {
                tracing::warn!(
                    command_id,
                    itsi,
                    "SwMI link unavailable; completing pending location update in local-site trunking"
                );
                let energy_economy = self
                    .pending_registrations
                    .get(&command_id)
                    .and_then(|pending| pending.energy_saving_information.as_ref())
                    .map(|info| EnergyEconomyAssignment {
                        mode: info.energy_saving_mode as u8,
                        frame_number: info.frame_number,
                        multiframe_number: info.multiframe_number,
                    })
                    .unwrap_or_default();
                self.apply_swmi_registration_decision(
                    queue,
                    command_id,
                    itsi as u64,
                    air_handle,
                    true,
                    0,
                    energy_economy,
                    false,
                    None,
                    AieLocationUpdateDecision::default(),
                );
            }
            let recover_attachments: Vec<(u64, u32, u32, Vec<AttachmentResult>)> = self
                .pending_attachments
                .iter()
                .map(|(command_id, pending)| {
                    (
                        *command_id,
                        pending.itsi,
                        pending.air_handle,
                        Self::local_attachment_results(pending),
                    )
                })
                .collect();
            for (command_id, itsi, air_handle, results) in recover_attachments {
                tracing::warn!(
                    command_id,
                    itsi,
                    "SwMI link unavailable; completing pending group operation in local-site trunking"
                );
                self.apply_swmi_attachment_decision(queue, command_id, itsi as u64, air_handle, false, results);
            }
            let recover_location_attachments: Vec<(u64, u32, u32, Vec<AttachmentResult>)> = self
                .pending_location_attachments
                .iter()
                .map(|(command_id, pending)| {
                    (
                        *command_id,
                        pending.registration.itsi,
                        pending.registration.air_handle,
                        Self::local_attachment_results(&pending.attachment),
                    )
                })
                .collect();
            for (command_id, itsi, air_handle, results) in recover_location_attachments {
                tracing::warn!(
                    command_id,
                    itsi,
                    "SwMI link unavailable; completing location-update group operation in local-site trunking"
                );
                self.apply_swmi_location_attachment_decision(queue, command_id, itsi as u64, air_handle, false, results);
            }
        }
        if let Some(cep) = &self.control {
            while let Some(cmd) = cep.try_recv() {
                match cmd {
                    // ControlCommand::CommandA { handle, parameter } => {
                    //     cep.respond(ControlResponse::CommandAResponse { handle, result: parameter * 2 });
                    // }
                    _ => {
                        panic!("Unsupported command {:?}", cmd);
                    }
                }
            }
        }
    }

    fn rx_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::debug!("rx_prim: {:?}", message);
        // tracing::debug!(ts=%message.dltime, "rx_prim: {:?}", message);

        match message.sap {
            Sap::LmmSap => match message.msg {
                SapMsgInner::LmmMleUnitdataInd(_) => self.rx_lmm_mle_unitdata_ind(queue, message),
                message => panic!("unexpected MM LMM primitive: {:?}", message),
            },
            Sap::Control => match message.msg {
                SapMsgInner::CmceCallControl(CallControl::LivelinessCheckReady { itsi }) => {
                    if self.config.state_read().subscribers.is_registered(itsi) {
                        self.send_d_location_update_command(queue, itsi, 0, false);
                        tracing::debug!(itsi, "sent deferred D-LOCATION UPDATE COMMAND for SwMI liveliness check");
                    } else {
                        tracing::debug!(itsi, "discarding deferred liveliness check for no-longer-registered terminal");
                    }
                }
                message => panic!("unexpected MM control primitive: {:?}", message),
            },
            sap => panic!("unexpected MM SAP: {:?}", sap),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MmBs, OtarDownlinkKind, OtarTerminalResponse, sc2_ksg_number};
    use tetra_config::bluestation::RuntimeSc2TeaAlgorithm;
    use tetra_core::typed_pdu_fields::Type3FieldGeneric;
    use tetra_swmi_protocol::EnergyEconomyAssignment;

    #[test]
    fn sc2_ksg_numbers_match_the_on_air_table() {
        assert_eq!(sc2_ksg_number(RuntimeSc2TeaAlgorithm::Tea1), 0b0000);
        assert_eq!(sc2_ksg_number(RuntimeSc2TeaAlgorithm::Tea3), 0b0010);
    }

    #[test]
    fn authentication_correlation_distinguishes_terminals_with_handle_zero() {
        assert_ne!(
            MmBs::authentication_correlation_key(77491, 0),
            MmBs::authentication_correlation_key(77492, 0)
        );
    }

    #[test]
    fn authentication_uplink_two_bit_sck_request_is_not_discarded() {
        let field = Type3FieldGeneric {
            field_id: 9,
            len: 2,
            data: 0b10,
            raw: Vec::new(),
        };
        assert_eq!(MmBs::authentication_uplink(&field), Some((true, None)));
    }

    #[test]
    fn periodic_or_demand_update_without_energy_mode_retains_assignment() {
        let current = Some(EnergyEconomyAssignment {
            mode: 4,
            frame_number: Some(12),
            multiframe_number: Some(7),
        });

        assert_eq!(
            MmBs::energy_economy_for_omitted_request(
                tetra_pdus::mm::enums::location_update_type::LocationUpdateType::PeriodicLocationUpdating,
                current,
            ),
            current.unwrap(),
        );
        assert_eq!(
            MmBs::energy_economy_for_omitted_request(
                tetra_pdus::mm::enums::location_update_type::LocationUpdateType::DemandLocationUpdating,
                current,
            ),
            current.unwrap(),
        );
    }

    #[test]
    fn only_gsko_bootstrap_downlinks_are_clear_otar_exceptions() {
        assert!(OtarDownlinkKind::GskoProvide.is_clear_gsko_bootstrap());
        assert!(OtarDownlinkKind::GskoReject.is_clear_gsko_bootstrap());
        assert!(!OtarDownlinkKind::SckProvide.is_clear_gsko_bootstrap());
        assert!(!OtarDownlinkKind::KeyStatusDemand.is_clear_gsko_bootstrap());
    }

    #[test]
    fn otar_result_correlation_keeps_link_ack_and_terminal_result_distinct() {
        assert_eq!(
            OtarDownlinkKind::SckProvide.expected_response(),
            Some(OtarTerminalResponse::SckResult)
        );
        assert_eq!(
            OtarDownlinkKind::KeyStatusDemand.expected_response(),
            Some(OtarTerminalResponse::KeyStatusResponse)
        );
        assert_eq!(OtarDownlinkKind::SckReject.expected_response(), None);
    }
}
