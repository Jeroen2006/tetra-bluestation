use crate::net_control::ControlEndpoint;
use crate::net_telemetry::channel::TelemetrySink;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::net_swmi::SwmiMmEndpoint;
use crate::{MessageQueue, TetraEntityTrait, net_brew};
use tetra_config::bluestation::{DmMsRouteAddress, DmoCarrierState, SharedConfig};
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::typed_pdu_fields::Type3FieldGeneric;
use tetra_core::{
    AieRequest, AieScope, AieSubject, BitBuffer, Layer2Service, Sap, Sc3KeyType, SsiType, TdmaTime, TetraAddress, TxReporter, TxState,
    assert_warn, unimplemented_log,
};
use tetra_saps::control::brew::{BrewSubscriberAction, MmSubscriberUpdate};
use tetra_saps::control::call_control::CallControl;
use tetra_saps::lmm::{LmmMleSeamlessHandover, LmmMleUnitdataReq};
use tetra_saps::tla::TlaTlDataReqBl;
use tetra_saps::{SapMsg, SapMsgInner};
use tetra_swmi_protocol::{
    AieLocationUpdateDecision, AieObservationEvent, AieObservationState, AttachmentOperation, AttachmentResult, DmGatewayAddress,
    DmGatewayCarrier, EnergyEconomyAssignment, HandoverChannelAllocation, Sc3RetrievalEvidence, SwmiMessage, TerminalAieCapabilities,
    TerminalAieObservation, TerminalControlAction, TerminalInformation, TerminalSecurityClass,
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
use tetra_pdus::mm::fields::group_identity_security_related_information::{
    GckSelectNumber, GroupGckAssociation, GroupIdentitySecurityRelatedInformation,
};
use tetra_pdus::mm::fields::group_identity_uplink::GroupIdentityUplink;
use tetra_pdus::mm::fields::security_downlink::SecurityDownlink;
use tetra_pdus::mm::pdus::ck_change::{CkChangeTime, DAllGcksChangeDemand, DCkChangeDemand, SckChangeData, UCkChangeResult};
use tetra_pdus::mm::pdus::d_attach_detach_group_identity::DAttachDetachGroupIdentity;
use tetra_pdus::mm::pdus::d_attach_detach_group_identity_acknowledgement::DAttachDetachGroupIdentityAcknowledgement;
use tetra_pdus::mm::pdus::d_authentication_demand::DAuthenticationDemand;
use tetra_pdus::mm::pdus::d_authentication_response::DAuthenticationResponse;
use tetra_pdus::mm::pdus::d_authentication_result::DAuthenticationResult;
use tetra_pdus::mm::pdus::d_location_update_accept::DLocationUpdateAccept;
use tetra_pdus::mm::pdus::d_location_update_command::DLocationUpdateCommand;
use tetra_pdus::mm::pdus::d_location_update_reject::DLocationUpdateReject;
use tetra_pdus::mm::pdus::d_mm_status::DMmStatus;
use tetra_pdus::mm::pdus::d_mm_status::DMmStatusGatewayPayload;
use tetra_pdus::mm::pdus::otar::{DOtar, OtarSessionKey, UOtar};
use tetra_pdus::mm::pdus::u_attach_detach_group_identity::UAttachDetachGroupIdentity;
use tetra_pdus::mm::pdus::u_attach_detach_group_identity_acknowledgement::UAttachDetachGroupIdentityAcknowledgement;
use tetra_pdus::mm::pdus::u_authentication::UAuthentication;
use tetra_pdus::mm::pdus::u_information_provide::UInformationProvide;
use tetra_pdus::mm::pdus::u_itsi_detach::UItsiDetach;
use tetra_pdus::mm::pdus::u_location_update_demand::ULocationUpdateDemand;
use tetra_pdus::mm::pdus::u_mm_status::UMmStatus;
use tetra_pdus::mm::pdus::u_mm_status::UMmStatusGatewayPayload;
use tetra_pdus::mm::pdus::u_tei_provide::UTeiProvide;

/// ETSI T351 = 10 seconds. TETRA has 18 TDMA frames of four slots per second.
const T351_TIMESLOTS: i32 = 10 * 18 * 4;
/// Use the standardized attach/detach response interval as the upper bound for
/// the layer-3 acknowledgement to an infrastructure-initiated Figure-20
/// amendment.  A basic-link ACK is delivery evidence only.
const GROUP_SECURITY_ACK_TIMEOUT_TIMESLOTS: i32 = 10 * 18 * 4;
/// A terminal may still be completing MM registration after it has generated
/// the BL-ACK for D-LOCATION UPDATE ACCEPT.  Registration overrides a colliding
/// group attachment procedure (TS 100 392-2 clause 16.8.6), so leave one
/// multiframe before sending an association that arrived too late for the
/// location-update response itself.
const GROUP_SECURITY_REGISTRATION_GUARD_TIMESLOTS: i32 = 18 * 4;
/// Initial transmission plus two bounded application-layer retries. LLC keeps
/// ownership of the independent basic-link retransmissions for each attempt.
const MAX_GROUP_SECURITY_RETRIES: u8 = 2;
const TERMINAL_CONTROL_TIMEOUT_TIMESLOTS: i32 = 10 * 18 * 4;
const TERMINAL_CONTROL_CAUSE_RADIO_LINK_FAILED: u8 = 240;
const TERMINAL_CONTROL_CAUSE_RESPONSE_TIMEOUT: u8 = 241;

// EN 300 392-7 table A.46, in on-air order: KSG(4), SC(1), TM-SCK,
// SDMO/DM-SCK, GCK, security-information protocol, reserved.
const CIPHERING_PARAMETERS_SC3: u64 = 1 << 5;
const CIPHERING_PARAMETERS_SECURITY_INFORMATION: u64 = 1 << 1;

fn supports_security_information_protocol(parameters: u64) -> bool {
    parameters & CIPHERING_PARAMETERS_SC3 != 0 && parameters & CIPHERING_PARAMETERS_SECURITY_INFORMATION != 0
}

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
/// EG7 terminals may monitor the MCCH only once per 64 multiframes.  Every
/// all-MS rollover announcement is additionally aligned by UMAC to the next
/// two known EE monitoring occasions.  Repeat once per complete maximum EE
/// cycle as well, covering terminals which register or change EE phase later.
const ROLLOVER_BROADCAST_INTERVAL_TIMESLOTS: i32 = 64 * 18 * 4;
/// Linked GCK crypto periods use the same maximum-EE-cycle repetition as an
/// SCK rollover. Unlike the short SYSINFO value, this PDU carries all 16 bits
/// and therefore also repairs terminals returning after several periods.
const GCK_VERSION_BROADCAST_INTERVAL_TIMESLOTS: i32 = 64 * 18 * 4;
/// Repeat the planned change on a short cadence. The scheduler may defer these
/// low-priority messages behind SDS/call traffic.
const GCK_ROLLOVER_BROADCAST_INTERVAL_TIMESLOTS: i32 = 5 * 18 * 4;
/// An individually addressed copy can be acknowledged on a listener's
/// assigned channel. Space retries so several listeners do not monopolize
/// the call's FN18 signalling opportunities.
const GCK_ASSIGNED_NOTICE_INTERVAL_TIMESLOTS: i32 = 60 * 18 * 4;
/// Repeat the exact same Absolute-IV demand in three separate rounds shortly
/// before cutover.  Each round is sent on MCCH and as STCH on every active
/// traffic channel.  Four frames of final lead time leaves the entity and
/// one-slot-ahead scheduler pipelines enough room to put the last copy on air
/// before the activation slot.
const ROLLOVER_LATE_BROADCAST_OFFSETS_TIMESLOTS: [i32; 3] = [12 * 4, 8 * 4, 4 * 4];
const ROLLOVER_OTAR_RESULT_TIMEOUT_TIMESLOTS: i32 = 128 * 18 * 4;

fn absolute_iv_time(time: TdmaTime) -> CkChangeTime {
    CkChangeTime::AbsoluteIv {
        // EN 300 392-7 §6.3.2.1: only the two-bit slot component is
        // zero-based (slot 1 is encoded as 0). Frame and multiframe are the
        // normal on-air counters, respectively 1..=18 and 1..=60. Sending
        // either of those one lower makes an MS apply a D-CK CHANGE DEMAND
        // at a different IV from the BS, corrupting encrypted traffic at
        // the rollover boundary.
        slot_number: time.t - 1,
        frame_number: time.f,
        multiframe_number: time.m,
        hyperframe_number: time.h,
    }
}

/// The response type which completes an OTAR transaction at the application
/// layer.  This is deliberately separate from a basic-link acknowledgement:
/// BL-ACK proves radio delivery, while a U-OTAR result reports provisioning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OtarTerminalResponse {
    CckResult,
    SckResult,
    GckResult,
    GskoResult,
    KeyDeleteResult,
    KeyStatusResponse,
    CmgGtsiResult,
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
    KeyDeleteDemand,
    KeyStatusDemand,
    CmgGtsiProvide,
}

/// A group sealing key does not by itself make an OTAR PDU group-addressed.
/// The radio address determines the basic-link service and the AIE route.
fn otar_downlink_is_group_addressed(pdu: &DOtar, address_ssi: u32, issi: u32) -> bool {
    matches!(
        pdu,
        DOtar::GckProvide(provide)
            if matches!(provide.session_key, OtarSessionKey::Group { .. })
    ) && address_ssi != issi
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
            DOtar::KeyDeleteDemand(_) => Self::KeyDeleteDemand,
            DOtar::KeyStatusDemand(_) => Self::KeyStatusDemand,
            DOtar::CmgGtsiProvide(_) => Self::CmgGtsiProvide,
        }
    }

    fn expected_response(self) -> Option<OtarTerminalResponse> {
        match self {
            Self::CckProvide => Some(OtarTerminalResponse::CckResult),
            Self::SckProvide => Some(OtarTerminalResponse::SckResult),
            Self::GckProvide => Some(OtarTerminalResponse::GckResult),
            Self::GskoProvide => Some(OtarTerminalResponse::GskoResult),
            Self::KeyDeleteDemand => Some(OtarTerminalResponse::KeyDeleteResult),
            Self::KeyStatusDemand => Some(OtarTerminalResponse::KeyStatusResponse),
            Self::CmgGtsiProvide => Some(OtarTerminalResponse::CmgGtsiResult),
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
    TimedOut,
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
    /// GCK RESULT has no command identifier; retain the public key identities.
    gck_keys: Option<Vec<(u16, u16)>>,
    tx_reporter: TxReporter,
    status: OtarDeliveryStatus,
    result_deadline: TdmaTime,
}

/// Latest D-LOCATION UPDATE ACCEPT delivery for one local terminal. LLC owns
/// the encoded retransmission; MM retains only the shared link receipt and
/// non-sensitive correlation metadata needed to commit the registration.
#[derive(Debug)]
struct PendingRegistrationDelivery {
    command_id: Option<u64>,
    issi: u32,
    authentication_downlink: bool,
    /// Groups whose GCK association was included in this location update
    /// accept, retained only for delivery diagnostics.
    security_groups: Vec<u32>,
    tx_reporter: TxReporter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GroupSecurityAssociationPhase {
    LinkDelivery,
    AwaitingMmAcknowledgement,
}

/// One Figure-20 transaction. There is no transaction identifier in the air
/// PDU, therefore at most one instance may exist for a terminal at a time.
/// The structure contains only public GSSI/GCKN selection metadata; key bytes
/// remain inside the runtime AIE provider.
#[derive(Debug)]
struct PendingGroupSecurityAssociation {
    air_handle: u32,
    groups: Vec<u32>,
    tx_reporter: TxReporter,
    phase: GroupSecurityAssociationPhase,
    acknowledgement_deadline: Option<TdmaTime>,
    retries: u8,
}

#[derive(Debug, Default)]
struct QueuedGroupSecurityAssociation {
    air_handle: u32,
    groups: HashSet<u32>,
    retries: u8,
}

#[derive(Debug)]
struct PendingTerminalControl {
    command_id: u64,
    action: TerminalControlAction,
    operations: Vec<AttachmentOperation>,
    tx_reporter: Option<TxReporter>,
    /// Starts immediately for location-update controls and only after LLC
    /// delivery for group controls that have their own MM acknowledgement.
    response_deadline: Option<TdmaTime>,
    information: TerminalInformation,
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
    /// A registration is not active merely because its accept was queued.
    /// Keep the newest delivery per ISSI pending until LLC observes BL-ACK.
    pending_registration_deliveries: HashMap<u32, PendingRegistrationDelivery>,
    /// SwMI-initiated GSSI -> GCKN amendments awaiting their normative MM ACK.
    pending_group_security_associations: HashMap<u32, PendingGroupSecurityAssociation>,
    /// Coalesced desired associations which cannot start while registration or
    /// another Figure-20 transaction owns the terminal's MM exchange.
    queued_group_security_associations: HashMap<u32, QueuedGroupSecurityAssociation>,
    /// Earliest safe start after a registration BL-ACK, preventing the new
    /// attachment exchange from colliding with terminal-side registration MM.
    group_security_not_before: HashMap<u32, TdmaTime>,
    /// Empty acknowledged BL-DATA presence probes requested by the SwMI.
    /// These deliberately live outside MM registration state: a reachability
    /// check must not mutate affiliations, security associations or roaming.
    pending_liveliness_probes: HashMap<u32, TxReporter>,
    pending_terminal_controls: HashMap<u32, PendingTerminalControl>,
    security_information_protocol_supported: HashSet<u32>,
    /// SwMI command id of the newest accepted local registration. Roaming
    /// cleanup is safe only while this still matches the superseded session.
    registration_generations: HashMap<u32, u64>,
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
    pending_security_activations: HashMap<u32, (TerminalSecurityClass, TxReporter)>,
    /// Last all-MS rollover announcement. This is metadata only; the SCK
    /// remains inside runtime AIE state.
    last_rollover_broadcast: Option<(u64, TdmaTime)>,
    /// Last periodic full current GCK-VN advertisement.
    last_gck_version_broadcast: Option<(u16, TdmaTime)>,
    last_gck_rollover_broadcast: Option<(u64, TdmaTime)>,
    /// Last individual Absolute-IV notice for each current listening route.
    assigned_gck_notices: HashMap<(u64, u32), (u8, TdmaTime)>,
    /// The final all-timeslot `Immediate` demand is one-shot and sent by a
    /// dedicated scheduler reservation, never by the best-effort queue.
    gck_rollover_immediate_sent: Option<u64>,
    /// Bit mask of the three pre-cutover all-MS broadcast rounds already
    /// queued for the current rollover.  This replaces per-terminal D-CK
    /// CHANGE delivery; OTAR key provisioning remains individually tracked.
    rollover_late_broadcast_mask: Option<(u64, u8)>,
    current_time: TdmaTime,
}

struct PendingRegistration {
    itsi: u32,
    air_handle: u32,
    /// Whether this exact U-LOCATION UPDATE DEMAND was successfully decoded
    /// under SC2.  Registration responses must follow this bearer, rather
    /// than a possibly stale terminal binding left by the previous SCK.
    air_interface_encrypted: bool,
    location_update_type: LocationUpdateType,
    address_extension: Option<u64>,
    energy_saving_information: Option<EnergySavingInformation>,
    has_group_identity_location_demand: bool,
    location_attachment: Option<PendingAttachment>,
    /// GCK associations from a colliding Figure-20 transaction. Registration
    /// overrides that transaction, so its associations move into the ensuing
    /// D-LOCATION UPDATE ACCEPT rather than being silently discarded.
    interrupted_group_security_gssis: Vec<u32>,
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
    fn normalized_group_security_gssis(&self, gssis: impl IntoIterator<Item = u32>) -> Vec<u32> {
        let state = self.config.state_read();
        let Some(sc3) = state.aie.sc3.as_ref().filter(|sc3| sc3.linked_gck_crypto_periods()) else {
            return Vec::new();
        };
        let mut groups = gssis
            .into_iter()
            .filter(|gssi| sc3.gckn_for_gssi(*gssi).is_some())
            .collect::<Vec<_>>();
        groups.sort_unstable();
        groups.dedup();
        groups.truncate(30);
        groups
    }

    /// Include the associations requested by this registration. Existing
    /// scan groups restored from the SwMI do not need another air-interface
    /// attachment or association exchange (TTR 001-01 6.4/8.3 and TTR 001-11
    /// 6.2.8.2). Their presence must not enlarge the registration accept.
    fn registration_group_security_gssis(&self, _issi: u32, gssis: impl IntoIterator<Item = u32>) -> Vec<u32> {
        self.normalized_group_security_gssis(gssis)
    }

    fn group_security_information(&self, gssis: impl IntoIterator<Item = u32>) -> Option<Vec<GroupIdentitySecurityRelatedInformation>> {
        let gssis = self.normalized_group_security_gssis(gssis);
        let state = self.config.state_read();
        let sc3 = state.aie.sc3.as_ref()?;
        if !sc3.linked_gck_crypto_periods() {
            return None;
        }
        let associations = gssis
            .into_iter()
            // TTR 001-11 table 14 permits only an actual GCKN in group
            // attachment signalling.  Although the underlying security
            // specification defines 2^16 as "No GCKN selected", the SC3G
            // interoperability profile reserves that value.  Emitting it
            // automatically for every CCK-only or detached group can make an
            // MS discard the complete D-ATTACH/DETACH acknowledgement.
            .filter_map(|gssi| {
                sc3.gckn_for_gssi(gssi).map(|gckn| GroupGckAssociation {
                    gssi,
                    selection: GckSelectNumber::Selected(gckn),
                })
            })
            .collect::<Vec<_>>();
        let mut elements: Vec<GroupIdentitySecurityRelatedInformation> = Vec::new();
        for association in associations {
            if let Some(element) = elements
                .iter_mut()
                .find(|e| e.associations[0].selection == association.selection && e.associations.len() < 30)
            {
                element.associations.push(association);
            } else {
                elements.push(GroupIdentitySecurityRelatedInformation {
                    associations: vec![association],
                });
            }
        }
        (!elements.is_empty()).then_some(elements)
    }

    /// Select an explicit downlink policy while the MM transaction still
    /// knows whether this terminal completed the SC2 bootstrap. Registration
    /// constructors deliberately use `clear`; OTAR uses the stricter helper
    /// below. A terminal without a binding must never be guessed capable of
    /// protected normal OTAR.
    fn downlink_aie_request(&self, issi: u32) -> AieRequest {
        let state = self.config.state_read();
        if !state.aie.enabled || state.aie_sessions.terminal_allows_clear(issi) {
            return AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource);
        }
        if state.aie_sessions.terminal_class(issi) == TerminalSecurityClass::Sc3
            && state.aie.sc3.as_ref().is_some_and(|sc3| sc3.has_dck(issi))
        {
            return AieRequest::sc3(AieSubject::Individual { issi }, AieScope::MacResource);
        }
        if state.aie_sessions.terminal_class(issi) == TerminalSecurityClass::Sc2 && state.aie_sessions.terminal(issi).is_some() {
            AieRequest::sc2(AieSubject::Individual { issi }, AieScope::MacResource)
        } else if state.subscribers.is_registered(issi) {
            // Unknown/partially restored registered state is fail-closed.
            if state.aie.sc3.is_some() {
                AieRequest::sc3(AieSubject::Individual { issi }, AieScope::MacResource)
            } else {
                AieRequest::sc2(AieSubject::Individual { issi }, AieScope::MacResource)
            }
        } else {
            AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource)
        }
    }

    /// Class-3 group-addressed signalling uses MGCK when the GSSI has an
    /// association and CCK otherwise. CMG-addressed security OTAR uses the
    /// latter because CMG is never an ordinary talkgroup.
    fn group_downlink_aie_request(&self, gssi: u32) -> AieRequest {
        let state = self.config.state_read();
        let sc3g = state.aie.sc3.as_ref().is_some_and(|sc3| sc3.gckn_for_gssi(gssi).is_some());
        if !sc3g && state.aie_sessions.group_protection(gssi) == tetra_swmi_protocol::GroupProtection::Clear {
            return AieRequest::clear(AieSubject::Group { gssi }, AieScope::MacResource);
        }
        if state.aie.enabled && state.aie.sc3.is_some() {
            return AieRequest::sc3(AieSubject::Group { gssi }, AieScope::MacResource);
        }
        if state.aie.enabled && state.aie.sc2.is_some() {
            AieRequest::sc2(AieSubject::Group { gssi }, AieScope::MacResource)
        } else {
            AieRequest::clear(AieSubject::Group { gssi }, AieScope::MacResource)
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
        if state.aie.sc3.as_ref().is_some_and(|sc3| sc3.has_dck(issi)) {
            return Ok(AieRequest::sc3(AieSubject::Individual { issi }, AieScope::MacResource));
        }
        if state.aie_sessions.terminal(issi).is_some() {
            return Ok(AieRequest::sc2(AieSubject::Individual { issi }, AieScope::MacResource));
        }
        if state.aie_sessions.terminal_allows_clear(issi) && kind.is_clear_gsko_bootstrap() {
            return Ok(AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource));
        }
        Err("SC2-only OTAR downlink has no active terminal cipher context")
    }

    /// CMG-addressed GCK OTAR is group-addressed, unacknowledged at basic
    /// link and protected by the class-3 CCK context. Its GCK payload is
    /// separately sealed with EGSKO (TTR 001-11 §§6.2.10 and 6.3.2.3).
    fn cmg_otar_downlink_aie_request(&self, cmg_gssi: u32) -> Result<AieRequest, &'static str> {
        let state = self.config.state_read();
        if !state.aie.enabled {
            return Ok(AieRequest::clear(AieSubject::Group { gssi: cmg_gssi }, AieScope::MacResource));
        }
        if state.aie.sc3.is_some() {
            // A CMG is a key-management group without an ordinary GCK
            // association. Its group-addressed signalling uses the CCK;
            // group_protection() describes voice groups and may be Clear.
            return Ok(AieRequest::sc3(AieSubject::Group { gssi: cmg_gssi }, AieScope::MacResource));
        }
        Err("CMG-addressed GCK OTAR requires class-3 air-interface security")
    }

    fn remember_otar_outcome(&mut self, delivery: CompletedOtarDelivery) {
        if self.recent_otar_deliveries.len() == MAX_RECENT_OTAR_DELIVERIES {
            self.recent_otar_deliveries.pop_front();
        }
        self.recent_otar_deliveries.push_back(delivery);
    }

    fn rollover_otar_id(command_id: u64, issi: u32, kind: OtarDownlinkKind) -> Option<u64> {
        (kind == OtarDownlinkKind::SckProvide && (command_id & 0x00ff_ffff) == u64::from(issi) && command_id >> 24 != 0)
            .then_some(command_id >> 24)
    }

    fn report_rollover_otar_status(
        &mut self,
        command_id: u64,
        issi: u32,
        air_handle: u32,
        kind: OtarDownlinkKind,
        state: &str,
        success: Option<bool>,
    ) {
        let Some(rollover_id) = Self::rollover_otar_id(command_id, issi, kind) else {
            return;
        };
        self.report_aie_observation(
            issi,
            air_handle,
            AieObservationEvent::Otar,
            self.effective_aie_state(issi, true),
            Some(true),
            None,
            None,
            None,
            success,
            None,
            Some(format!("rollover-otar:{rollover_id}:{state}")),
        );
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
            let (issi, air_handle, kind, status_change, complete, rollover_event) = {
                let Some(pending) = self.pending_otar_deliveries.get_mut(&command_id) else {
                    continue;
                };
                let tx_state = pending.tx_reporter.get_state();
                let link_ack_expected = pending.tx_reporter.expects_ack();
                let previous_status = pending.status;
                let mut complete = None;
                let mut rollover_event = None;

                match tx_state {
                    TxState::Pending => {}
                    TxState::Discarded | TxState::Lost => {
                        let failed = OtarDeliveryStatus::LinkFailed { state: tx_state };
                        pending.status = failed;
                        complete = Some(failed);
                        rollover_event = Some(("link-failed", Some(false)));
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
                            rollover_event = Some(("link-ack", Some(true)));
                        } else {
                            complete = Some(OtarDeliveryStatus::LinkAcknowledged);
                        }
                    }
                    TxState::Acknowledged => {}
                }
                if pending.status == OtarDeliveryStatus::AwaitingTerminalResult && pending.result_deadline.age(self.current_time) >= 0 {
                    pending.status = OtarDeliveryStatus::TimedOut;
                    complete = Some(OtarDeliveryStatus::TimedOut);
                    rollover_event = Some(("timeout", Some(false)));
                }

                (
                    pending.issi,
                    pending.air_handle,
                    pending.kind,
                    (previous_status != pending.status).then_some(pending.status),
                    complete,
                    rollover_event,
                )
            };
            if let Some(status) = status_change {
                tracing::debug!(command_id, issi, ?kind, ?status, "D-OTAR delivery status changed");
            }
            if let Some(status) = complete {
                self.complete_otar_delivery(command_id, status);
            }
            if let Some((event, success)) = rollover_event {
                self.report_rollover_otar_status(command_id, issi, air_handle, kind, event, success);
            }
        }
    }

    fn track_registration_delivery(
        &mut self,
        command_id: Option<u64>,
        issi: u32,
        authentication_downlink: bool,
        security_groups: Vec<u32>,
        tx_reporter: TxReporter,
    ) {
        self.config.state_write().subscribers.set_registration_delivery_pending(issi, true);
        self.pending_registration_deliveries.insert(
            issi,
            PendingRegistrationDelivery {
                command_id,
                issi,
                authentication_downlink,
                security_groups,
                tx_reporter,
            },
        );
        tracing::info!(
            command_id = ?command_id,
            issi,
            authentication_downlink,
            "D-LOCATION UPDATE ACCEPT queued on MCCH; awaiting BL-ACK"
        );
    }

    fn update_registration_delivery_statuses(&mut self, queue: &mut MessageQueue) {
        let outcomes = self
            .pending_registration_deliveries
            .iter()
            .filter_map(|(&issi, pending)| match pending.tx_reporter.get_state() {
                TxState::Acknowledged => Some((issi, true)),
                TxState::Discarded | TxState::Lost => Some((issi, false)),
                TxState::Pending | TxState::Transmitted => None,
            })
            .collect::<Vec<_>>();

        for (issi, delivered) in outcomes {
            let Some(pending) = self.pending_registration_deliveries.remove(&issi) else {
                continue;
            };
            let state = pending.tx_reporter.get_state();
            if delivered {
                self.config.state_write().subscribers.mark_active(issi);
                self.group_security_not_before
                    .insert(issi, self.current_time.add_timeslots(GROUP_SECURITY_REGISTRATION_GUARD_TIMESLOTS));
                // TTR 001-01 6.4/8.3: ordinary roaming retains existing
                // attachments (lifetime 01). Restoring them at this BS is
                // not a new attachment at the MS. TTR 001-11 6.2.8.2 does
                // not require resending unchanged stored GCK associations.
                // Actual attachment requests and key-provisioning results
                // retain their separate association-signalling paths.
                let association_count = pending.security_groups.len();
                let restored_group_count = self.client_mgr.get_client_by_issi(issi).map_or(0, |client| client.groups.len());
                self.send_current_gck_version_to_terminal(queue, issi, 0);
                tracing::info!(
                    command_id = ?pending.command_id,
                    issi = pending.issi,
                    authentication_downlink = pending.authentication_downlink,
                    association_count,
                    restored_group_count,
                    "location update accepted and link-acknowledged on air interface"
                );
            } else {
                let mut state_registry = self.config.state_write();
                state_registry.subscribers.set_registration_delivery_pending(issi, false);
                state_registry.subscribers.note_registration_delivery_failure();
                tracing::warn!(
                    command_id = ?pending.command_id,
                    issi = pending.issi,
                    ?state,
                    "D-LOCATION UPDATE ACCEPT was not link-acknowledged; registration remains inactive"
                );
            }
            if self.pending_terminal_controls.get(&issi).is_some_and(|control| {
                matches!(
                    control.action,
                    TerminalControlAction::Reregister | TerminalControlAction::Reauthenticate
                )
            }) {
                self.finish_terminal_control(issi, delivered, u8::from(!delivered), Vec::new(), None);
            }
        }
    }

    /// Report completed ETSI basic-link presence probes to the SwMI. LLC owns
    /// all retransmission timing; MM only observes the shared receipt and
    /// never turns an unanswered probe into a registration procedure.
    fn update_liveliness_probe_statuses(&mut self) {
        let outcomes = self
            .pending_liveliness_probes
            .iter()
            .filter_map(|(&issi, reporter)| match reporter.get_state() {
                TxState::Acknowledged => Some((issi, true, TxState::Acknowledged)),
                TxState::Discarded | TxState::Lost => Some((issi, false, reporter.get_state())),
                TxState::Pending | TxState::Transmitted => None,
            })
            .collect::<Vec<_>>();

        for (issi, reachable, state) in outcomes {
            self.pending_liveliness_probes.remove(&issi);
            if let Some(swmi) = &self.swmi
                && let Err(error) = swmi.submit(SwmiMessage::LivelinessResult {
                    itsi: u64::from(issi),
                    reachable,
                })
            {
                tracing::warn!(issi, reachable, ?error, "cannot report terminal presence-probe result to SwMI");
            }
            if reachable {
                tracing::debug!(issi, "terminal presence confirmed by empty BL-DATA acknowledgement");
            } else {
                tracing::warn!(issi, ?state, "terminal did not acknowledge empty BL-DATA presence probe");
            }
        }
    }

    fn update_terminal_control_statuses(&mut self) {
        let mut failed = Vec::new();
        for (&issi, pending) in &mut self.pending_terminal_controls {
            if let Some(reporter) = pending.tx_reporter.as_ref() {
                match reporter.get_state() {
                    TxState::Discarded | TxState::Lost => {
                        failed.push((issi, TERMINAL_CONTROL_CAUSE_RADIO_LINK_FAILED));
                        continue;
                    }
                    TxState::Acknowledged if pending.response_deadline.is_none() => {
                        pending.response_deadline = Some(self.current_time.add_timeslots(TERMINAL_CONTROL_TIMEOUT_TIMESLOTS));
                    }
                    TxState::Pending | TxState::Transmitted | TxState::Acknowledged => {}
                }
            }
            if pending
                .response_deadline
                .is_some_and(|deadline| deadline.age(self.current_time) >= 0)
            {
                failed.push((issi, TERMINAL_CONTROL_CAUSE_RESPONSE_TIMEOUT));
            }
        }
        for (issi, cause) in failed {
            self.finish_terminal_control(issi, false, cause, Vec::new(), None);
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
        let kind = self
            .pending_otar_deliveries
            .get(&command_id)
            .expect("correlated pending OTAR delivery")
            .kind;
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
        self.report_rollover_otar_status(command_id, issi, air_handle, kind, "key-result", Some(success));
    }

    fn complete_gck_terminal_response(
        &mut self,
        issi: u32,
        air_handle: u32,
        result: &tetra_pdus::mm::pdus::otar::UGckResult,
    ) {
        if result.results.is_empty() {
            return;
        }
        let mut result_keys = result.results.iter()
            .map(|entry| (entry.gck_number, entry.version_number))
            .collect::<Vec<_>>();
        result_keys.sort_unstable();
        let success = result.results.iter().all(|entry| entry.provision_result == 0);
        let matching = self.pending_otar_deliveries.iter().filter_map(|(&command_id, pending)| {
            (pending.issi == issi
                && pending.air_handle == air_handle
                && pending.expected_response == Some(OtarTerminalResponse::GckResult)
                && matches!(pending.status, OtarDeliveryStatus::AirTransmitted
                    | OtarDeliveryStatus::LinkAcknowledged
                    | OtarDeliveryStatus::AwaitingTerminalResult)
                && pending.gck_keys.as_deref() == Some(result_keys.as_slice()))
                .then_some(command_id)
        }).collect::<Vec<_>>();
        if matching.is_empty() {
            tracing::debug!(issi, air_handle, ?result_keys,
                "U-OTAR GCK RESULT has no matching transmitted provision");
            return;
        }
        // Identical already-transmitted provisions carry the same key set;
        // the air result cannot identify one of their command IDs.
        for command_id in matching {
            self.complete_otar_delivery(command_id, OtarDeliveryStatus::TerminalResult { success });
            tracing::debug!(command_id, issi, air_handle, success,
                "U-OTAR GCK RESULT correlated by GCKN and version");
        }
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

    /// Table A.46: KSG(4), security class, then either SCKN (SC2) or
    /// capability bits (SC3). Downlink SC3 capability bits are zero.
    fn aie_ciphering_parameters(&self) -> Option<u16> {
        let state = self.config.state_read();
        if !state.aie.enabled {
            return None;
        }
        if let Some(sc3) = state.aie.sc3.as_ref() {
            let ksg: u8 = match sc3.algorithm {
                tetra_config::bluestation::RuntimeSc3TeaAlgorithm::Tea1 => 0,
                tetra_config::bluestation::RuntimeSc3TeaAlgorithm::Tea3 => 2,
            };
            return Some((u16::from(ksg) << 6) | (1 << 5));
        }
        state.aie.sc2.as_ref().map(|sc2| {
            let ksg = sc2_ksg_number(sc2.algorithm);
            (u16::from(ksg) << 6) | u16::from(sc2.sckn)
        })
    }

    fn validate_aie_location_update(&self, pdu: &ULocationUpdateDemand) -> Result<(), (u8, u16)> {
        let Some(expected) = self.aie_ciphering_parameters() else {
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
        // The security-class bit must agree. For SC2 the remaining five bits
        // are SCKN and must match. For SC3 they are uplink capability flags,
        // which the BS accepts independently of its zeroed downlink form.
        if (provided & 0x20) != (expected & 0x20) || (expected & 0x20 == 0 && (provided & 0x1f) != (expected & 0x1f)) {
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
            pending_registration_deliveries: HashMap::new(),
            pending_group_security_associations: HashMap::new(),
            queued_group_security_associations: HashMap::new(),
            group_security_not_before: HashMap::new(),
            pending_liveliness_probes: HashMap::new(),
            pending_terminal_controls: HashMap::new(),
            security_information_protocol_supported: HashSet::new(),
            registration_generations: HashMap::new(),
            gsko_bootstraps: HashMap::new(),
            ck_change_results: HashMap::new(),
            pending_security_activations: HashMap::new(),
            last_rollover_broadcast: None,
            last_gck_version_broadcast: None,
            last_gck_rollover_broadcast: None,
            assigned_gck_notices: HashMap::new(),
            gck_rollover_immediate_sent: None,
            rollover_late_broadcast_mask: None,
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

    fn aie_request_is_encrypted(request: Option<&AieRequest>) -> bool {
        matches!(request, Some(AieRequest::Sc2 { .. } | AieRequest::Sc3 { .. }))
    }

    fn packet_aie_state(request: Option<&AieRequest>) -> AieObservationState {
        match request {
            Some(AieRequest::Sc3 { .. }) => AieObservationState::Sc3,
            Some(AieRequest::Sc2 { .. }) => AieObservationState::Sc2,
            Some(AieRequest::Clear { .. }) | None => AieObservationState::Clear,
        }
    }

    /// A clear MM bootstrap is allowed for a terminal that already has an
    /// active SC2 binding.  Report that terminal's effective security state as
    /// SC2 while retaining `air_interface_encrypted = false` as the raw packet
    /// fact.  This prevents a successful clear bootstrap/authentication from
    /// overwriting the terminal's established SC2 state in the SwMI view.
    fn effective_aie_state(&self, issi: u32, air_interface_encrypted: bool) -> AieObservationState {
        let state = self.config.state_read();
        if state.aie.enabled && state.aie.sc3.as_ref().is_some_and(|sc3| sc3.has_dck(issi)) {
            return AieObservationState::Sc3;
        }
        if air_interface_encrypted {
            return AieObservationState::Sc2;
        }
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
    fn activate_terminal_security_class(&self, issi: u32, security_class: TerminalSecurityClass) {
        let mut state = self.config.state_write();
        if !state.aie.enabled {
            return;
        }
        let sc2 = state.aie.sc2.clone();
        state.aie_sessions.set_terminal_class(issi, security_class, sc2.as_ref());
    }

    /// Keep an already encrypted location-update exchange encrypted. In
    /// particular this covers D-AUTHENTICATION and D-LOCATION UPDATE ACCEPT
    /// sent after UMAC has decoded an initial SC2 ESI. A clear bootstrap has
    /// no binding yet and therefore remains clear until its accept is sent.
    fn aie_request_for_terminal(&self, issi: u32) -> AieRequest {
        let state = self.config.state_read();
        if !state.aie.enabled || state.aie_sessions.terminal_allows_clear(issi) {
            return AieRequest::clear(AieSubject::System, AieScope::MacResource);
        }
        if state.aie.enabled
            && state.aie_sessions.terminal_class(issi) == TerminalSecurityClass::Sc3
            && state.aie.sc3.as_ref().is_some_and(|sc3| sc3.has_dck(issi))
        {
            return AieRequest::sc3(AieSubject::Individual { issi }, AieScope::MacResource);
        }
        if state.aie.enabled && state.aie_sessions.terminal(issi).is_some() {
            AieRequest::sc2(AieSubject::Individual { issi }, AieScope::MacResource)
        } else {
            AieRequest::clear(AieSubject::System, AieScope::MacResource)
        }
    }

    /// Keep one registration/authentication transaction on the same clear or
    /// encrypted bearer on which its U-LOCATION UPDATE DEMAND arrived.  In
    /// particular, a clear CK request cannot receive its sealed current SCK
    /// inside an SC2-encrypted D-LOCATION UPDATE ACCEPT: the MS is requesting
    /// that key precisely because it cannot decrypt with it yet.
    fn aie_request_for_registration(&self, issi: u32, air_interface_encrypted: bool) -> AieRequest {
        if air_interface_encrypted {
            self.aie_request_for_terminal(issi)
        } else {
            AieRequest::clear(AieSubject::System, AieScope::MacResource)
        }
    }

    fn aie_request_for_registration_command(&self, command_id: u64, issi: u32) -> AieRequest {
        let encrypted = self
            .pending_registrations
            .get(&command_id)
            .is_some_and(|registration| registration.air_interface_encrypted);
        self.aie_request_for_registration(issi, encrypted)
    }

    fn defer_security_activation(&mut self, issi: u32, aie: &AieLocationUpdateDecision, receipt: TxReporter) -> bool {
        // Cipher Control announces the cell's selected SC2 parameters, but
        // it does not itself give a previously clear MS an SCK.  Activating
        // the BS binding in that case makes the cell reject the MS's next
        // clear bootstrap retry even though it never received a key.  Only
        // the full Table A.94 CK/SCK provision (228 bits for current-only or
        // 369 bits when it also carries the future SCK) can transition a
        // clear terminal into SC2 here.  An already ciphered registration
        // already has its binding before this function is reached.
        let deferred = aie.selected_class != TerminalSecurityClass::Unknown;
        if deferred {
            self.pending_security_activations.insert(issi, (aie.selected_class, receipt));
        }
        deferred
    }

    /// Queue one all-MS D-CK CHANGE DEMAND.  `traffic_channels` selects the
    /// STCH copy; the ordinary copy remains on MCCH.  Both contain the same
    /// Absolute IV and are deliberately clear, as permitted by TTR 001-11
    /// clause 6.2.14, so a terminal which is still on the old key can parse
    /// the announcement.
    fn send_rollover_broadcast(&self, queue: &mut MessageQueue, traffic_channels: bool) -> bool {
        let Some((key, absolute_iv)) = self.config.state_read().aie.rollover_notification() else {
            return false;
        };
        let pdu = DCkChangeDemand {
            acknowledgement_required: false,
            // Table 8 (change of TM-SCK), not table 5 (transition to SC2).
            change_of_security_class: 0,
            scks: vec![SckChangeData {
                sck_number: key.key.sckn,
                version_number: key.key.sck_vn,
            }],
            time: absolute_iv.map(absolute_iv_time).unwrap_or(CkChangeTime::CurrentlyInUse),
        };
        let mut sdu = BitBuffer::new_autoexpand(96);
        if pdu.to_bitbuf(&mut sdu).is_err() {
            tracing::warn!("cannot encode broadcast SC2 rollover demand");
            return false;
        }
        sdu.seek(0);
        queue.push_back(SapMsg {
            sap: Sap::LmmSap,
            src: TetraEntity::Mm,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                sdu,
                handle: 0,
                address: TetraAddress::new(0x00ff_ffff, SsiType::Gssi),
                // A broadcast D-CK CHANGE has no application/link-layer
                // acknowledgement. BL-DATA is individual-addressed only;
                // using it for the all-MS GSSI would panic in LLC.
                layer2service: Layer2Service::Unacknowledged,
                // Rollover announcements may be copied to an assigned
                // channel, but only as an expendable FN18 resource.  They
                // must never steal a traffic half-slot from voice or pre-empt
                // SDS/call signalling.
                stealing_permission: false,
                stealing_repeats_flag: false,
                encryption_flag: false,
                aie_request: AieRequest::clear(AieSubject::System, AieScope::MacResource),
                is_null_pdu: false,
                assigned_channel_frame18_broadcast: traffic_channels,
                frame18_rollover_activation: None,
                tx_reporter: None,
                seamless_handover: None,
            }),
        });
        tracing::info!(
            sckn = key.key.sckn,
            sck_vn = key.key.sck_vn,
            scheduled = absolute_iv.is_some(),
            bearer = if traffic_channels { "all-active-TCH/STCH" } else { "MCCH" },
            "queued all-MS SC2 rollover demand"
        );
        true
    }

    /// One announcement round covers both common-mode and assigned-mode
    /// listeners without creating one basic-link transaction per terminal.
    fn send_rollover_broadcast_round(&self, queue: &mut MessageQueue) -> bool {
        let mcch = self.send_rollover_broadcast(queue, false);
        let traffic = self.send_rollover_broadcast(queue, true);
        mcch && traffic
    }

    /// Queue the TTR 001-11 table-1 full current GCK-VN advertisement. It is
    /// broadcast-addressed and unacknowledged. Send it clear as permitted by
    /// TTR 001-11 clause 6.2.14.2: a terminal still using an old GCK version
    /// must be able to read the full current version on MCCH.
    fn send_gck_change_broadcast(
        &self,
        queue: &mut MessageQueue,
        gck_vn: u16,
        time: CkChangeTime,
        traffic_channels: bool,
        frame18_rollover_activation: Option<TdmaTime>,
        cmg_gssi: Option<u32>,
    ) -> bool {
        let pdu = DAllGcksChangeDemand {
            acknowledgement_required: false,
            gck_version_number: gck_vn,
            time,
        };
        let mut sdu = BitBuffer::new_autoexpand(32);
        if pdu.to_bitbuf(&mut sdu).is_err() {
            tracing::warn!(gck_vn, "cannot encode full current GCK-VN advertisement");
            return false;
        }
        sdu.seek(0);
        queue.push_back(SapMsg {
            sap: Sap::LmmSap,
            src: TetraEntity::Mm,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                sdu,
                handle: 0,
                address: TetraAddress::new(cmg_gssi.unwrap_or(0x00ff_ffff), SsiType::Gssi),
                layer2service: Layer2Service::Unacknowledged,
                stealing_permission: traffic_channels && cmg_gssi.is_none(),
                stealing_repeats_flag: false,
                encryption_flag: false,
                aie_request: cmg_gssi.map_or_else(
                    || AieRequest::clear(AieSubject::System, AieScope::MacResource),
                    |gssi| AieRequest::sc3(AieSubject::Group { gssi }, AieScope::MacResource),
                ),
                is_null_pdu: false,
                assigned_channel_frame18_broadcast: traffic_channels && cmg_gssi.is_some(),
                frame18_rollover_activation,
                tx_reporter: None,
                seamless_handover: None,
            }),
        });
        tracing::debug!(
            gck_vn,
            cmg_gssi,
            bearer = if traffic_channels { "assigned-FN18" } else { "MCCH" },
            "queued full GCK-VN change advertisement"
        );
        true
    }

    fn send_gck_version_broadcast(&self, queue: &mut MessageQueue, gck_vn: u16, traffic_channels: bool) -> bool {
        self.send_gck_change_broadcast(queue, gck_vn, CkChangeTime::CurrentlyInUse, traffic_channels, None, None)
    }

    fn send_gck_version_broadcast_round(&self, queue: &mut MessageQueue, gck_vn: u16) -> bool {
        let mcch = self.send_gck_version_broadcast(queue, gck_vn, false);
        let traffic = self.send_gck_version_broadcast(queue, gck_vn, true);
        mcch && traffic
    }

    fn rollover_cmg_gssis(&self) -> Vec<u32> {
        let mut gssis = self.config.config().swmi.as_ref()
            .map_or_else(Vec::new, |swmi| swmi.cmg_gssis.clone());
        gssis.extend(self.gsko_bootstraps.values().filter_map(|status| match status {
            GskoBootstrapStatus::Provisioned { cmg_gssi, .. } if *cmg_gssi > 0 && *cmg_gssi < 0x00ff_ffff => Some(*cmg_gssi),
            _ => None,
        }));
        gssis.sort_unstable();
        gssis.dedup();
        gssis
    }

    fn send_gck_rollover_broadcast_round(&self, queue: &mut MessageQueue, gck_vn: u16, activation: TdmaTime) -> bool {
        let time = absolute_iv_time(activation);
        let cmgs = self.rollover_cmg_gssis();
        if cmgs.is_empty() {
            tracing::warn!(gck_vn, "no provisioned CMG available; using all-MS rollover address");
        }
        let targets: Vec<_> = if cmgs.is_empty() { vec![None] } else { cmgs.into_iter().map(Some).collect() };
        targets.into_iter().all(|cmg| {
            let mcch = self.send_gck_change_broadcast(queue, gck_vn, time.clone(), false, None, cmg);
            let traffic = self.send_gck_change_broadcast(queue, gck_vn, time.clone(), true, None, cmg);
            mcch && traffic
        })
    }

    /// Repeat the same Absolute-IV indication individually to MSs that call
    /// control currently places on a traffic channel. A delivery route is
    /// enough evidence here: after a BS restart a listener may be on a group
    /// traffic channel before it has performed a new registration. TTR 001-11 §6.2.7.1
    /// explicitly allows an individual D-CK CHANGE DEMAND on an assigned
    /// channel. A basic-link ACK supplies delivery evidence without asking
    /// for the layer-3 U-CK CHANGE RESULT prohibited by that clause. LLC
    /// resolves the live route at transmission time, including a changed
    /// scan-list slot. Two new transactions per five-second round leave the
    /// assigned FN18 channel available for call control and SDS.
    fn send_assigned_gck_rollover_notices(
        &mut self,
        queue: &mut MessageQueue,
        rollover_id: u64,
        gck_vn: u16,
        activation: TdmaTime,
        now: TdmaTime,
    ) {
        if activation.diff(now) <= 2 * 18 * 4 {
            return;
        }
        self.assigned_gck_notices.retain(|(id, _), _| *id == rollover_id);
        let mut listeners = {
            let state = self.config.state_read();
            state.subscriber_delivery_routes.iter()
                .filter_map(|(&issi, routes)| {
                    routes.first().map(|route| (issi, route.timeslot))
                })
                .filter(|(_, timeslot)| (2..=4).contains(timeslot))
                .collect::<Vec<_>>()
        };
        listeners.retain(|&(issi, timeslot)| {
            self.assigned_gck_notices.get(&(rollover_id, issi)).is_none_or(|&(previous_slot, sent)| {
                previous_slot != timeslot || sent.age(now) >= GCK_ASSIGNED_NOTICE_INTERVAL_TIMESLOTS
            })
        });
        listeners.sort_unstable_by_key(|&(issi, _)| (self.assigned_gck_notices.contains_key(&(rollover_id, issi)), issi));
        for (issi, timeslot) in listeners.into_iter().take(2) {
            let demand = DAllGcksChangeDemand {
                acknowledgement_required: false,
                gck_version_number: gck_vn,
                time: absolute_iv_time(activation),
            };
            let mut sdu = BitBuffer::new_autoexpand(64);
            if demand.to_bitbuf(&mut sdu).is_err() {
                tracing::warn!(issi, gck_vn, "cannot encode individual assigned GCK rollover notice");
                continue;
            }
            sdu.seek(0);
            queue.push_back(SapMsg {
                sap: Sap::LmmSap,
                src: TetraEntity::Mm,
                dest: TetraEntity::Mle,
                msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                    sdu,
                    handle: 0,
                    address: TetraAddress::issi(issi),
                    layer2service: Layer2Service::Acknowledged,
                    stealing_permission: false,
                    stealing_repeats_flag: false,
                    encryption_flag: false,
                    aie_request: self.downlink_aie_request(issi),
                    is_null_pdu: false,
                    assigned_channel_frame18_broadcast: false,
                    frame18_rollover_activation: None,
                    tx_reporter: None,
                    seamless_handover: None,
                }),
            });
            self.assigned_gck_notices.insert((rollover_id, issi), (timeslot, now));
            tracing::info!(issi, timeslot, gck_vn, activation = %activation,
                "queued acknowledged individual GCK rollover notice for assigned listener");
        }
    }

    /// The final change indication is not an ordinary traffic-channel copy.
    /// At the pipeline tick preceding TS1/FN18, UMAC reserves each of TS1..4
    /// and emits this `Immediate` all-GCK demand on the four physical slots.
    fn send_gck_rollover_immediate(&self, queue: &mut MessageQueue, gck_vn: u16, activation: TdmaTime) -> bool {
        let cmgs = self.rollover_cmg_gssis();
        // One physical FN18 resource exists on each timeslot. Multiple CMGs
        // cannot each receive an Immediate on every timeslot at this boundary;
        // their Absolute-IV notices remain authoritative in that case.
        if cmgs.len() > 1 {
            tracing::warn!(?cmgs, gck_vn, "multiple CMGs: relying on Absolute-IV; no final Immediate can cover every CMG on every timeslot");
            return true;
        }
        self.send_gck_change_broadcast(
            queue,
            gck_vn,
            CkChangeTime::Immediate,
            false,
            Some(activation),
            cmgs.first().copied(),
        )
    }

    /// A newly registered MS can have missed the periodic full-VN broadcast.
    /// Use its negotiated signalling protection for the individual copy,
    /// consistently with the following group association. TTR 001-11
    /// 6.2.14.2 permits clear CK CHANGE but does not require it; the cell-wide
    /// broadcast uses the serving CCK so registered SC3 terminals can decode it.
    fn send_current_gck_version_to_terminal(&self, queue: &mut MessageQueue, issi: u32, handle: u32) -> bool {
        let (gck_vn, pending_rollover) = {
            let state = self.config.state_read();
            let Some(sc3) = state.aie.sc3.as_ref().filter(|sc3| sc3.gck_supported()) else {
                return false;
            };
            (
                sc3.gck_vn(),
                sc3.gck_rollover_notification().and_then(|(_, future_vn, activation)| {
                    activation.map(|activation| (future_vn, activation))
                }),
            )
        };
        let aie_request = self.downlink_aie_request(issi);
        let has_pending_rollover = pending_rollover.is_some();
        let mut indications = vec![(gck_vn, CkChangeTime::CurrentlyInUse)];
        if let Some((future_vn, activation)) = pending_rollover {
            // A terminal which reselects or roams forgets a pending key-change
            // notification.  Send the target cell's local Absolute-IV after
            // the current indication so it can retain both stored versions.
            indications.push((future_vn, absolute_iv_time(activation)));
        }
        for (version, time) in indications {
            let pdu = DAllGcksChangeDemand {
                acknowledgement_required: false,
                gck_version_number: version,
                time,
            };
            let mut sdu = BitBuffer::new_autoexpand(32);
            if pdu.to_bitbuf(&mut sdu).is_err() {
                tracing::warn!(issi, version, "cannot encode individual GCK-VN advertisement");
                return false;
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
                    aie_request,
                    is_null_pdu: false,
                    assigned_channel_frame18_broadcast: false,
                    frame18_rollover_activation: None,
                    tx_reporter: None,
                    seamless_handover: None,
                }),
            });
        }
        tracing::info!(issi, gck_vn, pending = has_pending_rollover, ?aie_request, "queued current and pending full GCK-VN advertisements");
        true
    }

    /// TTR 001-11 6.2.23.1: following a clear location update the ciphering
    /// state changes after the last D-LOCATION UPDATE ACCEPT repeat is sent,
    /// or on its clear BL-ACK, whichever comes first. `Transmitted` is the
    /// former event in this stack. A dropped/lost clear accept must never
    /// leave an SC2 binding active.
    fn update_security_activations(&mut self, queue: &mut MessageQueue) {
        let outcomes = self
            .pending_security_activations
            .iter()
            .filter_map(|(&issi, (security_class, receipt))| match receipt.get_state() {
                TxState::Transmitted | TxState::Acknowledged => Some((issi, *security_class, true, receipt.get_state())),
                TxState::Discarded | TxState::Lost => Some((issi, *security_class, false, receipt.get_state())),
                TxState::Pending => None,
            })
            .collect::<Vec<_>>();
        for (issi, security_class, activate, state) in outcomes {
            self.pending_security_activations.remove(&issi);
            if activate {
                self.activate_terminal_security_class(issi, security_class);
                self.report_aie_observation(
                    issi,
                    0,
                    AieObservationEvent::TerminalActivation,
                    match security_class {
                        TerminalSecurityClass::Sc1 => AieObservationState::Sc1,
                        TerminalSecurityClass::Sc2 => AieObservationState::Sc2,
                        TerminalSecurityClass::Sc3 => AieObservationState::Sc3,
                        TerminalSecurityClass::Unknown => AieObservationState::Unknown,
                    },
                    Some(security_class.is_encrypted()),
                    None,
                    None,
                    None,
                    Some(true),
                    None,
                    Some(format!(
                        "{:?} terminal class activated after delivered registration",
                        security_class
                    )),
                );
                tracing::debug!(
                    issi,
                    ?state,
                    ?security_class,
                    "activated terminal security class after location-update response transmission"
                );
                // A future SCK may have been provisioned in the same
                // Authentication-downlink element (Table A.94). Announce its
                // pending Absolute IV only after this activation, now as an
                // all-MS MCCH/TCH broadcast instead of an individual BL-DATA.
                let _ = self.send_rollover_broadcast_round(queue);
            } else {
                tracing::warn!(
                    issi,
                    ?state,
                    ?security_class,
                    "location-update response was not delivered; security-class activation cancelled"
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
        let client = self.client_mgr.remove_client(issi);
        self.security_information_protocol_supported.remove(&issi);
        self.registration_generations.remove(&issi);
        let had_local_state = {
            let mut state = self.config.state_write();
            let existed = state.subscribers.is_registered(issi) || state.aie_sessions.terminal(issi).is_some();
            state.subscribers.deregister(issi);
            state.aie_sessions.deactivate_terminal(issi);
            existed
        };
        let was_gateway = self.config.state_read().dm_gateways.is_active(issi);
        if was_gateway {
            self.config.state_write().dm_gateways.deactivate(issi);
            self.publish_dm_gateway_state(issi, false);
        }
        if let Some(client) = client.as_ref() {
            if !client.groups.is_empty() {
                let groups: Vec<u32> = client.groups.keys().copied().collect();
                self.emit_subscriber_update(queue, issi, groups, BrewSubscriberAction::Deaffiliate);
            }
            self.emit_subscriber_update(queue, issi, Vec::new(), BrewSubscriberAction::Deregister);
        }
        if client.is_none() && had_local_state {
            tracing::debug!(issi, "removed stale subscriber/AIE state without an MM client");
        }
        client.is_some() || had_local_state || was_gateway
    }

    fn apply_old_serving_cleanup(&mut self, queue: &mut MessageQueue, issi: u32, expected_generation: u64) {
        match self.registration_generations.get(&issi).copied() {
            Some(current_generation) if current_generation == expected_generation => {
                if self.remove_local_subscriber(queue, issi) {
                    tracing::info!(issi, expected_generation, "discarded superseded old-serving-cell subscriber state");
                }
            }
            // An LST recovery can restore the local subscriber record without
            // its transient SwMI command id. The SwMI's cleanup is still
            // authoritative in that case: a newer accepted registration would
            // have installed a generation, so no generation means this cell
            // cannot be the terminal's newer serving cell.
            None => {
                if self.remove_local_subscriber(queue, issi) {
                    tracing::info!(
                        issi,
                        expected_generation,
                        "discarded superseded old-serving-cell subscriber state without local generation"
                    );
                }
            }
            current_generation => tracing::info!(
                issi,
                expected_generation,
                ?current_generation,
                "ignored stale old-serving-cell cleanup after a newer registration"
            ),
        }
    }

    fn submit_terminal_control_result(
        &self,
        command_id: u64,
        issi: u32,
        action: TerminalControlAction,
        success: bool,
        cause: u8,
        results: Vec<AttachmentResult>,
        information: Option<TerminalInformation>,
    ) {
        let Some(swmi) = self.swmi.as_ref() else {
            return;
        };
        if let Err(error) = swmi.submit(SwmiMessage::TerminalControlResult {
            command_id,
            itsi: u64::from(issi),
            action,
            success,
            cause,
            results,
            information,
        }) {
            tracing::warn!(command_id, issi, ?action, ?error, "failed to report terminal-control result");
        }
    }

    fn finish_terminal_control(
        &mut self,
        issi: u32,
        success: bool,
        cause: u8,
        results: Vec<AttachmentResult>,
        information: Option<TerminalInformation>,
    ) {
        let Some(pending) = self.pending_terminal_controls.remove(&issi) else {
            return;
        };
        self.submit_terminal_control_result(pending.command_id, issi, pending.action, success, cause, results, information);
    }

    fn handle_terminal_control(
        &mut self,
        queue: &mut MessageQueue,
        command_id: u64,
        itsi: u64,
        action: TerminalControlAction,
        operations: Vec<AttachmentOperation>,
    ) {
        let Ok(issi) = u32::try_from(itsi) else {
            return;
        };
        if action == TerminalControlAction::Disconnect {
            if self.pending_terminal_controls.contains_key(&issi) {
                self.finish_terminal_control(issi, false, 6, Vec::new(), None);
            }
            if !self.config.state_read().subscribers.is_registered(issi) {
                self.submit_terminal_control_result(command_id, issi, action, false, 2, Vec::new(), None);
                return;
            }
            // TS 100 392-2 clause 16.4.3 supplies the only non-disable
            // infrastructure-initiated MM path that makes the MS register.
            // The blocked SwMI will reject that demand over the air; retaining
            // local state until then is required to deliver the rejection.
        }
        if !self.config.state_read().subscribers.is_registered(issi) {
            self.submit_terminal_control_result(command_id, issi, action, false, 2, Vec::new(), None);
            return;
        }
        if self.pending_terminal_controls.contains_key(&issi) {
            self.submit_terminal_control_result(command_id, issi, action, false, 5, Vec::new(), None);
            return;
        }
        if matches!(
            action,
            TerminalControlAction::AmendTalkgroups | TerminalControlAction::ReplaceTalkgroups
        ) {
            self.start_terminal_group_control(queue, command_id, issi, action, operations);
            return;
        }
        self.pending_terminal_controls.insert(
            issi,
            PendingTerminalControl {
                command_id,
                action,
                operations,
                tx_reporter: None,
                response_deadline: Some(self.current_time.add_timeslots(TERMINAL_CONTROL_TIMEOUT_TIMESLOTS)),
                information: TerminalInformation::default(),
            },
        );
        // Core clauses 8.7.4 and 8.7.5 both permit SwMI-initiated
        // registration. These operator commands do not require a group
        // report; talkgroup reconciliation is a separate explicit action.
        self.send_d_location_update_command(queue, issi, 0, false);
    }

    fn rx_u_tei_provide(&mut self, mut message: SapMsg) {
        let SapMsgInner::LmmMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        let pdu = match UTeiProvide::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => pdu,
            Err(error) => {
                tracing::warn!(issi = prim.received_address.ssi, ?error, "invalid U-TEI PROVIDE");
                return;
            }
        };
        let issi = prim.received_address.ssi;
        if pdu.ssi != issi {
            tracing::warn!(issi, pdu_ssi = pdu.ssi, "discarding U-TEI PROVIDE with mismatched SSI");
            return;
        }
        if self
            .pending_terminal_controls
            .get(&issi)
            .is_some_and(|pending| pending.action == TerminalControlAction::RequestInformation)
        {
            self.finish_terminal_control(
                issi,
                true,
                0,
                Vec::new(),
                Some(TerminalInformation {
                    tei: Some(pdu.tei),
                    ..TerminalInformation::default()
                }),
            );
        }
    }

    fn rx_u_information_provide(&mut self, mut message: SapMsg) {
        let SapMsgInner::LmmMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        let pdu = match UInformationProvide::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => pdu,
            Err(error) => {
                tracing::warn!(issi = prim.received_address.ssi, ?error, "invalid U-INFORMATION PROVIDE");
                return;
            }
        };
        let issi = prim.received_address.ssi;
        if pdu.ssi != issi {
            tracing::warn!(issi, pdu_ssi = pdu.ssi, "discarding U-INFORMATION PROVIDE with mismatched SSI");
            return;
        }
        if let Some(pending) = self
            .pending_terminal_controls
            .get_mut(&issi)
            .filter(|pending| pending.action == TerminalControlAction::RequestInformation)
        {
            if pdu.tei.is_some() {
                pending.information.tei = pdu.tei;
            }
            if pdu.model.is_some() {
                pending.information.model = pdu.model;
            }
            if pdu.hardware_version.is_some() {
                pending.information.hardware_version = pdu.hardware_version;
            }
            if pdu.software_version.is_some() {
                pending.information.software_version = pdu.software_version;
            }
            if pdu.further_information_follows {
                tracing::debug!(issi, "awaiting next U-INFORMATION PROVIDE part");
                return;
            }
            let information = pending.information.clone();
            self.finish_terminal_control(issi, true, 0, Vec::new(), Some(information));
        }
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
        // EN 300 392-7 clause 4.4a defines this capability indication only
        // for an ITSI attach. A later attach also replaces a cached claim.
        if pdu.location_update_type == LocationUpdateType::ItsiAttach {
            if pdu.ciphering_parameters.is_some_and(supports_security_information_protocol) {
                self.security_information_protocol_supported.insert(prim.received_address.ssi);
            } else {
                self.security_information_protocol_supported.remove(&prim.received_address.ssi);
            }
        }

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
        // The connected SwMI owns SC1 fallback and cipher negotiation policy.
        // Local validation remains the LST/offline guard only; otherwise the
        // SwMI must see Class-of-MS capabilities and whether K-based OTAR is
        // possible before choosing clear or proposing encrypted parameters.
        let swmi_owns_aie_decision = self.swmi.as_ref().is_some_and(SwmiMmEndpoint::is_online);
        if !swmi_owns_aie_decision && let Err((cause, parameters)) = self.validate_aie_location_update(&pdu) {
            let air_interface_encrypted = prim.air_interface_encryption.is_some_and(AieRequest::is_encrypted);
            self.report_aie_observation(
                prim.received_address.ssi,
                prim.handle,
                AieObservationEvent::CipheringMismatch,
                Self::packet_aie_state(prim.air_interface_encryption.as_ref()),
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
        // TS 100 392-2 clause 16.8.6: registration overrides a colliding
        // attachment transaction. Its current desired associations are folded
        // into the ensuing D-LOCATION UPDATE ACCEPT instead.
        let interrupted_group_security_gssis = self.cancel_group_security_association_for_registration(issi);
        // ETSI TS 100 392-2 §16.7.1/§16.10.10: the BS may choose a mode and
        // startpoint. Current policy accepts the requested mode and selects
        // the next MCCH phase from the local TDMA clock. For periodic/demand
        // updates, an omitted mode is explicitly a request to retain the
        // existing assignment; it is not a request for StayAlive.
        let energy_economy = match pdu.energy_saving_mode {
            Some(mode) => self.energy_economy_assignment(mode),
            None => Self::energy_economy_for_omitted_request(pdu.location_update_type, self.current_energy_economy(issi)),
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
            let air_interface_encrypted = prim.air_interface_encryption.is_some_and(AieRequest::is_encrypted);
            let sc3_retrieval = prim
                .air_interface_encryption
                .and_then(AieRequest::sc3_key)
                .filter(|key| key.key_type == Sc3KeyType::Dck)
                .map(|key| Sc3RetrievalEvidence {
                    cck_id: key.cck_id,
                    dck_context_id: key.context_id,
                });
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
                    capabilities: pdu.class_of_ms.as_ref().map(|class| TerminalAieCapabilities {
                        sck_encryption: class.sck_encryption,
                        dck_encryption: class.dck_encryption,
                        authentication: class.authentication,
                    }),
                },
                sc3_retrieval,
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
                        air_interface_encrypted,
                        location_update_type: pdu.location_update_type,
                        address_extension: pdu.address_extension,
                        energy_saving_information: esi,
                        has_group_identity_location_demand,
                        location_attachment,
                        interrupted_group_security_gssis,
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

        let registration_security_groups = self.registration_group_security_gssis(issi, interrupted_group_security_gssis);

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
            group_identity_security_related_information: self.group_security_information(registration_security_groups.iter().copied()),
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
        let tx_reporter = TxReporter::new();
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
                            assigned_channel_frame18_broadcast: false,
                            frame18_rollover_activation: None,
                tx_reporter: Some(tx_reporter.clone()),
                seamless_handover: None,
            }),
        };
        queue.push_back(msg);
        self.track_registration_delivery(None, issi, false, registration_security_groups, tx_reporter);

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
                                assigned_channel_frame18_broadcast: false,
                                frame18_rollover_activation: None,
                tx_reporter: None,
                seamless_handover: None,
            }),
        };
        queue.push_back(msg);
    }

    fn rx_u_attach_detach_group_identity_acknowledgement(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        let SapMsgInner::LmmMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        let pdu = match UAttachDetachGroupIdentityAcknowledgement::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => pdu,
            Err(error) => {
                tracing::warn!(
                    issi = prim.received_address.ssi,
                    ?error,
                    "failed parsing group-security attachment acknowledgement"
                );
                return;
            }
        };
        if self
            .pending_terminal_controls
            .get(&prim.received_address.ssi)
            .is_some_and(|pending| {
                matches!(
                    pending.action,
                    TerminalControlAction::AmendTalkgroups | TerminalControlAction::ReplaceTalkgroups
                )
            })
        {
            self.complete_terminal_group_control(queue, prim.received_address.ssi, pdu);
        } else {
            self.complete_group_security_association_ack(queue, prim.received_address.ssi, pdu);
        }
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
            state.aie.enabled
                && state.subscribers.is_registered(prim.received_address.ssi)
                && !state.aie_sessions.terminal_allows_clear(prim.received_address.ssi)
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
            MmPduTypeUl::UOtar => self.rx_u_otar(queue, message),
            MmPduTypeUl::UInformationProvide => self.rx_u_information_provide(message),
            MmPduTypeUl::UAttachDetachGroupIdentity => self.rx_u_attach_detach_group_identity(queue, message),
            MmPduTypeUl::UAttachDetachGroupIdentityAcknowledgement => {
                self.rx_u_attach_detach_group_identity_acknowledgement(queue, message)
            }
            MmPduTypeUl::UTeiProvide => self.rx_u_tei_provide(message),
            MmPduTypeUl::UDisableStatus => unimplemented_log!("UDisableStatus"),
            MmPduTypeUl::MmPduFunctionNotSupported => unimplemented_log!("MmPduFunctionNotSupported"),
        };
    }

    /// The BS validates and transports OTAR but never receives key material
    /// from the SwMI.  This keeps TAA1-K, KSO and clear SCK/GSKO state in the
    /// central key provider, while retaining the exact air-interface handle
    /// needed to schedule the response.
    fn rx_u_otar(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
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
                    Self::packet_aie_state(prim.air_interface_encryption.as_ref()),
                    Some(Self::aie_request_is_encrypted(prim.air_interface_encryption.as_ref())),
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
            UOtar::KeyDeleteResult(_) => "key-delete-result",
            UOtar::KeyStatusResponse(_) => "key-status-response",
            UOtar::CmgGtsiResult(_) => "cmg-gtsi-result",
        };
        let is_clear_from_bound_sc2_terminal = matches!(prim.air_interface_encryption, Some(AieRequest::Clear { .. }) | None) && {
            let state = self.config.state_read();
            state.aie.enabled
                && state.subscribers.is_registered(prim.received_address.ssi)
                && !state.aie_sessions.terminal_allows_clear(prim.received_address.ssi)
        };
        if is_clear_from_bound_sc2_terminal
            && !matches!(
                pdu,
                UOtar::CckResult(_) | UOtar::SckResult(_) | UOtar::GskoDemand(_) | UOtar::GskoResult(_) | UOtar::KeyDeleteResult(_)
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
            UOtar::GckResult(result) => {
                self.complete_gck_terminal_response(prim.received_address.ssi, prim.handle, result);

                self.refresh_group_security_after_gck_result(queue, prim.received_address.ssi, prim.handle, result);
            }
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
            UOtar::KeyDeleteResult(result) => self.complete_otar_terminal_response(
                prim.received_address.ssi,
                prim.handle,
                OtarTerminalResponse::KeyDeleteResult,
                result.is_success(),
            ),
            UOtar::CmgGtsiResult(_) => {
                self.complete_otar_terminal_response(prim.received_address.ssi, prim.handle, OtarTerminalResponse::CmgGtsiResult, true)
            }
            UOtar::CckDemand(_) | UOtar::SckDemand(_) | UOtar::GckDemand(_) => {}
        }
        let (event, success, cause) = match &pdu {
            UOtar::KeyStatusResponse(_) => (AieObservationEvent::KeyStatus, Some(true), None),
            UOtar::KeyDeleteResult(result) => (
                AieObservationEvent::Otar,
                Some(result.is_success()),
                (!result.is_success()).then_some(0),
            ),
            UOtar::CckResult(result) => {
                let success = result.provision_result == 0 && result.future_provision_result.is_none_or(|code| code == 0);
                (
                    AieObservationEvent::Otar,
                    Some(success),
                    (!success).then_some(u16::from(result.provision_result)),
                )
            }
            UOtar::SckResult(result) => {
                let cause = result
                    .results
                    .iter()
                    .find_map(|entry| (entry.provision_result != 0).then_some(u16::from(entry.provision_result)));
                (AieObservationEvent::Otar, Some(cause.is_none()), cause)
            }
            UOtar::GckResult(result) => {
                let cause = result
                    .results
                    .iter()
                    .find_map(|entry| (entry.provision_result != 0).then_some(u16::from(entry.provision_result)));
                (AieObservationEvent::Otar, Some(cause.is_none()), cause)
            }
            UOtar::GskoResult(result) => (
                AieObservationEvent::Otar,
                Some(result.provision_result == 0),
                (!result.provision_result.eq(&0)).then_some(u16::from(result.provision_result)),
            ),
            UOtar::CmgGtsiResult(_) => (AieObservationEvent::Otar, Some(true), None),
            UOtar::CckDemand(_) | UOtar::SckDemand(_) | UOtar::GckDemand(_) | UOtar::GskoDemand(_) => {
                (AieObservationEvent::Otar, None, None)
            }
        };
        self.report_aie_observation(
            prim.received_address.ssi,
            prim.handle,
            event,
            self.effective_aie_state(
                prim.received_address.ssi,
                Self::aie_request_is_encrypted(prim.air_interface_encryption.as_ref()),
            ),
            Some(Self::aie_request_is_encrypted(prim.air_interface_encryption.as_ref())),
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
                    Self::packet_aie_state(prim.air_interface_encryption.as_ref()),
                    Some(Self::aie_request_is_encrypted(prim.air_interface_encryption.as_ref())),
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
            self.effective_aie_state(
                prim.received_address.ssi,
                Self::aie_request_is_encrypted(prim.air_interface_encryption.as_ref()),
            ),
            Some(Self::aie_request_is_encrypted(prim.air_interface_encryption.as_ref())),
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
                    Self::packet_aie_state(prim.air_interface_encryption.as_ref()),
                    Some(Self::aie_request_is_encrypted(prim.air_interface_encryption.as_ref())),
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
                self.effective_aie_state(
                    prim.received_address.ssi,
                    Self::aie_request_is_encrypted(prim.air_interface_encryption.as_ref()),
                ),
                Some(Self::aie_request_is_encrypted(prim.air_interface_encryption.as_ref())),
                None,
                None,
                None,
                Some(authentication_result),
                (!authentication_result).then_some(1),
                Some(
                    if authentication_result {
                        "terminal authentication accepted"
                    } else {
                        "terminal authentication rejected"
                    }
                    .to_owned(),
                ),
            );
            if !authentication_result
                && self
                    .pending_terminal_controls
                    .get(&prim.received_address.ssi)
                    .is_some_and(|pending| pending.action == TerminalControlAction::Reauthenticate)
            {
                self.finish_terminal_control(prim.received_address.ssi, false, 1, Vec::new(), None);
            }
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
                self.effective_aie_state(
                    prim.received_address.ssi,
                    Self::aie_request_is_encrypted(prim.air_interface_encryption.as_ref()),
                ),
                Some(Self::aie_request_is_encrypted(prim.air_interface_encryption.as_ref())),
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
            if self
                .pending_terminal_controls
                .get(&pending.itsi)
                .is_some_and(|control| control.action == TerminalControlAction::Disconnect)
            {
                self.remove_local_subscriber(queue, pending.itsi);
                self.finish_terminal_control(pending.itsi, true, 0, Vec::new(), None);
            } else if self.pending_terminal_controls.contains_key(&pending.itsi) {
                self.finish_terminal_control(pending.itsi, false, cause as u8, Vec::new(), None);
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
            let _ = self.send_d_location_update_accept_with_handover(
                queue,
                pending.itsi,
                pending.air_handle,
                pending.location_update_type,
                pending.energy_saving_information,
                pending.authentication_successful,
                &pending.aie,
                self.aie_request_for_registration(pending.itsi, pending.air_interface_encrypted),
                pending.has_group_identity_location_demand.then_some(GroupIdentityLocationAccept {
                    group_identity_accept_reject: 0,
                    group_identity_downlink: None,
                }),
                pending.interrupted_group_security_gssis,
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
        self.registration_generations.insert(pending.itsi, command_id);
        self.config
            .state_write()
            .subscribers
            .set_registration_generation(pending.itsi, command_id);
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
            let (had_rejection, response_groups, security_groups) =
                self.apply_swmi_attachment_state(queue, command_id, itsi, false, &attachment, local_results);
            let security_groups = self.registration_group_security_gssis(
                pending.itsi,
                security_groups
                    .into_iter()
                    .chain(pending.interrupted_group_security_gssis.iter().copied()),
            );
            let receipt = self.send_d_location_update_accept_with_handover(
                queue,
                pending.itsi,
                pending.air_handle,
                pending.location_update_type,
                pending.energy_saving_information,
                pending.authentication_successful,
                &pending.aie,
                self.aie_request_for_registration(pending.itsi, pending.air_interface_encrypted),
                Some(GroupIdentityLocationAccept {
                    group_identity_accept_reject: u8::from(had_rejection),
                    group_identity_downlink: (!response_groups.is_empty()).then_some(response_groups),
                }),
                security_groups.clone(),
                None,
                rua_requested,
            );
            self.track_registration_delivery(
                Some(command_id),
                pending.itsi,
                pending.authentication_successful,
                security_groups,
                receipt.clone(),
            );
            let deferred = self.defer_security_activation(pending.itsi, &pending.aie, receipt);
            if !deferred {
                let _ = self.send_rollover_broadcast_round(queue);
            }
            return;
        }
        let security_groups =
            self.registration_group_security_gssis(pending.itsi, pending.interrupted_group_security_gssis.iter().copied());
        let receipt = self.send_d_location_update_accept_with_handover(
            queue,
            pending.itsi,
            pending.air_handle,
            pending.location_update_type,
            pending.energy_saving_information,
            pending.authentication_successful,
            &pending.aie,
            self.aie_request_for_registration(pending.itsi, pending.air_interface_encrypted),
            pending.has_group_identity_location_demand.then_some(GroupIdentityLocationAccept {
                group_identity_accept_reject: 0,
                group_identity_downlink: None,
            }),
            security_groups.clone(),
            None,
            rua_requested,
        );
        self.track_registration_delivery(
            Some(command_id),
            pending.itsi,
            pending.authentication_successful,
            security_groups,
            receipt.clone(),
        );
        let deferred = self.defer_security_activation(pending.itsi, &pending.aie, receipt);
        if !deferred {
            let _ = self.send_rollover_broadcast_round(queue);
        }
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
        // Cause 2 is the SwMI's explicit "unknown terminal" result. This can
        // happen after the BS and SwMI have both restarted while the MS still
        // considers its registration valid. Reject the stale attachment as
        // requested, then use the infrastructure-initiated MM recovery from
        // TS 100 392-2 clause 16.4.3 to make the MS register and report its
        // groups again.
        let registration_recovery_required = results.iter().any(|result| !result.accepted && result.cause == 2);

        let (had_rejection, response_groups, security_groups) =
            self.apply_swmi_attachment_state(queue, command_id, itsi, has_rejection, &pending, results);
        // TTR 001-11 figure 19 defines the association in the ACK that answers
        // the MS-initiated attachment. The common talkgroup-switch transaction
        // has exactly one newly attached GSSI, so keep that association atomic
        // with its acknowledgement. Larger scan-list updates still use bounded
        // figure-20 amendments to avoid the previously observed fragmented ACK.
        let inline_security = security_groups.len() == 1;
        self.send_d_attachment_acknowledgement(
            queue,
            pending.itsi,
            pending.air_handle,
            had_rejection,
            response_groups,
            inline_security.then_some(security_groups.as_slice()).unwrap_or_default(),
        );
        if !inline_security {
            self.send_group_security_association_amendments(queue, pending.itsi, pending.air_handle, security_groups);
        }
        if registration_recovery_required {
            self.send_d_location_update_command(queue, pending.itsi, pending.air_handle, true);
            tracing::warn!(
                command_id,
                issi = pending.itsi,
                "SwMI does not know attaching MS; requested fresh location update and group report"
            );
        }
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
        security_class: TerminalSecurityClass,
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
        self.activate_terminal_security_class(issi, security_class);
        // This arrives before call replay during roaming, so UMAC has the
        // target-cell monitoring phase before it queues any MCCH setup.
        // Reconciliation must be idempotent: tearing down unchanged groups
        // creates a listener gap and makes the MS repeatedly replace its
        // GSSI -> GCKN association after ordinary registration traffic.
        self.store_energy_economy(issi, energy_economy);
        let old_groups = self
            .client_mgr
            .get_client_by_issi(issi)
            .map(|client| client.groups.clone())
            .unwrap_or_default();
        let desired_groups = groups
            .into_iter()
            .filter(|group| !group.detach)
            .map(|group| (group.gssi, group.class_of_usage))
            .collect::<HashMap<_, _>>();

        let mut detached = old_groups
            .keys()
            .filter(|gssi| !desired_groups.contains_key(gssi))
            .copied()
            .collect::<Vec<_>>();
        detached.sort_unstable();
        for gssi in &detached {
            if let Err(error) = self.client_mgr.client_group_attach_with_class_of_usage(issi, *gssi, false, 0) {
                tracing::warn!(issi, gssi, ?error, "unable to remove stale roaming affiliation");
            } else {
                self.config.state_write().subscribers.deaffiliate(issi, *gssi);
            }
        }
        if !detached.is_empty() {
            self.emit_subscriber_update(queue, issi, detached.clone(), BrewSubscriberAction::Deaffiliate);
        }

        let mut added = Vec::new();
        let mut class_updates = Vec::new();
        let mut desired = desired_groups.iter().map(|(&gssi, &cou)| (gssi, cou)).collect::<Vec<_>>();
        desired.sort_unstable_by_key(|(gssi, _)| *gssi);
        for (gssi, class_of_usage) in desired {
            if old_groups.get(&gssi).copied() == Some(class_of_usage) {
                continue;
            }
            match self
                .client_mgr
                .client_group_attach_with_class_of_usage(issi, gssi, true, class_of_usage)
            {
                Ok(_) if old_groups.contains_key(&gssi) => class_updates.push(gssi),
                Ok(_) => {
                    self.config.state_write().subscribers.affiliate(issi, gssi);
                    added.push(gssi);
                }
                Err(error) => tracing::warn!(issi, gssi, ?error, "unable to restore roaming affiliation"),
            }
        }
        if !added.is_empty() {
            self.emit_subscriber_update(queue, issi, added.clone(), BrewSubscriberAction::Affiliate);
        }
        if !class_updates.is_empty() {
            let class_of_usage = class_updates
                .iter()
                .map(|gssi| self.client_mgr.client_group_class_of_usage(issi, *gssi).unwrap_or(0))
                .collect();
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Mm,
                dest: TetraEntity::Cmce,
                msg: SapMsgInner::MmSubscriberUpdate(MmSubscriberUpdate {
                    issi,
                    groups: class_updates.clone(),
                    action: BrewSubscriberAction::Affiliate,
                    class_of_usage,
                    scanning_enabled: None,
                }),
            });
        }

        let scanning_changed = self.client_mgr.client_scanning_enabled(issi) != Some(scanning_enabled);
        if scanning_changed && self.client_mgr.set_client_scanning_enabled(issi, scanning_enabled).is_ok() {
            self.config.state_write().subscribers.set_scanning_enabled(issi, scanning_enabled);
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Mm,
                dest: TetraEntity::Cmce,
                msg: SapMsgInner::MmSubscriberUpdate(MmSubscriberUpdate {
                    issi,
                    groups: Vec::new(),
                    action: BrewSubscriberAction::ScanningState,
                    class_of_usage: Vec::new(),
                    scanning_enabled: Some(scanning_enabled),
                }),
            });
        }

        // A group new to this BS is not necessarily new to the MS. This
        // authoritative snapshot restores network state only (TTR 001-01
        // 6.4), even when it arrives after the registration BL-ACK.
        let restored_count = desired_groups.len();
        tracing::info!(
            issi,
            groups = restored_count,
            added = added.len(),
            removed = detached.len(),
            class_updates = class_updates.len(),
            scanning_changed,
            scanning_enabled,
            ?energy_economy,
            "reconciled roaming group-scanning state from SwMI"
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
    ) -> (bool, Vec<GroupIdentityDownlink>, Vec<u32>) {
        let mut had_rejection = has_rejection;
        if pending.replace_all {
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

        let mut response_groups = Vec::new();
        let mut security_groups = Vec::new();
        let mut affiliated = Vec::new();
        let mut deaffiliated = Vec::new();
        for (result, original) in results.into_iter().zip(&pending.operations) {
            if !result.accepted {
                had_rejection = true;
                // TS 100 392-2 annex G requires every rejected operation to
                // be explicit.  A rejected attachment is represented as a
                // detachment, while a rejected detachment is represented as
                // an attachment because the group remains attached.
                let gssi = result.operation.gssi;
                if result.operation.detach {
                    let class_of_usage = self.client_mgr.client_group_class_of_usage(pending.itsi, gssi).unwrap_or(0);
                    response_groups.push(GroupIdentityDownlink {
                        group_identity_attachment: Some(GroupIdentityAttachment {
                            group_identity_attachment_lifetime: 1,
                            class_of_usage,
                        }),
                        group_identity_detachment_uplink: None,
                        gssi: Some(gssi),
                        address_extension: None,
                        vgssi: None,
                    });
                    security_groups.push(gssi);
                } else {
                    response_groups.push(GroupIdentityDownlink {
                        group_identity_attachment: None,
                        group_identity_detachment_uplink: Some(0),
                        gssi: Some(gssi),
                        address_extension: None,
                        vgssi: None,
                    });
                }
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
                    // Re-advertise the GCK association for every accepted
                    // attachment, including an idempotent retry. The terminal
                    // may be retrying because it missed the first ACK even
                    // though the BS already committed the local affiliation.
                    // Multi-group retries remain bounded amendments, so this
                    // does not reintroduce the former fragmented ACK.
                    if !detach {
                        security_groups.push(gssi);
                        // A successful operation is implicitly accepted.  It
                        // is only repeated in the acknowledgement when the
                        // SwMI actually changed the requested class of usage.
                        if changed && original.class_of_usage != Some(result.operation.class_of_usage) {
                            response_groups.push(GroupIdentityDownlink {
                                group_identity_attachment: Some(GroupIdentityAttachment {
                                    group_identity_attachment_lifetime: 1,
                                    class_of_usage: result.operation.class_of_usage,
                                }),
                                group_identity_detachment_uplink: None,
                                gssi: Some(gssi),
                                address_extension: None,
                                vgssi: None,
                            });
                        }
                    }
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
        (had_rejection, response_groups, security_groups)
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
        let (had_rejection, response_groups, security_groups) =
            self.apply_swmi_attachment_state(queue, command_id, itsi, has_rejection, &pending.attachment, results);
        let registration = pending.registration;
        let security_groups = self.registration_group_security_gssis(
            registration.itsi,
            security_groups
                .into_iter()
                .chain(registration.interrupted_group_security_gssis.iter().copied()),
        );
        let receipt = self.send_d_location_update_accept_with_handover(
            queue,
            registration.itsi,
            registration.air_handle,
            registration.location_update_type,
            registration.energy_saving_information,
            registration.authentication_successful,
            &registration.aie,
            self.aie_request_for_registration(registration.itsi, registration.air_interface_encrypted),
            Some(GroupIdentityLocationAccept {
                group_identity_accept_reject: u8::from(had_rejection),
                group_identity_downlink: (!response_groups.is_empty()).then_some(response_groups),
            }),
            security_groups.clone(),
            None,
            pending.rua_requested,
        );
        self.track_registration_delivery(
            Some(command_id),
            registration.itsi,
            registration.authentication_successful,
            security_groups,
            receipt.clone(),
        );
        let deferred = self.defer_security_activation(registration.itsi, &registration.aie, receipt);
        if !deferred {
            let _ = self.send_rollover_broadcast_round(queue);
        }
        tracing::info!(
            command_id,
            itsi,
            rejected = had_rejection,
            authentication_downlink = registration.authentication_successful,
            "SwMI location update and group attachment accepted; air-interface BL-ACK pending"
        );
    }

    fn send_d_attachment_acknowledgement(
        &mut self,
        queue: &mut MessageQueue,
        issi: u32,
        handle: u32,
        has_rejection: bool,
        groups: Vec<GroupIdentityDownlink>,
        security_groups: &[u32],
    ) {
        let pdu = DAttachDetachGroupIdentityAcknowledgement {
            group_identity_accept_reject: u8::from(has_rejection),
            reserved: false,
            proprietary: None,
            group_identity_downlink: (!groups.is_empty()).then_some(groups),
            // A single newly attached SC3G group follows the normative figure
            // 19 path in this ACK. Multi-group lists are intentionally kept out
            // of the ACK and sent as bounded figure-20 amendments by the caller.
            group_identity_security_related_information: self.group_security_information(security_groups.iter().copied()),
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
                                assigned_channel_frame18_broadcast: false,
                                frame18_rollover_activation: None,
                tx_reporter: None,
                seamless_handover: None,
            }),
        });
        // Do not start a queued SwMI-initiated amendment in the same instant
        // as this response to an MS-initiated attachment. The PDU types have
        // no transaction identifiers and the terminal MM must first complete
        // the exchange it initiated.
        self.group_security_not_before
            .insert(issi, self.current_time.add_timeslots(GROUP_SECURITY_REGISTRATION_GUARD_TIMESLOTS));
    }

    /// Announce the version to use before reapplying group associations.
    /// TTR 001-11 6.2.4/6.2.8: storing a future key does not activate it.
    /// A future-only or stale result must not refresh a live association as
    /// though the current key had been accepted. A partial result can still
    /// recover the groups whose current key succeeded.
    fn refresh_group_security_after_gck_result(
        &mut self,
        queue: &mut MessageQueue,
        issi: u32,
        handle: u32,
        result: &tetra_pdus::mm::pdus::otar::UGckResult,
    ) {
        let accepted_gckns = {
            let state = self.config.state_read();
            let Some(sc3) = state.aie.sc3.as_ref() else { return };
            result.results.iter()
                .filter(|entry| entry.provision_result == 0 && entry.version_number == sc3.gck_vn())
                .map(|entry| entry.gck_number)
                .collect::<HashSet<_>>()
        };
        if accepted_gckns.is_empty() {
            return;
        }
        // Both PDUs use the same acknowledged individual basic link. Queue
        // the current-version indication first, so attachment cannot select
        // a stale version while the following indication is still in flight.
        self.send_current_gck_version_to_terminal(queue, issi, handle);
        self.send_group_security_association_refresh(queue, issi, handle, &accepted_gckns);
    }

    /// Re-advertise the currently attached GSSI associations whose GCK was
    /// just accepted by the terminal.  TTR 001-11 figure 20 carries both the
    /// Group identity downlink and its Group Identity Security Related
    /// Information in this SwMI-initiated amendment.  Some terminals ignore a
    /// security-only D-ATTACH/DETACH PDU even though they link-acknowledge it,
    /// leaving the group locally unusable after accepting the GCK.
    fn send_group_security_association_refresh(&mut self, queue: &mut MessageQueue, issi: u32, handle: u32, accepted_gckns: &HashSet<u16>) {
        let attached_groups = self
            .client_mgr
            .get_client_by_issi(issi)
            .map(|client| client.groups.keys().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        let groups = {
            let state = self.config.state_read();
            let Some(sc3) = state.aie.sc3.as_ref() else {
                return;
            };
            attached_groups
                .into_iter()
                .filter(|gssi| sc3.gckn_for_gssi(*gssi).is_some_and(|gckn| accepted_gckns.contains(&gckn)))
                .collect::<Vec<_>>()
        };
        let associations = groups.len();
        self.send_group_security_association_amendments(queue, issi, handle, groups);
        tracing::info!(
            issi,
            ?accepted_gckns,
            associations,
            "queued group-security association refresh after accepted GCK provision"
        );
    }

    fn group_security_exchange_blocked(&self, issi: u32) -> bool {
        self.config.state_read().subscribers.is_registration_pending(issi)
            || self.pending_group_security_associations.contains_key(&issi)
            || self.pending_attachments.values().any(|pending| pending.itsi == issi)
            || self
                .pending_location_attachments
                .values()
                .any(|pending| pending.registration.itsi == issi)
    }

    fn enqueue_group_security_associations(&mut self, issi: u32, handle: u32, groups: Vec<u32>, retries: u8) {
        if groups.is_empty() {
            return;
        }
        let pending = self.queued_group_security_associations.entry(issi).or_default();
        if handle != 0 || pending.air_handle == 0 {
            pending.air_handle = handle;
        }
        pending.groups.extend(groups);
        pending.retries = pending.retries.max(retries);
    }

    fn group_security_guard_active(&self, issi: u32) -> bool {
        self.group_security_not_before
            .get(&issi)
            .is_some_and(|not_before| not_before.age(self.current_time) < 0)
    }

    fn terminal_group_diff(
        &mut self,
        issi: u32,
        action: TerminalControlAction,
        requested: Vec<AttachmentOperation>,
    ) -> Vec<AttachmentOperation> {
        if action == TerminalControlAction::AmendTalkgroups {
            return requested;
        }
        let current = self
            .client_mgr
            .get_client_by_issi(issi)
            .map(|client| client.groups.clone())
            .unwrap_or_default();
        let desired = requested
            .into_iter()
            .filter(|operation| !operation.detach)
            .map(|operation| (operation.gssi, operation.class_of_usage))
            .collect::<HashMap<_, _>>();
        let mut operations = current
            .keys()
            .filter(|gssi| !desired.contains_key(gssi))
            .map(|gssi| AttachmentOperation {
                gssi: *gssi,
                detach: true,
                class_of_usage: 0,
            })
            .collect::<Vec<_>>();
        operations.extend(desired.into_iter().filter_map(|(gssi, class_of_usage)| {
            (current.get(&gssi).copied() != Some(class_of_usage)).then_some(AttachmentOperation {
                gssi,
                detach: false,
                class_of_usage,
            })
        }));
        operations.sort_unstable_by_key(|operation| (operation.detach, operation.gssi));
        operations
    }

    fn start_terminal_group_control(
        &mut self,
        queue: &mut MessageQueue,
        command_id: u64,
        issi: u32,
        action: TerminalControlAction,
        requested: Vec<AttachmentOperation>,
    ) {
        let operations = self.terminal_group_diff(issi, action, requested);
        if operations.is_empty() {
            self.submit_terminal_control_result(command_id, issi, action, true, 0, Vec::new(), None);
            return;
        }
        let group_identity_downlink = operations
            .iter()
            .map(|operation| GroupIdentityDownlink {
                group_identity_attachment: (!operation.detach).then_some(GroupIdentityAttachment {
                    group_identity_attachment_lifetime: 1,
                    class_of_usage: operation.class_of_usage,
                }),
                // Temporary-1 detachment is a reversible network policy
                // change; it is intentionally not a permanent disable.
                group_identity_detachment_uplink: operation.detach.then_some(1),
                gssi: Some(operation.gssi),
                address_extension: None,
                vgssi: None,
            })
            .collect();
        let pdu = DAttachDetachGroupIdentity {
            group_identity_report: false,
            group_identity_acknowledgement_request: true,
            // TTR 001-01 §8.7.2 requires amendment mode for SwMI-initiated changes.
            group_identity_attach_detach_mode: false,
            proprietary: None,
            group_report_response: None,
            group_identity_downlink: Some(group_identity_downlink),
            group_identity_security_related_information: self.group_security_information(
                operations
                    .iter()
                    .filter(|operation| !operation.detach)
                    .map(|operation| operation.gssi),
            ),
        };
        let mut sdu = BitBuffer::new_autoexpand(128);
        if let Err(error) = pdu.to_bitbuf(&mut sdu) {
            tracing::warn!(command_id, issi, ?error, "cannot serialize terminal talkgroup amendment");
            self.submit_terminal_control_result(command_id, issi, action, false, 3, Vec::new(), None);
            return;
        }
        sdu.seek(0);
        let tx_reporter = TxReporter::new();
        queue.push_back(SapMsg {
            sap: Sap::LmmSap,
            src: TetraEntity::Mm,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                sdu,
                handle: 0,
                address: TetraAddress::issi(issi),
                layer2service: Layer2Service::Acknowledged,
                stealing_permission: false,
                stealing_repeats_flag: false,
                encryption_flag: false,
                aie_request: self.downlink_aie_request(issi),
                is_null_pdu: false,
                            assigned_channel_frame18_broadcast: false,
                            frame18_rollover_activation: None,
                tx_reporter: Some(tx_reporter.clone()),
                seamless_handover: None,
            }),
        });
        self.pending_terminal_controls.insert(
            issi,
            PendingTerminalControl {
                command_id,
                action,
                operations,
                tx_reporter: Some(tx_reporter),
                response_deadline: None,
                information: TerminalInformation::default(),
            },
        );
    }

    fn complete_terminal_group_control(&mut self, queue: &mut MessageQueue, issi: u32, pdu: UAttachDetachGroupIdentityAcknowledgement) {
        let Some(pending) = self.pending_terminal_controls.remove(&issi) else {
            return;
        };
        let returned = pdu.group_identity_uplink.as_deref().unwrap_or_default();
        let rejected = if pdu.group_identity_acknowledgement_type {
            returned
                .iter()
                .filter_map(|group| Some((group.gssi?, group.group_identity_detachment_uplink?)))
                .collect::<HashMap<_, _>>()
        } else {
            HashMap::new()
        };
        let returned_classes = returned
            .iter()
            .filter_map(|group| Some((group.gssi?, group.class_of_usage?)))
            .collect::<HashMap<_, _>>();
        let mut attached = Vec::new();
        let mut detached = Vec::new();
        let mut results = Vec::with_capacity(pending.operations.len());
        for mut operation in pending.operations {
            let mut accepted = !rejected.contains_key(&operation.gssi);
            let mut cause = rejected.get(&operation.gssi).copied().unwrap_or(0);
            if accepted
                && !operation.detach
                && let Some(class_of_usage) = returned_classes.get(&operation.gssi).copied()
            {
                operation.class_of_usage = class_of_usage;
            }
            if accepted {
                if self
                    .client_mgr
                    .client_group_attach_with_class_of_usage(issi, operation.gssi, !operation.detach, operation.class_of_usage)
                    .is_ok()
                {
                    if operation.detach {
                        self.config.state_write().subscribers.deaffiliate(issi, operation.gssi);
                        detached.push(operation.gssi);
                    } else {
                        self.config.state_write().subscribers.affiliate(issi, operation.gssi);
                        attached.push(operation.gssi);
                    }
                } else {
                    accepted = false;
                    cause = 3;
                }
            }
            results.push(AttachmentResult {
                operation,
                accepted,
                cause,
            });
        }
        if !attached.is_empty() {
            self.emit_subscriber_update(queue, issi, attached, BrewSubscriberAction::Affiliate);
        }
        if !detached.is_empty() {
            self.emit_subscriber_update(queue, issi, detached, BrewSubscriberAction::Deaffiliate);
        }
        let success = results.iter().all(|result| result.accepted);
        self.submit_terminal_control_result(pending.command_id, issi, pending.action, success, u8::from(!success), results, None);
    }

    /// Begin exactly one Figure-20 transaction. TTR 001-11 table 14 permits
    /// up to thirty associations in one security element, which covers the
    /// supported twenty-group scan list. LLC/MAC may fragment this one PDU;
    /// its BL-ACK and the terminal's MM acknowledgement remain distinct.
    fn start_group_security_association_transaction(
        &mut self,
        queue: &mut MessageQueue,
        issi: u32,
        handle: u32,
        groups: Vec<u32>,
        retries: u8,
    ) {
        debug_assert!(!self.pending_group_security_associations.contains_key(&issi));
        let groups = self.normalized_group_security_gssis(groups);
        let Some(security) = self.group_security_information(groups.iter().copied()) else {
            return;
        };
        let group_identity_downlink = security
            .iter()
            .flat_map(|information| &information.associations)
            .map(|association| GroupIdentityDownlink {
                group_identity_attachment: Some(GroupIdentityAttachment {
                    group_identity_attachment_lifetime: 1,
                    class_of_usage: self.client_mgr.client_group_class_of_usage(issi, association.gssi).unwrap_or(0),
                }),
                group_identity_detachment_uplink: None,
                gssi: Some(association.gssi),
                address_extension: None,
                vgssi: None,
            })
            .collect::<Vec<_>>();
        let pdu = DAttachDetachGroupIdentity {
            group_identity_report: false,
            // Figure 20 uses an MM acknowledgement for a SwMI-initiated
            // attachment amendment. This gives the complete association set
            // one transaction instead of relying only on lower-layer BL-ACKs.
            group_identity_acknowledgement_request: true,
            group_identity_attach_detach_mode: false,
            proprietary: None,
            group_report_response: None,
            group_identity_downlink: Some(group_identity_downlink),
            group_identity_security_related_information: Some(security),
        };
        let mut sdu = BitBuffer::new_autoexpand(64);
        pdu.to_bitbuf(&mut sdu).expect("serialize GCK association refresh");
        sdu.seek(0);
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
                aie_request: self.downlink_aie_request(issi),
                is_null_pdu: false,
                assigned_channel_frame18_broadcast: false,
                frame18_rollover_activation: None,
                tx_reporter: Some(tx_reporter.clone()),
                seamless_handover: None,
            }),
        });
        let association_count = groups.len();
        self.pending_group_security_associations.insert(
            issi,
            PendingGroupSecurityAssociation {
                air_handle: handle,
                groups,
                tx_reporter,
                phase: GroupSecurityAssociationPhase::LinkDelivery,
                acknowledgement_deadline: None,
                retries,
            },
        );
        tracing::info!(
            issi,
            association_count,
            attempt = retries + 1,
            "queued transactional group-security association amendment"
        );
    }

    fn send_group_security_association_amendments(
        &mut self,
        queue: &mut MessageQueue,
        issi: u32,
        handle: u32,
        groups: impl IntoIterator<Item = u32>,
    ) {
        let groups = self.normalized_group_security_gssis(groups);
        if groups.is_empty() {
            return;
        }
        if self.group_security_exchange_blocked(issi) || self.group_security_guard_active(issi) {
            self.enqueue_group_security_associations(issi, handle, groups, 0);
            return;
        }
        // Do not retain an expired wrapped TDMA deadline indefinitely. Apart
        // from keeping the map bounded, removal prevents an ancient guard
        // from looking future again after half of the hyperframe counter
        // range has elapsed.
        self.group_security_not_before.remove(&issi);
        self.start_group_security_association_transaction(queue, issi, handle, groups, 0);
    }

    fn flush_queued_group_security_associations(&mut self, queue: &mut MessageQueue) {
        let ready = self
            .queued_group_security_associations
            .keys()
            .copied()
            .filter(|issi| !self.group_security_exchange_blocked(*issi) && !self.group_security_guard_active(*issi))
            .collect::<Vec<_>>();
        for issi in ready {
            self.group_security_not_before.remove(&issi);
            let Some(queued) = self.queued_group_security_associations.remove(&issi) else {
                continue;
            };
            self.start_group_security_association_transaction(
                queue,
                issi,
                queued.air_handle,
                queued.groups.into_iter().collect(),
                queued.retries,
            );
        }
    }

    fn retry_group_security_association(
        &mut self,
        queue: &mut MessageQueue,
        issi: u32,
        pending: PendingGroupSecurityAssociation,
        groups: Vec<u32>,
        reason: &'static str,
    ) {
        let retries = pending.retries.saturating_add(1);
        if pending.retries >= MAX_GROUP_SECURITY_RETRIES {
            tracing::warn!(
                issi,
                association_count = groups.len(),
                attempts = pending.retries + 1,
                reason,
                "group-security association transaction exhausted bounded retries"
            );
            return;
        }
        tracing::warn!(
            issi,
            association_count = groups.len(),
            attempt = retries + 1,
            reason,
            "retrying group-security association transaction"
        );
        if self.group_security_exchange_blocked(issi) || self.group_security_guard_active(issi) {
            self.enqueue_group_security_associations(issi, pending.air_handle, groups, retries);
        } else {
            self.start_group_security_association_transaction(queue, issi, pending.air_handle, groups, retries);
        }
    }

    fn update_group_security_association_statuses(&mut self, queue: &mut MessageQueue) {
        enum Failed {
            Link(TxState),
            MmTimeout,
        }

        let issis = self.pending_group_security_associations.keys().copied().collect::<Vec<_>>();
        let mut failures = Vec::new();
        for issi in issis {
            let Some(pending) = self.pending_group_security_associations.get_mut(&issi) else {
                continue;
            };
            match pending.phase {
                GroupSecurityAssociationPhase::LinkDelivery => match pending.tx_reporter.get_state() {
                    TxState::Pending | TxState::Transmitted => {}
                    TxState::Discarded | TxState::Lost => failures.push((issi, Failed::Link(pending.tx_reporter.get_state()))),
                    TxState::Acknowledged => {
                        pending.phase = GroupSecurityAssociationPhase::AwaitingMmAcknowledgement;
                        pending.acknowledgement_deadline = Some(self.current_time.add_timeslots(GROUP_SECURITY_ACK_TIMEOUT_TIMESLOTS));
                        tracing::debug!(
                            issi,
                            association_count = pending.groups.len(),
                            "group-security association link-acknowledged; awaiting terminal MM acknowledgement"
                        );
                    }
                },
                GroupSecurityAssociationPhase::AwaitingMmAcknowledgement => {
                    if pending
                        .acknowledgement_deadline
                        .is_some_and(|deadline| deadline.age(self.current_time) >= 0)
                    {
                        failures.push((issi, Failed::MmTimeout));
                    }
                }
            }
        }

        for (issi, failure) in failures {
            let Some(pending) = self.pending_group_security_associations.remove(&issi) else {
                continue;
            };
            let groups = pending.groups.clone();
            match failure {
                Failed::Link(state) => {
                    tracing::warn!(issi, ?state, "group-security association basic-link delivery failed");
                    self.retry_group_security_association(queue, issi, pending, groups, "basic-link-failure");
                }
                Failed::MmTimeout => {
                    self.retry_group_security_association(queue, issi, pending, groups, "terminal-mm-ack-timeout");
                }
            }
        }
        self.flush_queued_group_security_associations(queue);
    }

    fn complete_group_security_association_ack(
        &mut self,
        queue: &mut MessageQueue,
        issi: u32,
        pdu: UAttachDetachGroupIdentityAcknowledgement,
    ) {
        let Some(pending) = self.pending_group_security_associations.remove(&issi) else {
            tracing::warn!(
                issi,
                accepted = !pdu.group_identity_acknowledgement_type,
                returned_groups = pdu.group_identity_uplink.as_ref().map_or(0, Vec::len),
                "ignoring group-security attachment acknowledgement without a pending Figure-20 transaction"
            );
            return;
        };

        let offered = pending.groups.iter().copied().collect::<HashSet<_>>();
        let mut rejected = Vec::new();
        let mut malformed = false;
        let mut class_updates = Vec::new();
        for returned in pdu.group_identity_uplink.as_deref().unwrap_or_default() {
            let Some(gssi) = returned.gssi else {
                malformed = true;
                continue;
            };
            if !offered.contains(&gssi) {
                tracing::warn!(issi, gssi, "terminal returned a group outside the pending Figure-20 request");
                malformed = true;
                continue;
            }
            if returned.group_identity_detachment_uplink.is_some() {
                rejected.push(gssi);
                continue;
            }
            if let Some(class_of_usage) = returned.class_of_usage
                && self
                    .client_mgr
                    .client_group_attach_with_class_of_usage(issi, gssi, true, class_of_usage)
                    .unwrap_or(false)
            {
                class_updates.push((gssi, class_of_usage));
            }
        }
        rejected.sort_unstable();
        rejected.dedup();

        // Annex F: type 0 accepts the complete request; type 1 requires every
        // rejected attachment to be returned explicitly. Contradictory or
        // empty rejection data cannot safely identify what the MS retained.
        if !pdu.group_identity_acknowledgement_type && !rejected.is_empty() {
            malformed = true;
        }
        if pdu.group_identity_acknowledgement_type && rejected.is_empty() {
            malformed = true;
        }

        if !class_updates.is_empty() {
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Mm,
                dest: TetraEntity::Cmce,
                msg: SapMsgInner::MmSubscriberUpdate(MmSubscriberUpdate {
                    issi,
                    groups: class_updates.iter().map(|(gssi, _)| *gssi).collect(),
                    action: BrewSubscriberAction::Affiliate,
                    class_of_usage: class_updates.iter().map(|(_, cou)| *cou).collect(),
                    scanning_enabled: None,
                }),
            });
        }

        tracing::info!(
            issi,
            accepted = !pdu.group_identity_acknowledgement_type && !malformed,
            returned_groups = pdu.group_identity_uplink.as_ref().map_or(0, Vec::len),
            rejected_groups = rejected.len(),
            malformed,
            "group-security attachment amendment acknowledged by terminal"
        );

        if malformed {
            let groups = pending.groups.clone();
            self.retry_group_security_association(queue, issi, pending, groups, "ambiguous-terminal-mm-ack");
        } else if !rejected.is_empty() {
            self.retry_group_security_association(queue, issi, pending, rejected, "terminal-rejected-association");
        }
        self.flush_queued_group_security_associations(queue);
    }

    fn cancel_group_security_association_for_registration(&mut self, issi: u32) -> Vec<u32> {
        let pending = self.pending_group_security_associations.remove(&issi);
        let queued = self.queued_group_security_associations.remove(&issi);
        self.group_security_not_before.remove(&issi);
        let mut groups = pending
            .as_ref()
            .into_iter()
            .flat_map(|pending| pending.groups.iter().copied())
            .chain(queued.as_ref().into_iter().flat_map(|queued| queued.groups.iter().copied()))
            .collect::<Vec<_>>();
        groups.sort_unstable();
        groups.dedup();
        if pending.is_some() || queued.is_some() {
            tracing::info!(
                issi,
                association_count = groups.len(),
                "abandoned colliding Figure-20 association transaction in favour of registration"
            );
        }
        groups
    }

    fn send_d_location_update_accept(
        &self,
        queue: &mut MessageQueue,
        issi: u32,
        handle: u32,
        location_update_type: LocationUpdateType,
        energy_saving_information: Option<EnergySavingInformation>,
        authentication_successful: bool,
        group_identity_location_accept: Option<GroupIdentityLocationAccept>,
    ) {
        let _ = self.send_d_location_update_accept_with_handover(
            queue,
            issi,
            handle,
            location_update_type,
            energy_saving_information,
            authentication_successful,
            &AieLocationUpdateDecision::default(),
            AieRequest::clear(AieSubject::System, AieScope::MacResource),
            group_identity_location_accept,
            Vec::new(),
            None,
            false,
        );
    }

    fn send_d_location_update_accept_with_handover(
        &self,
        queue: &mut MessageQueue,
        issi: u32,
        handle: u32,
        location_update_type: LocationUpdateType,
        energy_saving_information: Option<EnergySavingInformation>,
        authentication_successful: bool,
        aie: &AieLocationUpdateDecision,
        aie_request: AieRequest,
        group_identity_location_accept: Option<GroupIdentityLocationAccept>,
        group_security_gssis: Vec<u32>,
        seamless_handover: Option<LmmMleSeamlessHandover>,
        rua_requested: bool,
    ) -> TxReporter {
        let security = self.group_security_information(group_security_gssis);
        let information_requested = self
            .pending_terminal_controls
            .get(&issi)
            .is_some_and(|pending| pending.action == TerminalControlAction::RequestInformation);
        let information_via_security = information_requested && self.security_information_protocol_supported.contains(&issi);
        let information_via_authentication = information_requested && !information_via_security;
        let pdu = DLocationUpdateAccept {
            location_update_accept_type: location_update_type,
            ssi: Some(issi as u64),
            address_extension: None,
            subscriber_class: None,
            energy_saving_information,
            scch_information_and_distribution_on_18th_frame: None,
            new_registered_area: None,
            security_downlink: information_via_security.then(SecurityDownlink::terminal_information_request),
            group_identity_location_accept,
            default_group_attachment_lifetime: None,
            authentication_downlink: aie
                .authentication_downlink_bit_len
                .map(|len| {
                    let mut first = aie
                        .authentication_downlink
                        .get(..8)
                        .and_then(|bytes| bytes.try_into().ok())
                        .map(u64::from_be_bytes)
                        .unwrap_or_default();
                    if information_via_authentication {
                        // Table A.34: TEI request is the second transmitted
                        // bit. These SwMI payloads are longer than 64 bits, so
                        // it is bit 62 in the writer's first u64 chunk.
                        first |= 1_u64 << 62;
                    }
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
                        data: 0b100 | u64::from(information_via_authentication) << 1,
                        raw: Vec::new(),
                    })
                })
                .or_else(|| {
                    information_via_authentication.then(|| Type3FieldGeneric {
                        field_id: MmType34ElemIdDl::AuthenticationDownlink.into(),
                        len: 3,
                        // Authentication result 1 means successful or no
                        // authentication currently in progress (A.8.5).
                        data: 0b110,
                        raw: Vec::new(),
                    })
                }),
            group_identity_security_related_information: security,
            cell_type_control: None,
            proprietary: rua_requested.then(|| Type3FieldGeneric {
                field_id: MmType34ElemIdDl::Proprietary.into(),
                // TTR 001-17 table 1: TETRA MoU (0x01), RUA requested
                // (0x2), followed by the configured requested RUI type.
                len: 15,
                data: (1 << 7) | (2 << 3) | u64::from(self.config.config().rua.requested_rui_type.assignment_request()),
                raw: Vec::new(),
            }),
        };
        let authentication_downlink_present = pdu.authentication_downlink.is_some();
        let mut sdu = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut sdu).expect("serialize SwMI D-LOCATION UPDATE ACCEPT");
        sdu.seek(0);
        tracing::debug!(
            issi,
            authentication_downlink = authentication_downlink_present,
            downlink_encrypted = aie_request.is_encrypted(),
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
                assigned_channel_frame18_broadcast: false,
                frame18_rollover_activation: None,
                tx_reporter: Some(tx_reporter.clone()),
                seamless_handover,
            }),
        });
        tx_reporter
    }

    /// TTR 001-01 clause 14.2.4 presence check: an individually addressed
    /// BL-DATA without a layer-3 TL-SDU. The MS answers with BL-ACK even though
    /// no MM/CMCE PDU is present. Sending this directly to LLC is intentional;
    /// routing it through MLE would prepend a protocol discriminator and turn
    /// it into a malformed layer-3 PDU rather than an empty basic-link page.
    fn send_liveliness_probe(&mut self, queue: &mut MessageQueue, issi: u32) {
        if self.pending_liveliness_probes.contains_key(&issi) {
            tracing::debug!(issi, "coalescing duplicate terminal presence probe");
            return;
        }

        let tx_reporter = TxReporter::new();
        queue.push_back(SapMsg {
            sap: Sap::TlaSap,
            src: TetraEntity::Mm,
            dest: TetraEntity::Llc,
            msg: SapMsgInner::TlaTlDataReqBl(TlaTlDataReqBl {
                main_address: TetraAddress::issi(issi),
                link_id: 0,
                endpoint_id: 0,
                tl_sdu: BitBuffer::new_autoexpand(0),
                stealing_permission: false,
                subscriber_class: 0,
                fcs_flag: false,
                packet_data_flag: false,
                air_interface_encryption: Some(self.downlink_aie_request(issi)),
                stealing_repeats_flag: None,
                data_class_info: None,
                req_handle: 0,
                graceful_degradation: None,
                chan_alloc: None,
                associated_channel: None,
                tx_reporter: Some(tx_reporter.clone()),
            }),
        });
        self.pending_liveliness_probes.insert(issi, tx_reporter);
        tracing::debug!(issi, "queued acknowledged empty BL-DATA terminal presence probe");
    }

    /// Sends a D-LOCATION UPDATE COMMAND for explicit MM recovery paths that
    /// require a fresh group report. Presence checks must use
    /// `send_liveliness_probe` instead, because this command starts a complete
    /// location-update and security-state procedure in the MS.
    fn send_d_location_update_command(&self, queue: &mut MessageQueue, issi: u32, handle: u32, group_identity_report: bool) {
        let ciphering_parameters = self.aie_ciphering_parameters();
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
                // A liveliness/recovery command is normal individual MM
                // signalling, not a bootstrap exception. Protect it with the
                // terminal's established DCK/SCK context when one exists.
                aie_request: self.downlink_aie_request(issi),
                is_null_pdu: false,
                assigned_channel_frame18_broadcast: false,
                frame18_rollover_activation: None,
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
                assigned_channel_frame18_broadcast: false,
                frame18_rollover_activation: None,
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
                assigned_channel_frame18_broadcast: false,
                frame18_rollover_activation: None,
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
                assigned_channel_frame18_broadcast: false,
                frame18_rollover_activation: None,
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
                assigned_channel_frame18_broadcast: false,
                frame18_rollover_activation: None,
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
        self.update_registration_delivery_statuses(queue);
        self.update_group_security_association_statuses(queue);
        self.update_liveliness_probe_statuses();
        self.update_terminal_control_statuses();
        self.update_security_activations(queue);
        self.update_otar_delivery_statuses();
        // TTR 001-11 permits the Absolute-IV all-GCK demand on any channel.
        // It is deliberately best-effort: normal SDS and call signalling own
        // the queues, while the five-second cadence gives each free MCCH,
        // traffic and PD monitoring opportunity a repeated announcement.
        let gck_rollover = self.config.state_read().aie.sc3.as_ref().and_then(|sc3| sc3.gck_rollover_notification());
        if let Some((rollover_id, target_vn, Some(activation))) = gck_rollover {
            let due = self.last_gck_rollover_broadcast.is_none_or(|(last_id, last)| {
                last_id != rollover_id || last.age(ts) >= GCK_ROLLOVER_BROADCAST_INTERVAL_TIMESLOTS
            });
            if due && self.send_gck_rollover_broadcast_round(queue, target_vn, activation) {
                self.last_gck_rollover_broadcast = Some((rollover_id, ts));
                self.send_assigned_gck_rollover_notices(queue, rollover_id, target_vn, activation, ts);
            }
            // UMAC finalizes one slot ahead, after consuming messages routed
            // through MM, MLE and LLC.  Queue the dedicated marker two
            // physical slots before TS1/FN18 so UMAC receives it before it
            // finalizes that TS, then reserves TS1..TS4 of FN18.  The last
            // of those resources is directly before the TS1/FN1 `Immediate`
            // activation boundary.
            if self.gck_rollover_immediate_sent != Some(rollover_id)
                && ts == activation.add_timeslots(-6)
                && self.send_gck_rollover_immediate(queue, target_vn, activation)
            {
                self.gck_rollover_immediate_sent = Some(rollover_id);
                tracing::info!(rollover_id, activation = %activation, "queued final all-timeslot SC3G GCK rollover Immediate");
            }
        } else {
            self.last_gck_rollover_broadcast = None;
            self.assigned_gck_notices.clear();
            self.gck_rollover_immediate_sent = None;
        }
        let active_gck_vn = {
            let state = self.config.state_read();
            state.aie.sc3.as_ref().filter(|sc3| sc3.gck_supported()).map(|sc3| sc3.gck_vn())
        };
        if let Some(gck_vn) = active_gck_vn {
            let due = self.last_gck_version_broadcast.is_none_or(|(last_gck_vn, last_time)| {
                last_gck_vn != gck_vn || last_time.age(ts) >= GCK_VERSION_BROADCAST_INTERVAL_TIMESLOTS
            });
            if due && self.send_gck_version_broadcast_round(queue, gck_vn) {
                self.last_gck_version_broadcast = Some((gck_vn, ts));
            }
        } else {
            self.last_gck_version_broadcast = None;
        }
        let staged_rollover_id = self.config.state_read().aie.staged_rollover_id();
        if let Some(rollover_id) = staged_rollover_id {
            let activation = self
                .config
                .state_read()
                .aie
                .rollover_notification()
                .and_then(|(_, activation)| activation);
            let due = self
                .last_rollover_broadcast
                .is_none_or(|(last_id, last_time)| last_id != rollover_id || last_time.age(ts) >= ROLLOVER_BROADCAST_INTERVAL_TIMESLOTS);
            if due && self.send_rollover_broadcast_round(queue) {
                self.last_rollover_broadcast = Some((rollover_id, ts));
                tracing::debug!(rollover_id, "repeated MCCH/TCH all-MS SC2 rollover announcement");
            }

            let mut late_mask = self
                .rollover_late_broadcast_mask
                .filter(|(id, _)| *id == rollover_id)
                .map(|(_, mask)| mask)
                .unwrap_or(0);
            if let Some(activation) = activation {
                let remaining = activation.diff(ts);
                for (index, offset) in ROLLOVER_LATE_BROADCAST_OFFSETS_TIMESLOTS.into_iter().enumerate() {
                    let bit = 1_u8 << index;
                    if remaining > 0 && remaining <= offset && late_mask & bit == 0 && self.send_rollover_broadcast_round(queue) {
                        late_mask |= bit;
                        tracing::info!(
                            rollover_id,
                            remaining_timeslots = remaining,
                            activation = %activation,
                            round = index + 1,
                            "queued late MCCH/TCH all-MS SC2 rollover announcement"
                        );
                    }
                }
            }
            self.rollover_late_broadcast_mask = Some((rollover_id, late_mask));
        }
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
                SwmiMessage::TerminalControl {
                    command_id,
                    itsi,
                    action,
                    operations,
                } => self.handle_terminal_control(queue, command_id, itsi, action, operations),
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
                            aie_request: self.aie_request_for_registration_command(command_id, itsi as u32),
                            is_null_pdu: false,
                            assigned_channel_frame18_broadcast: false,
                            frame18_rollover_activation: None,
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
                                aie_request: self.aie_request_for_registration_command(command_id, itsi as u32),
                                is_null_pdu: false,
                                assigned_channel_frame18_broadcast: false,
                                frame18_rollover_activation: None,
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
                    if !success
                        && self
                            .pending_terminal_controls
                            .get(&(itsi as u32))
                            .is_some_and(|pending| pending.action == TerminalControlAction::Reauthenticate)
                    {
                        self.finish_terminal_control(itsi as u32, false, 1, Vec::new(), None);
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
                                aie_request: self.aie_request_for_registration_command(command_id, itsi as u32),
                                is_null_pdu: false,
                                assigned_channel_frame18_broadcast: false,
                                frame18_rollover_activation: None,
                                tx_reporter: None,
                                seamless_handover: None,
                            }),
                        });
                    }
                    self.pending_auth_commands
                        .insert(Self::authentication_correlation_key(itsi as u32, air_handle), command_id);
                }
                SwmiMessage::Sc2RolloverPrepare { rollover_id, .. } => {
                    // MLE derives the serving-cell Absolute IV from the live
                    // TDMA clock. HashMap entity order is intentionally not a
                    // synchronization primitive. If this MM tick already
                    // announced this same rollover, retain its markers;
                    // clearing them here queued a duplicate batch on the next
                    // tick and left all nine basic links needlessly blocked.
                    // A marker for any older rollover is invalidated, while a
                    // genuinely early prepare naturally leaves `None` and is
                    // retried after MLE has installed the Absolute IV.
                    if self.last_rollover_broadcast.is_some_and(|(id, _)| id != rollover_id) {
                        self.last_rollover_broadcast = None;
                    }
                    if self.rollover_late_broadcast_mask.is_some_and(|(id, _)| id != rollover_id) {
                        self.rollover_late_broadcast_mask = None;
                    }
                    tracing::debug!(
                        rollover_id,
                        "SC2 rollover prepare synchronized with serving-cell announcement state"
                    );
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
                    let group_addressed = otar_downlink_is_group_addressed(&pdu, address_ssi, issi);
                    if address_ssi != issi && !group_addressed {
                        tracing::warn!(command_id, itsi, address_ssi, ?kind, "discarding OTAR downlink with mismatched terminal address");
                        continue;
                    }
                    if group_addressed && acknowledged {
                        tracing::warn!(command_id, issi, cmg_gssi = address_ssi, "discarding CMG-addressed GCK OTAR with acknowledged basic-link service");
                        continue;
                    }
                    if !group_addressed && !acknowledged {
                        tracing::warn!(command_id, issi, ?kind, "discarding unacknowledged individually addressed OTAR");
                        continue;
                    }
                    let aie_request = match if group_addressed {
                        self.cmg_otar_downlink_aie_request(address_ssi)
                    } else {
                        self.otar_downlink_aie_request(issi, kind)
                    } {
                        Ok(request) => request,
                        Err(reason) => {
                            tracing::warn!(command_id, issi, ?kind, reason, "rejecting unsafe clear D-OTAR in SC2-only mode");
                            // A connected BS can receive proactive rollover
                            // OTAR before its terminal contexts have been
                            // recovered.  Tell the SwMI this attempt was not
                            // admitted so it can retry after the terminal has
                            // registered; silently dropping it leaves the
                            // central sent-marker set until cutover.
                            self.report_rollover_otar_status(command_id, issi, air_handle, kind, "link-failed", Some(false));
                            continue;
                        }
                    };
                    if !group_addressed {
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
                    }
                    let tx_reporter = acknowledged.then(TxReporter::new);
                    if let Some(tx_reporter) = tx_reporter.as_ref() {
                    self.pending_otar_deliveries.insert(
                        command_id,
                        PendingOtarDelivery {
                            command_id,
                            issi,
                            air_handle,
                            kind,
                            expected_response: kind.expected_response(),
                            gck_keys: match &pdu {
                                DOtar::GckProvide(provide) => {
                                    let mut keys = provide.keys.iter()
                                        .map(|key| (key.gck_number, key.version_number))
                                        .collect::<Vec<_>>();
                                    keys.sort_unstable();
                                    Some(keys)
                                }
                                _ => None,
                            },
                            tx_reporter: tx_reporter.clone(),
                            status: OtarDeliveryStatus::Queued,
                            result_deadline: self.current_time.add_timeslots(ROLLOVER_OTAR_RESULT_TIMEOUT_TIMESLOTS),
                        },
                    );
                    self.report_rollover_otar_status(command_id, issi, air_handle, kind, "announced", None);
                    }
                    sdu.seek(0);
                    queue.push_back(SapMsg {
                        sap: Sap::LmmSap,
                        src: TetraEntity::Mm,
                        dest: TetraEntity::Mle,
                        msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                            sdu,
                            handle: air_handle,
                            address: if group_addressed { TetraAddress::new(address_ssi, SsiType::Gssi) } else { TetraAddress::issi(address_ssi) },
                            layer2service: if acknowledged { Layer2Service::Acknowledged } else { Layer2Service::Unacknowledged },
                            stealing_permission: false,
                            stealing_repeats_flag: false,
                            encryption_flag: false,
                            aie_request,
                            is_null_pdu: false,
                            assigned_channel_frame18_broadcast: false,
                            frame18_rollover_activation: None,
                            tx_reporter,
                            seamless_handover: None,
                        }),
                    });
                    tracing::debug!(
                        command_id,
                        issi,
                        address_ssi,
                        acknowledged,
                        group_addressed,
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
                    security_class,
                } => self.apply_swmi_subscriber_state_sync(queue, itsi, groups, scanning_enabled, energy_economy, security_class),
                SwmiMessage::LstRecoveryRequest { command_id } => {
                    if !self.pending_lst_recoveries.insert(command_id) {
                        tracing::warn!(command_id, "duplicate LST recovery request ignored");
                        continue;
                    }
                    let rua_state = self.config.state_read().subscribers.clone();
                    let mut subscribers = self.client_mgr.lst_recovery_snapshot(|issi| rua_state.rua_assignment_state(issi));
                    let state = self.config.state_read();
                    for subscriber in &mut subscribers {
                        subscriber.security_class = state.aie_sessions.terminal_class(subscriber.itsi as u32);
                    }
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
                        let recovered_rua_state = subscriber.rua_assigned;
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
                            subscriber.security_class,
                        );
                        if let (Ok(issi), Some(assigned)) =
                            (u32::try_from(subscriber.itsi), recovered_rua_state)
                        {
                            // The SwMI returns its durable assignment in an
                            // LST recovery result when a BS restart erased the
                            // local observation.  This is an internal cache
                            // repair: no over-air RUA Book On is sent and the
                            // terminal is not prompted to log on again.
                            self.config
                                .state_write()
                                .subscribers
                                .set_rua_assignment_state(issi, Some(assigned));
                        }
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
                // In this direction command_id identifies the exact local
                // registration superseded by a roam. A delayed A->B cleanup
                // must not remove a newer A->B->A registration.
                SwmiMessage::DeregistrationNotice { command_id, itsi } => {
                    let Ok(issi) = u32::try_from(itsi) else {
                        tracing::warn!(itsi, "discarding old-serving-cell cleanup with invalid ISSI");
                        continue;
                    };
                    self.apply_old_serving_cleanup(queue, issi, command_id);
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
                        self.send_liveliness_probe(queue, itsi);
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
    use super::{
        GskoBootstrapStatus, MmBs, OtarDeliveryStatus, OtarDownlinkKind, OtarTerminalResponse, PendingAttachment, PendingOtarDelivery, PendingTerminalControl, TERMINAL_CONTROL_TIMEOUT_TIMESLOTS,
        otar_downlink_is_group_addressed,
        sc2_ksg_number, supports_security_information_protocol,
    };
    use crate::MessageQueue;
    use std::collections::HashSet;
    use tetra_config::bluestation::{
        RuntimeAieConfig, RuntimeSc2TeaAlgorithm, RuntimeSc3Aie, RuntimeSc3Dck, RuntimeSc3Gck, RuntimeSc3TeaAlgorithm, SharedConfig,
        SubscriberDeliveryRoute,
    };
    use tetra_core::{
        AieRequest, AieScope, AieSubject, Layer2Service, Sap, SsiType, TdmaTime, TxReporter, tetra_entities::TetraEntity,
        typed_pdu_fields::Type3FieldGeneric,
    };
    use tetra_pdus::mm::enums::location_update_type::LocationUpdateType;
    use tetra_pdus::mm::fields::group_identity_security_related_information::GckSelectNumber;
    use tetra_pdus::mm::fields::group_identity_uplink::GroupIdentityUplink;
    use tetra_pdus::mm::pdus::ck_change::{CkChangeTime, DAllGcksChangeDemand};
    use tetra_pdus::mm::pdus::d_attach_detach_group_identity::DAttachDetachGroupIdentity;
    use tetra_pdus::mm::pdus::d_attach_detach_group_identity_acknowledgement::DAttachDetachGroupIdentityAcknowledgement;
    use tetra_pdus::mm::pdus::d_location_update_accept::DLocationUpdateAccept;
    use tetra_pdus::mm::pdus::d_location_update_command::DLocationUpdateCommand;
    use tetra_pdus::mm::pdus::u_attach_detach_group_identity_acknowledgement::UAttachDetachGroupIdentityAcknowledgement;
    use tetra_saps::SapMsgInner;
    use tetra_swmi_protocol::{
        AieLocationUpdateDecision, AttachmentOperation, AttachmentResult, EnergyEconomyAssignment, TerminalControlAction,
        TerminalInformation, TerminalSecurityClass,
    };

    fn test_config() -> SharedConfig {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        SharedConfig::from_parts(config, None)
    }

    fn test_sc3g_mm(issi: u32, groups: &[u32]) -> MmBs {
        let config = test_config();
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x6c; 10], true, true);
        sc3.apply_sc3g_snapshot(
            1,
            true,
            1,
            vec![RuntimeSc3Gck::new(1, 1, [0x31; 10])],
            groups.iter().map(|gssi| (*gssi, 1)).collect(),
        )
        .expect("valid linked SC3G snapshot");
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(sc3),
            rollover: None,
        };
        let mut mm = MmBs::new(config, None, None, None);
        mm.client_mgr.try_register_client(issi, true).expect("test terminal must register");
        for gssi in groups {
            mm.client_mgr
                .client_group_attach_with_class_of_usage(issi, *gssi, true, 3)
                .expect("test group must attach");
        }
        mm
    }

    #[test]
    fn rollover_uses_provisioned_cmg_on_mcch_and_assigned_channels() {
        let mut mm = test_sc3g_mm(77_468, &[1502]);
        mm.gsko_bootstraps.insert(77_468, GskoBootstrapStatus::Provisioned {
            version_number: 2,
            cmg_gssi: 42_001,
        });
        let activation = TdmaTime { t: 1, f: 1, m: 2, h: 0 };
        let mut queue = MessageQueue::new();
        assert!(mm.send_gck_rollover_broadcast_round(&mut queue, 18, activation));
        for assigned in [false, true] {
            let SapMsgInner::LmmMleUnitdataReq(mut request) = queue.pop_front().expect("CMG notice").msg else {
                panic!("MM unitdata required")
            };
            assert_eq!(request.address.ssi, 42_001);
            assert_eq!(request.address.ssi_type, SsiType::Gssi);
            assert_eq!(request.layer2service, Layer2Service::Unacknowledged);
            assert_eq!(request.aie_request, AieRequest::sc3(AieSubject::Group { gssi: 42_001 }, AieScope::MacResource));
            assert_eq!(request.assigned_channel_frame18_broadcast, assigned);
            assert!(!request.stealing_permission);
            let demand = DAllGcksChangeDemand::from_bitbuf(&mut request.sdu).expect("valid GCK change");
            assert_eq!(demand.gck_version_number, 18);
            assert!(matches!(demand.time, CkChangeTime::AbsoluteIv { .. }));
        }
        assert!(queue.pop_front().is_none());

        assert!(mm.send_gck_rollover_immediate(&mut queue, 18, activation));
        let SapMsgInner::LmmMleUnitdataReq(mut request) = queue.pop_front().expect("CMG Immediate").msg else {
            panic!("MM unitdata required")
        };
        assert_eq!(request.address.ssi, 42_001);
        assert_eq!(request.frame18_rollover_activation, Some(activation));
        assert!(matches!(DAllGcksChangeDemand::from_bitbuf(&mut request.sdu).unwrap().time, CkChangeTime::Immediate));
    }

    #[test]
    fn configured_cmg_is_available_before_any_new_gsko_result() {
        let mut parsed = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"), "/../../example_config/config.toml"
        ))).unwrap();
        parsed.swmi.as_mut().expect("SwMI example").cmg_gssis = vec![16_000_001];
        let mm = MmBs::new(SharedConfig::from_parts(parsed, None), None, None, None);
        assert_eq!(mm.rollover_cmg_gssis(), vec![16_000_001]);
    }

    #[test]
    fn assigned_gck_rollover_notices_are_individual_acknowledged_and_bounded() {
        let mut mm = test_sc3g_mm(77_468, &[1502]);
        {
            let mut state = mm.config.state_write();
            for issi in [77_468, 77_479, 77_480, 77_491] {
                state.subscribers.register(issi);
                state.subscriber_delivery_routes.insert(issi, vec![SubscriberDeliveryRoute {
                    call_id: 12,
                    timeslot: 2,
                    usage: 4,
                }]);
            }
            // A listener can have a valid traffic route without a completed
            // registration transaction since this BS restarted.
        }
        let now = TdmaTime { t: 1, f: 1, m: 1, h: 0 };
        let activation = now.add_timeslots(5 * 60 * 18 * 4);
        let mut first = MessageQueue::new();
        mm.send_assigned_gck_rollover_notices(&mut first, 7, 15, activation, now);
        for _ in 0..2 {
            let message = first.pop_front().expect("two listeners in the first round");
            let SapMsgInner::LmmMleUnitdataReq(mut request) = message.msg else {
                panic!("individual MM notice required")
            };
            assert_eq!(request.layer2service, Layer2Service::Acknowledged);
            assert!(!request.stealing_permission);
            assert!([77_468, 77_479, 77_480, 77_491].contains(&request.address.ssi));
            let demand = DAllGcksChangeDemand::from_bitbuf(&mut request.sdu).expect("valid CK change");
            assert!(!demand.acknowledgement_required, "TTR 001-11 forbids L3 ACK here");
            assert_eq!(demand.gck_version_number, 15);
            assert!(matches!(demand.time, CkChangeTime::AbsoluteIv { .. }));
        }
        assert!(first.pop_front().is_none(), "one round must leave FN18 capacity for other signalling");
        let mut second = MessageQueue::new();
        mm.send_assigned_gck_rollover_notices(&mut second, 7, 15, activation, now.add_timeslots(5 * 18 * 4));
        for expected in [77_480, 77_491] {
            let SapMsgInner::LmmMleUnitdataReq(request) = second.pop_front().expect("remaining listener").msg else {
                panic!("individual MM notice required")
            };
            assert_eq!(request.address.ssi, expected);
        }
        assert!(second.pop_front().is_none());
        let mut third = MessageQueue::new();
        mm.send_assigned_gck_rollover_notices(&mut third, 7, 15, activation, now.add_timeslots(10 * 18 * 4));
        assert!(third.pop_front().is_none(), "a previous round must not immediately repeat the same notice");
    }

    #[test]
    fn sc2_ksg_numbers_match_the_on_air_table() {
        assert_eq!(sc2_ksg_number(RuntimeSc2TeaAlgorithm::Tea1), 0b0000);
        assert_eq!(sc2_ksg_number(RuntimeSc2TeaAlgorithm::Tea3), 0b0010);
    }

    #[test]
    fn security_information_support_requires_sc3_and_table_a46_support_bit() {
        assert!(supports_security_information_protocol(0b10_0010));
        assert!(!supports_security_information_protocol(0b10_0000));
        assert!(!supports_security_information_protocol(0b00_0010));
        assert!(!supports_security_information_protocol(60));
    }

    #[test]
    fn information_request_without_security_protocol_sets_successful_tei_query() {
        let issi = 77_468;
        let mut mm = MmBs::new(test_config(), None, None, None);
        mm.pending_terminal_controls.insert(
            issi,
            PendingTerminalControl {
                command_id: 1,
                action: TerminalControlAction::RequestInformation,
                operations: Vec::new(),
                tx_reporter: None,
                response_deadline: Some(mm.current_time.add_timeslots(TERMINAL_CONTROL_TIMEOUT_TIMESLOTS)),
                information: TerminalInformation::default(),
            },
        );
        let mut queue = MessageQueue::new();

        mm.send_d_location_update_accept(&mut queue, issi, 0, LocationUpdateType::DemandLocationUpdating, None, false, None);

        let message = queue.pop_front().expect("location-update accept must be queued");
        let SapMsgInner::LmmMleUnitdataReq(mut request) = message.msg else {
            panic!("expected an LMM downlink request")
        };
        let accept = DLocationUpdateAccept::from_bitbuf(&mut request.sdu).expect("valid location-update accept");
        assert_eq!(accept.authentication_downlink.expect("TEI query").data, 0b110);
        assert!(accept.security_downlink.is_none());
    }

    #[test]
    fn delayed_old_cell_cleanup_cannot_remove_new_registration() {
        let issi = 77_468;
        let config = test_config();
        config.state_write().subscribers.register(issi);
        let mut mm = MmBs::new(config, None, None, None);
        mm.client_mgr.try_register_client(issi, true).expect("test terminal must register");
        mm.registration_generations.insert(issi, 12);
        let mut queue = MessageQueue::new();

        mm.apply_old_serving_cleanup(&mut queue, issi, 11);
        assert!(mm.client_mgr.client_is_known(issi));
        assert_eq!(mm.registration_generations.get(&issi), Some(&12));

        mm.apply_old_serving_cleanup(&mut queue, issi, 12);
        assert!(!mm.client_mgr.client_is_known(issi));
        assert!(!mm.registration_generations.contains_key(&issi));

        // LST recovery can restore the subscriber state without the ephemeral
        // per-registration command id. A later authoritative cleanup must
        // still remove that old-serving-cell state.
        mm.config.state_write().subscribers.register(issi);
        mm.client_mgr.try_register_client(issi, true).expect("test terminal must register");
        mm.apply_old_serving_cleanup(&mut queue, issi, 11);
        assert!(!mm.client_mgr.client_is_known(issi));
        assert!(!mm.config.state_read().subscribers.is_registered(issi));
    }

    #[test]
    fn group_control_response_timer_waits_for_basic_link_ack() {
        let mut mm = test_sc3g_mm(77_468, &[91]);
        let mut queue = MessageQueue::new();
        mm.start_terminal_group_control(
            &mut queue,
            1,
            77_468,
            TerminalControlAction::AmendTalkgroups,
            vec![AttachmentOperation {
                gssi: 91,
                detach: true,
                class_of_usage: 0,
            }],
        );
        let reporter = mm.pending_terminal_controls[&77_468]
            .tx_reporter
            .as_ref()
            .expect("group command must track LLC delivery")
            .clone();

        mm.current_time = mm.current_time.add_timeslots(TERMINAL_CONTROL_TIMEOUT_TIMESLOTS + 1);
        mm.update_terminal_control_statuses();
        assert!(mm.pending_terminal_controls.contains_key(&77_468));

        reporter.mark_transmitted();
        reporter.mark_acknowledged();
        mm.update_terminal_control_statuses();
        assert!(mm.pending_terminal_controls[&77_468].response_deadline.is_some());
    }

    #[test]
    fn terminal_talkgroup_replacement_uses_amendment_and_supports_empty_list() {
        let config = test_config();
        let mut mm = MmBs::new(config, None, None, None);
        let issi = 77_493;
        mm.client_mgr.try_register_client(issi, true).expect("test terminal must register");
        mm.client_mgr
            .client_group_attach_with_class_of_usage(issi, 91, true, 3)
            .expect("existing group must attach");
        let mut queue = MessageQueue::new();

        mm.start_terminal_group_control(&mut queue, 1, issi, TerminalControlAction::ReplaceTalkgroups, Vec::new());

        let message = queue.pop_front().expect("replacement must queue an amendment");
        let SapMsgInner::LmmMleUnitdataReq(mut request) = message.msg else {
            panic!("expected an LMM downlink request")
        };
        let pdu = DAttachDetachGroupIdentity::from_bitbuf(&mut request.sdu).expect("queued amendment must parse");
        assert!(!pdu.group_identity_attach_detach_mode);
        let groups = pdu.group_identity_downlink.expect("detachment must be present");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].gssi, Some(91));
        assert!(groups[0].group_identity_detachment_uplink.is_some());
    }

    #[test]
    fn terminal_talkgroup_ack_applies_partial_acceptance_and_ms_cou_change() {
        let config = test_config();
        let mut mm = MmBs::new(config, None, None, None);
        let issi = 77_494;
        mm.client_mgr.try_register_client(issi, true).expect("test terminal must register");
        let mut queue = MessageQueue::new();
        mm.start_terminal_group_control(
            &mut queue,
            2,
            issi,
            TerminalControlAction::AmendTalkgroups,
            vec![
                AttachmentOperation {
                    gssi: 91,
                    detach: false,
                    class_of_usage: 3,
                },
                AttachmentOperation {
                    gssi: 92,
                    detach: false,
                    class_of_usage: 2,
                },
            ],
        );
        while queue.pop_front().is_some() {}

        mm.complete_terminal_group_control(
            &mut queue,
            issi,
            UAttachDetachGroupIdentityAcknowledgement {
                group_identity_acknowledgement_type: true,
                group_identity_uplink: Some(vec![
                    GroupIdentityUplink {
                        class_of_usage: None,
                        group_identity_detachment_uplink: Some(2),
                        gssi: Some(91),
                        address_extension: None,
                        vgssi: None,
                    },
                    GroupIdentityUplink {
                        class_of_usage: Some(5),
                        group_identity_detachment_uplink: None,
                        gssi: Some(92),
                        address_extension: None,
                        vgssi: None,
                    },
                ]),
                proprietary: None,
            },
        );

        assert_eq!(mm.client_mgr.client_group_class_of_usage(issi, 91), None);
        assert_eq!(mm.client_mgr.client_group_class_of_usage(issi, 92), Some(5));
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
    fn egsko_sealed_gck_uses_the_individual_path_when_radio_addressed_to_an_issi() {
        use tetra_pdus::mm::pdus::otar::{DGckProvide, GroupAssociation, OtarSessionKey, OtarTail, DOtar};

        let pdu = DOtar::GckProvide(DGckProvide {
            acknowledgement_required: true,
            explicit_response: true,
            max_response_timer: 0,
            session_key: OtarSessionKey::Group {
                gsko_version_number: 2,
            },
            keys: Vec::new(),
            ksg_number: 0,
            association: GroupAssociation::GckNumber,
            retry_interval: 1,
            tail: OtarTail::default(),
        });
        assert!(!otar_downlink_is_group_addressed(&pdu, 77_492, 77_492));
        assert!(otar_downlink_is_group_addressed(&pdu, 16_000_001, 77_492));
    }

    #[test]
    fn only_gsko_bootstrap_downlinks_are_clear_otar_exceptions() {
        assert!(OtarDownlinkKind::GskoProvide.is_clear_gsko_bootstrap());
        assert!(OtarDownlinkKind::GskoReject.is_clear_gsko_bootstrap());
        assert!(!OtarDownlinkKind::SckProvide.is_clear_gsko_bootstrap());
        assert!(!OtarDownlinkKind::KeyStatusDemand.is_clear_gsko_bootstrap());
    }

    #[test]
    fn attachment_security_information_omits_cck_only_groups() {
        let config = test_config();
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x6c; 10], true, true);
        sc3.apply_sc3g_snapshot(1, true, 7, vec![RuntimeSc3Gck::new(1, 7, [0x31; 10])], vec![(91, 1)])
            .expect("valid linked SC3G snapshot");
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(sc3),
            rollover: None,
        };
        let mm = MmBs::new(config, None, None, None);

        let information = mm
            .group_security_information([91, 92])
            .expect("GCK group must produce security information");
        assert_eq!(information.len(), 1);
        assert_eq!(information[0].associations.len(), 1);
        assert_eq!(information[0].associations[0].gssi, 91);
        assert_eq!(information[0].associations[0].selection, GckSelectNumber::Selected(1));
        assert!(mm.group_security_information([92]).is_none());
    }

    #[test]
    fn accepted_attachment_and_detachment_are_implicitly_acknowledged() {
        let config = test_config();
        let mut mm = MmBs::new(config, None, None, None);
        let issi = 77_479;
        mm.client_mgr.try_register_client(issi, true).expect("test terminal must register");
        mm.client_mgr
            .client_group_attach_with_class_of_usage(issi, 92, true, 3)
            .expect("existing group must attach");
        let pending = PendingAttachment {
            itsi: issi,
            air_handle: 0,
            replace_all: false,
            operations: vec![
                GroupIdentityUplink {
                    class_of_usage: Some(4),
                    group_identity_detachment_uplink: None,
                    gssi: Some(91),
                    address_extension: None,
                    vgssi: None,
                },
                GroupIdentityUplink {
                    class_of_usage: None,
                    group_identity_detachment_uplink: Some(2),
                    gssi: Some(92),
                    address_extension: None,
                    vgssi: None,
                },
            ],
        };
        let results = MmBs::local_attachment_results(&pending);
        let mut queue = MessageQueue::new();

        let (had_rejection, response_groups, security_groups) =
            mm.apply_swmi_attachment_state(&mut queue, 1, u64::from(issi), false, &pending, results);

        assert!(!had_rejection);
        assert!(response_groups.is_empty());
        assert_eq!(security_groups, vec![91]);

        let repeated_results = MmBs::local_attachment_results(&pending);
        let (had_rejection, response_groups, security_groups) =
            mm.apply_swmi_attachment_state(&mut queue, 2, u64::from(issi), false, &pending, repeated_results);
        assert!(!had_rejection);
        assert!(response_groups.is_empty());
        assert_eq!(
            security_groups,
            vec![91],
            "an identical attachment retry must replay the association in a bounded response"
        );
    }

    #[test]
    fn single_talkgroup_switch_carries_gck_association_in_attachment_ack() {
        let config = test_config();
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x6c; 10], true, true);
        sc3.apply_sc3g_snapshot(1, true, 1, vec![RuntimeSc3Gck::new(2, 1, [0x32; 10])], vec![(1201, 2)])
            .expect("valid linked SC3G snapshot");
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(sc3),
            rollover: None,
        };
        let mut mm = MmBs::new(config, None, None, None);
        let mut queue = MessageQueue::new();

        mm.send_d_attachment_acknowledgement(&mut queue, 430_893, 0, false, Vec::new(), &[1201]);

        let message = queue.pop_front().expect("attachment ACK must be queued");
        let SapMsgInner::LmmMleUnitdataReq(mut request) = message.msg else {
            panic!("expected an LMM downlink request")
        };
        let pdu = DAttachDetachGroupIdentityAcknowledgement::from_bitbuf(&mut request.sdu).expect("valid attachment ACK");
        let security = pdu
            .group_identity_security_related_information
            .expect("figure-19 GCK association must be in the ACK");
        assert_eq!(security[0].associations.len(), 1);
        assert_eq!(security[0].associations[0].gssi, 1201);
        assert_eq!(security[0].associations[0].selection, GckSelectNumber::Selected(2));
        assert!(queue.pop_front().is_none(), "single switch needs no follow-up amendment");
    }

    #[test]
    fn accepted_gck_refreshes_matching_attached_group_associations() {
        let config = test_config();
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x6c; 10], true, true);
        sc3.apply_sc3g_snapshot(1, true, 1, vec![RuntimeSc3Gck::new(2, 1, [0x32; 10])], vec![(1202, 2)])
            .expect("valid linked SC3G snapshot");
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(sc3),
            rollover: None,
        };
        let issi = 77_492;
        let mut mm = MmBs::new(config, None, None, None);
        mm.client_mgr.try_register_client(issi, true).expect("test terminal must register");
        mm.client_mgr
            .client_group_attach_with_class_of_usage(issi, 1202, true, 4)
            .expect("test group must attach");
        let mut queue = MessageQueue::new();

        mm.send_group_security_association_refresh(&mut queue, issi, 0, &HashSet::from([2]));

        let message = queue.pop_front().expect("association refresh must be queued");
        let SapMsgInner::LmmMleUnitdataReq(mut request) = message.msg else {
            panic!("expected an LMM downlink request")
        };
        let pdu = DAttachDetachGroupIdentity::from_bitbuf(&mut request.sdu).expect("valid association refresh PDU");
        assert!(pdu.group_identity_acknowledgement_request);
        let groups = pdu.group_identity_downlink.expect("attachment amendment must be present");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].gssi, Some(1202));
        assert_eq!(
            groups[0]
                .group_identity_attachment
                .as_ref()
                .expect("group must be attached")
                .class_of_usage,
            4
        );
        let security = pdu
            .group_identity_security_related_information
            .expect("security association must be present");
        assert_eq!(security[0].associations[0].gssi, 1202);
        assert_eq!(security[0].associations[0].selection, GckSelectNumber::Selected(2));
    }

    #[test]
    fn gck_result_announces_current_version_before_group_attachment() {
        use tetra_pdus::mm::pdus::otar::{GckProvisionResult, OtarTail, UGckResult};
        let issi = 77_479;
        let mut mm = test_sc3g_mm(issi, &[1502]);
        let mut queue = MessageQueue::new();
        // A failure for a future key must not prevent recovery of the
        // successfully accepted current key, or reverse the signalling order.
        let result = UGckResult {
            results: vec![
                GckProvisionResult { gck_number: 1, version_number: 1, provision_result: 0, current_version_number: None },
                GckProvisionResult { gck_number: 1, version_number: 2, provision_result: 1, current_version_number: None },
            ],
            tail: OtarTail::default(),
        };
        mm.refresh_group_security_after_gck_result(&mut queue, issi, 0, &result);
        let SapMsgInner::LmmMleUnitdataReq(mut version) = queue.pop_front().unwrap().msg else { panic!() };
        let pdu = DAllGcksChangeDemand::from_bitbuf(&mut version.sdu).unwrap();
        assert_eq!(pdu.gck_version_number, 1);
        assert!(matches!(pdu.time, CkChangeTime::CurrentlyInUse));
        let SapMsgInner::LmmMleUnitdataReq(mut attachment) = queue.pop_front().unwrap().msg else { panic!() };
        let pdu = DAttachDetachGroupIdentity::from_bitbuf(&mut attachment.sdu).unwrap();
        assert!(pdu.group_identity_acknowledgement_request);
        assert_eq!(pdu.group_identity_security_related_information.unwrap()[0].associations[0].gssi, 1502);
        assert!(queue.pop_front().is_none());
    }

    #[test]
    fn future_or_stale_gck_result_does_not_reactivate_group_attachment() {
        use tetra_pdus::mm::pdus::otar::{GckProvisionResult, OtarTail, UGckResult};
        let issi = 77_479;
        let mut mm = test_sc3g_mm(issi, &[1502]);
        let mut queue = MessageQueue::new();
        for (vn, code) in [(0, 0), (2, 0), (1, 1)] {
            mm.refresh_group_security_after_gck_result(&mut queue, issi, 0, &UGckResult {
                results: vec![GckProvisionResult { gck_number: 1, version_number: vn, provision_result: code, current_version_number: None }],
                tail: OtarTail::default(),
            });
            assert!(queue.pop_front().is_none());
            assert!(!mm.pending_group_security_associations.contains_key(&issi));
        }
    }

    #[test]
    fn twenty_scanned_group_security_amendments_use_one_transactional_pdu() {
        let config = test_config();
        let expected_groups = (1200..1220).collect::<Vec<_>>();
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x6c; 10], true, true);
        sc3.apply_sc3g_snapshot(
            1,
            true,
            1,
            vec![RuntimeSc3Gck::new(2, 1, [0x32; 10])],
            expected_groups.iter().map(|gssi| (*gssi, 2)).collect(),
        )
        .expect("valid twenty-group SC3G snapshot");
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(sc3),
            rollover: None,
        };
        let issi = 77_492;
        let mut mm = MmBs::new(config, None, None, None);
        mm.client_mgr.try_register_client(issi, true).expect("test terminal must register");
        for gssi in &expected_groups {
            mm.client_mgr
                .client_group_attach_with_class_of_usage(issi, *gssi, true, 3)
                .expect("test group must attach");
        }
        let mut queue = MessageQueue::new();

        mm.send_group_security_association_amendments(&mut queue, issi, 0, expected_groups.iter().copied());

        let message = queue.pop_front().expect("one combined amendment must be queued");
        let SapMsgInner::LmmMleUnitdataReq(mut request) = message.msg else {
            panic!("expected an LMM downlink request")
        };
        let pdu = DAttachDetachGroupIdentity::from_bitbuf(&mut request.sdu).expect("valid combined association amendment");
        let groups = pdu.group_identity_downlink.expect("group amendment");
        assert_eq!(groups.iter().filter_map(|group| group.gssi).collect::<Vec<_>>(), expected_groups);
        let security = pdu.group_identity_security_related_information.expect("security associations");
        assert_eq!(
            security[0]
                .associations
                .iter()
                .map(|association| association.gssi)
                .collect::<Vec<_>>(),
            expected_groups
        );
        assert!(queue.pop_front().is_none(), "the complete association set must use one PDU");
    }

    #[test]
    fn figure20_link_ack_waits_for_distinct_terminal_mm_ack() {
        let issi = 77_492;
        let mut mm = test_sc3g_mm(issi, &[1202]);
        let mut queue = MessageQueue::new();

        mm.send_group_security_association_amendments(&mut queue, issi, 0, [1202]);
        queue.pop_front().expect("initial Figure-20 PDU");
        let reporter = mm
            .pending_group_security_associations
            .get(&issi)
            .expect("transaction must be pending")
            .tx_reporter
            .clone();
        reporter.mark_transmitted();
        reporter.mark_acknowledged();
        mm.update_group_security_association_statuses(&mut queue);

        let pending = mm
            .pending_group_security_associations
            .get(&issi)
            .expect("BL-ACK must not complete the MM transaction");
        assert_eq!(pending.phase, super::GroupSecurityAssociationPhase::AwaitingMmAcknowledgement);
        assert!(pending.acknowledgement_deadline.is_some());
        assert!(queue.pop_front().is_none());
    }

    #[test]
    fn figure20_empty_accept_ack_completes_the_full_offered_set() {
        let issi = 77_492;
        let mut mm = test_sc3g_mm(issi, &[1202, 1203]);
        let mut queue = MessageQueue::new();
        mm.send_group_security_association_amendments(&mut queue, issi, 0, [1202, 1203]);
        queue.pop_front().expect("initial Figure-20 PDU");

        mm.complete_group_security_association_ack(
            &mut queue,
            issi,
            UAttachDetachGroupIdentityAcknowledgement {
                group_identity_acknowledgement_type: false,
                group_identity_uplink: None,
                proprietary: None,
            },
        );

        assert!(!mm.pending_group_security_associations.contains_key(&issi));
        assert!(queue.pop_front().is_none());
    }

    #[test]
    fn figure20_timeout_retries_the_same_transaction_boundedly() {
        let issi = 77_492;
        let mut mm = test_sc3g_mm(issi, &[1202]);
        let mut queue = MessageQueue::new();
        mm.send_group_security_association_amendments(&mut queue, issi, 0, [1202]);
        queue.pop_front().expect("initial Figure-20 PDU");
        let reporter = mm.pending_group_security_associations[&issi].tx_reporter.clone();
        reporter.mark_transmitted();
        reporter.mark_acknowledged();
        mm.update_group_security_association_statuses(&mut queue);

        mm.current_time = mm.current_time.add_timeslots(super::GROUP_SECURITY_ACK_TIMEOUT_TIMESLOTS);
        mm.update_group_security_association_statuses(&mut queue);

        let retry = queue.pop_front().expect("MM timeout must queue one retry");
        let SapMsgInner::LmmMleUnitdataReq(mut request) = retry.msg else {
            panic!("retry must be an LMM downlink")
        };
        let pdu = DAttachDetachGroupIdentity::from_bitbuf(&mut request.sdu).expect("valid retried Figure-20 PDU");
        assert_eq!(
            pdu.group_identity_downlink
                .expect("retried group")
                .iter()
                .filter_map(|group| group.gssi)
                .collect::<Vec<_>>(),
            vec![1202]
        );
        assert_eq!(mm.pending_group_security_associations[&issi].retries, 1);
        assert!(queue.pop_front().is_none());
    }

    #[test]
    fn figure20_reject_ack_retries_only_explicitly_rejected_groups() {
        let issi = 77_492;
        let mut mm = test_sc3g_mm(issi, &[1202, 1203]);
        let mut queue = MessageQueue::new();
        mm.send_group_security_association_amendments(&mut queue, issi, 0, [1202, 1203]);
        queue.pop_front().expect("initial Figure-20 PDU");

        mm.complete_group_security_association_ack(
            &mut queue,
            issi,
            UAttachDetachGroupIdentityAcknowledgement {
                group_identity_acknowledgement_type: true,
                group_identity_uplink: Some(vec![GroupIdentityUplink {
                    class_of_usage: None,
                    group_identity_detachment_uplink: Some(0),
                    gssi: Some(1203),
                    address_extension: None,
                    vgssi: None,
                }]),
                proprietary: None,
            },
        );

        let retry = queue.pop_front().expect("rejected association must be retried");
        let SapMsgInner::LmmMleUnitdataReq(mut request) = retry.msg else {
            panic!("retry must be an LMM downlink")
        };
        let pdu = DAttachDetachGroupIdentity::from_bitbuf(&mut request.sdu).expect("valid rejected-group retry");
        assert_eq!(
            pdu.group_identity_downlink
                .expect("retried group")
                .iter()
                .filter_map(|group| group.gssi)
                .collect::<Vec<_>>(),
            vec![1203]
        );
    }

    #[test]
    fn figure20_coalesces_new_groups_without_overlapping_transactions() {
        let issi = 77_492;
        let mut mm = test_sc3g_mm(issi, &[1202, 1203]);
        let mut queue = MessageQueue::new();
        mm.send_group_security_association_amendments(&mut queue, issi, 0, [1202]);
        mm.send_group_security_association_amendments(&mut queue, issi, 0, [1203]);
        assert_eq!(queue.iter_mut().count(), 1, "only the first transaction may be on air");
        queue.pop_front().expect("first Figure-20 PDU");

        mm.complete_group_security_association_ack(
            &mut queue,
            issi,
            UAttachDetachGroupIdentityAcknowledgement {
                group_identity_acknowledgement_type: false,
                group_identity_uplink: None,
                proprietary: None,
            },
        );

        assert_eq!(queue.iter_mut().count(), 1, "the coalesced successor starts only after the MM ACK");
        assert_eq!(mm.pending_group_security_associations[&issi].groups, vec![1203]);
    }

    #[test]
    fn figure20_exhausts_after_two_application_retries() {
        let issi = 77_492;
        let mut mm = test_sc3g_mm(issi, &[1202]);
        let mut queue = MessageQueue::new();
        mm.send_group_security_association_amendments(&mut queue, issi, 0, [1202]);

        for retry in 0..=super::MAX_GROUP_SECURITY_RETRIES {
            queue.pop_front().expect("current Figure-20 attempt");
            let reporter = mm.pending_group_security_associations[&issi].tx_reporter.clone();
            reporter.mark_transmitted();
            reporter.mark_acknowledged();
            mm.update_group_security_association_statuses(&mut queue);
            mm.current_time = mm.current_time.add_timeslots(super::GROUP_SECURITY_ACK_TIMEOUT_TIMESLOTS);
            mm.update_group_security_association_statuses(&mut queue);

            if retry < super::MAX_GROUP_SECURITY_RETRIES {
                assert_eq!(mm.pending_group_security_associations[&issi].retries, retry + 1);
                assert_eq!(queue.iter_mut().count(), 1, "exactly one bounded retry must be queued");
            }
        }

        assert!(!mm.pending_group_security_associations.contains_key(&issi));
        assert!(!mm.queued_group_security_associations.contains_key(&issi));
        assert!(queue.pop_front().is_none(), "retry exhaustion must not loop forever");
    }

    #[test]
    fn registration_accept_only_embeds_requested_sc3g_associations() {
        let issi = 77_492;
        let expected_groups = vec![1202];
        let mm = test_sc3g_mm(issi, &[1202, 1203, 1204]);
        let security_groups = mm.registration_group_security_gssis(issi, [1202]);
        let mut queue = MessageQueue::new();

        mm.send_d_location_update_accept_with_handover(
            &mut queue,
            issi,
            0,
            LocationUpdateType::ItsiAttach,
            None,
            true,
            &AieLocationUpdateDecision::default(),
            AieRequest::clear(AieSubject::System, AieScope::MacResource),
            None,
            security_groups,
            None,
            false,
        );

        let message = queue.pop_front().expect("registration accept");
        let SapMsgInner::LmmMleUnitdataReq(mut request) = message.msg else {
            panic!("registration accept must be an LMM downlink")
        };
        let pdu = DLocationUpdateAccept::from_bitbuf(&mut request.sdu).expect("valid D-LOCATION UPDATE ACCEPT");
        let associations = pdu
            .group_identity_security_related_information
            .expect("registration must embed the requested association")[0]
            .associations
            .iter()
            .map(|association| association.gssi)
            .collect::<Vec<_>>();
        assert_eq!(associations, expected_groups);
        assert!(
            queue.pop_front().is_none(),
            "the associations belong to the single registration PDU"
        );
    }

    #[test]
    fn registration_accept_requests_the_configured_rui_type() {
        use tetra_config::bluestation::CfgRuiType;

        for (rui_type, expected) in [
            (CfgRuiType::Run, 0b001_u64),
            (CfgRuiType::Ssi, 0b010),
            (CfgRuiType::MsIsdn, 0b011),
            (CfgRuiType::AlphaTag, 0b100),
        ] {
            let mut config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../example_config/config.toml"
            )))
            .expect("example configuration must remain valid");
            config.rua.requested_rui_type = rui_type;
            let mm = MmBs::new(SharedConfig::from_parts(config, None), None, None, None);
            let mut queue = MessageQueue::new();

            mm.send_d_location_update_accept_with_handover(
                &mut queue,
                77_468,
                0,
                LocationUpdateType::ItsiAttach,
                None,
                true,
                &AieLocationUpdateDecision::default(),
                AieRequest::clear(AieSubject::System, AieScope::MacResource),
                None,
                Vec::new(),
                None,
                true,
            );

            let SapMsgInner::LmmMleUnitdataReq(mut request) = queue.pop_front().expect("registration accept").msg else {
                panic!("registration accept must be an LMM downlink")
            };
            let accept = DLocationUpdateAccept::from_bitbuf(&mut request.sdu).expect("valid D-LOCATION UPDATE ACCEPT");
            let proprietary = accept.proprietary.expect("RUA request must be present");
            assert_eq!(proprietary.data & 0b111, expected);
        }
    }

    #[test]
    fn roaming_scan_groups_are_retained_without_unsolicited_association_amendments() {
        let issi = 77_492;
        let groups = [1202, 1203, 1204, 1205, 1206, 1207];
        let mut mm = test_sc3g_mm(issi, &groups);
        let reporter = TxReporter::new();
        let mut queue = MessageQueue::new();
        mm.track_registration_delivery(Some(41), issi, false, vec![1202], reporter.clone());
        reporter.mark_transmitted();
        mm.update_registration_delivery_statuses(&mut queue);
        assert!(!mm.queued_group_security_associations.contains_key(&issi));
        reporter.mark_acknowledged();
        mm.update_registration_delivery_statuses(&mut queue);
        assert!(!mm.queued_group_security_associations.contains_key(&issi));
        assert_eq!(mm.client_mgr.get_client_by_issi(issi).unwrap().groups.len(), 6);
        assert!(!mm.pending_group_security_associations.contains_key(&issi));
        mm.current_time = mm.current_time.add_timeslots(super::GROUP_SECURITY_REGISTRATION_GUARD_TIMESLOTS);
        mm.update_group_security_association_statuses(&mut queue);
        assert!(!mm.pending_group_security_associations.contains_key(&issi));
    }

    #[test]
    fn registration_moves_colliding_figure20_associations_into_accept() {
        let issi = 77_492;
        let mut mm = test_sc3g_mm(issi, &[1202, 1203]);
        let mut queue = MessageQueue::new();
        mm.send_group_security_association_amendments(&mut queue, issi, 0, [1202]);
        mm.send_group_security_association_amendments(&mut queue, issi, 0, [1203]);
        assert!(mm.pending_group_security_associations.contains_key(&issi));
        assert!(mm.queued_group_security_associations.contains_key(&issi));

        let interrupted = mm.cancel_group_security_association_for_registration(issi);

        assert!(!mm.pending_group_security_associations.contains_key(&issi));
        assert!(!mm.queued_group_security_associations.contains_key(&issi));
        assert!(!mm.group_security_not_before.contains_key(&issi));
        assert_eq!(interrupted, vec![1202, 1203]);

        let mut queue = MessageQueue::new();
        mm.send_d_location_update_accept_with_handover(
            &mut queue,
            issi,
            0,
            LocationUpdateType::ItsiAttach,
            None,
            false,
            &AieLocationUpdateDecision::default(),
            AieRequest::clear(AieSubject::System, AieScope::MacResource),
            None,
            interrupted,
            None,
            false,
        );
        let SapMsgInner::LmmMleUnitdataReq(mut request) = queue.pop_front().expect("registration accept").msg else {
            panic!("registration accept must be an LMM downlink")
        };
        let accept = DLocationUpdateAccept::from_bitbuf(&mut request.sdu).expect("valid registration accept");
        let associations = accept
            .group_identity_security_related_information
            .expect("interrupted associations must be embedded")
            .into_iter()
            .flat_map(|information| information.associations)
            .map(|association| association.gssi)
            .collect::<Vec<_>>();
        assert_eq!(associations, vec![1202, 1203]);
    }

    #[test]
    fn liveliness_probe_does_not_change_a_pending_figure20_transaction() {
        let issi = 77_492;
        let mut mm = test_sc3g_mm(issi, &[1202]);
        let mut queue = MessageQueue::new();
        mm.send_group_security_association_amendments(&mut queue, issi, 0, [1202]);
        let figure20_reporter = mm.pending_group_security_associations[&issi].tx_reporter.clone();
        let groups_before = mm.pending_group_security_associations[&issi].groups.clone();

        mm.send_liveliness_probe(&mut queue, issi);
        let liveliness_reporter = mm.pending_liveliness_probes[&issi].clone();
        liveliness_reporter.mark_transmitted();
        liveliness_reporter.mark_acknowledged();
        mm.update_liveliness_probe_statuses();

        let pending = &mm.pending_group_security_associations[&issi];
        assert_eq!(pending.groups, groups_before);
        assert_eq!(pending.tx_reporter.get_state(), figure20_reporter.get_state());
        assert!(!mm.pending_liveliness_probes.contains_key(&issi));
    }

    #[test]
    fn registered_terminal_receives_full_current_gck_version() {
        let config = test_config();
        let issi = 77_492;
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x6c; 10], true, true);
        // VN9 and VN1 have the same short SYSINFO value. The individual
        // indication must preserve the full value and the registered DCK.
        sc3.apply_sc3g_snapshot(1, true, 9, vec![RuntimeSc3Gck::new(2, 9, [0x32; 10])], vec![(1202, 2)])
            .expect("valid linked SC3G snapshot");
        sc3.install_dck(issi, RuntimeSc3Dck::new([0xd3; 16], [0x5a; 10], true, None));
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(sc3),
            rollover: None,
        };
        config.state_write().aie_sessions.set_terminal_class(issi, TerminalSecurityClass::Sc3, None);
        let mm = MmBs::new(config, None, None, None);
        let mut queue = MessageQueue::new();

        assert!(mm.send_current_gck_version_to_terminal(&mut queue, issi, 0));

        let message = queue.pop_front().expect("GCK-VN advertisement must be queued");
        let SapMsgInner::LmmMleUnitdataReq(mut request) = message.msg else {
            panic!("expected an LMM downlink request")
        };
        assert_eq!(request.address.ssi, issi);
        assert_eq!(request.address.ssi_type, tetra_core::SsiType::Issi);
        assert_eq!(request.layer2service, tetra_core::Layer2Service::Acknowledged);
        assert!(matches!(request.aie_request, AieRequest::Sc3 {
            subject: AieSubject::Individual { issi: protected_issi },
            scope: AieScope::MacResource,
            ..
        } if protected_issi == issi));
        // TTR 001-11 table 1, independent of the decoder under test.
        assert_eq!(request.sdu.dump_bin(), "^0010000100000000000000100111");
        let pdu = DAllGcksChangeDemand::from_bitbuf(&mut request.sdu).expect("valid full GCK-VN advertisement");
        assert_eq!(pdu.gck_version_number, 9);
        assert!(!pdu.acknowledgement_required);
        assert_eq!(pdu.time, CkChangeTime::CurrentlyInUse);
    }

    #[test]
    fn full_gck_version_broadcast_is_explicitly_clear_for_key_recovery() {
        let config = test_config();
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x6c; 10], true, true);
        sc3.apply_sc3g_snapshot(1, true, 1, vec![RuntimeSc3Gck::new(2, 1, [0x32; 10])], vec![(1202, 2)])
            .expect("valid linked SC3G snapshot");
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(sc3),
            rollover: None,
        };
        let mm = MmBs::new(config, None, None, None);
        let mut queue = MessageQueue::new();

        assert!(mm.send_gck_version_broadcast(&mut queue, 1, false));

        let message = queue.pop_front().expect("GCK-VN broadcast must be queued");
        let SapMsgInner::LmmMleUnitdataReq(request) = message.msg else {
            panic!("expected an LMM downlink request")
        };
        assert_eq!(request.address.ssi, 0x00ff_ffff);
        assert!(matches!(request.address.ssi_type, tetra_core::SsiType::Gssi));
        assert!(matches!(
            request.aie_request,
            AieRequest::Clear {
                subject: AieSubject::System,
                scope: AieScope::MacResource,
            }
        ));
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
        assert_eq!(
            OtarDownlinkKind::KeyDeleteDemand.expected_response(),
            Some(OtarTerminalResponse::KeyDeleteResult)
        );
        assert_eq!(
            OtarDownlinkKind::CmgGtsiProvide.expected_response(),
            Some(OtarTerminalResponse::CmgGtsiResult)
        );
        assert_eq!(OtarDownlinkKind::SckReject.expected_response(), None);
    }

    #[test]
    fn concurrent_gck_results_match_the_provided_key_set() {
        use tetra_pdus::mm::pdus::otar::{GckProvisionResult, OtarTail, UGckResult};

        let mut mm = MmBs::new(test_config(), None, None, None);
        let issi = 77_491;
        for (command_id, keys) in [
            (1, vec![(2, 13), (2, 14), (4, 13), (4, 14)]),
            (2, vec![(1, 13), (1, 14)]),
            (3, vec![(2, 13), (2, 14), (4, 13), (4, 14)]),
        ] {
            mm.pending_otar_deliveries.insert(command_id, PendingOtarDelivery {
                command_id, issi, air_handle: 0, kind: OtarDownlinkKind::GckProvide,
                expected_response: Some(OtarTerminalResponse::GckResult),
                gck_keys: Some(keys), tx_reporter: TxReporter::new(),
                status: OtarDeliveryStatus::AwaitingTerminalResult,
                result_deadline: mm.current_time.add_timeslots(100),
            });
        }
        let result = UGckResult {
            results: [(4, 14), (2, 13), (4, 13), (2, 14)].into_iter().map(|(gck_number, version_number)| {
                GckProvisionResult { gck_number, version_number, provision_result: 0, current_version_number: None }
            }).collect(),
            tail: OtarTail::default(),
        };
        mm.complete_gck_terminal_response(issi, 0, &result);
        assert!(!mm.pending_otar_deliveries.contains_key(&1));
        assert!(mm.pending_otar_deliveries.contains_key(&2));
        assert!(!mm.pending_otar_deliveries.contains_key(&3));
        assert_eq!(mm.recent_otar_deliveries.iter().filter(|entry|
            matches!(entry.status, OtarDeliveryStatus::TerminalResult { success: true })).count(), 2);
    }

    #[test]
    fn location_update_command_uses_the_registered_terminals_sc3_dck() {
        let issi = 430_905;
        let config = test_config();
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x6c; 10], true, true);
        sc3.install_dck(issi, RuntimeSc3Dck::new([0xd3; 16], [0x5a; 10], true, None));
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(sc3),
            rollover: None,
        };
        config
            .state_write()
            .aie_sessions
            .set_terminal_class(issi, TerminalSecurityClass::Sc3, None);
        let mm = MmBs::new(config, None, None, None);
        let mut queue = MessageQueue::new();

        mm.send_d_location_update_command(&mut queue, issi, 0, false);

        let message = queue.pop_front().expect("D-LOCATION UPDATE COMMAND must be queued");
        let SapMsgInner::LmmMleUnitdataReq(request) = message.msg else {
            panic!("expected an LMM downlink request")
        };
        assert!(matches!(
            request.aie_request,
            AieRequest::Sc3 {
                subject: AieSubject::Individual { issi: protected_issi },
                scope: AieScope::MacResource,
                ..
            } if protected_issi == issi
        ));
    }

    #[test]
    fn liveliness_probe_is_empty_acknowledged_bl_data_and_does_not_enter_mm() {
        let issi = 430_905;
        let config = test_config();
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x6c; 10], true, true);
        sc3.install_dck(issi, RuntimeSc3Dck::new([0xd3; 16], [0x5a; 10], true, None));
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(sc3),
            rollover: None,
        };
        config
            .state_write()
            .aie_sessions
            .set_terminal_class(issi, TerminalSecurityClass::Sc3, None);
        let mut mm = MmBs::new(config, None, None, None);
        let mut queue = MessageQueue::new();

        mm.send_liveliness_probe(&mut queue, issi);

        let message = queue.pop_front().expect("presence probe must be queued");
        assert_eq!(message.sap, Sap::TlaSap);
        assert_eq!(message.src, TetraEntity::Mm);
        assert_eq!(message.dest, TetraEntity::Llc);
        let SapMsgInner::TlaTlDataReqBl(request) = message.msg else {
            panic!("presence probe must bypass MLE and enter LLC as BL-DATA")
        };
        assert_eq!(request.main_address.ssi, issi);
        assert!(matches!(request.main_address.ssi_type, SsiType::Issi));
        assert_eq!(
            request.tl_sdu.get_len_remaining(),
            0,
            "presence BL-DATA must not carry a layer-3 PDU"
        );
        assert!(!request.stealing_permission);
        assert!(request.tx_reporter.is_some());
        assert!(matches!(
            request.air_interface_encryption,
            Some(AieRequest::Sc3 {
                subject: AieSubject::Individual { issi: protected_issi },
                scope: AieScope::MacResource,
                ..
            }) if protected_issi == issi
        ));
        assert!(queue.pop_front().is_none());
        assert!(mm.pending_registrations.is_empty());
        assert!(mm.pending_registration_deliveries.is_empty());
    }

    #[test]
    fn identical_roaming_state_sync_preserves_groups_without_events() {
        let issi = 430_904;
        let config = test_config();
        config.state_write().subscribers.register(issi);
        let mut mm = MmBs::new(config, None, None, None);
        mm.client_mgr.try_register_client(issi, true).expect("test terminal must register");
        mm.client_mgr
            .client_group_attach_with_class_of_usage(issi, 1202, true, 4)
            .expect("test group must attach");
        mm.config.state_write().subscribers.affiliate(issi, 1202);
        let groups = vec![AttachmentOperation {
            gssi: 1202,
            detach: false,
            class_of_usage: 4,
        }];
        let energy_economy = EnergyEconomyAssignment {
            mode: 0,
            frame_number: None,
            multiframe_number: None,
        };
        let mut queue = MessageQueue::new();

        mm.apply_swmi_subscriber_state_sync(
            &mut queue,
            u64::from(issi),
            groups,
            true,
            energy_economy,
            TerminalSecurityClass::Unknown,
        );

        assert!(
            queue.pop_front().is_none(),
            "an identical snapshot must not deaffiliate, reaffiliate or amend GCK state"
        );
        assert_eq!(mm.client_mgr.client_group_class_of_usage(issi, 1202), Some(4));
    }

    #[test]
    fn unknown_terminal_attachment_requests_fresh_location_update() {
        let issi = 77_468;
        let command_id = 41;
        let operation = AttachmentOperation {
            gssi: 204,
            detach: false,
            class_of_usage: 4,
        };
        let mut mm = MmBs::new(test_config(), None, None, None);
        mm.pending_attachments.insert(
            command_id,
            PendingAttachment {
                itsi: issi,
                air_handle: 7,
                replace_all: false,
                operations: vec![GroupIdentityUplink {
                    class_of_usage: Some(4),
                    group_identity_detachment_uplink: None,
                    gssi: Some(204),
                    address_extension: None,
                    vgssi: None,
                }],
            },
        );
        let mut queue = MessageQueue::new();

        mm.apply_swmi_attachment_decision(
            &mut queue,
            command_id,
            u64::from(issi),
            7,
            true,
            vec![AttachmentResult {
                operation,
                accepted: false,
                cause: 2,
            }],
        );

        let location_update = queue.iter_mut().find_map(|message| {
            let SapMsgInner::LmmMleUnitdataReq(request) = &mut message.msg else {
                return None;
            };
            DLocationUpdateCommand::from_bitbuf(&mut request.sdu).ok()
        });
        assert!(
            location_update.is_some_and(|command| command.group_identity_report),
            "unknown terminal rejection must trigger a complete registration and group report"
        );
    }

    #[test]
    fn delayed_roaming_state_sync_restores_group_internally_after_registration_ack() {
        let issi = 430_904;
        let gssi = 1202;
        let config = test_config();
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x6c; 10], true, true);
        sc3.apply_sc3g_snapshot(1, true, 1, vec![RuntimeSc3Gck::new(2, 1, [0x32; 10])], vec![(gssi, 2)])
            .expect("valid roaming SC3G snapshot");
        {
            let mut state = config.state_write();
            state.aie = RuntimeAieConfig {
                enabled: true,
                sc1_allowed: false,
                sc2: None,
                sc3: Some(sc3),
                rollover: None,
            };
            state.subscribers.register(issi);
            state.subscribers.mark_active(issi);
        }
        let mut mm = MmBs::new(config, None, None, None);
        mm.client_mgr.try_register_client(issi, true).expect("test terminal must register");
        let mut queue = MessageQueue::new();

        mm.apply_swmi_subscriber_state_sync(
            &mut queue,
            u64::from(issi),
            vec![AttachmentOperation {
                gssi,
                detach: false,
                class_of_usage: 4,
            }],
            true,
            EnergyEconomyAssignment {
                mode: 0,
                frame_number: None,
                multiframe_number: None,
            },
            TerminalSecurityClass::Sc3,
        );

        assert_eq!(mm.client_mgr.client_group_class_of_usage(issi, gssi), Some(4));
        assert!(queue.iter_mut().any(|message| matches!(&message.msg,
            SapMsgInner::MmSubscriberUpdate(update) if update.groups.contains(&gssi))));
        assert!(
            queue
                .iter_mut()
                .all(|message| !matches!(&message.msg, SapMsgInner::LmmMleUnitdataReq(_))),
            "restoring a snapshot must not send an air-interface PDU"
        );
        assert!(!mm.queued_group_security_associations.contains_key(&issi));
        assert!(!mm.pending_group_security_associations.contains_key(&issi));
    }

    #[test]
    fn registration_becomes_active_only_after_link_ack() {
        let issi = 430_905;
        let config = test_config();
        config.state_write().subscribers.register(issi);
        let mut mm = MmBs::new(config.clone(), None, None, None);
        let reporter = TxReporter::new();
        let mut queue = MessageQueue::new();

        mm.track_registration_delivery(Some(41), issi, true, Vec::new(), reporter.clone());
        assert!(config.state_read().subscribers.is_registration_pending(issi));
        assert!(!config.state_read().subscribers.is_active(issi));

        reporter.mark_transmitted();
        mm.update_registration_delivery_statuses(&mut queue);
        assert!(config.state_read().subscribers.is_registration_pending(issi));
        assert!(!config.state_read().subscribers.is_active(issi));

        reporter.mark_acknowledged();
        mm.update_registration_delivery_statuses(&mut queue);
        assert!(!config.state_read().subscribers.is_registration_pending(issi));
        assert!(config.state_read().subscribers.is_active(issi));
    }

    #[test]
    fn registration_guard_still_defers_explicit_security_amendments() {
        let issi = 77_468;
        let gssi = 91;
        let config = test_config();
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x6c; 10], true, true);
        sc3.apply_sc3g_snapshot(1, true, 1, vec![RuntimeSc3Gck::new(1, 1, [0x31; 10])], vec![(gssi, 1)])
            .expect("valid linked SC3G snapshot");
        {
            let mut state = config.state_write();
            state.aie = RuntimeAieConfig {
                enabled: true,
                sc1_allowed: false,
                sc2: None,
                sc3: Some(sc3),
                rollover: None,
            };
            state.subscribers.register(issi);
        }
        let mut mm = MmBs::new(config, None, None, None);
        mm.client_mgr.try_register_client(issi, true).expect("test terminal must register");
        mm.client_mgr
            .client_group_attach_with_class_of_usage(issi, gssi, true, 4)
            .expect("test group must attach");
        let reporter = TxReporter::new();
        let mut queue = MessageQueue::new();

        // The location update itself did not carry this group. It was restored
        // from central roaming state while registration awaited its BL-ACK.
        mm.track_registration_delivery(Some(41), issi, true, Vec::new(), reporter.clone());
        reporter.mark_transmitted();
        mm.update_registration_delivery_statuses(&mut queue);
        assert!(queue.pop_front().is_none(), "association must wait for the registration BL-ACK");

        reporter.mark_acknowledged();
        mm.update_registration_delivery_statuses(&mut queue);

        let version_message = queue.pop_front().expect("full current GCK-VN follows registration");
        let SapMsgInner::LmmMleUnitdataReq(mut version_request) = version_message.msg else {
            panic!("expected an LMM downlink request")
        };
        DAllGcksChangeDemand::from_bitbuf(&mut version_request.sdu).expect("valid full current GCK-VN advertisement");
        assert!(
            queue.pop_front().is_none(),
            "Figure-20 must not collide with terminal-side registration MM"
        );
        assert!(
            !mm.queued_group_security_associations.contains_key(&issi),
            "restored group needs no amendment"
        );
        // An actual provisioning/association change remains a separate
        // transaction and must still respect the registration guard.
        mm.send_group_security_association_amendments(&mut queue, issi, 0, [gssi]);
        assert!(queue.pop_front().is_none());

        mm.current_time = mm.current_time.add_timeslots(super::GROUP_SECURITY_REGISTRATION_GUARD_TIMESLOTS);
        mm.update_group_security_association_statuses(&mut queue);

        let message = queue.pop_front().expect("late Figure-20 association amendment after guard");
        let SapMsgInner::LmmMleUnitdataReq(mut request) = message.msg else {
            panic!("expected an LMM downlink request")
        };
        assert!(request.sdu.get_len() < 200, "registration amendment must not fragment");
        let pdu = DAttachDetachGroupIdentity::from_bitbuf(&mut request.sdu).expect("valid association amendment");
        assert!(pdu.group_identity_acknowledgement_request);
        let groups = pdu.group_identity_downlink.expect("group attachment amendment");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].gssi, Some(gssi));
        let security = pdu
            .group_identity_security_related_information
            .expect("GCK association must be present");
        assert_eq!(security[0].associations[0].gssi, gssi);
        assert_eq!(security[0].associations[0].selection, GckSelectNumber::Selected(1));

        assert!(queue.pop_front().is_none());
    }

    #[test]
    fn failed_registration_delivery_remains_inactive_and_is_counted() {
        let issi = 430_905;
        let config = test_config();
        config.state_write().subscribers.register(issi);
        let mut mm = MmBs::new(config.clone(), None, None, None);
        let reporter = TxReporter::new();
        let mut queue = MessageQueue::new();

        mm.track_registration_delivery(Some(41), issi, true, Vec::new(), reporter.clone());
        reporter.mark_transmitted();
        reporter.mark_lost();
        mm.update_registration_delivery_statuses(&mut queue);

        let mut state = config.state_write();
        assert!(!state.subscribers.is_registration_pending(issi));
        assert!(!state.subscribers.is_active(issi));
        assert_eq!(state.subscribers.take_registration_delivery_failures(), 1);
    }
}
