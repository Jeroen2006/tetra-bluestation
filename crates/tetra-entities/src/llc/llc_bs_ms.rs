use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::panic;

use crate::{MessageQueue, TetraEntityTrait};
use tetra_config::bluestation::SharedConfig;
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{AieRequest, AieScope, AieSubject, BitBuffer, Layer2Service, Sap, SsiType, TdmaTime, TetraAddress, TxReporter, TxState};
use tetra_saps::lcmc::enums::alloc_type::ChanAllocType;
use tetra_saps::lcmc::enums::ul_dl_assignment::UlDlAssignment;
use tetra_saps::lcmc::fields::chan_alloc_req::CmceChanAllocReq;
use tetra_saps::tla::{TlaTlDataIndBl, TlaTlDataReqAl, TlaTlUnitdataIndBl};
use tetra_saps::tma::TmaUnitdataReq;
use tetra_saps::{SapMsg, SapMsgInner};

use crate::llc::components::fcs;
use tetra_pdus::llc::consts::consts::{N252_BL_MAX_TLSDU_RETRANSMITS_ACKED, N262_AL_MAX_CONNECTION_SETUP_RETRIES};
use tetra_pdus::llc::consts::timers::{
    T251_SENDER_RETRY_TIMER, T252_ACK_WAITING_TIMER, T261_SETUP_WAITING_TIMER, T271_RECEIVER_NOT_READY_FOR_TX_TIMER,
};
use tetra_pdus::llc::enums::llc_pdu_type::LlcPduType;
use tetra_pdus::llc::pdus::al::{AlAck, AlAckBlock, AlDataHeader, AlDisconnect, AlReconnect, AlSetup};
use tetra_pdus::llc::pdus::bl_ack::BlAck;
use tetra_pdus::llc::pdus::bl_adata::BlAdata;
use tetra_pdus::llc::pdus::bl_data::BlData;
use tetra_pdus::llc::pdus::bl_udata::BlUdata;
use tetra_pdus::mle::enums::mle_protocol_discriminator::MleProtocolDiscriminator;

// T.251 is expressed in downlink signalling frames for the channel on which
// the response is expected (TS 100 392-2 Annex A). While an active traffic
// channel owns FN1..17, SACCH has one such frame per 18-frame multiframe.
// Convert the four-frame T.251 value to four actual SACCH opportunities.
const ASSIGNED_CHANNEL_ACK_RETRY_TIMER_MULTIPLIER: u32 = 18;
const ASSIGNED_CHANNEL_ACK_EXTRA_RETRANSMITS: u8 = 2;
// A routed copy may still be queued or fragmented when another concurrent
// copy completes and starts T.251.  Allow enough channel opportunities for a
// maximum-sized basic-link PDU to finish before replacing the whole attempt.
// The estimate below deliberately includes one extra MAC frame for headers,
// a grant, or a mandatory broadcast interruption.
const CONSERVATIVE_SCH_F_PAYLOAD_BITS: usize = 200;
// Keep a common-channel basic-link transaction alive for one complete TETRA
// frame after N.252 is exhausted. An MS can only put its BL-ACK on air a few
// slots after receiving the last fragmented retry.
const COMMON_CHANNEL_FINAL_ACK_GRACE_TIMESLOTS: u32 = 4;
// An assigned-channel retry can reach an MS immediately before it returns to
// MCCH. The MS may then send the BL-ACK through MCCH random access. ETSI
// TS 100 392-2 annex B permits T.205 to be as short as five multiframes, so
// retain the outstanding LLC transaction for that minimum random-access
// window instead of classifying the valid ACK as a late duplicate.
const ASSIGNED_CHANNEL_FINAL_ACK_GRACE_TIMESLOTS: u32 = 5 * 18 * 4;
// TTR 001-05 section 6.5 fixes the original advanced-link downlink segment
// capacity at 214 bits when MAC-RESOURCE uses event-label addressing and
// reserves room for an eventual eight-bit slot grant.  That capacity keeps a
// 1500-octet IPv4 packet, including SNDCP/MLE headers and the LLC FCS, within
// one 62-position acknowledgement block.
const AL_DOWNLINK_SEGMENT_BITS_WITH_EVENT_LABEL_AND_GRANT: usize = 214;
const AL_FINAL_FCS_BITS: usize = 32;
// T.252 expiry repeats the acknowledgement request; it does not consume the
// negotiated N.273 whole-TL-SDU retransmission budget. Keep this bounded so a
// peer that has left the channel cannot hold the link forever.
const MAX_AL_ACK_REQUEST_REPEATS: u8 = 5;
// An MS that requested a multislot PDCH establishes its advanced link after
// the channel assignment.  Bound the wait by the standard setup timer and
// retry count so an MS that never completes AL-SETUP cannot retain IP packets
// indefinitely.
const AL_SETUP_NEGOTIATION_TIMEOUT: u32 = T261_SETUP_WAITING_TIMER * (N262_AL_MAX_CONNECTION_SETUP_RETRIES + 1);
const MAX_PENDING_ADVANCED_TLSDUS_PER_LINK: usize = 64;
/// Struct that maintains state expected acknowledgement data for a transmitted message.
/// Aka, we still expect an ack for this.
pub struct ExpectedInAck {
    /// Timeslot on which the original message was sent
    pub ts: u8,
    /// Address to which the message was sent
    pub addr: TetraAddress,

    /// Expected ack sequence number for the original message
    pub ns: u8,

    pub bl_type: Layer2Service,

    /// The SNDCP response which assigns an MS from CCCH to a PDCH must stay
    /// on the common channel even if an earlier advanced link and packet
    /// delivery route still exist for the same PDP context.
    force_common_channel: bool,

    /// Packet signalling has one authoritative location: its explicit PDCH
    /// route, or the MCCH when no route is attached. Duplicating the same LLC
    /// transaction on both can make half-duplex terminals process it twice.
    packet_data: bool,

    /// Time this message was received from the MLE
    pub t_first: TdmaTime,
    /// Time this message was actually passed down to the Umac. If a previous message on the basic link is already
    /// submitted, the message has to wait until that previous message was sent and acknowledged, or lost.
    pub t_submitted_to_umac: Option<TdmaTime>,
    /// Time the RxReporter signalled the message was fully transmitted. Also set if the Umac discarded the message
    /// This helps attempting to retransmit the message after a brief delay.
    pub t_umac_done: Option<TdmaTime>,
    /// At least one attempt reached the air interface.  Keep this across
    /// retries because their shared reporter is reset to Pending while the MS
    /// may still return a valid, delayed BL-ACK for an earlier copy.
    pub has_transmitted_attempt: bool,
    /// TxReporter struct. Used by Umac to signal Tx time to Llc, so llc can do retransmissions if needed.
    /// Also used by Llc to signal Ack to upper layer (if appliccable)
    pub tx_reporter: TxReporter,
    /// Per-route reporters for the copies which make up the current radio
    /// attempt.  A scanning MS can be listening on only one of several active
    /// group bearers.  Each copy needs its own reporter so one congested route
    /// cannot mark a concurrently transmitted copy as discarded.
    pub attempt_reporters: Vec<TxReporter>,
    /// Physical bearer for each entry in `attempt_reporters`; TS1 denotes the
    /// MCCH and TS2..4 denote associated traffic-channel control.
    attempt_timeslots: Vec<u8>,
    /// Number of route copies whose complete over-air transmission has already
    /// been observed. A later copy completing restarts T.251 for that copy.
    observed_transmitted_copies: usize,

    // Optional retransmission buffer, to allow for automatic retransmission of the PDU if no acknowledgement is received
    pub retransmission_buf: SapMsg,
    /// Number of retransmissions performed so far
    pub retransmit_count: u8,
}

/// Struct that maintains state for an ACK we still need to send back.
pub struct ScheduledOutAck {
    pub addr: TetraAddress,
    pub t_start: TdmaTime,
    /// Received sequence number
    pub nr: u8,
    /// Timeslot on which the original message was received
    pub ts: u8,
    /// Key-free AIE policy of the PDU being acknowledged.  A BL-ACK is not
    /// allowed to downgrade an SC2-protected basic-link PDU to clear.
    pub aie_request: AieRequest,
}

#[derive(Debug, Clone)]
struct AdvancedRxSdu {
    ns: u8,
    segments: BTreeMap<u8, BitBuffer>,
    final_segment: Option<u8>,
    /// A correctly reassembled TL-SDU waits here until every older TL-SDU in
    /// the negotiated receive window has also completed.  EN 300 392-2
    /// 22.3.3.2.2 requires delivery in N(S) order even when radio segments
    /// arrive on different slots out of order.
    complete: Option<BitBuffer>,
}

impl AdvancedRxSdu {
    fn acknowledgement_block(&self) -> AlAckBlock {
        if self.complete.is_some() {
            return AlAckBlock {
                nr: self.ns,
                acknowledgement_length: 0,
                first_missing_segment: None,
                acknowledgement_bitmap: Vec::new(),
            };
        }

        let highest = self
            .final_segment
            .or_else(|| self.segments.last_key_value().map(|(segment, _)| *segment))
            .unwrap_or(0);
        let first_missing = (0..=highest)
            .find(|segment| !self.segments.contains_key(segment))
            .unwrap_or(highest.saturating_add(1));
        // One original-link acknowledgement block can describe at most 62
        // segment positions.  A later AL-DATA-AR recovery round reports any
        // still-missing positions beyond this range.
        let last_described = first_missing.saturating_add(61).min(highest);
        let acknowledgement_length = last_described.saturating_sub(first_missing).saturating_add(1).max(1);
        let acknowledgement_bitmap = ((first_missing.saturating_add(1))..=last_described)
            .map(|segment| self.segments.contains_key(&segment))
            .collect();
        AlAckBlock {
            nr: self.ns,
            acknowledgement_length,
            first_missing_segment: Some(first_missing),
            acknowledgement_bitmap,
        }
    }
}

#[derive(Debug, Clone)]
struct AdvancedTxSdu {
    ns: u8,
    segments: Vec<BitBuffer>,
    chan_alloc: Option<CmceChanAllocReq>,
    endpoint_id: u32,
    aie_request: AieRequest,
    reporter: TxReporter,
    attempt_reporter: Option<TxReporter>,
    /// True only for the transmitted segment which asked the peer for the
    /// current window acknowledgement. T.252 applies to that request, not to
    /// every TL-SDU which is awaiting the same acknowledgement.
    acknowledgement_requested: bool,
    sent_at: Option<TdmaTime>,
    ack_request_repetitions: u8,
    retransmissions: u8,
    segment_retransmissions: Vec<u8>,
    pending_segments: Option<Vec<usize>>,
}

#[derive(Debug, Clone)]
struct AdvancedLink {
    link_number: u8,
    maximum_sdu: u8,
    slots: u8,
    throughput: u8,
    window_size: u8,
    max_sdu_retransmissions: u8,
    max_segment_retransmissions: u8,
    endpoint_id: u32,
    next_tx_ns: u8,
    /// Lower boundary of the modulo-8 original advanced-link receive window.
    next_rx_ns: u8,
    receiver_ready: bool,
    /// The most recent AL-RNR reception. T.271 starts again on every RNR;
    /// once it expires the sender may resume at its oldest unacknowledged
    /// TL-SDU even if the peer never follows up with AL-ACK.
    receiver_not_ready_since: Option<TdmaTime>,
    /// True after the AL-SETUP Success response has been sent or received.
    /// A Service change proposal remains false until the peer confirms it.
    ready: bool,
    setup_started_at: Option<TdmaTime>,
    rx_sdus: BTreeMap<u8, AdvancedRxSdu>,
    tx: VecDeque<AdvancedTxSdu>,
    reset: Option<AdvancedLinkReset>,
}

#[derive(Debug, Clone)]
struct PendingAdvancedData {
    prim: TlaTlDataReqAl,
    queued_at: TdmaTime,
}

#[derive(Debug, Clone)]
struct AdvancedLinkReset {
    setup: AlSetup,
    aie_request: AieRequest,
    attempt_reporter: TxReporter,
    sent_at: Option<TdmaTime>,
    retries: u32,
}

impl AdvancedLink {
    fn acknowledgement_blocks(&self, override_block: Option<AlAckBlock>) -> Vec<AlAckBlock> {
        (0..self.window_size)
            .map(|offset| {
                let nr = (self.next_rx_ns + offset) & 0x07;
                if override_block.as_ref().is_some_and(|block| block.nr == nr) {
                    return override_block.clone().expect("matching acknowledgement override");
                }
                self.rx_sdus.get(&nr).map_or(
                    AlAckBlock {
                        nr,
                        acknowledgement_length: 1,
                        first_missing_segment: Some(0),
                        acknowledgement_bitmap: Vec::new(),
                    },
                    AdvancedRxSdu::acknowledgement_block,
                )
            })
            .collect()
    }
}

pub struct Llc {
    config: SharedConfig,
    dltime: TdmaTime,

    /// When we receive a message, and it needs to be acknowledged, we store it here for later
    /// integration into a response message, or we will make a separate BL-ACK for it.
    scheduled_out_acks: VecDeque<ScheduledOutAck>,

    /// Outbound messages, that are either already submitted to the Umac, and wait for ack,
    /// or, messages that can't be sent until previous messages for the same SSI have been
    /// acknowledged, first.
    outbound_messages: VecDeque<ExpectedInAck>,
    outbound_udata_messages: VecDeque<SapMsg>,

    /// Per-link send sequence variable per SSI. Alternates between 0 and 1.
    link_send_seq: HashMap<u32, u8>,
    advanced_links: HashMap<u32, AdvancedLink>,
    pending_advanced_data: HashMap<u32, VecDeque<PendingAdvancedData>>,
}

impl Llc {
    pub fn new(config: SharedConfig) -> Self {
        Self {
            dltime: TdmaTime::default(),
            config,
            scheduled_out_acks: VecDeque::new(),
            outbound_messages: VecDeque::new(),
            outbound_udata_messages: VecDeque::new(),
            link_send_seq: HashMap::new(),
            advanced_links: HashMap::new(),
            pending_advanced_data: HashMap::new(),
        }
    }

    /// Schedule an ACK to be sent at a later time
    pub fn schedule_outgoing_ack(&mut self, dltime: TdmaTime, addr: TetraAddress, ns: u8, aie_request: AieRequest) {
        self.scheduled_out_acks.push_back(ScheduledOutAck {
            t_start: dltime,
            nr: ns,
            addr,
            ts: dltime.t,
            aie_request,
        });
    }

    /// Resolve the best channel on which the addressed MS is listening now.
    /// A fresh MAC-ACCESS response deliberately stays on MCCH; otherwise an
    /// active call route wins so MM/OTAR is not sent to a channel the MS has
    /// stopped monitoring.  The lookup is repeated for every BL attempt.
    fn delivery_routes(config: &SharedConfig, issi: u32, dltime: TdmaTime) -> Vec<tetra_saps::tma::AssociatedChannel> {
        let mut state = config.state_write();
        // Registration/authentication is a common-channel procedure. A stale
        // call listener can remain in the CC routing table while the MS has
        // already returned to MCCH for location updating, so never inherit a
        // traffic route until D-LOCATION UPDATE ACCEPT is link-acknowledged.
        if state.subscribers.is_registration_pending(issi) {
            return Vec::new();
        }
        let direct_response_window = state.subscribers.direct_response_window_active(issi, dltime);
        // A TIP MS uses MAC-ACCESS for each uplink burst on its assigned
        // PDCH. That refreshes the short direct-response window continuously,
        // but the MS remains on the PDCH and cannot receive an unsolicited
        // SDS on MCCH. During such a window suppress only a possibly stale
        // circuit route; an active packet route is still authoritative.
        let mut routes = state
            .subscriber_delivery_routes
            .get(&issi)
            .filter(|_| !direct_response_window)
            .into_iter()
            .flat_map(|routes| routes.iter())
            .filter(|route| (2..=4).contains(&route.timeslot))
            .map(|route| tetra_saps::tma::AssociatedChannel {
                call_id: route.call_id,
                timeslot: route.timeslot,
                usage: route.usage,
                best_effort_key: None,
            })
            .collect::<Vec<_>>();
        // Every timeslot in an SNDCP context belongs to one multislot packet
        // bearer. The MS monitors that bearer as a unit, so one basic-link
        // copy on its primary PDCH is sufficient. Treating TS2..TS4 as three
        // possible terminal locations needlessly transmits the same SDS three
        // times and can displace in-flight advanced-link IP segments.
        if let Some(packet_route) = state
            .subscriber_packet_delivery_routes
            .get(&issi)
            .into_iter()
            .flat_map(|routes| routes.iter())
            .find(|route| (2..=4).contains(&route.timeslot))
            .map(|route| tetra_saps::tma::AssociatedChannel {
                call_id: route.call_id,
                timeslot: route.timeslot,
                usage: route.usage,
                best_effort_key: None,
            })
        {
            // During a voice/packet transition both routing tables can still
            // name the same physical slot. Prefer the packet route there;
            // UMAC validates any remaining distinct circuit routes against
            // their current owner immediately before enqueueing.
            routes.retain(|route| route.timeslot != packet_route.timeslot);
            routes.insert(0, packet_route);
        }

        // Scan-list call routes remain separate possible terminal locations.
        let mut seen_timeslots = HashSet::new();
        routes.retain(|route| seen_timeslots.insert(route.timeslot));
        routes
    }

    /// Returns details for outstanding to-be-sent ACK, if any. Returned u8 is the sequence number.
    /// ETSI 22.3.2.3 case d: when a waiting ACK and outgoing TL-DATA exist for the same link, the
    /// LLC shall emit a combined BL-ADATA PDU. The ACK must belong to both the
    /// same SSI/protection context and the channel on which the MS is
    /// listening; an FN18 ACK must never be bundled into MCCH BL-DATA.
    fn get_out_ack_seq_if_any(&mut self, addr: TetraAddress, timeslot: u8, aie_request: AieRequest) -> Option<u8> {
        for i in 0..self.scheduled_out_acks.len() {
            if self.scheduled_out_acks[i].addr.ssi == addr.ssi
                && self.scheduled_out_acks[i].ts == timeslot
                && self.scheduled_out_acks[i].aie_request.same_protection_as(aie_request)
            {
                let n = self.scheduled_out_acks[i].nr;
                self.scheduled_out_acks.remove(i);
                return Some(n);
            }
        }
        None
    }

    /// Returns the next send sequence number V(S) for this link, then toggles it.
    /// Each link independently starts at 0 and alternates 0,1,0,1,...
    fn get_next_send_seq(&mut self, addr: &TetraAddress) -> u8 {
        let vs = self.link_send_seq.entry(addr.ssi).or_insert(0);
        let ns = *vs;
        *vs ^= 1;
        ns
    }

    /// Returns and removes the expected ACK entry for the given SSI, if any
    fn take_expected_ack_for_ssi(&mut self, ssi: u32) -> Option<ExpectedInAck> {
        for i in 0..self.outbound_messages.len() {
            let msg = &self.outbound_messages[i];
            if msg.addr.ssi == ssi && msg.t_submitted_to_umac.is_some() {
                return self.outbound_messages.remove(i);
            }
        }
        None
    }

    /// A clear post-SC2 MAC-DATA is accepted only when it is either the bare
    /// BL-ACK that completes a clear bootstrap downlink, or carries an MM
    /// PDU. The latter is not a general exception: MLE then permits only MM
    /// and MM validates its narrow location-update/OTAR bootstrap allow-list.
    /// The BL-ACK check remains against the exact outstanding clear basic-link
    /// message and its sequence number; it is not a temporary all-clear
    /// window.
    fn clear_transition_ack_expected(&self, addr: TetraAddress, nr: u8) -> bool {
        let state = self.config.state_read();
        if !state.aie.enabled || !state.subscribers.is_registered(addr.ssi) || state.aie_sessions.terminal_allows_clear(addr.ssi) {
            return false;
        }
        self.outbound_messages.iter().any(|expected| {
            expected.addr.ssi == addr.ssi
                && expected.ns == nr
                && expected.t_submitted_to_umac.is_some()
                && (expected.has_transmitted_attempt
                    || expected.t_umac_done.is_some()
                    || expected.tx_reporter.is_transmitted()
                    || expected.attempt_reporters.iter().any(TxReporter::is_transmitted))
                && matches!(
                    &expected.retransmission_buf.msg,
                    SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                        air_interface_encryption: Some(AieRequest::Clear { .. }) | None,
                        ..
                    })
                )
        })
    }

    /// Process incoming ACK per ETSI 22.3.2.3(k).
    /// Matches by SSI and N(R) so that retransmitted BL-DATA entries are matched correctly.
    fn process_incoming_ack(&mut self, addr: TetraAddress, nr: u8, aie_request: AieRequest) {
        // Get the expected ACK entry
        let Some(mut expected_ack) = self.take_expected_ack_for_ssi(addr.ssi) else {
            // A repeated BL-ACK after the first copy completed the transaction
            // is harmless and common when the MS heard a repeated downlink.
            // Keep sequence mismatches against a live transaction at WARN,
            // but do not flood operational logs for this late duplicate.
            tracing::debug!("received late/duplicate ACK for SSI {} N(R) {}", addr.ssi, nr);
            return;
        };

        // UMAC may receive the response in the scheduler turn immediately
        // after it reported the downlink as transmitted, before LLC's normal
        // retry tick has copied that report into `t_umac_done`. Treat that
        // concrete reporter state as transmitted here so a clear bootstrap
        // BL-ACK cannot race the deferred SC2 activation.
        if expected_ack.t_umac_done.is_none()
            && (expected_ack.tx_reporter.is_transmitted() || expected_ack.attempt_reporters.iter().any(TxReporter::is_transmitted))
        {
            expected_ack.has_transmitted_attempt = true;
            if !expected_ack.tx_reporter.is_transmitted() {
                expected_ack.tx_reporter.reset();
                expected_ack.tx_reporter.mark_transmitted();
            }
        }

        // Check it was indeed already transmitted by the Umac
        if expected_ack.t_umac_done.is_none() && !expected_ack.has_transmitted_attempt {
            // This may be an old retransmission of an ack for the before-last basic link message
            // Let's push the ack back into the head of the queue (not tail)..
            tracing::warn!(
                "received ACK for SSI {} N(R) {} that was not yet transmitted by Umac. Ignoring",
                addr.ssi,
                nr
            );
            self.outbound_messages.push_front(expected_ack);
            return;
        }

        let expected_aie_request = match &expected_ack.retransmission_buf.msg {
            SapMsgInner::TmaUnitdataReq(prim) => prim
                .air_interface_encryption
                .unwrap_or_else(|| AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource)),
            _ => unreachable!("basic-link acknowledgement must retain a TMA request"),
        };
        if !expected_aie_request.same_protection_as(aie_request) {
            tracing::warn!(
                issi = addr.ssi,
                nr,
                "rejecting BL-ACK whose AIE status differs from its outstanding basic-link PDU"
            );
            self.outbound_messages.push_front(expected_ack);
            return;
        }

        // Check N(R)
        if expected_ack.ns == nr {
            // Successful ACK: N(R) matches N(S)
            tracing::debug!("received ACK for SSI {} N(R) {}", addr.ssi, expected_ack.ns);
            // A retry may already be queued with the shared reporter reset to
            // Pending (or have been discarded) when an ACK for an earlier,
            // transmitted copy arrives.  Restore the legal reporter transition
            // without requiring that redundant retry to finish first.
            if !expected_ack.tx_reporter.is_transmitted() {
                expected_ack.tx_reporter.reset();
                expected_ack.tx_reporter.mark_transmitted();
            }
            expected_ack.tx_reporter.mark_acknowledged();
            Self::cancel_pending_attempt_copies(&expected_ack);
            return;
        } else {
            // N(R) mismatch — per ETSI 22.3.2.3(k), not a successful ACK. Maybe a retransmission?
            // Let's push it back into the queue head (not the tail) and see if an ack arrives later
            tracing::warn!(
                "received unexpected ACK for SSI {}: N(R)={}, expected N(S)={}. Ignoring",
                addr.ssi,
                nr,
                expected_ack.ns
            );
            self.outbound_messages.push_front(expected_ack);
            return;
        }

        // The expected_ack is confirmed as matched and goes out of scope here
    }

    /// Stop copies which have not reached the air yet.  UMAC treats the
    /// discarded per-route reporter as cancellation and removes the queued
    /// resource or fragment.  Copies already transmitted remain valid parts
    /// of this one basic-link transaction.
    fn cancel_pending_attempt_copies(ack: &ExpectedInAck) {
        for reporter in &ack.attempt_reporters {
            if reporter.get_state() == tetra_core::TxState::Pending {
                reporter.mark_discarded();
            }
        }
    }

    fn rx_tma_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tma_prim");
        match message.msg {
            SapMsgInner::TmaUnitdataInd(_) => {
                self.rx_tma_unitdata_ind(queue, message);
            }
            SapMsgInner::TmaReportInd(_) => {
                self.rx_tma_report_ind(queue, message);
            }
            _ => {
                panic!();
            }
        }
    }

    fn rx_tla_tlunitdata_req_bl(&mut self, _queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tla_tlunitdata_req_bl");
        let SapMsgInner::TlaTlUnitdataReqBl(mut prim) = message.msg else {
            panic!()
        };

        let mut pdu_buf = BitBuffer::new_autoexpand(32);
        let pdu = BlUdata { has_fcs: false };
        pdu.to_bitbuf(&mut pdu_buf);
        let sdu_len = prim.tl_sdu.get_len_remaining();
        pdu_buf.copy_bits(&mut prim.tl_sdu, sdu_len);
        pdu_buf.seek(0);
        tracing::debug!("-> {:?} sdu {}", pdu, pdu_buf.dump_bin());

        let sapmsg = SapMsg {
            sap: Sap::TmaSap,
            src: self.entity(),
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                req_handle: prim.req_handle,
                pdu: pdu_buf,
                main_address: prim.main_address,
                endpoint_id: prim.endpoint_id,
                stealing_permission: prim.stealing_permission,
                subscriber_class: prim.subscriber_class,
                air_interface_encryption: prim.air_interface_encryption,
                stealing_repeats_flag: None, // fixme
                data_category: prim.data_class_info,
                chan_alloc: prim.chan_alloc,
                associated_channel: prim.associated_channel,
                assigned_channel_frame18_broadcast: prim.assigned_channel_frame18_broadcast,
                tx_reporter: prim.tx_reporter.take(),
            }),
        };

        // Put into transmit queue
        self.outbound_udata_messages.push_back(sapmsg);
    }

    /// Schedules a message that was not acked in time for a retransmission
    fn submit_for_acknowledged_transmission(config: &SharedConfig, queue: &mut MessageQueue, ack: &mut ExpectedInAck, dltime: TdmaTime) {
        let preferred_route = match &ack.retransmission_buf.msg {
            SapMsgInner::TmaUnitdataReq(req) => req.associated_channel.clone(),
            _ => None,
        };
        let packet_associated_route = ack.packet_data && preferred_route.as_ref().is_some_and(|route| (2..=4).contains(&route.timeslot));
        let mut routes = if ack.force_common_channel || ack.packet_data {
            Vec::new()
        } else {
            Self::delivery_routes(config, ack.addr.ssi, dltime)
        };
        if let Some(route) = preferred_route.filter(|route| (2..=4).contains(&route.timeslot)) {
            // CMCE may have selected a traffic bearer while registration or a
            // direct-response window deliberately suppresses inferred LLC
            // routing. Keep that explicit SDS route: UMAC validates that the
            // circuit is still active immediately before enqueueing it.
            routes.retain(|candidate| candidate.timeslot != route.timeslot);
            routes.insert(0, route);
        }

        ack.t_submitted_to_umac = Some(dltime);
        ack.t_umac_done = None;
        Self::cancel_pending_attempt_copies(ack);
        ack.attempt_reporters.clear();
        ack.attempt_timeslots.clear();
        ack.observed_transmitted_copies = 0;

        tracing::info!(
            issi = ack.addr.ssi,
            traffic_copies = routes.len(),
            "sending acknowledged downlink on every plausible active bearer"
        );
        for route in routes {
            let mut sapmsg = ack.retransmission_buf.clone();
            let reporter = TxReporter::new();
            let SapMsgInner::TmaUnitdataReq(req) = &mut sapmsg.msg else {
                unreachable!("basic-link retransmission must retain a TMA request")
            };
            req.associated_channel = Some(route);
            req.tx_reporter = Some(reporter.clone());
            ack.attempt_reporters.push(reporter);
            ack.attempt_timeslots.push(route.timeslot);
            ack.ts = route.timeslot;
            tracing::info!(
                issi = ack.addr.ssi,
                timeslot = route.timeslot,
                call_id = route.call_id,
                usage = route.usage,
                "queued concurrent acknowledged downlink copy"
            );
            queue.push_back(sapmsg);
        }

        // Non-packet signalling may need fan-out because a scanning MS can be
        // on a traffic bearer or MCCH. Packet signalling already carries its
        // authoritative PDCH route; when that route is absent, MCCH is the
        // sole destination for the current packet state.
        if packet_associated_route {
            return;
        }
        let mut sapmsg = ack.retransmission_buf.clone();
        let reporter = TxReporter::new();
        let SapMsgInner::TmaUnitdataReq(req) = &mut sapmsg.msg else {
            unreachable!("basic-link retransmission must retain a TMA request")
        };
        req.associated_channel = None;
        req.tx_reporter = Some(reporter.clone());
        ack.attempt_reporters.push(reporter);
        ack.attempt_timeslots.push(1);
        if ack.attempt_reporters.len() == 1 {
            ack.ts = 1;
        }
        tracing::info!(issi = ack.addr.ssi, "queued concurrent acknowledged downlink MCCH copy");
        queue.push_back(sapmsg);
    }

    fn has_assigned_channel_context(ack: &ExpectedInAck) -> bool {
        let SapMsgInner::TmaUnitdataReq(ref req) = ack.retransmission_buf.msg else {
            return false;
        };

        ack.ts != 1
            || req.associated_channel.is_some()
            || req
                .chan_alloc
                .as_ref()
                .is_some_and(|alloc| alloc.usage.is_some() || alloc.timeslots[1..].iter().any(|assigned| *assigned))
    }

    fn basic_link_retry_timer(ack: &ExpectedInAck) -> u32 {
        if Self::has_assigned_channel_context(ack) {
            T251_SENDER_RETRY_TIMER * ASSIGNED_CHANNEL_ACK_RETRY_TIMER_MULTIPLIER
        } else {
            T251_SENDER_RETRY_TIMER
        }
    }

    fn estimated_mac_frames(ack: &ExpectedInAck) -> u32 {
        let bits = match &ack.retransmission_buf.msg {
            SapMsgInner::TmaUnitdataReq(req) => req.pdu.get_len(),
            _ => 0,
        };
        ((bits + CONSERVATIVE_SCH_F_PAYLOAD_BITS - 1) / CONSERVATIVE_SCH_F_PAYLOAD_BITS) as u32 + 1
    }

    /// Maximum time from attempt submission for every still-pending route to
    /// get its complete PDU on air. This is separate from T.251: T.251 may
    /// already be running for an earlier concurrent copy.
    fn pending_route_completion_window(config: &SharedConfig, ack: &ExpectedInAck) -> u32 {
        let mac_frames = Self::estimated_mac_frames(ack);
        let ee_period_multiframes = config
            .state_read()
            .subscribers
            .energy_economy(ack.addr.ssi)
            .map(|(mode, _, _)| {
                if mode == 0 {
                    0
                } else {
                    // TETRA defines EG1..EG7. Treat a corrupt persisted value
                    // as the longest valid period instead of allowing an
                    // unchecked shift to panic the scheduler.
                    1_u32 << u32::from(mode.min(7) - 1)
                }
            })
            .unwrap_or(0);

        ack.attempt_reporters
            .iter()
            .zip(&ack.attempt_timeslots)
            .filter(|(reporter, _)| reporter.get_state() == tetra_core::TxState::Pending)
            .map(|(_, timeslot)| {
                if *timeslot == 1 {
                    // An EE-gated MCCH copy first waits for its monitoring
                    // occasion, then uses ordinary consecutive signalling
                    // frames for any MAC fragments.
                    ee_period_multiframes
                        .saturating_mul(18 * 4)
                        .saturating_add(mac_frames.saturating_mul(4))
                } else {
                    // Associated control has one opportunity per 18-frame
                    // multiframe. Include the normal T.251 interval as queue
                    // grace for another PDU already owning this SACCH.
                    Self::basic_link_retry_timer(ack).saturating_add(mac_frames.saturating_mul(18 * 4))
                }
            })
            .max()
            .unwrap_or(0)
    }

    fn max_over_air_retransmits(ack: &ExpectedInAck) -> u8 {
        if Self::has_assigned_channel_context(ack) {
            N252_BL_MAX_TLSDU_RETRANSMITS_ACKED.saturating_add(ASSIGNED_CHANNEL_ACK_EXTRA_RETRANSMITS)
        } else {
            N252_BL_MAX_TLSDU_RETRANSMITS_ACKED
        }
    }

    fn final_ack_grace_elapsed(age: i32, retry_timer: u32, assigned_channel: bool) -> bool {
        let grace = if assigned_channel {
            ASSIGNED_CHANNEL_FINAL_ACK_GRACE_TIMESLOTS
        } else {
            COMMON_CHANNEL_FINAL_ACK_GRACE_TIMESLOTS
        };
        age >= 0 && (age as u32) >= retry_timer.saturating_add(grace)
    }

    fn mark_reporter_lost(reporter: &TxReporter) {
        // The last retry can be discarded or still queued after an earlier
        // attempt reached the air.  TxReporter requires Transmitted -> Lost,
        // so normalize the per-attempt state before completing the overall
        // acknowledged transaction.
        match reporter.get_state() {
            TxState::Acknowledged | TxState::Lost => return,
            TxState::Pending | TxState::Discarded => {
                reporter.reset();
                reporter.mark_transmitted();
            }
            TxState::Transmitted => {}
        }
        reporter.mark_lost();
    }

    fn mark_advanced_sdu_acknowledged(sdu: &AdvancedTxSdu) {
        if sdu.reporter.get_state() == TxState::Pending {
            sdu.reporter.mark_transmitted();
        }
        if sdu.reporter.get_state() == TxState::Transmitted {
            sdu.reporter.mark_acknowledged();
        }
    }

    fn packet_routes(config: &SharedConfig, issi: u32) -> Vec<tetra_saps::tma::AssociatedChannel> {
        config
            .state_read()
            .subscriber_packet_delivery_routes
            .get(&issi)
            .into_iter()
            .flat_map(|routes| routes.iter())
            .filter(|route| (2..=4).contains(&route.timeslot))
            .map(|route| tetra_saps::tma::AssociatedChannel {
                call_id: route.call_id,
                timeslot: route.timeslot,
                usage: route.usage,
                best_effort_key: None,
            })
            .collect()
    }

    fn packet_route(config: &SharedConfig, issi: u32, timeslot: u8) -> Option<tetra_saps::tma::AssociatedChannel> {
        Self::packet_routes(config, issi)
            .into_iter()
            .find(|route| route.timeslot == timeslot)
    }

    fn queue_advanced_pdu(
        queue: &mut MessageQueue,
        address: TetraAddress,
        endpoint_id: u32,
        pdu: BitBuffer,
        route: Option<tetra_saps::tma::AssociatedChannel>,
        chan_alloc: Option<CmceChanAllocReq>,
        aie_request: AieRequest,
        tx_reporter: Option<TxReporter>,
    ) {
        queue.push_back(SapMsg::new(
            Sap::TmaSap,
            TetraEntity::Llc,
            TetraEntity::Umac,
            SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                req_handle: 0,
                pdu,
                main_address: address,
                endpoint_id,
                stealing_permission: false,
                subscriber_class: 0,
                air_interface_encryption: Some(aie_request.with_scope(AieScope::MacResource)),
                stealing_repeats_flag: None,
                data_category: None,
                chan_alloc,
                associated_channel: route,
                assigned_channel_frame18_broadcast: false,
                tx_reporter,
            }),
        ));
    }

    fn queue_advanced_link_reset_attempt(
        queue: &mut MessageQueue,
        address: TetraAddress,
        endpoint_id: u32,
        setup: AlSetup,
        route: Option<tetra_saps::tma::AssociatedChannel>,
        aie_request: AieRequest,
        reporter: TxReporter,
    ) {
        let mut pdu = BitBuffer::new_autoexpand(32);
        if setup.to_bitbuf(&mut pdu).is_err() {
            Self::mark_reporter_lost(&reporter);
            return;
        }
        pdu.seek(0);
        Self::queue_advanced_pdu(queue, address, endpoint_id, pdu, route, None, aie_request, Some(reporter));
    }

    /// Reset an acknowledged original link without releasing the SNDCP/PDP
    /// context. TS 100 392-2 22.3.3.2.4 requires the service user to stop
    /// using a link after N.273 exhaustion. Clause 22.3.3.1.1 defines
    /// AL-SETUP(Reset) as the in-place recovery procedure and requires both
    /// sequence directions and the old data buffers to be reset.
    fn begin_advanced_link_reset(&mut self, queue: &mut MessageQueue, issi: u32, failed_ns: u8, reason: &'static str) {
        let route = Self::packet_routes(&self.config, issi).first().cloned();
        let Some(link) = self.advanced_links.get_mut(&issi) else {
            return;
        };
        if link.reset.is_some() {
            return;
        }

        let aie_request = link
            .tx
            .iter()
            .find(|sdu| sdu.ns == failed_ns)
            .or_else(|| link.tx.front())
            .map(|sdu| sdu.aie_request)
            .unwrap_or_else(|| AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource));
        let failed_position = link.tx.iter().position(|sdu| sdu.ns == failed_ns);
        let mut retained = VecDeque::new();
        let mut abandoned = 0;
        for (position, mut sdu) in link.tx.drain(..).enumerate() {
            let never_offered = Some(position) != failed_position
                && sdu.attempt_reporter.is_none()
                && sdu.sent_at.is_none()
                && sdu.reporter.get_state() == TxState::Pending
                && !sdu.acknowledgement_requested
                && sdu.ack_request_repetitions == 0
                && sdu.retransmissions == 0
                && sdu.segment_retransmissions.iter().all(|repetitions| *repetitions == 0)
                && sdu.pending_segments.is_none();
            if never_offered {
                sdu.ns = (retained.len() as u8) & 0x07;
                retained.push_back(sdu);
            } else {
                Self::mark_reporter_lost(&sdu.reporter);
                abandoned += 1;
            }
        }
        let retained_count = retained.len();
        link.tx = retained;
        link.next_tx_ns = (retained_count as u8) & 0x07;
        link.next_rx_ns = 0;
        link.rx_sdus.clear();
        link.receiver_ready = false;
        link.receiver_not_ready_since = None;
        link.ready = false;
        link.setup_started_at = None;

        let setup = AlSetup {
            acknowledged: true,
            link_number: link.link_number,
            maximum_sdu: link.maximum_sdu,
            connection_width: link.slots > 1,
            asymmetric: false,
            uplink_slots: (link.slots > 1).then_some(link.slots),
            downlink_slots: None,
            throughput: link.throughput,
            window_size: link.window_size,
            sdu_retransmissions: link.max_sdu_retransmissions,
            segment_retransmissions: link.max_segment_retransmissions,
            report: 3,
        };
        let endpoint_id = link.endpoint_id;
        let attempt_reporter = TxReporter::new();
        link.reset = Some(AdvancedLinkReset {
            setup,
            aie_request,
            attempt_reporter: attempt_reporter.clone(),
            sent_at: None,
            retries: 0,
        });
        tracing::warn!(
            issi,
            ns = failed_ns,
            abandoned_tlsdus = abandoned,
            retained_tlsdus = retained_count,
            reason,
            "advanced-link transfer failed; starting in-place AL-SETUP reset"
        );
        Self::queue_advanced_link_reset_attempt(
            queue,
            TetraAddress::issi(issi),
            endpoint_id,
            setup,
            route,
            aie_request,
            attempt_reporter,
        );
    }

    fn advanced_segments(mut tl_sdu: BitBuffer) -> Vec<BitBuffer> {
        let mut protected = BitBuffer::new_autoexpand(tl_sdu.get_len_remaining() + 32);
        let length = tl_sdu.get_len_remaining();
        protected.copy_bits(&mut tl_sdu, length);
        let checksum = fcs::compute_fcs(&protected, 0, protected.get_len_written());
        protected.write_bits(checksum.into(), 32);
        protected.seek(0);

        let total_bits = protected.get_len_remaining();
        let mut segment_lengths = Vec::new();
        if total_bits <= AL_DOWNLINK_SEGMENT_BITS_WITH_EVENT_LABEL_AND_GRANT {
            segment_lengths.push(total_bits);
        } else {
            let segment_count = total_bits.div_ceil(AL_DOWNLINK_SEGMENT_BITS_WITH_EVENT_LABEL_AND_GRANT);
            // TIP 6.5 permits the first segment to differ, but equal-sized
            // non-final downlink segments avoid receiver-specific ambiguity.
            // Choose the largest uniform length that leaves at least the
            // complete 32-bit FCS in AL-FINAL.
            let non_final_length =
                AL_DOWNLINK_SEGMENT_BITS_WITH_EVENT_LABEL_AND_GRANT.min((total_bits - AL_FINAL_FCS_BITS) / (segment_count - 1));
            segment_lengths.resize(segment_count - 1, non_final_length);
            segment_lengths.push(total_bits - non_final_length * (segment_count - 1));
        }

        let mut segments = Vec::with_capacity(segment_lengths.len());
        for length in segment_lengths {
            let mut segment = BitBuffer::new_autoexpand(length);
            segment.copy_bits(&mut protected, length);
            segment.seek(0);
            segments.push(segment);
        }
        segments
    }

    fn rx_tla_tldata_req_al(&mut self, prim: TlaTlDataReqAl) -> Result<(), TlaTlDataReqAl> {
        let issi = prim.main_address.ssi;
        let Some(link) = self.advanced_links.get_mut(&issi) else {
            return Err(prim);
        };
        if link.link_number != 0 || link.tx.len() >= MAX_PENDING_ADVANCED_TLSDUS_PER_LINK {
            return Err(prim);
        }
        let reporter = prim.tx_reporter.unwrap_or_else(TxReporter::new);
        let segments = Self::advanced_segments(prim.tl_sdu);
        let ns = link.next_tx_ns;
        link.next_tx_ns = (link.next_tx_ns + 1) & 0x07;
        link.endpoint_id = prim.endpoint_id;
        link.tx.push_back(AdvancedTxSdu {
            ns,
            segment_retransmissions: vec![0; segments.len()],
            segments,
            chan_alloc: prim.chan_alloc,
            endpoint_id: prim.endpoint_id,
            aie_request: prim
                .air_interface_encryption
                .unwrap_or_else(|| AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource)),
            reporter,
            attempt_reporter: None,
            acknowledgement_requested: false,
            sent_at: None,
            ack_request_repetitions: 0,
            retransmissions: 0,
            pending_segments: None,
        });
        Ok(())
    }

    fn queue_pending_advanced_data(&mut self, prim: TlaTlDataReqAl) {
        let issi = prim.main_address.ssi;
        let linked = self.advanced_links.get(&issi).map_or(0, |link| link.tx.len());
        let pending = self.pending_advanced_data.entry(issi).or_default();
        if linked + pending.len() >= MAX_PENDING_ADVANCED_TLSDUS_PER_LINK {
            if let Some(reporter) = &prim.tx_reporter {
                Self::mark_reporter_lost(reporter);
            }
            tracing::warn!(
                issi,
                linked,
                pending = pending.len(),
                limit = MAX_PENDING_ADVANCED_TLSDUS_PER_LINK,
                "advanced-link setup queue full; rejecting packet data"
            );
            return;
        }
        pending.push_back(PendingAdvancedData {
            prim,
            queued_at: self.dltime,
        });
        tracing::debug!(
            issi,
            queued = pending.len(),
            "holding packet data until advanced-link setup completes"
        );
    }

    /// Move setup-waiting packet data into the negotiated AL in original
    /// arrival order.  Entries without any AL are failed after the bounded
    /// setup interval; entries already attached to a Service change are
    /// failed by that negotiation's timeout instead.
    fn process_pending_advanced_data(&mut self) -> bool {
        let now = self.dltime;
        let mut activity = false;
        let issis = self.pending_advanced_data.keys().copied().collect::<Vec<_>>();
        for issi in issis {
            let Some(mut pending) = self.pending_advanced_data.remove(&issi) else {
                continue;
            };
            let mut retained = VecDeque::new();
            while let Some(mut entry) = pending.pop_front() {
                if now.diff(entry.queued_at) >= AL_SETUP_NEGOTIATION_TIMEOUT as i32 {
                    if let Some(reporter) = &entry.prim.tx_reporter {
                        Self::mark_reporter_lost(reporter);
                    }
                    tracing::warn!(issi, "advanced-link setup did not start before packet-data timeout");
                    activity = true;
                    continue;
                }
                match self.rx_tla_tldata_req_al(entry.prim) {
                    Ok(()) => activity = true,
                    Err(prim) => {
                        entry.prim = prim;
                        retained.push_back(entry);
                        retained.append(&mut pending);
                        break;
                    }
                }
            }
            if !retained.is_empty() {
                self.pending_advanced_data.insert(issi, retained);
            }
        }
        activity
    }

    fn rx_tla_tldata_req_al_message(&mut self, message: SapMsg) {
        let SapMsgInner::TlaTlDataReqAl(prim) = message.msg else { panic!() };
        if let Err(prim) = self.rx_tla_tldata_req_al(prim) {
            self.queue_pending_advanced_data(prim);
        }
    }

    fn send_al_ack(
        queue: &mut MessageQueue,
        address: TetraAddress,
        endpoint_id: u32,
        route: Option<tetra_saps::tma::AssociatedChannel>,
        aie_request: AieRequest,
        blocks: Vec<AlAckBlock>,
    ) {
        let mut pdu = BitBuffer::new_autoexpand(32);
        let result = (AlAck {
            receiver_ready: true,
            blocks,
        })
        .to_bitbuf(&mut pdu);
        match result {
            Ok(()) => {
                pdu.seek(0);
                Self::queue_advanced_pdu(queue, address, endpoint_id, pdu, route, None, aie_request, None);
            }
            Err(error) => {
                tracing::warn!(issi = address.ssi, ?error, "failed to encode advanced-link acknowledgement");
            }
        }
    }

    fn deliver_advanced_sdu(queue: &mut MessageQueue, prim: &tetra_saps::tma::TmaUnitdataInd, mut sdu: BitBuffer) {
        sdu.seek(0);
        queue.push_back(SapMsg::new(
            Sap::TlaSap,
            TetraEntity::Llc,
            TetraEntity::Mle,
            SapMsgInner::TlaTlDataIndBl(TlaTlDataIndBl {
                main_address: prim.main_address,
                link_id: 0,
                endpoint_id: prim.endpoint_id,
                new_endpoint_id: prim.new_endpoint_id,
                css_endpoint_id: prim.css_endpoint_id,
                tl_sdu: Some(sdu),
                scrambling_code: prim.scrambling_code,
                fcs_flag: true,
                air_interface_encryption: prim.air_interface_encryption,
                chan_change_resp_req: prim.chan_change_response_req,
                chan_change_handle: prim.chan_change_handle,
                chan_info: prim.chan_info,
                req_handle: 0,
            }),
        ));
    }

    fn handle_al_setup(&mut self, queue: &mut MessageQueue, prim: &tetra_saps::tma::TmaUnitdataInd, mut pdu: BitBuffer) {
        let Ok(request) = AlSetup::from_bitbuf(&mut pdu) else {
            tracing::warn!(issi = prim.main_address.ssi, "invalid AL-SETUP");
            return;
        };
        if request.link_number != 0 || request.asymmetric {
            tracing::warn!(
                issi = prim.main_address.ssi,
                link_number = request.link_number,
                asymmetric = request.asymmetric,
                "unsupported TIP advanced-link profile"
            );
            return;
        }
        // TTR 001-05 figures 26 and 29 make AL-SETUP a negotiation: a
        // Service definition or Service change is answered, while Success
        // completes the exchange.  Answering a Success with another Success
        // causes the MS and SwMI to keep the setup transaction alive while
        // user data is already waiting behind it.
        if !matches!(request.report, 0..=4) {
            tracing::warn!(
                issi = prim.main_address.ssi,
                report = request.report,
                "ignored reserved AL-SETUP report"
            );
            return;
        }
        let requested_slots = request.uplink_slots.unwrap_or(1);
        let slots = requested_slots.clamp(1, 3);
        let maximum_sdu = request.maximum_sdu.min(6);
        let window_size = request.window_size.clamp(1, 3);
        let successful_response = matches!(request.report, 0 | 4);
        let changed = slots != requested_slots || maximum_sdu != request.maximum_sdu || window_size != request.window_size;
        // A constrained Service definition is answered with Service change.
        // The link only becomes usable when the MS confirms that proposal
        // with Success.  Every other request is completed by our queued
        // Success response (or is itself that Success response).
        let awaiting_peer_success = request.report == 1 && changed;
        let negotiated_link = AdvancedLink {
            link_number: 0,
            maximum_sdu,
            slots,
            throughput: request.throughput,
            window_size,
            max_sdu_retransmissions: request.sdu_retransmissions,
            max_segment_retransmissions: request.segment_retransmissions,
            endpoint_id: prim.endpoint_id,
            next_tx_ns: 0,
            next_rx_ns: 0,
            receiver_ready: true,
            receiver_not_ready_since: None,
            ready: !awaiting_peer_success,
            setup_started_at: awaiting_peer_success.then_some(self.dltime),
            rx_sdus: BTreeMap::new(),
            tx: VecDeque::new(),
            reset: None,
        };
        if successful_response {
            if let Some(link) = self.advanced_links.get_mut(&prim.main_address.ssi) {
                // Keep sequence variables and queued data from the proposal
                // that this Success confirms.
                link.maximum_sdu = maximum_sdu;
                link.slots = slots;
                link.throughput = request.throughput;
                link.window_size = window_size;
                link.max_sdu_retransmissions = request.sdu_retransmissions;
                link.max_segment_retransmissions = request.segment_retransmissions;
                link.endpoint_id = prim.endpoint_id;
                link.ready = true;
                link.setup_started_at = None;
                link.receiver_not_ready_since = None;
                if link.reset.take().is_some() {
                    // begin_advanced_link_reset already cleared both sequence
                    // directions and the old buffers. Success makes the link
                    // available again; data queued while waiting starts at
                    // the new N(S)=0 boundary.
                    link.receiver_ready = true;
                    tracing::info!(issi = prim.main_address.ssi, "in-place advanced-link reset accepted by terminal");
                }
            } else {
                self.advanced_links.insert(prim.main_address.ssi, negotiated_link);
            }
        } else {
            if let Some(mut old) = self.advanced_links.remove(&prim.main_address.ssi) {
                for sdu in old.tx.drain(..) {
                    Self::mark_reporter_lost(&sdu.reporter);
                }
            }
            self.advanced_links.insert(prim.main_address.ssi, negotiated_link);
        }
        if !successful_response {
            let response = AlSetup {
                acknowledged: true,
                link_number: 0,
                maximum_sdu,
                connection_width: slots > 1,
                asymmetric: false,
                uplink_slots: (slots > 1).then_some(slots),
                downlink_slots: None,
                throughput: request.throughput,
                window_size,
                sdu_retransmissions: request.sdu_retransmissions,
                segment_retransmissions: request.segment_retransmissions,
                // A Service change received from the MS is accepted with
                // Success.  A locally constrained Service definition is
                // answered with Service change and awaits the MS Success.
                report: if request.report == 1 && changed { 2 } else { 0 },
            };
            let mut response_pdu = BitBuffer::new_autoexpand(32);
            if response.to_bitbuf(&mut response_pdu).is_ok() {
                response_pdu.seek(0);
                let route = Self::packet_route(&self.config, prim.main_address.ssi, self.dltime.add_timeslots(-2).t);
                let aie = prim.air_interface_encryption.unwrap_or_else(|| {
                    AieRequest::clear(
                        AieSubject::Individual {
                            issi: prim.main_address.ssi,
                        },
                        AieScope::MacResource,
                    )
                });
                Self::queue_advanced_pdu(queue, prim.main_address, prim.endpoint_id, response_pdu, route, None, aie, None);
            }
        }
        self.process_pending_advanced_data();
        if awaiting_peer_success {
            tracing::info!(
                issi = prim.main_address.ssi,
                slots,
                window_size,
                maximum_sdu,
                "advanced-link service change proposed; awaiting terminal Success"
            );
        } else {
            tracing::info!(
                issi = prim.main_address.ssi,
                slots,
                window_size,
                maximum_sdu,
                setup_report = request.report,
                "established original acknowledged advanced link"
            );
        }
    }

    fn handle_al_data(&mut self, queue: &mut MessageQueue, prim: &tetra_saps::tma::TmaUnitdataInd, mut pdu: BitBuffer) {
        let Ok(header) = AlDataHeader::from_bitbuf(&mut pdu) else {
            tracing::warn!(issi = prim.main_address.ssi, "invalid AL-DATA/FINAL");
            return;
        };
        let issi = prim.main_address.ssi;
        let route = Self::packet_route(&self.config, issi, self.dltime.add_timeslots(-2).t);
        let aie = prim
            .air_interface_encryption
            .unwrap_or_else(|| AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource));
        let Some(link) = self.advanced_links.get_mut(&issi) else {
            tracing::warn!(issi, "AL-DATA received without an established advanced link");
            return;
        };
        if link.reset.is_some() {
            tracing::debug!(issi, "discarding AL-DATA while acknowledged advanced link is resetting");
            return;
        }
        let distance = header.ns.wrapping_sub(link.next_rx_ns) & 0x07;
        if distance >= link.window_size {
            // An acknowledgement may be lost even though the complete SDU
            // was delivered.  Note 6 of 22.3.3.2.7 requires the receiver to
            // positively acknowledge retransmissions from every N(S) in the
            // N.272 positions below its current window.
            let behind = link.next_rx_ns.wrapping_sub(header.ns) & 0x07;
            if (1..=link.window_size).contains(&behind) {
                tracing::debug!(
                    issi,
                    lower = link.next_rx_ns,
                    received = header.ns,
                    "acknowledging retransmitted TL-SDU below receive window"
                );
                let blocks = (0..behind)
                    .map(|offset| AlAckBlock {
                        nr: (header.ns + offset) & 0x07,
                        acknowledgement_length: 0,
                        first_missing_segment: None,
                        acknowledgement_bitmap: Vec::new(),
                    })
                    .collect();
                Self::send_al_ack(queue, prim.main_address, prim.endpoint_id, route, aie, blocks);
            } else {
                tracing::warn!(
                    issi,
                    lower = link.next_rx_ns,
                    window_size = link.window_size,
                    received = header.ns,
                    "AL-DATA outside receive window"
                );
            }
            return;
        }

        let rx = link.rx_sdus.entry(header.ns).or_insert_with(|| AdvancedRxSdu {
            ns: header.ns,
            segments: BTreeMap::new(),
            final_segment: None,
            complete: None,
        });
        if rx.complete.is_some() {
            // This SDU is complete but cannot be delivered until a gap at the
            // lower edge closes.  Repeat its positive acknowledgement.
            let blocks = link.acknowledgement_blocks(None);
            Self::send_al_ack(queue, prim.main_address, prim.endpoint_id, route, aie, blocks);
            return;
        }
        pdu.set_raw_start(pdu.get_raw_pos());
        pdu.seek(0);
        rx.segments.entry(header.segment).or_insert(pdu);
        if header.final_segment {
            rx.final_segment = Some(header.segment);
        }

        let complete = rx
            .final_segment
            .is_some_and(|last| (0..=last).all(|segment| rx.segments.contains_key(&segment)));
        let mut fcs_failed = false;
        let should_ack = if complete {
            let last = rx.final_segment.expect("complete receive state has final segment");
            let total_bits = (0..=last)
                .filter_map(|segment| rx.segments.get(&segment))
                .map(BitBuffer::get_len_remaining)
                .sum();
            let mut assembled = BitBuffer::new_autoexpand(total_bits);
            for segment in 0..=last {
                let mut bits = rx.segments.get(&segment).expect("complete receive state has segment").clone();
                let length = bits.get_len_remaining();
                assembled.copy_bits(&mut bits, length);
            }
            assembled.seek(0);
            if fcs::check_fcs(&assembled) {
                assembled.set_raw_end(assembled.get_raw_end() - 32);
                assembled.seek(0);
                rx.complete = Some(assembled);
            } else {
                fcs_failed = true;
            }
            true
        } else if header.acknowledgement_requested {
            true
        } else {
            false
        };

        if fcs_failed {
            // The sender must retransmit this same N(S) from segment 0.
            link.rx_sdus.remove(&header.ns);
        }
        if should_ack {
            let override_block = fcs_failed.then_some(AlAckBlock {
                nr: header.ns,
                acknowledgement_length: 63,
                first_missing_segment: None,
                acknowledgement_bitmap: Vec::new(),
            });
            let blocks = link.acknowledgement_blocks(override_block);
            Self::send_al_ack(queue, prim.main_address, prim.endpoint_id, route, aie, blocks);
        }

        // Completion and acknowledgement are independent from ordered
        // delivery.  Advance the receive window only over a consecutive run
        // of correct TL-SDUs beginning at its lower boundary.
        let mut delivered = Vec::new();
        loop {
            let lower = link.next_rx_ns;
            let Some(mut ready) = link.rx_sdus.remove(&lower) else {
                break;
            };
            let Some(sdu) = ready.complete.take() else {
                link.rx_sdus.insert(lower, ready);
                break;
            };
            debug_assert_eq!(ready.ns, lower);
            delivered.push(sdu);
            link.next_rx_ns = (lower + 1) & 0x07;
        }
        for sdu in delivered {
            Self::deliver_advanced_sdu(queue, prim, sdu);
        }
    }

    fn handle_al_ack(&mut self, queue: &mut MessageQueue, prim: &tetra_saps::tma::TmaUnitdataInd, mut pdu: BitBuffer) {
        let Ok(ack) = AlAck::from_bitbuf(&mut pdu) else {
            tracing::warn!(issi = prim.main_address.ssi, "invalid AL-ACK/RNR");
            return;
        };
        let now = self.dltime;
        let issi = prim.main_address.ssi;
        let Some(link) = self.advanced_links.get_mut(&issi) else {
            return;
        };
        if link.reset.is_some() {
            tracing::debug!(issi, "ignoring stale AL-ACK while acknowledged advanced link is resetting");
            return;
        }
        link.receiver_ready = ack.receiver_ready;
        // TS 100 392-2 22.3.3.2.5: an AL-RNR remains valid from the most
        // recent RNR for T.271. Refreshing this timestamp prevents an MS
        // that keeps reporting busy from being treated as ready too early.
        link.receiver_not_ready_since = (!ack.receiver_ready).then_some(now);
        let mut failed_ns = None;
        let complete_window_report = ack.blocks.len() == usize::from(link.window_size)
            && ack.blocks.windows(2).all(|blocks| blocks[1].nr == (blocks[0].nr + 1) & 0x07);
        if complete_window_report {
            let receiver_base = ack.blocks[0].nr;
            // The acknowledgement blocks start at the peer's current receive
            // window. A previously missing base disappears from the next
            // report once its selective retransmission has completed, so
            // retire sent entries which the peer's window has passed.
            loop {
                let Some(front) = link.tx.front() else {
                    break;
                };
                if front.ns == receiver_base {
                    break;
                }
                let advance = receiver_base.wrapping_sub(front.ns) & 0x07;
                let was_sent =
                    front.attempt_reporter.is_some() || front.sent_at.is_some() || front.reporter.get_state() != TxState::Pending;
                if advance == 0 || advance > link.window_size || !was_sent {
                    break;
                }
                let sdu = link.tx.pop_front().expect("advanced-link send window has a front");
                Self::mark_advanced_sdu_acknowledged(&sdu);
                tracing::debug!(
                    issi,
                    ns = sdu.ns,
                    receiver_base,
                    "retired advanced-link TL-SDU passed by peer receive window"
                );
            }
        }
        for block in ack.blocks {
            tracing::debug!(
                issi = prim.main_address.ssi,
                receiver_ready = ack.receiver_ready,
                nr = block.nr,
                acknowledgement_length = block.acknowledgement_length,
                first_missing_segment = block.first_missing_segment,
                acknowledgement_bitmap = ?block.acknowledgement_bitmap,
                "received advanced-link acknowledgement block"
            );
            let Some(position) = link.tx.iter().position(|sdu| sdu.ns == block.nr) else {
                continue;
            };
            let was_sent = {
                let sdu = &link.tx[position];
                sdu.attempt_reporter.is_some() || sdu.sent_at.is_some() || sdu.reporter.get_state() != TxState::Pending
            };
            // A TIP acknowledgement covers the whole N.272 receive window,
            // which can include a TL-SDU that this transmitter has queued but
            // has not put on air yet.  Such a block carries no information for
            // the local sending state.
            if !was_sent {
                continue;
            }
            if block.acknowledgement_length == 0 {
                if let Some(sdu) = link.tx.remove(position) {
                    Self::mark_advanced_sdu_acknowledged(&sdu);
                }
                continue;
            }

            let sdu = &mut link.tx[position];
            // Receipt of any acknowledgement block proves that the peer saw
            // the AR. Subsequent recovery is governed by N.273/N.274.
            sdu.ack_request_repetitions = 0;
            sdu.acknowledgement_requested = false;
            if block.acknowledgement_length == 63 {
                sdu.retransmissions = sdu.retransmissions.saturating_add(1);
                sdu.pending_segments = None;
            } else if let Some(first) = block.first_missing_segment {
                let mut missing = vec![first as usize];
                for (offset, received) in block.acknowledgement_bitmap.iter().copied().enumerate() {
                    if !received {
                        missing.push(first as usize + offset + 1);
                    }
                }
                missing.retain(|segment| *segment < sdu.segments.len());
                let segment_limit_exceeded = missing.iter().any(|segment| {
                    sdu.segment_retransmissions[*segment] = sdu.segment_retransmissions[*segment].saturating_add(1);
                    sdu.segment_retransmissions[*segment] > link.max_segment_retransmissions
                });
                if segment_limit_exceeded {
                    sdu.retransmissions = sdu.retransmissions.saturating_add(1);
                    sdu.pending_segments = None;
                } else if !missing.is_empty() {
                    sdu.pending_segments = Some(missing);
                }
            }
            if sdu.reporter.get_state() == TxState::Transmitted {
                sdu.reporter.reset();
            }
            sdu.sent_at = None;
            sdu.attempt_reporter = None;
            if sdu.retransmissions > link.max_sdu_retransmissions {
                failed_ns = Some(sdu.ns);
                break;
            }
        }
        if let Some(failed_ns) = failed_ns {
            self.begin_advanced_link_reset(queue, issi, failed_ns, "N.273/N.274 retry limit exceeded");
        }
    }

    fn handle_al_reconnect(&mut self, queue: &mut MessageQueue, prim: &tetra_saps::tma::TmaUnitdataInd, mut pdu: BitBuffer) {
        let Ok(request) = AlReconnect::from_bitbuf(&mut pdu) else {
            return;
        };
        // Only the MS initiates advanced-link roaming.  Accepting or replying
        // to an "accept"/"reject" report here would turn a response into a
        // new request and can create an AL-RECONNECT exchange loop.
        if request.report != 0 {
            tracing::warn!(
                issi = prim.main_address.ssi,
                report = request.report,
                "ignored non-propose AL-RECONNECT from MS"
            );
            return;
        }
        let accepted = request.link_number == 0
            && self.advanced_links.get_mut(&prim.main_address.ssi).is_some_and(|link| {
                // Reconnection carries every link parameter and sequence
                // variable forward.  Only the MAC endpoint changes with
                // the new cell/resource.
                link.endpoint_id = prim.endpoint_id;
                true
            });
        let response = AlReconnect {
            acknowledged: true,
            link_number: request.link_number,
            report: if accepted { 2 } else { 1 },
        };
        let mut response_pdu = BitBuffer::new_autoexpand(16);
        if response.to_bitbuf(&mut response_pdu).is_ok() {
            response_pdu.seek(0);
            let aie = prim.air_interface_encryption.unwrap_or_else(|| {
                AieRequest::clear(
                    AieSubject::Individual {
                        issi: prim.main_address.ssi,
                    },
                    AieScope::MacResource,
                )
            });
            Self::queue_advanced_pdu(
                queue,
                prim.main_address,
                prim.endpoint_id,
                response_pdu,
                Self::packet_route(&self.config, prim.main_address.ssi, self.dltime.add_timeslots(-2).t),
                None,
                aie,
                None,
            );
        }
    }

    fn handle_al_disconnect(&mut self, queue: &mut MessageQueue, prim: &tetra_saps::tma::TmaUnitdataInd, mut pdu: BitBuffer) {
        let Ok(request) = AlDisconnect::from_bitbuf(&mut pdu) else {
            return;
        };
        if request.link_number != 0 {
            return;
        }
        if let Some(mut link) = self.advanced_links.remove(&prim.main_address.ssi) {
            for sdu in link.tx.drain(..) {
                Self::mark_reporter_lost(&sdu.reporter);
            }
        }
        if let Some(mut pending) = self.pending_advanced_data.remove(&prim.main_address.ssi) {
            for entry in pending.drain(..) {
                if let Some(reporter) = &entry.prim.tx_reporter {
                    Self::mark_reporter_lost(reporter);
                }
            }
        }
        // Success confirms a Close previously sent by this side. Only an
        // incoming Close is answered; echoing Success starts an AL-DISC loop.
        if request.report != 1 {
            return;
        }
        let mut response_pdu = BitBuffer::new_autoexpand(16);
        AlDisconnect {
            acknowledged: true,
            link_number: 0,
            report: 0,
        }
        .to_bitbuf(&mut response_pdu);
        response_pdu.seek(0);
        let aie = prim.air_interface_encryption.unwrap_or_else(|| {
            AieRequest::clear(
                AieSubject::Individual {
                    issi: prim.main_address.ssi,
                },
                AieScope::MacResource,
            )
        });
        Self::queue_advanced_pdu(
            queue,
            prim.main_address,
            prim.endpoint_id,
            response_pdu,
            Self::packet_route(&self.config, prim.main_address.ssi, self.dltime.add_timeslots(-2).t),
            None,
            aie,
            None,
        );
    }

    fn rx_tma_unitdata_ind_al(&mut self, queue: &mut MessageQueue, mut message: SapMsg, pdu_type: LlcPduType) {
        let SapMsgInner::TmaUnitdataInd(prim) = &mut message.msg else {
            return;
        };
        let Some(pdu) = prim.pdu.take() else {
            return;
        };
        match pdu_type {
            LlcPduType::AlSetup => self.handle_al_setup(queue, prim, pdu),
            LlcPduType::AlDataAlFinal => self.handle_al_data(queue, prim, pdu),
            LlcPduType::AlAckAlRnr => self.handle_al_ack(queue, prim, pdu),
            LlcPduType::AlReconnect => self.handle_al_reconnect(queue, prim, pdu),
            LlcPduType::AlDisc => self.handle_al_disconnect(queue, prim, pdu),
            LlcPduType::AlAlUdataAlUfinal => {
                tracing::warn!(
                    issi = prim.main_address.ssi,
                    "unacknowledged advanced link is outside the TIP profile"
                )
            }
            _ => unreachable!(),
        }
    }

    fn submit_advanced_link_messages(&mut self, queue: &mut MessageQueue) -> bool {
        let now = self.dltime;
        let mut activity = false;
        let mut failed_links = Vec::new();
        let mut setup_failures = Vec::new();
        let mut negotiation_failures = Vec::new();
        // A queued TL-SDU can outlive a PDCH resize. Resolve the routes at
        // submission time so segments and selective retransmissions never
        // target a timeslot that voice has taken from packet data.
        let active_routes = self
            .advanced_links
            .iter()
            .map(|(&issi, link)| {
                (
                    issi,
                    Self::packet_routes(&self.config, issi)
                        .into_iter()
                        .take(link.slots as usize)
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<HashMap<_, _>>();
        for (issi, link) in &mut self.advanced_links {
            if let Some(reset) = link.reset.as_mut() {
                let retry = match reset.attempt_reporter.get_state() {
                    TxState::Transmitted | TxState::Acknowledged => {
                        let sent_at = *reset.sent_at.get_or_insert(now);
                        now.diff(sent_at) >= T261_SETUP_WAITING_TIMER as i32
                    }
                    TxState::Discarded | TxState::Lost => true,
                    TxState::Pending => false,
                };
                if retry {
                    if reset.retries < N262_AL_MAX_CONNECTION_SETUP_RETRIES {
                        reset.retries += 1;
                        reset.sent_at = None;
                        let reporter = TxReporter::new();
                        reset.attempt_reporter = reporter.clone();
                        tracing::info!(
                            issi = *issi,
                            attempt = reset.retries,
                            maximum = N262_AL_MAX_CONNECTION_SETUP_RETRIES,
                            "repeating in-place AL-SETUP reset after T.261"
                        );
                        Self::queue_advanced_link_reset_attempt(
                            queue,
                            TetraAddress::issi(*issi),
                            link.endpoint_id,
                            reset.setup,
                            active_routes[issi].first().cloned(),
                            reset.aie_request,
                            reporter,
                        );
                        activity = true;
                    } else {
                        setup_failures.push(*issi);
                    }
                }
                continue;
            }

            if !link.ready {
                if link
                    .setup_started_at
                    .is_some_and(|started| now.diff(started) >= AL_SETUP_NEGOTIATION_TIMEOUT as i32)
                {
                    negotiation_failures.push(*issi);
                }
                continue;
            }

            let mut failed_ns = None;
            for sdu in link.tx.iter_mut() {
                if let Some(attempt) = &sdu.attempt_reporter {
                    match attempt.get_state() {
                        TxState::Transmitted | TxState::Acknowledged => {
                            if sdu.reporter.get_state() == TxState::Pending {
                                sdu.reporter.mark_transmitted();
                            }
                            if sdu.acknowledgement_requested {
                                sdu.sent_at.get_or_insert(now);
                            }
                        }
                        TxState::Discarded | TxState::Lost => {
                            sdu.attempt_reporter = None;
                            sdu.acknowledgement_requested = false;
                            sdu.sent_at = None;
                        }
                        TxState::Pending => {}
                    }
                }
                let timed_out = sdu.sent_at.is_some_and(|sent| now.diff(sent) >= T252_ACK_WAITING_TIMER as i32);
                if timed_out {
                    if sdu.ack_request_repetitions < MAX_AL_ACK_REQUEST_REPEATS {
                        sdu.ack_request_repetitions += 1;
                        if sdu.reporter.get_state() == TxState::Transmitted {
                            sdu.reporter.reset();
                        }
                        sdu.attempt_reporter = None;
                        sdu.acknowledgement_requested = false;
                        sdu.sent_at = None;
                        // TS 100 392-2 section 22.3.3.2.3 and TTR 001-05
                        // figure 34: repeat an already transmitted segment
                        // with AR after T.252. This is independent of N.273.
                        sdu.pending_segments = Some(vec![sdu.segments.len().saturating_sub(1)]);
                        tracing::info!(
                            issi = *issi,
                            ns = sdu.ns,
                            attempt = sdu.ack_request_repetitions,
                            maximum = MAX_AL_ACK_REQUEST_REPEATS,
                            "repeating advanced-link acknowledgement request after T.252"
                        );
                    } else if sdu.retransmissions >= link.max_sdu_retransmissions {
                        failed_ns = Some(sdu.ns);
                        break;
                    } else {
                        sdu.retransmissions += 1;
                        if sdu.reporter.get_state() == TxState::Transmitted {
                            sdu.reporter.reset();
                        }
                        sdu.attempt_reporter = None;
                        sdu.acknowledgement_requested = false;
                        sdu.sent_at = None;
                        sdu.ack_request_repetitions = 0;
                        sdu.pending_segments = None;
                    }
                }
            }
            if let Some(failed_ns) = failed_ns {
                failed_links.push((*issi, failed_ns));
                continue;
            }

            let mut receiver_not_ready = !link.receiver_ready;
            if receiver_not_ready {
                let receiver_not_ready_expired = link
                    .receiver_not_ready_since
                    .is_some_and(|since| now.diff(since) >= T271_RECEIVER_NOT_READY_FOR_TX_TIMER as i32);
                if receiver_not_ready_expired {
                    // T.271 expiry is an active recovery point, rather than
                    // a permanent flow-control state. Resume from the oldest
                    // unacknowledged N(S) below.
                    link.receiver_ready = true;
                    link.receiver_not_ready_since = None;
                    receiver_not_ready = false;
                    tracing::info!(issi = *issi, "resuming advanced-link transmission after receiver-not-ready timer");
                } else if link.receiver_not_ready_since.is_none() {
                    // `receiver_ready = false` also represents the distinct
                    // AL-SETUP reset state. That path is handled above and
                    // must not be mistaken for a peer AL-RNR.
                    continue;
                }
            }
            let routes = &active_routes[issi];
            if routes.is_empty() {
                continue;
            }
            // On a frequency-simplex MS the downlink batch must finish before
            // the one reserved uplink acknowledgement opportunity.  Do not
            // create a second independent AR while that turn is still
            // pending.  TTR 001-05 §7.12.2 and TS 100 392-2 §22.3.3.2.3 then
            // allow the sender to fill the negotiated N.272 window and ask
            // for a single acknowledgement on its final segment.
            if link.tx.iter().any(|sdu| sdu.acknowledgement_requested) {
                continue;
            }
            let in_flight = link
                .tx
                .iter()
                .filter(|sdu| sdu.attempt_reporter.is_some() || sdu.sent_at.is_some())
                .count();
            let window_size = link.window_size.clamp(1, 3);
            let Some(send_base) = link.tx.front().map(|sdu| sdu.ns) else {
                continue;
            };
            let generation_end = link
                .tx
                .iter()
                .enumerate()
                .skip(1)
                .find_map(|(index, sdu)| (sdu.ns == send_base).then_some(index))
                .unwrap_or(link.tx.len());
            let window_capacity = usize::from(window_size);
            let available = window_capacity.saturating_sub(in_flight.min(window_capacity));
            let selected_sdus = link
                .tx
                .iter_mut()
                .enumerate()
                .filter_map(|(index, sdu)| {
                    let sequence_distance = sdu.ns.wrapping_sub(send_base) & 0x07;
                    (index < generation_end
                        && sequence_distance < window_size
                        && sdu.attempt_reporter.is_none()
                        && sdu.sent_at.is_none()
                        && !sdu.acknowledgement_requested
                        && sdu.retransmissions <= link.max_sdu_retransmissions
                        // An AL-RNR suppresses new TL-SDUs, but ETSI
                        // 22.3.3.2.5 permits retransmitting the segments it
                        // (or an earlier acknowledgement) identified as
                        // missing while the flow-control timer is running.
                        && (!receiver_not_ready || sdu.pending_segments.as_ref().is_some_and(|segments| !segments.is_empty())))
                    .then_some(index)
                })
                .take(available)
                .collect::<Vec<_>>();
            let Some(&acknowledgement_sdu) = selected_sdus.last() else {
                continue;
            };
            for sdu_index in selected_sdus {
                let sdu = &mut link.tx[sdu_index];
                let request_acknowledgement = sdu_index == acknowledgement_sdu;
                let selected = sdu
                    .pending_segments
                    .clone()
                    .filter(|segments| !segments.is_empty())
                    .unwrap_or_else(|| (0..sdu.segments.len()).collect());
                // The final selected segment of the batch carries the only
                // AR.  Earlier TL-SDUs keep their per-attempt reporters so
                // their delivery is accounted for when that one AL-ACK covers
                // the whole N.272 window, but they do not force a premature
                // half-duplex turn or an extra uplink grant.
                let attempt_reporter = TxReporter::new();
                for (selected_index, segment_index) in selected.iter().copied().enumerate() {
                    let mut pdu = BitBuffer::new_autoexpand(AL_DOWNLINK_SEGMENT_BITS_WITH_EVENT_LABEL_AND_GRANT + 24);
                    let last_selected = selected_index + 1 == selected.len();
                    let final_segment = segment_index + 1 == sdu.segments.len();
                    let header = AlDataHeader {
                        final_segment,
                        acknowledgement_requested: request_acknowledgement && last_selected,
                        ns: sdu.ns,
                        segment: segment_index as u8,
                    };
                    if header.to_bitbuf(&mut pdu).is_err() {
                        continue;
                    }
                    let mut payload = sdu.segments[segment_index].clone();
                    let length = payload.get_len_remaining();
                    pdu.copy_bits(&mut payload, length);
                    pdu.seek(0);
                    // TIP 6.10 defines every member of a multislot PDCH as
                    // equivalent. Spread the successive S(S) values of one
                    // TL-SDU across the *current* bearer so a large packet
                    // makes use of every assigned slot. These routes are
                    // resolved immediately before submission: a resize may
                    // have removed a slot since SNDCP queued the TL-SDU.
                    //
                    // UMAC enforces the complementary rule: an S(S) is not
                    // transmitted before any lower S(S) for the same N(S),
                    // even when the preceding segment was deferred for a
                    // half-duplex uplink turn or a full SCH/F block.
                    let route = Some(routes[segment_index % routes.len()]);
                    Self::queue_advanced_pdu(
                        queue,
                        TetraAddress::issi(*issi),
                        sdu.endpoint_id,
                        pdu,
                        route,
                        last_selected.then(|| sdu.chan_alloc.clone()).flatten(),
                        sdu.aie_request,
                        last_selected.then(|| attempt_reporter.clone()),
                    );
                }
                sdu.attempt_reporter = Some(attempt_reporter);
                sdu.acknowledgement_requested = request_acknowledgement;
                sdu.pending_segments = None;
                activity = true;
            }
        }
        for (issi, failed_ns) in failed_links {
            self.begin_advanced_link_reset(queue, issi, failed_ns, "T.252 acknowledgement recovery exhausted");
            activity = true;
        }
        for issi in setup_failures {
            if let Some(mut link) = self.advanced_links.remove(&issi) {
                for sdu in link.tx.drain(..) {
                    Self::mark_reporter_lost(&sdu.reporter);
                }
            }
            tracing::warn!(
                issi,
                retries = N262_AL_MAX_CONNECTION_SETUP_RETRIES,
                "in-place advanced-link reset failed after T.261 retries; leaving link idle"
            );
            activity = true;
        }
        for issi in negotiation_failures {
            if let Some(mut link) = self.advanced_links.remove(&issi) {
                for sdu in link.tx.drain(..) {
                    Self::mark_reporter_lost(&sdu.reporter);
                }
            }
            tracing::warn!(issi, "advanced-link Service change was not confirmed before setup timeout");
            activity = true;
        }
        activity
    }

    /// See Clause 22.3.2.3 for Acknowledged data transmission in basic link
    fn rx_tla_tldata_req_bl(&mut self, _queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tla_tldata_req_bl");
        let SapMsgInner::TlaTlDataReqBl(mut prim) = message.msg else {
            panic!()
        };

        let packet_data = prim.packet_data_flag;
        let force_common_channel = packet_data
            && prim
                .chan_alloc
                .as_ref()
                .is_some_and(|allocation| allocation.alloc_type == ChanAllocType::Replace);
        // TTR 001-05 figures 13 and 15 carry the SN-DATA TRANSMIT RESPONSE
        // and its Replace allocation on CCCH.  An existing AL is retained in
        // STANDBY, but must not capture this new CCCH-to-PDCH assignment.
        if prim.stealing_permission {
            panic!("Can't send BL-DATA for STCH message");
        }
        if prim.main_address.ssi_type == SsiType::Gssi {
            panic!("Can't send BL-DATA for GSSI-addressed message. ");
        }

        // If an ack still needs to be sent, get the relevant expected sequence number
        let outgoing_aie_request = prim.air_interface_encryption.unwrap_or_else(|| {
            AieRequest::clear(
                AieSubject::Individual {
                    issi: prim.main_address.ssi,
                },
                AieScope::MacResource,
            )
        });
        let delivery_timeslot = prim
            .associated_channel
            .as_ref()
            .map(|channel| channel.timeslot)
            .or_else(|| {
                Self::delivery_routes(&self.config, prim.main_address.ssi, self.dltime)
                    .first()
                    .map(|channel| channel.timeslot)
            })
            .unwrap_or(1);
        let out_ack_n = self.get_out_ack_seq_if_any(prim.main_address, delivery_timeslot, outgoing_aie_request);

        // Get per-link send sequence number N(S) = V(S), then toggle V(S)
        let ns = self.get_next_send_seq(&prim.main_address);

        // Construct PDU, write header
        let mut pdu_buf = BitBuffer::new_autoexpand(32);
        let sdu_len = prim.tl_sdu.get_len_remaining();
        let checksum = prim
            .fcs_flag
            .then(|| fcs::compute_fcs(&prim.tl_sdu, prim.tl_sdu.get_pos(), prim.tl_sdu.get_len()));

        // Determine message type and build
        if let Some(out_ack_n) = out_ack_n {
            // BL-ADATA (acknowledged, with or without FCS)
            let pdu = BlAdata {
                has_fcs: prim.fcs_flag,
                nr: out_ack_n,
                ns,
            };
            pdu.to_bitbuf(&mut pdu_buf);
            // Append SDU
            pdu_buf.copy_bits(&mut prim.tl_sdu, sdu_len);
            if let Some(checksum) = checksum {
                pdu_buf.write_bits(checksum.into(), 32);
            }
            pdu_buf.seek(0);
            tracing::debug!(ts=%self.dltime, "-> {:?} sdu {}", pdu, pdu_buf.dump_bin());
        } else {
            // BL-DATA (acknowledged, with or without FCS) — ETSI Clause 22.3.2.3
            let pdu = BlData {
                has_fcs: prim.fcs_flag,
                ns,
            };
            pdu.to_bitbuf(&mut pdu_buf);
            // Append SDU
            pdu_buf.copy_bits(&mut prim.tl_sdu, sdu_len);
            if let Some(checksum) = checksum {
                pdu_buf.write_bits(checksum.into(), 32);
            }
            pdu_buf.seek(0);
            tracing::debug!(ts=%self.dltime, "-> {:?} sdu {}", pdu, pdu_buf.dump_bin());
        }

        // Either take tx_reporter passed down or create a new one
        let tx_reporter = prim.tx_reporter.take().unwrap_or_else(|| TxReporter::new());

        let sapmsg = SapMsg {
            sap: Sap::TmaSap,
            src: self.entity(),
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                req_handle: prim.req_handle,
                pdu: pdu_buf,
                main_address: prim.main_address,
                endpoint_id: prim.endpoint_id,
                stealing_permission: prim.stealing_permission,
                subscriber_class: prim.subscriber_class,
                air_interface_encryption: prim.air_interface_encryption,
                stealing_repeats_flag: prim.stealing_repeats_flag,
                data_category: prim.data_class_info,
                chan_alloc: prim.chan_alloc,
                associated_channel: prim.associated_channel,
                assigned_channel_frame18_broadcast: false,
                tx_reporter: Some(tx_reporter.clone()),
            }),
        };

        // The basic-link acknowledgement returns on the associated traffic
        // channel when this message was delivered through FN18; otherwise it
        // uses the MCCH.  Keep that context for retransmission/accounting.
        let ack_timeslot = prim.associated_channel.as_ref().map(|channel| channel.timeslot).unwrap_or(1);
        self.outbound_messages.push_back(ExpectedInAck {
            ns,
            addr: prim.main_address,
            ts: ack_timeslot,
            bl_type: Layer2Service::Acknowledged,
            force_common_channel,
            packet_data,
            tx_reporter,
            attempt_reporters: Vec::new(),
            attempt_timeslots: Vec::new(),
            observed_transmitted_copies: 0,
            t_first: self.dltime,
            t_submitted_to_umac: None,
            t_umac_done: None,
            has_transmitted_attempt: false,
            retransmission_buf: sapmsg, // Clone the message to keep a copy for potential retransmission
            retransmit_count: 0,
        });

        // The message will now be picked up for transmission at end-of-tick, if the ssi does not yet have
        // a pending message waiting for an ack.
    }

    fn rx_tla_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tla_prim");
        match &message.msg {
            SapMsgInner::TlaTlDataReqAl(_) => {
                self.rx_tla_tldata_req_al_message(message);
            }
            SapMsgInner::TlaTlDataReqBl(_) => {
                self.rx_tla_tldata_req_bl(queue, message);
            }
            SapMsgInner::TlaTlUnitdataReqBl(_) => {
                self.rx_tla_tlunitdata_req_bl(queue, message);
            }
            _ => panic!(),
        }
    }

    fn rx_tma_report_ind(&mut self, _queue: &mut MessageQueue, mut _message: SapMsg) {
        tracing::trace!("rx_tma_report_ind, ignoring");
    }

    /// Clause 20.4.1.1.4 TMA-UNITDATA primitive
    /// TMA-UNITDATA indication: this primitive shall be used by the MAC to deliver a received TM-SDU. This primitive
    /// may also be used with no TM-SDU if the MAC needs to inform the higher layers of a channel allocation received
    /// without an associated TM-SDU.
    fn rx_tma_unitdata_ind(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("rx_tma_unitdata_ind");

        // Determine which type of TL-SDU we have
        let pdu_type = if let SapMsgInner::TmaUnitdataInd(prim) = &mut message.msg {
            let Some(pdu) = prim.pdu.as_ref() else {
                panic!("no pdu");
            };
            let Some(bits) = pdu.peek_bits(4) else {
                tracing::warn!("insufficient bits: {}", pdu.dump_bin());
                return;
            };
            let Ok(pdu_type) = LlcPduType::try_from(bits) else {
                tracing::warn!("invalid pdu type: {} in {}", bits, pdu.dump_bin());
                return;
            };

            pdu_type
        } else {
            panic!();
        };

        // Supplementary LLC and layer-2 signalling PDUs are standard LLC
        // types, even though this BS does not yet implement their services.
        // Keep their subtype and sender for diagnostics, but never let an
        // unsupported radio PDU take the complete base station down.
        let (issi, llc_subtype) = if let SapMsgInner::TmaUnitdataInd(prim) = &message.msg {
            let llc_subtype = prim.pdu.as_ref().and_then(|pdu| pdu.peek_bits(8)).map(|bits| (bits & 0x0f) as u8);
            (prim.main_address.ssi, llc_subtype)
        } else {
            unreachable!("TMA indication checked above");
        };

        // Call handler function
        match pdu_type {
            // All Basic Link types can be handled by the same function
            LlcPduType::BlAdata
            | LlcPduType::BlAdataFcs
            | LlcPduType::BlData
            | LlcPduType::BlDataFcs
            | LlcPduType::BlUdata
            | LlcPduType::BlUdataFcs
            | LlcPduType::BlAck
            | LlcPduType::BlAckFcs => {
                self.rx_tma_unitdata_ind_bl(queue, message);
            }

            LlcPduType::AlSetup
            | LlcPduType::AlDataAlFinal
            | LlcPduType::AlAlUdataAlUfinal
            | LlcPduType::AlAckAlRnr
            | LlcPduType::AlReconnect
            | LlcPduType::AlDisc => {
                self.rx_tma_unitdata_ind_al(queue, message, pdu_type);
            }

            LlcPduType::SuppLlcPdu | LlcPduType::L2SigPdu => {
                tracing::warn!(
                    issi,
                    ?pdu_type,
                    llc_subtype,
                    "discarding unsupported supplementary/layer-2 signalling LLC PDU"
                );
            }
        }
    }

    fn rx_tma_unitdata_ind_bl(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("rx_tma_unitdata_ind_bl");

        // Get header bits (again) and prepare MLE message
        let SapMsgInner::TmaUnitdataInd(prim) = &mut message.msg else {
            panic!();
        };
        let Some(mut pdu) = prim.pdu.take() else {
            panic!("no pdu");
        };
        let Some(bits) = pdu.peek_bits(4) else {
            tracing::warn!("insufficient bits: {}", pdu.dump_bin());
            return;
        };
        let Ok(pdu_type) = LlcPduType::try_from(bits) else {
            tracing::warn!("invalid pdu type: {} in {}", bits, pdu.dump_bin());
            return;
        };

        let (has_fcs, ns, nr) = match pdu_type {
            LlcPduType::BlAdata | LlcPduType::BlAdataFcs => match BlAdata::from_bitbuf(&mut pdu) {
                Ok(pdu) => {
                    tracing::debug!(ts=%self.dltime, "<- {:?}", pdu);
                    (pdu.has_fcs, Some(pdu.ns), Some(pdu.nr))
                }
                Err(e) => {
                    tracing::warn!("Failed parsing BlAdata: {:?} {}", e, pdu.dump_bin());
                    return;
                }
            },

            LlcPduType::BlData | LlcPduType::BlDataFcs => match BlData::from_bitbuf(&mut pdu) {
                Ok(pdu) => {
                    tracing::debug!(ts=%self.dltime, "<- {:?}", pdu);
                    (pdu.has_fcs, Some(pdu.ns), None)
                }
                Err(e) => {
                    tracing::warn!("Failed parsing BlData: {:?} {}", e, pdu.dump_bin());
                    return;
                }
            },
            LlcPduType::BlAck | LlcPduType::BlAckFcs => match BlAck::from_bitbuf(&mut pdu) {
                Ok(pdu) => {
                    tracing::debug!(ts=%self.dltime, "<- {:?}", pdu);
                    (pdu.has_fcs, None, Some(pdu.nr))
                }
                Err(e) => {
                    tracing::warn!("Failed parsing BlAck: {:?} {}", e, pdu.dump_bin());
                    return;
                }
            },
            LlcPduType::BlUdata | LlcPduType::BlUdataFcs => match BlUdata::from_bitbuf(&mut pdu) {
                Ok(pdu) => {
                    tracing::debug!(ts=%self.dltime, "<- {:?}", pdu);
                    (pdu.has_fcs, None, None)
                }
                Err(e) => {
                    tracing::warn!("Failed parsing BlUdata: {:?} {}", e, pdu.dump_bin());
                    return;
                }
            },
            _ => {
                panic!();
            }
        };

        // If FCS is present, check it. If wrong, we bail here
        if has_fcs && !fcs::check_fcs(&pdu) {
            tracing::warn!("FCS check failed");
            return;
        }

        let clear_from_bound_sc2_terminal = matches!(prim.air_interface_encryption, Some(AieRequest::Clear { .. }) | None) && {
            let state = self.config.state_read();
            state.aie.enabled
                && state.subscribers.is_registered(prim.main_address.ssi)
                && !state.aie_sessions.terminal_allows_clear(prim.main_address.ssi)
        };
        if clear_from_bound_sc2_terminal {
            let bare_ack_bits = if has_fcs { 36 } else { 4 };
            let transition_ack = matches!(pdu_type, LlcPduType::BlAck | LlcPduType::BlAckFcs)
                && pdu.get_len_remaining() <= bare_ack_bits
                && nr.is_some_and(|ack_nr| self.clear_transition_ack_expected(prim.main_address, ack_nr));
            let mm_bootstrap = matches!(
                pdu.peek_bits(3).and_then(|bits| MleProtocolDiscriminator::try_from(bits).ok()),
                Some(MleProtocolDiscriminator::Mm)
            );
            if !transition_ack && !mm_bootstrap {
                tracing::warn!(
                    issi = prim.main_address.ssi,
                    ?pdu_type,
                    "rejecting clear post-SC2 basic-link PDU outside MM bootstrap and transition ACK allow-lists"
                );
                return;
            }
        }

        // If ns is present, we need to send an ACK
        let msg_dltime = self.dltime.add_timeslots(-2); // Msg on uplink was sent two timeslots ago.
        if let Some(ns) = ns {
            // Send ACK
            let incoming_aie_request = prim.air_interface_encryption.unwrap_or_else(|| {
                AieRequest::clear(
                    AieSubject::Individual {
                        issi: prim.main_address.ssi,
                    },
                    AieScope::MacData,
                )
            });
            self.schedule_outgoing_ack(msg_dltime, prim.main_address, ns, incoming_aie_request);
        }

        // if nr is present, we have received an ACK on a previous message
        if let Some(nr) = nr {
            let incoming_aie_request = prim.air_interface_encryption.unwrap_or_else(|| {
                AieRequest::clear(
                    AieSubject::Individual {
                        issi: prim.main_address.ssi,
                    },
                    AieScope::MacData,
                )
            });
            self.process_incoming_ack(prim.main_address, nr, incoming_aie_request);
        }

        if pdu_type == LlcPduType::BlAck || pdu_type == LlcPduType::BlAckFcs {
            // A bare BL-ACK can carry up to four radio-fill bits after its
            // five-bit header; those are not a TL-SDU.
            if pdu.get_len_remaining() <= 4 {
                return;
            }
            // Some MS implementations piggyback the acknowledged TL-SDU on
            // the BL-ACK that confirms its downlink.  In particular this is
            // how the tested terminals return an SS-DGNA ASSIGN ACK.  The
            // five LLC ACK bits have already been consumed, so pass the
            // remaining TL-SDU through the normal acknowledged-data path.
            tracing::debug!(
                ts = %self.dltime,
                payload_bits = pdu.get_len_remaining(),
                "delivering BL-ACK piggyback payload"
            );
        }

        // If unacknowledged data transfer service, we send a TL-UNITDATA indication
        // to MLE. If acknowledged data transfer service, we send a TL-DATA indication
        pdu.set_raw_start(pdu.get_raw_pos());
        let s = if pdu_type == LlcPduType::BlUdata || pdu_type == LlcPduType::BlUdataFcs {
            // Unacknowledged data transfer service
            let m = TlaTlUnitdataIndBl {
                // address_type: 0, // TODO FIXME
                main_address: prim.main_address,
                link_id: 0,
                endpoint_id: prim.endpoint_id,
                new_endpoint_id: prim.new_endpoint_id,
                css_endpoint_id: prim.css_endpoint_id,
                tl_sdu: if pdu.get_len_remaining() > 0 { Some(pdu) } else { None },
                scrambling_code: prim.scrambling_code,
                fcs_flag: has_fcs,
                air_interface_encryption: prim.air_interface_encryption,
                chan_change_resp_req: prim.chan_change_response_req,
                chan_change_handle: prim.chan_change_handle,
                chan_info: prim.chan_info,
                report: None, // TODO FIXME
            };
            SapMsg {
                sap: Sap::TlaSap,
                src: TetraEntity::Llc,
                dest: TetraEntity::Mle,
                msg: SapMsgInner::TlaTlUnitdataIndBl(m),
            }
        } else {
            // Acknowledged data transfer service
            let m = TlaTlDataIndBl {
                // address_type: 0, // TODO FIXME
                main_address: prim.main_address,
                link_id: 0,
                endpoint_id: prim.endpoint_id,
                new_endpoint_id: prim.new_endpoint_id,
                css_endpoint_id: prim.css_endpoint_id,
                tl_sdu: if pdu.get_len_remaining() > 0 { Some(pdu) } else { None },
                scrambling_code: prim.scrambling_code,
                fcs_flag: has_fcs,
                air_interface_encryption: prim.air_interface_encryption,
                chan_change_resp_req: prim.chan_change_response_req,
                chan_change_handle: prim.chan_change_handle,
                chan_info: prim.chan_info,
                req_handle: 0, // TODO FIXME
            };
            SapMsg {
                sap: Sap::TlaSap,
                src: TetraEntity::Llc,
                dest: TetraEntity::Mle,
                msg: SapMsgInner::TlaTlDataIndBl(m),
            }
        };

        queue.push_back(s);
    }

    fn submit_retransmissions_to_umac(&mut self, queue: &mut MessageQueue) -> bool {
        let mut had_activity = false;
        let dltime = self.dltime;
        let mut removals: Option<Vec<u32>> = None;

        // if !self.outbound_messages.is_empty() {
        //     tracing::error!("{}", Self::format_expected_ack_list(&self.outbound_messages));
        // }

        for ack in self.outbound_messages.iter_mut() {
            // First, check which have newly been txed, or discarded by Umac. If so, start t_umac_done.
            let transmitted_route_count = ack.attempt_reporters.iter().filter(|reporter| reporter.is_transmitted()).count();
            let all_routes_done = !ack.attempt_reporters.is_empty()
                && ack
                    .attempt_reporters
                    .iter()
                    .all(|reporter| reporter.is_transmitted() || reporter.is_discarded());
            if transmitted_route_count > ack.observed_transmitted_copies {
                // T.251 belongs to the basic-link transmission, so start it as
                // soon as a concurrent copy reaches the air. If another copy
                // completes later, restart it from that complete transmission;
                // retransmitting while that route is still fragmented corrupts
                // the receiver's MAC reconstruction chain.
                ack.has_transmitted_attempt = true;
                ack.observed_transmitted_copies = transmitted_route_count;
                if !ack.tx_reporter.is_transmitted() {
                    ack.tx_reporter.reset();
                    ack.tx_reporter.mark_transmitted();
                }
                ack.t_umac_done = Some(self.dltime);
                tracing::trace!("schedule_retransmissions: {} umac_done at {}", ack.addr.ssi, dltime);
            } else if ack.t_umac_done.is_none() && all_routes_done {
                // Every route was discarded before transmission. Use the same
                // retry window before selecting a fresh live route set.
                ack.t_umac_done = Some(self.dltime);
                tracing::trace!("schedule_retransmissions: {} all routes discarded at {}", ack.addr.ssi, dltime);
            }

            // If we don't have a t_umac_done, there is no need for a retransmission in any case
            let Some(t_umac_done) = ack.t_umac_done else {
                continue;
            };

            // Retransmit scenario 1: it was transmitted but no ack received within the expected window (ETSI T.251 / N.252)
            // Retransmission scenario 2: it has been dropped by Umac due to congestion. Retransmit after same window
            let age = dltime.diff(t_umac_done); // Never fails
            let retry_timer = Self::basic_link_retry_timer(ack);
            let max_retransmits = Self::max_over_air_retransmits(ack);
            if age as u32 >= retry_timer {
                let pending_window = Self::pending_route_completion_window(&self.config, ack);
                let attempt_age = ack.t_submitted_to_umac.map(|submitted| dltime.diff(submitted)).unwrap_or(i32::MAX);
                if pending_window > 0 && attempt_age >= 0 && (attempt_age as u32) < pending_window {
                    tracing::debug!(
                        issi = ack.addr.ssi,
                        ns = ack.ns,
                        attempt_age,
                        pending_window,
                        "deferring basic-link retry while a concurrent route copy is unfinished"
                    );
                    continue;
                }
                // Time for either retransmitting or giving up
                if ack.retransmit_count < max_retransmits {
                    // Retransmit
                    ack.retransmit_count += 1;
                    tracing::info!(
                        "retransmitting SSI {} N(S) {} attempt {}{}",
                        ack.addr.ssi,
                        ack.ns,
                        ack.retransmit_count,
                        if Self::has_assigned_channel_context(ack) {
                            " after assigned-channel grace"
                        } else {
                            ""
                        }
                    );

                    Self::submit_for_acknowledged_transmission(&self.config, queue, ack, self.dltime.forward_to_timeslot(ack.t_first.t));
                    had_activity = true;
                } else if Self::final_ack_grace_elapsed(age, retry_timer, Self::has_assigned_channel_context(ack)) {
                    // Exhausted retransmissions, flag for discard
                    removals.get_or_insert(Vec::new()).push(ack.addr.ssi);
                }
            }
        }

        // Remove any expired entries
        if let Some(removals) = removals {
            for ssi in removals {
                let ack = self.take_expected_ack_for_ssi(ssi).unwrap(); // Never fails
                tracing::warn!(
                    "schedule_retransmissions: SSI {} N(S) {} exhausted retransmissions",
                    ack.addr.ssi,
                    ack.ns
                );
                Self::mark_reporter_lost(&ack.tx_reporter);
            }
            // The ack expires here
        }

        had_activity
    }

    fn submit_free_messages_to_umac(&mut self, queue: &mut MessageQueue) -> bool {
        let mut had_activity = false;
        let mut ssi_blocked: HashSet<u32> = HashSet::new();
        for ack in self.outbound_messages.iter_mut() {
            // Check if already submitted to umac
            if ack.t_submitted_to_umac.is_some() {
                // This ssi currently waits for an ack, and is thus blocked
                ssi_blocked.insert(ack.addr.ssi);
                continue;
            }

            // Not submitted; check if blocked
            if ssi_blocked.contains(&ack.addr.ssi) {
                // SSI already has another message waiting for ack, so we cannot submit this one yet
                tracing::debug!(
                    "SSI {} N(S) {} still blocked by previous message, cannot submit next message",
                    ack.addr.ssi,
                    ack.ns
                );
                continue;
            }

            // Not submitted and not blocked. We can submit it now.
            // tracing::debug!("submitting message for SSI {} N(S) {} to umac", ack.addr.ssi, ack.ns);
            tracing::debug!(
                "submitting message for SSI {} N(S) {} to umac: {:?}",
                ack.addr.ssi,
                ack.ns,
                ack.retransmission_buf.msg
            );
            Self::submit_for_acknowledged_transmission(&self.config, queue, ack, self.dltime.forward_to_timeslot(ack.t_first.t));
            ssi_blocked.insert(ack.addr.ssi);
            had_activity = true;
        }

        had_activity
    }

    /// Pops all elements from the scheduled_out_acks queue, prepares BL-ACK messages, and send them down
    fn submit_ack_replies_to_umac(&mut self, queue: &mut MessageQueue) -> bool {
        let had_activity = !self.scheduled_out_acks.is_empty();
        while let Some(ack) = self.scheduled_out_acks.pop_front() {
            tracing::debug!("auto-ack for ssi: {}, n: {}, ts: {}", ack.addr.ssi, ack.nr, ack.ts);

            // An assigned PDCH is an SCH/F signalling channel, even though it
            // uses TS2..4. Sending its BL-ACK as FACCH leaves the ACK queued
            // forever when no voice circuit exists, so the MS repeats the
            // uplink SDS and blocks packet traffic. Preserve the live packet
            // route and reserve stealing for an actual traffic channel.
            let packet_route = Self::packet_route(&self.config, ack.addr.ssi, ack.ts);
            let steal = matches!(ack.ts, 2..=4) && packet_route.is_none();
            let mut pdu_buf = BitBuffer::new_autoexpand(5);
            let pdu = BlAck {
                has_fcs: false,
                nr: ack.nr,
            };
            pdu.to_bitbuf(&mut pdu_buf);
            pdu_buf.seek(0);
            tracing::debug!(ts=%self.dltime, "-> {:?} {}", pdu, pdu_buf.dump_bin());

            // We're sending an ACK for a received uplink message, however, we don't have that message here
            // Since DL is two slots ahead of UL, we will correct that. We now have the dltime for reception
            // of the original message.
            let chan_alloc = match steal {
                true => {
                    let mut timeslots = [false; 4];
                    timeslots[(ack.ts - 1) as usize] = true;
                    Some(CmceChanAllocReq {
                        usage: None,
                        timeslots,
                        alloc_type: ChanAllocType::Replace,
                        cell_change_flag: false,
                        ul_dl_assigned: UlDlAssignment::Both,
                        carrier: None,
                    })
                }
                false => None,
            };
            let sapmsg = SapMsg {
                sap: Sap::TmaSap,
                src: TetraEntity::Llc,
                dest: TetraEntity::Umac,
                msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                    req_handle: 0, // TODO FIXME
                    pdu: pdu_buf,
                    main_address: ack.addr,
                    endpoint_id: 0, // todo fixme
                    stealing_permission: steal,
                    subscriber_class: 0, // TODO FIXME
                    air_interface_encryption: Some(ack.aie_request.with_scope(AieScope::MacResource)),
                    stealing_repeats_flag: None, // TODO FIXME
                    data_category: None,         // TODO FIXME
                    chan_alloc,
                    associated_channel: packet_route,
                    assigned_channel_frame18_broadcast: false,
                    tx_reporter: None, // By definition, no higher layer entity is interested
                }),
            };
            queue.push_back(sapmsg);
        }
        had_activity
    }

    /// Pops all elements from the scheduled_out_acks queue, prepares BL-ACK messages, and send them down
    fn submit_udata_msgs_to_umac(&mut self, queue: &mut MessageQueue) -> bool {
        let had_activity = !self.outbound_udata_messages.is_empty();
        while let Some(msg) = self.outbound_udata_messages.pop_front() {
            tracing::debug!("submitting udata msg to umac: {:?}", msg.msg);
            queue.push_back(msg);
        }
        had_activity
    }

    fn format_expected_ack_list(ack_list: &VecDeque<ExpectedInAck>) -> String {
        let mut ret = String::new();
        ret.push_str("Expected in acks:\n");
        for ack in ack_list {
            ret.push_str(&format!(
                "  ssi: {}, n: {}, retransmissions: {}, t_first: {:?}, t_umac_done: {:?}, state: {:?}\n",
                ack.addr.ssi,
                ack.ns,
                ack.retransmit_count,
                ack.t_first,
                ack.t_umac_done,
                ack.tx_reporter.get_state()
            ));
        }
        ret
    }

    fn format_scheduled_ack_list(ack_list: &Vec<ScheduledOutAck>) -> String {
        let mut ret = String::new();
        ret.push_str("Scheduled out acks:\n");
        for ack in ack_list {
            ret.push_str(&format!("  t_start: {}, ssi: {}, n: {}\n", ack.t_start.t, ack.addr.ssi, ack.nr));
        }
        ret
    }
}

impl TetraEntityTrait for Llc {
    fn entity(&self) -> TetraEntity {
        TetraEntity::Llc
    }

    fn set_config(&mut self, config: SharedConfig) {
        self.config = config;
    }

    fn rx_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::debug!("rx_prim: {:?}", message);
        // tracing::debug!(ts=%message.dltime, "rx_prim: {:?}", message);

        match message.sap {
            Sap::TmaSap => {
                self.rx_tma_prim(queue, message);
            }

            // TMB-SAP and TMC-SAP are skipped and passed straight between MAC and MLE
            Sap::TlaSap => {
                self.rx_tla_prim(queue, message);
            }
            _ => panic!(),
        }
    }

    fn tick_start(&mut self, _queue: &mut MessageQueue, ts: TdmaTime) {
        self.dltime = ts;
    }

    fn tick_end(&mut self, queue: &mut MessageQueue, _ts: TdmaTime) -> bool {
        let mut had_activity = false;

        // Step 1 / 4: Check if we have any transmitted messages that were not acked within the expected window
        // Schedule a retransmission if appropriate.
        had_activity |= self.submit_retransmissions_to_umac(queue);

        // Step 2 / 4: Check if there are any messages that were not yet sent down, that we can now send down the stack
        // Messages may be kept since the target SSI has not yet acked them . If the link is now free, we can send the message down and register that we expect an ACK for it.
        had_activity |= self.submit_free_messages_to_umac(queue);

        // Step 3 / 4: Check if any unsent ACKs are still here
        // Take oldest element from scheduled_out_acks, and remove it from the list
        had_activity |= self.submit_ack_replies_to_umac(queue);

        // Step 4 / 4: Send any U-DATA messages
        had_activity |= self.submit_udata_msgs_to_umac(queue);

        had_activity |= self.process_pending_advanced_data();

        // Packet data is deliberately submitted after all basic-link and
        // control work; UMAC applies the same ordering inside packet bearers.
        had_activity |= self.submit_advanced_link_messages(queue);

        had_activity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tetra_saps::tma::TmaUnitdataInd;

    fn test_config() -> SharedConfig {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let shared = SharedConfig::from_parts(config, None);
        shared.state_write().subscriber_packet_delivery_routes.insert(
            77_468,
            vec![
                tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 32,
                    timeslot: 2,
                    usage: 55,
                },
                tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 32,
                    timeslot: 3,
                    usage: 55,
                },
                tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 32,
                    timeslot: 4,
                    usage: 55,
                },
            ],
        );
        shared
    }

    fn advanced_indication(issi: u32, pdu: BitBuffer) -> SapMsg {
        SapMsg::new(
            Sap::TmaSap,
            TetraEntity::Umac,
            TetraEntity::Llc,
            SapMsgInner::TmaUnitdataInd(TmaUnitdataInd {
                pdu: Some(pdu),
                main_address: TetraAddress::issi(issi),
                scrambling_code: 0,
                endpoint_id: 7,
                new_endpoint_id: None,
                css_endpoint_id: None,
                air_interface_encryption: Some(AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacData)),
                chan_change_response_req: false,
                chan_change_handle: None,
                chan_info: None,
            }),
        )
    }

    fn establish_advanced_link(llc: &mut Llc, queue: &mut MessageQueue, issi: u32) {
        llc.dltime = TdmaTime { h: 0, m: 1, f: 2, t: 4 };
        let mut pdu = BitBuffer::new_autoexpand(32);
        AlSetup {
            acknowledged: true,
            link_number: 0,
            maximum_sdu: 6,
            connection_width: true,
            asymmetric: false,
            uplink_slots: Some(3),
            downlink_slots: None,
            throughput: 7,
            window_size: 2,
            sdu_retransmissions: 3,
            segment_retransmissions: 5,
            report: 1,
        }
        .to_bitbuf(&mut pdu)
        .unwrap();
        pdu.seek(0);
        llc.rx_tma_unitdata_ind(queue, advanced_indication(issi, pdu));
    }

    fn receive_advanced_sdu(llc: &mut Llc, queue: &mut MessageQueue, issi: u32, ns: u8, payload: BitBuffer) {
        let segments = Llc::advanced_segments(payload);
        for (index, mut segment) in segments.iter().cloned().enumerate() {
            let mut pdu = BitBuffer::new_autoexpand(AL_DOWNLINK_SEGMENT_BITS_WITH_EVENT_LABEL_AND_GRANT + 24);
            AlDataHeader {
                final_segment: index + 1 == segments.len(),
                acknowledgement_requested: index + 1 == segments.len(),
                ns,
                segment: index as u8,
            }
            .to_bitbuf(&mut pdu)
            .unwrap();
            let length = segment.get_len_remaining();
            pdu.copy_bits(&mut segment, length);
            pdu.seek(0);
            llc.rx_tma_unitdata_ind(queue, advanced_indication(issi, pdu));
        }
    }

    fn queue_advanced_downlink(llc: &mut Llc, _queue: &mut MessageQueue, issi: u32, payload: &str) -> TxReporter {
        let reporter = TxReporter::new();
        llc.rx_tla_tldata_req_al_message(SapMsg::new(
            Sap::TlaSap,
            TetraEntity::Mle,
            TetraEntity::Llc,
            SapMsgInner::TlaTlDataReqAl(tetra_saps::tla::TlaTlDataReqAl {
                main_address: TetraAddress::issi(issi),
                link_id: 0,
                endpoint_id: 7,
                tl_sdu: BitBuffer::from_bitstr(payload),
                stealing_permission: false,
                subscriber_class: 0,
                fcs_flag: true,
                packet_data_flag: true,
                air_interface_encryption: None,
                stealing_repeats_flag: None,
                data_class_info: None,
                req_handle: 0,
                graceful_degradation: None,
                chan_alloc: None,
                associated_channel: Llc::packet_route(&llc.config, issi, 2),
                tx_reporter: Some(reporter.clone()),
            }),
        ));
        reporter
    }

    #[test]
    fn ms_al_setup_establishes_tip_link_and_is_answered() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);

        let link = llc.advanced_links.get(&77_468).expect("advanced link established");
        assert_eq!(link.link_number, 0);
        assert_eq!(link.slots, 3);
        assert_eq!(link.window_size, 2);
        let response = queue.pop_front().expect("AL-SETUP response");
        let SapMsgInner::TmaUnitdataReq(mut response) = response.msg else {
            panic!("expected TMA response")
        };
        assert_eq!(
            response.associated_channel,
            Some(tetra_saps::tma::AssociatedChannel {
                call_id: 32,
                timeslot: 2,
                usage: 55,
                best_effort_key: None,
            })
        );
        assert_eq!(AlSetup::from_bitbuf(&mut response.pdu).unwrap().report, 0);
    }

    #[test]
    fn al_setup_success_completes_service_change_without_response() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        let mut definition = BitBuffer::new_autoexpand(32);
        AlSetup {
            acknowledged: true,
            link_number: 0,
            maximum_sdu: 6,
            connection_width: true,
            asymmetric: false,
            uplink_slots: Some(4),
            downlink_slots: None,
            throughput: 7,
            window_size: 3,
            sdu_retransmissions: 0,
            segment_retransmissions: 3,
            report: 1,
        }
        .to_bitbuf(&mut definition)
        .unwrap();
        definition.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_479, definition));

        let SapMsgInner::TmaUnitdataReq(mut change) = queue.pop_front().expect("service change response").msg else {
            panic!("expected TMA response")
        };
        assert!(!llc.advanced_links[&77_479].ready);
        let change = AlSetup::from_bitbuf(&mut change.pdu).unwrap();
        assert_eq!(change.uplink_slots, Some(3));
        assert_eq!(change.report, 2);
        llc.advanced_links.get_mut(&77_479).unwrap().next_tx_ns = 5;

        let mut success = BitBuffer::new_autoexpand(32);
        AlSetup { report: 0, ..change }.to_bitbuf(&mut success).unwrap();
        success.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_479, success));

        assert!(queue.pop_front().is_none(), "AL-SETUP Success must not be answered");
        let link = &llc.advanced_links[&77_479];
        assert!(link.ready);
        assert_eq!(link.slots, 3);
        assert_eq!(link.next_tx_ns, 5, "confirming a proposal must preserve queued-link state");
    }

    #[test]
    fn advanced_data_waits_for_al_setup_success_and_preserves_order() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        let first = queue_advanced_downlink(&mut llc, &mut queue, 77_468, "10101010");
        let second = queue_advanced_downlink(&mut llc, &mut queue, 77_468, "01010101");

        assert!(queue.pop_front().is_none(), "advanced data must never fall back to BL-DATA");
        assert_eq!(llc.pending_advanced_data[&77_468].len(), 2);
        assert!(llc.outbound_messages.is_empty());

        let mut definition = BitBuffer::new_autoexpand(32);
        AlSetup {
            acknowledged: true,
            link_number: 0,
            maximum_sdu: 6,
            connection_width: true,
            asymmetric: false,
            uplink_slots: Some(4),
            downlink_slots: None,
            throughput: 7,
            window_size: 2,
            sdu_retransmissions: 3,
            segment_retransmissions: 5,
            report: 1,
        }
        .to_bitbuf(&mut definition)
        .unwrap();
        definition.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, definition));

        assert!(!llc.advanced_links[&77_468].ready);
        assert!(!llc.pending_advanced_data.contains_key(&77_468));
        assert_eq!(
            llc.advanced_links[&77_468].tx.iter().map(|sdu| sdu.ns).collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert!(!llc.submit_advanced_link_messages(&mut queue));
        let SapMsgInner::TmaUnitdataReq(mut response) = queue.pop_front().expect("AL-SETUP Service change").msg else {
            panic!("expected TMA response")
        };
        let change = AlSetup::from_bitbuf(&mut response.pdu).unwrap();
        assert_eq!(change.report, 2);
        assert!(queue.pop_front().is_none());

        let mut success = BitBuffer::new_autoexpand(32);
        AlSetup { report: 0, ..change }.to_bitbuf(&mut success).unwrap();
        success.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, success));
        assert!(llc.advanced_links[&77_468].ready);
        assert!(llc.submit_advanced_link_messages(&mut queue));
        assert_eq!(queue.iter_mut().count(), 2);

        for expected_ns in [0, 1] {
            let SapMsgInner::TmaUnitdataReq(mut request) = queue.pop_front().unwrap().msg else {
                panic!("expected AL-DATA")
            };
            let header = AlDataHeader::from_bitbuf(&mut request.pdu).unwrap();
            assert_eq!(header.ns, expected_ns);
        }
        assert_eq!(first.get_state(), TxState::Pending);
        assert_eq!(second.get_state(), TxState::Pending);
    }

    #[test]
    fn advanced_data_without_al_setup_reports_link_failure() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        let start = TdmaTime { h: 0, m: 1, f: 1, t: 1 };
        llc.dltime = start;
        let reporter = queue_advanced_downlink(&mut llc, &mut queue, 77_468, "10101010");

        llc.dltime = start.add_timeslots(AL_SETUP_NEGOTIATION_TIMEOUT as i32);
        assert!(llc.process_pending_advanced_data());

        assert_eq!(reporter.get_state(), TxState::Lost);
        assert!(!llc.pending_advanced_data.contains_key(&77_468));
        assert!(queue.pop_front().is_none());
        assert!(llc.outbound_messages.is_empty());
    }

    #[test]
    fn advanced_uplink_reassembles_and_checks_fcs() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}
        let payload = BitBuffer::from_bitstr(&"10110010".repeat(40));
        let segments = Llc::advanced_segments(payload.clone());
        for (index, mut segment) in segments.iter().cloned().enumerate() {
            let mut pdu = BitBuffer::new_autoexpand(200);
            AlDataHeader {
                final_segment: index + 1 == segments.len(),
                acknowledgement_requested: index + 1 == segments.len(),
                ns: 0,
                segment: index as u8,
            }
            .to_bitbuf(&mut pdu)
            .unwrap();
            let length = segment.get_len_remaining();
            pdu.copy_bits(&mut segment, length);
            pdu.seek(0);
            llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, pdu));
        }

        let ack = queue.pop_front().unwrap();
        assert!(matches!(ack.msg, SapMsgInner::TmaUnitdataReq(_)));
        let delivered = queue.pop_front().unwrap();
        assert!(queue.pop_front().is_none());
        let SapMsgInner::TlaTlDataIndBl(delivered) = delivered.msg else {
            panic!("expected reassembled TL-DATA indication")
        };
        assert_eq!(delivered.tl_sdu.unwrap().dump_bin_unformatted(), payload.dump_bin_unformatted());
    }

    #[test]
    fn advanced_receive_window_buffers_out_of_order_sdus() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}
        let first = BitBuffer::from_bitstr(&"10100110".repeat(8));
        let second = BitBuffer::from_bitstr(&"01101001".repeat(8));

        receive_advanced_sdu(&mut llc, &mut queue, 77_468, 1, second.clone());
        let SapMsgInner::TmaUnitdataReq(mut acknowledgement) = queue.pop_front().unwrap().msg else {
            panic!("expected AL-ACK")
        };
        let acknowledgement = AlAck::from_bitbuf(&mut acknowledgement.pdu).unwrap();
        assert_eq!(acknowledgement.blocks.len(), 2);
        assert_eq!(acknowledgement.blocks[0].nr, 0);
        assert_eq!(acknowledgement.blocks[0].acknowledgement_length, 1);
        assert_eq!(acknowledgement.blocks[0].first_missing_segment, Some(0));
        assert_eq!(acknowledgement.blocks[1].nr, 1);
        assert_eq!(acknowledgement.blocks[1].acknowledgement_length, 0);
        assert!(queue.pop_front().is_none(), "N(S)=1 must wait for the lower window edge");

        receive_advanced_sdu(&mut llc, &mut queue, 77_468, 0, first.clone());
        assert!(matches!(queue.pop_front().unwrap().msg, SapMsgInner::TmaUnitdataReq(_)));
        for expected in [first, second] {
            let SapMsgInner::TlaTlDataIndBl(delivered) = queue.pop_front().unwrap().msg else {
                panic!("expected ordered advanced-link delivery")
            };
            assert_eq!(delivered.tl_sdu.unwrap().dump_bin_unformatted(), expected.dump_bin_unformatted());
        }
        assert!(queue.pop_front().is_none());
        assert_eq!(llc.advanced_links[&77_468].next_rx_ns, 2);
    }

    #[test]
    fn advanced_partial_ack_reports_holes_and_received_segments() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}

        let mut pdu = BitBuffer::new_autoexpand(64);
        AlDataHeader {
            final_segment: false,
            acknowledgement_requested: true,
            ns: 0,
            segment: 1,
        }
        .to_bitbuf(&mut pdu)
        .unwrap();
        pdu.write_bits(0x55, 8);
        pdu.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, pdu));

        let SapMsgInner::TmaUnitdataReq(mut acknowledgement) = queue.pop_front().unwrap().msg else {
            panic!("expected AL-ACK")
        };
        let acknowledgement = AlAck::from_bitbuf(&mut acknowledgement.pdu).unwrap();
        assert_eq!(acknowledgement.blocks.len(), 2);
        assert_eq!(
            acknowledgement.blocks[0],
            AlAckBlock {
                nr: 0,
                acknowledgement_length: 2,
                first_missing_segment: Some(0),
                acknowledgement_bitmap: vec![true],
            }
        );
        assert_eq!(
            acknowledgement.blocks[1],
            AlAckBlock {
                nr: 1,
                acknowledgement_length: 1,
                first_missing_segment: Some(0),
                acknowledgement_bitmap: Vec::new(),
            }
        );
    }

    #[test]
    fn advanced_receive_window_reacks_recently_delivered_sdu() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}
        receive_advanced_sdu(&mut llc, &mut queue, 77_468, 0, BitBuffer::from_bitstr(&"11001010".repeat(8)));
        while queue.pop_front().is_some() {}

        let mut duplicate = BitBuffer::new_autoexpand(32);
        AlDataHeader {
            final_segment: true,
            acknowledgement_requested: true,
            ns: 0,
            segment: 0,
        }
        .to_bitbuf(&mut duplicate)
        .unwrap();
        duplicate.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, duplicate));

        let SapMsgInner::TmaUnitdataReq(mut acknowledgement) = queue.pop_front().unwrap().msg else {
            panic!("expected repeated AL-ACK")
        };
        let acknowledgement = AlAck::from_bitbuf(&mut acknowledgement.pdu).unwrap();
        assert_eq!(acknowledgement.blocks[0].nr, 0);
        assert_eq!(acknowledgement.blocks[0].acknowledgement_length, 0);
        assert!(queue.pop_front().is_none(), "a retransmitted old SDU must not be delivered twice");
        assert_eq!(llc.advanced_links[&77_468].next_rx_ns, 1);
    }

    #[test]
    fn advanced_receive_window_handles_modulo_wrap() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}
        llc.advanced_links.get_mut(&77_468).unwrap().next_rx_ns = 7;
        let seven = BitBuffer::from_bitstr(&"11110000".repeat(8));
        let zero = BitBuffer::from_bitstr(&"00001111".repeat(8));

        receive_advanced_sdu(&mut llc, &mut queue, 77_468, 0, zero.clone());
        assert!(matches!(queue.pop_front().unwrap().msg, SapMsgInner::TmaUnitdataReq(_)));
        assert!(queue.pop_front().is_none());
        receive_advanced_sdu(&mut llc, &mut queue, 77_468, 7, seven.clone());
        assert!(matches!(queue.pop_front().unwrap().msg, SapMsgInner::TmaUnitdataReq(_)));
        for expected in [seven, zero] {
            let SapMsgInner::TlaTlDataIndBl(delivered) = queue.pop_front().unwrap().msg else {
                panic!("expected wrapped ordered delivery")
            };
            assert_eq!(delivered.tl_sdu.unwrap().dump_bin_unformatted(), expected.dump_bin_unformatted());
        }
        assert_eq!(llc.advanced_links[&77_468].next_rx_ns, 1);
    }

    #[test]
    fn advanced_receive_window_rejects_future_jump() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}

        receive_advanced_sdu(&mut llc, &mut queue, 77_468, 3, BitBuffer::from_bitstr(&"10101010".repeat(8)));
        assert!(queue.pop_front().is_none());
        let link = &llc.advanced_links[&77_468];
        assert_eq!(link.next_rx_ns, 0);
        assert!(link.rx_sdus.is_empty());
    }

    #[test]
    fn advanced_reconnect_preserves_link_windows_and_buffers() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}
        let reporter = TxReporter::new();
        {
            let link = llc.advanced_links.get_mut(&77_468).unwrap();
            link.next_tx_ns = 3;
            link.next_rx_ns = 7;
            link.rx_sdus.insert(
                7,
                AdvancedRxSdu {
                    ns: 7,
                    segments: BTreeMap::from([(0, BitBuffer::from_bitstr("1010"))]),
                    final_segment: None,
                    complete: None,
                },
            );
            link.tx.push_back(AdvancedTxSdu {
                ns: 2,
                segments: vec![BitBuffer::from_bitstr("0101")],
                chan_alloc: None,
                endpoint_id: 7,
                aie_request: AieRequest::clear(AieSubject::Individual { issi: 77_468 }, AieScope::MacData),
                reporter,
                attempt_reporter: None,
                acknowledgement_requested: false,
                sent_at: None,
                ack_request_repetitions: 0,
                retransmissions: 0,
                segment_retransmissions: vec![0],
                pending_segments: None,
            });
        }

        let mut reconnect = BitBuffer::new_autoexpand(16);
        AlReconnect {
            acknowledged: true,
            link_number: 0,
            report: 0,
        }
        .to_bitbuf(&mut reconnect)
        .unwrap();
        reconnect.seek(0);
        let mut indication = advanced_indication(77_468, reconnect);
        let SapMsgInner::TmaUnitdataInd(prim) = &mut indication.msg else {
            unreachable!()
        };
        prim.endpoint_id = 99;
        llc.rx_tma_unitdata_ind(&mut queue, indication);

        let link = &llc.advanced_links[&77_468];
        assert_eq!(link.next_tx_ns, 3);
        assert_eq!(link.next_rx_ns, 7);
        assert_eq!(link.tx.len(), 1);
        assert_eq!(link.rx_sdus.len(), 1);
        assert_eq!(link.endpoint_id, 99);
        let SapMsgInner::TmaUnitdataReq(mut response) = queue.pop_front().unwrap().msg else {
            panic!("expected AL-RECONNECT response")
        };
        assert_eq!(AlReconnect::from_bitbuf(&mut response.pdu).unwrap().report, 2);
    }

    #[test]
    fn advanced_downlink_completes_only_after_al_ack() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}
        let reporter = TxReporter::new();
        llc.rx_tla_tldata_req_al_message(SapMsg::new(
            Sap::TlaSap,
            TetraEntity::Mle,
            TetraEntity::Llc,
            SapMsgInner::TlaTlDataReqAl(tetra_saps::tla::TlaTlDataReqAl {
                main_address: TetraAddress::issi(77_468),
                link_id: 0,
                endpoint_id: 7,
                tl_sdu: BitBuffer::from_bitstr(&"11001010".repeat(30)),
                stealing_permission: false,
                subscriber_class: 0,
                fcs_flag: true,
                packet_data_flag: true,
                air_interface_encryption: None,
                stealing_repeats_flag: None,
                data_class_info: None,
                req_handle: 0,
                graceful_degradation: None,
                chan_alloc: None,
                associated_channel: Llc::packet_route(&llc.config, 77_468, 2),
                tx_reporter: Some(reporter.clone()),
            }),
        ));
        llc.submit_advanced_link_messages(&mut queue);
        assert_eq!(reporter.get_state(), TxState::Pending);
        let first = queue.pop_front().expect("first advanced-link segment");
        let second = queue.pop_front().expect("final advanced-link segment");
        assert!(queue.pop_front().is_none());
        let SapMsgInner::TmaUnitdataReq(first) = first.msg else {
            panic!("expected first TMA segment")
        };
        let SapMsgInner::TmaUnitdataReq(second) = second.msg else {
            panic!("expected final TMA segment")
        };
        assert_eq!(first.pdu.get_len_remaining(), 17 + 214);
        assert_eq!(
            first.associated_channel.map(|route| (route.call_id, route.timeslot, route.usage)),
            Some((32, 2, 55))
        );
        assert_eq!(
            second.associated_channel.map(|route| (route.call_id, route.timeslot, route.usage)),
            Some((32, 3, 55))
        );

        let mut ack = BitBuffer::new_autoexpand(16);
        AlAck {
            receiver_ready: true,
            blocks: vec![AlAckBlock {
                nr: 0,
                acknowledgement_length: 0,
                first_missing_segment: None,
                acknowledgement_bitmap: Vec::new(),
            }],
        }
        .to_bitbuf(&mut ack)
        .unwrap();
        ack.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, ack));
        assert_eq!(reporter.get_state(), TxState::Acknowledged);
        assert!(llc.advanced_links.get(&77_468).unwrap().tx.is_empty());
    }

    #[test]
    fn advanced_downlink_resumes_when_receiver_not_ready_timer_expires() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}
        let rnr_at = llc.dltime;
        queue_advanced_downlink(&mut llc, &mut queue, 77_468, "10101010");

        let mut rnr = BitBuffer::new_autoexpand(16);
        AlAck {
            receiver_ready: false,
            // This is a valid AL-RNR while N(S)=0 is still queued locally;
            // therefore its positive acknowledgement must not retire the
            // unsent TL-SDU.
            blocks: vec![AlAckBlock {
                nr: 0,
                acknowledgement_length: 0,
                first_missing_segment: None,
                acknowledgement_bitmap: Vec::new(),
            }],
        }
        .to_bitbuf(&mut rnr)
        .unwrap();
        rnr.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, rnr));

        let link = &llc.advanced_links[&77_468];
        assert!(!link.receiver_ready);
        assert_eq!(link.receiver_not_ready_since, Some(rnr_at));
        assert!(!llc.submit_advanced_link_messages(&mut queue));
        assert!(queue.pop_front().is_none());

        llc.dltime = rnr_at.add_timeslots(T271_RECEIVER_NOT_READY_FOR_TX_TIMER as i32 - 1);
        assert!(!llc.submit_advanced_link_messages(&mut queue));
        assert!(queue.pop_front().is_none());

        llc.dltime = rnr_at.add_timeslots(T271_RECEIVER_NOT_READY_FOR_TX_TIMER as i32);
        assert!(llc.submit_advanced_link_messages(&mut queue));
        let link = &llc.advanced_links[&77_468];
        assert!(link.receiver_ready);
        assert_eq!(link.receiver_not_ready_since, None);
        let SapMsgInner::TmaUnitdataReq(mut resumed) = queue.pop_front().expect("AL-DATA after T.271").msg else {
            panic!("expected advanced-link data")
        };
        assert_eq!(AlDataHeader::from_bitbuf(&mut resumed.pdu).unwrap().ns, 0);
    }

    #[test]
    fn advanced_downlink_retransmits_rnr_requested_segments_before_t271() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}
        queue_advanced_downlink(&mut llc, &mut queue, 77_468, &"10".repeat(200));
        assert!(llc.submit_advanced_link_messages(&mut queue));
        while queue.pop_front().is_some() {}

        let mut rnr = BitBuffer::new_autoexpand(16);
        AlAck {
            receiver_ready: false,
            blocks: vec![AlAckBlock {
                nr: 0,
                acknowledgement_length: 1,
                first_missing_segment: Some(0),
                acknowledgement_bitmap: Vec::new(),
            }],
        }
        .to_bitbuf(&mut rnr)
        .unwrap();
        rnr.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, rnr));

        let link = &llc.advanced_links[&77_468];
        assert!(!link.receiver_ready);
        assert_eq!(link.tx.front().and_then(|sdu| sdu.pending_segments.clone()), Some(vec![0]));
        assert!(llc.submit_advanced_link_messages(&mut queue));
        assert!(!llc.advanced_links[&77_468].receiver_ready);
        let SapMsgInner::TmaUnitdataReq(mut retransmission) = queue.pop_front().expect("RNR-requested AL-DATA").msg else {
            panic!("expected advanced-link data")
        };
        let header = AlDataHeader::from_bitbuf(&mut retransmission.pdu).unwrap();
        assert_eq!((header.ns, header.segment), (0, 0));
    }

    #[test]
    fn advanced_downlink_uses_uniform_segments_with_a_complete_fcs_tail() {
        let short = Llc::advanced_segments(BitBuffer::from_bitstr(&"0".repeat(64 * 8 + 19)));
        assert_eq!(
            short.iter().map(BitBuffer::get_len_remaining).collect::<Vec<_>>(),
            vec![214, 214, 135]
        );

        // When fewer than 32 bits would remain, every non-final segment must
        // be shortened equally and the final segment must contain the FCS.
        let short_remainder = Llc::advanced_segments(BitBuffer::from_bitstr(&"0".repeat(128 * 8 + 19)));
        assert_eq!(
            short_remainder.iter().map(BitBuffer::get_len_remaining).collect::<Vec<_>>(),
            vec![208, 208, 208, 208, 208, 35]
        );

        for (tl_sdu_bits, non_final_bits, final_bits) in [(4259, 212, 51), (2779, 213, 42), (411, 205, 33)] {
            let segments = Llc::advanced_segments(BitBuffer::from_bitstr(&"0".repeat(tl_sdu_bits)));
            assert!(
                segments[..segments.len() - 1]
                    .iter()
                    .all(|segment| segment.get_len_remaining() == non_final_bits),
                "all non-final segments must be uniform for a {tl_sdu_bits}-bit TL-SDU"
            );
            assert_eq!(segments.last().unwrap().get_len_remaining(), final_bits);
        }

        let long = Llc::advanced_segments(BitBuffer::from_bitstr(&"0".repeat(512 * 8 + 19)));
        assert!(long[..long.len() - 1].iter().all(|segment| segment.get_len_remaining() == 214));
        assert!(long.last().unwrap().get_len_remaining() >= 32);

        let mtu = Llc::advanced_segments(BitBuffer::from_bitstr(&"0".repeat(1500 * 8 + 19)));
        assert_eq!(mtu.len(), 57);
        assert!(mtu[..56].iter().all(|segment| segment.get_len_remaining() == 214));
        assert_eq!(mtu[56].get_len_remaining(), 67);
    }

    #[test]
    fn advanced_partial_ack_stays_within_one_original_link_block() {
        let mut segments = BTreeMap::new();
        segments.insert(61, BitBuffer::from_bitstr("1"));
        segments.insert(80, BitBuffer::from_bitstr("1"));
        let block = AdvancedRxSdu {
            ns: 3,
            segments,
            final_segment: Some(80),
            complete: None,
        }
        .acknowledgement_block();

        assert_eq!(block.nr, 3);
        assert_eq!(block.first_missing_segment, Some(0));
        assert_eq!(block.acknowledgement_length, 62);
        assert_eq!(block.acknowledgement_bitmap.len(), 61);
        assert!(block.acknowledgement_bitmap[60]);

        let mut encoded = BitBuffer::new_autoexpand(96);
        AlAck {
            receiver_ready: true,
            blocks: vec![block.clone()],
        }
        .to_bitbuf(&mut encoded)
        .unwrap();
        encoded.seek(0);
        assert_eq!(AlAck::from_bitbuf(&mut encoded).unwrap().blocks, vec![block]);
    }

    #[test]
    fn packet_advanced_link_batches_negotiated_window_before_waiting_for_ack() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        llc.advanced_links.get_mut(&77_468).unwrap().window_size = 3;
        while queue.pop_front().is_some() {}

        let mut reporters = Vec::new();
        for bit in ["0", "1", "0", "1"] {
            // Five segments per TL-SDU exercise every member of the
            // three-slot bearer (TS2 -> TS3 -> TS4 -> TS2 -> TS3).
            reporters.push(queue_advanced_downlink(&mut llc, &mut queue, 77_468, &bit.repeat(900)));
        }

        assert!(llc.submit_advanced_link_messages(&mut queue));
        let mut queued_ns = queue
            .iter_mut()
            .filter_map(|message| {
                let SapMsgInner::TmaUnitdataReq(request) = &mut message.msg else {
                    return None;
                };
                AlDataHeader::from_bitbuf(&mut request.pdu.clone()).ok().map(|header| header.ns)
            })
            .collect::<Vec<_>>();
        queued_ns.sort_unstable();
        queued_ns.dedup();
        assert_eq!(queued_ns, vec![0, 1, 2]);
        let routes = queue
            .iter_mut()
            .filter_map(|message| {
                let SapMsgInner::TmaUnitdataReq(request) = &mut message.msg else {
                    return None;
                };
                let header = AlDataHeader::from_bitbuf(&mut request.pdu.clone()).ok()?;
                request.associated_channel.map(|route| (header.ns, header.segment, route.timeslot))
            })
            .collect::<Vec<_>>();
        for ns in [0, 1, 2] {
            let segments = routes
                .iter()
                .filter(|(received_ns, _, _)| *received_ns == ns)
                .map(|(_, segment, received_timeslot)| (*segment, *received_timeslot))
                .collect::<Vec<_>>();
            assert!(segments.len() >= 5);
            assert!(segments.iter().all(|(segment, timeslot)| *timeslot == 2 + (*segment % 3)));
        }
        let acknowledgement_requests = queue
            .iter_mut()
            .filter_map(|message| {
                let SapMsgInner::TmaUnitdataReq(request) = &mut message.msg else {
                    return None;
                };
                let header = AlDataHeader::from_bitbuf(&mut request.pdu.clone()).ok()?;
                header.acknowledgement_requested.then_some(header.ns)
            })
            .collect::<Vec<_>>();
        assert_eq!(acknowledgement_requests, vec![2]);
        assert!(
            llc.advanced_links[&77_468]
                .tx
                .iter()
                .take(3)
                .all(|sdu| sdu.attempt_reporter.is_some())
        );
        assert!(
            llc.advanced_links[&77_468]
                .tx
                .iter()
                .take(2)
                .all(|sdu| !sdu.acknowledgement_requested)
        );
        assert!(llc.advanced_links[&77_468].tx[2].acknowledgement_requested);
        assert!(llc.advanced_links[&77_468].tx[3].attempt_reporter.is_none());

        let mut ack = BitBuffer::new_autoexpand(16);
        AlAck {
            receiver_ready: true,
            blocks: (0..3)
                .map(|nr| AlAckBlock {
                    nr,
                    acknowledgement_length: 0,
                    first_missing_segment: None,
                    acknowledgement_bitmap: Vec::new(),
                })
                .collect(),
        }
        .to_bitbuf(&mut ack)
        .unwrap();
        ack.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, ack));

        while queue.pop_front().is_some() {}
        assert!(llc.submit_advanced_link_messages(&mut queue));
        let queued_ns = queue
            .iter_mut()
            .filter_map(|message| {
                let SapMsgInner::TmaUnitdataReq(request) = &mut message.msg else {
                    return None;
                };
                AlDataHeader::from_bitbuf(&mut request.pdu.clone()).ok().map(|header| header.ns)
            })
            .collect::<Vec<_>>();
        assert!(!queued_ns.is_empty());
        assert!(queued_ns.iter().all(|ns| *ns == 3));
        assert!(reporters[..3].iter().all(|reporter| reporter.get_state() == TxState::Acknowledged));
        assert_eq!(reporters[3].get_state(), TxState::Pending);
    }

    #[test]
    fn packet_advanced_link_window_one_remains_stop_and_wait() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        llc.advanced_links.get_mut(&77_468).unwrap().window_size = 1;
        while queue.pop_front().is_some() {}

        queue_advanced_downlink(&mut llc, &mut queue, 77_468, &"0".repeat(240));
        queue_advanced_downlink(&mut llc, &mut queue, 77_468, &"1".repeat(240));
        assert!(llc.submit_advanced_link_messages(&mut queue));

        let queued_ns = queue
            .iter_mut()
            .filter_map(|message| {
                let SapMsgInner::TmaUnitdataReq(request) = &mut message.msg else {
                    return None;
                };
                AlDataHeader::from_bitbuf(&mut request.pdu.clone()).ok().map(|header| header.ns)
            })
            .collect::<Vec<_>>();
        assert!(!queued_ns.is_empty());
        assert!(queued_ns.iter().all(|ns| *ns == 0));
        assert!(llc.advanced_links[&77_468].tx[1].attempt_reporter.is_none());
    }

    #[test]
    fn queued_advanced_downlink_spreads_segments_over_live_pdchs_after_resize() {
        let config = test_config();
        let mut llc = Llc::new(config.clone());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}

        llc.rx_tla_tldata_req_al_message(SapMsg::new(
            Sap::TlaSap,
            TetraEntity::Mle,
            TetraEntity::Llc,
            SapMsgInner::TlaTlDataReqAl(tetra_saps::tla::TlaTlDataReqAl {
                main_address: TetraAddress::issi(77_468),
                link_id: 0,
                endpoint_id: 7,
                tl_sdu: BitBuffer::from_bitstr(&"10".repeat(400)),
                stealing_permission: false,
                subscriber_class: 0,
                fcs_flag: true,
                packet_data_flag: true,
                air_interface_encryption: None,
                stealing_repeats_flag: None,
                data_class_info: None,
                req_handle: 0,
                graceful_degradation: None,
                chan_alloc: None,
                associated_channel: Llc::packet_route(&llc.config, 77_468, 2),
                tx_reporter: Some(TxReporter::new()),
            }),
        ));

        // Voice takes TS4 after this TL-SDU entered LLC but before its
        // segments are submitted. TS2 and TS3 remain equivalent members of
        // the packet bearer, so the segments must use only those live slots.
        config
            .state_write()
            .subscriber_packet_delivery_routes
            .get_mut(&77_468)
            .unwrap()
            .retain(|route| route.timeslot != 4);
        assert!(llc.submit_advanced_link_messages(&mut queue));
        let routes = queue
            .iter_mut()
            .filter_map(|message| {
                let SapMsgInner::TmaUnitdataReq(request) = &message.msg else {
                    return None;
                };
                let header = AlDataHeader::from_bitbuf(&mut request.pdu.clone()).ok()?;
                request.associated_channel.map(|route| (header.segment, route.timeslot))
            })
            .collect::<Vec<_>>();
        assert!(routes.len() >= 4);
        assert!(routes.iter().all(|(segment, timeslot)| *timeslot == 2 + (*segment % 2)));
    }

    #[test]
    fn queued_advanced_downlink_spreads_over_surviving_pdchs_after_resize() {
        let config = test_config();
        let mut llc = Llc::new(config.clone());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}

        let reporter = queue_advanced_downlink(&mut llc, &mut queue, 77_468, &"10".repeat(400));

        // TS2 was part of the packet bearer when SNDCP queued the TL-SDU,
        // but a resize assigned it to voice before LLC could submit the
        // segments. TS3 and TS4 remain equivalent live bearer members.
        config
            .state_write()
            .subscriber_packet_delivery_routes
            .get_mut(&77_468)
            .unwrap()
            .retain(|route| route.timeslot != 2);
        assert!(llc.submit_advanced_link_messages(&mut queue));
        let routes = queue
            .iter_mut()
            .filter_map(|message| {
                let SapMsgInner::TmaUnitdataReq(request) = &message.msg else {
                    return None;
                };
                let header = AlDataHeader::from_bitbuf(&mut request.pdu.clone()).ok()?;
                request.associated_channel.map(|route| (header.segment, route.timeslot))
            })
            .collect::<Vec<_>>();
        assert!(routes.len() >= 4);
        assert!(routes.iter().all(|(segment, timeslot)| *timeslot == 3 + (*segment % 2)));
        assert_eq!(reporter.get_state(), TxState::Pending);
    }

    #[test]
    fn t252_repeats_only_the_ack_requesting_final_segment() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        // The test MS negotiates this value in the live TIP session. N.273=0
        // must still permit T.252 acknowledgement-request repetition.
        llc.advanced_links.get_mut(&77_468).unwrap().max_sdu_retransmissions = 0;
        while queue.pop_front().is_some() {}
        let reporter = TxReporter::new();
        llc.rx_tla_tldata_req_al_message(SapMsg::new(
            Sap::TlaSap,
            TetraEntity::Mle,
            TetraEntity::Llc,
            SapMsgInner::TlaTlDataReqAl(tetra_saps::tla::TlaTlDataReqAl {
                main_address: TetraAddress::issi(77_468),
                link_id: 0,
                endpoint_id: 7,
                tl_sdu: BitBuffer::from_bitstr(&"10".repeat(400)),
                stealing_permission: false,
                subscriber_class: 0,
                fcs_flag: true,
                packet_data_flag: true,
                air_interface_encryption: None,
                stealing_repeats_flag: None,
                data_class_info: None,
                req_handle: 0,
                graceful_degradation: None,
                chan_alloc: None,
                associated_channel: Llc::packet_route(&llc.config, 77_468, 2),
                tx_reporter: Some(reporter),
            }),
        ));
        assert!(llc.submit_advanced_link_messages(&mut queue));
        while queue.pop_front().is_some() {}
        llc.advanced_links[&77_468].tx[0]
            .attempt_reporter
            .as_ref()
            .unwrap()
            .mark_transmitted();
        llc.submit_advanced_link_messages(&mut queue);
        while queue.pop_front().is_some() {}

        llc.dltime = llc.dltime.add_timeslots(T252_ACK_WAITING_TIMER as i32);
        assert!(llc.submit_advanced_link_messages(&mut queue));
        assert_eq!(queue.iter_mut().count(), 1);
        let SapMsgInner::TmaUnitdataReq(mut repeated) = queue.pop_front().unwrap().msg else {
            panic!("expected repeated AL-FINAL-AR")
        };
        let header = AlDataHeader::from_bitbuf(&mut repeated.pdu).unwrap();
        let final_index = llc.advanced_links[&77_468].tx[0].segments.len() - 1;
        assert!(header.final_segment);
        assert!(header.acknowledgement_requested);
        assert_eq!(usize::from(header.segment), final_index);
        assert_eq!(llc.advanced_links[&77_468].tx[0].ack_request_repetitions, 1);
    }

    #[test]
    fn exhausted_ack_recovery_resets_link_in_place_and_waits_for_success() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}
        llc.advanced_links.get_mut(&77_468).unwrap().max_sdu_retransmissions = 0;

        let in_flight_reporter = queue_advanced_downlink(&mut llc, &mut queue, 77_468, &"10".repeat(400));
        let failed_reporter = queue_advanced_downlink(&mut llc, &mut queue, 77_468, &"01".repeat(400));
        let retained_reporter = queue_advanced_downlink(&mut llc, &mut queue, 77_468, &"11".repeat(128));
        assert!(llc.submit_advanced_link_messages(&mut queue));
        while queue.pop_front().is_some() {}
        for sdu in llc.advanced_links[&77_468].tx.iter().take(2) {
            sdu.attempt_reporter.as_ref().unwrap().mark_transmitted();
        }
        llc.submit_advanced_link_messages(&mut queue);
        {
            let pending = &mut llc.advanced_links.get_mut(&77_468).unwrap().tx[1];
            pending.ack_request_repetitions = MAX_AL_ACK_REQUEST_REPEATS;
        }
        llc.dltime = llc.dltime.add_timeslots(T252_ACK_WAITING_TIMER as i32);

        assert!(llc.submit_advanced_link_messages(&mut queue));
        assert_eq!(in_flight_reporter.get_state(), TxState::Lost);
        assert_eq!(failed_reporter.get_state(), TxState::Lost);
        assert_eq!(retained_reporter.get_state(), TxState::Pending);
        let link = &llc.advanced_links[&77_468];
        assert!(link.reset.is_some());
        assert_eq!(link.tx.len(), 1);
        assert_eq!(link.tx[0].ns, 0);
        assert_eq!((link.next_tx_ns, link.next_rx_ns), (1, 0));
        let SapMsgInner::TmaUnitdataReq(mut reset) = queue.pop_front().expect("AL-SETUP reset").msg else {
            panic!("expected TMA request")
        };
        let reset = AlSetup::from_bitbuf(&mut reset.pdu).unwrap();
        assert_eq!(reset.report, 3);
        assert!(queue.pop_front().is_none());

        let queued_after_reset = queue_advanced_downlink(&mut llc, &mut queue, 77_468, &"01".repeat(128));
        assert!(!llc.submit_advanced_link_messages(&mut queue));
        assert!(queue.pop_front().is_none(), "new data must wait for AL-SETUP Success");
        assert_eq!(queued_after_reset.get_state(), TxState::Pending);
        assert_eq!(
            llc.advanced_links[&77_468].tx.iter().map(|sdu| sdu.ns).collect::<Vec<_>>(),
            vec![0, 1]
        );

        let mut success = BitBuffer::new_autoexpand(32);
        AlSetup { report: 0, ..reset }.to_bitbuf(&mut success).unwrap();
        success.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, success));
        let link = &llc.advanced_links[&77_468];
        assert!(link.reset.is_none());
        assert!(link.receiver_ready);
        assert!(
            queue.pop_front().is_none(),
            "AL-SETUP Success must complete without another response"
        );
        assert!(llc.submit_advanced_link_messages(&mut queue));
        let SapMsgInner::TmaUnitdataReq(mut first) = queue.pop_front().expect("first post-reset AL-DATA").msg else {
            panic!("expected TMA request")
        };
        assert_eq!(AlDataHeader::from_bitbuf(&mut first.pdu).unwrap().ns, 0);
        assert!(queue.iter_mut().any(|message| {
            let SapMsgInner::TmaUnitdataReq(request) = &mut message.msg else {
                return false;
            };
            AlDataHeader::from_bitbuf(&mut request.pdu).is_ok_and(|header| header.ns == 1)
        }));
    }

    #[test]
    fn al_disconnect_success_is_not_echoed() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}

        let mut success = BitBuffer::new_autoexpand(16);
        AlDisconnect {
            acknowledged: true,
            link_number: 0,
            report: 0,
        }
        .to_bitbuf(&mut success);
        success.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, success));

        assert!(!llc.advanced_links.contains_key(&77_468));
        assert!(queue.pop_front().is_none(), "AL-DISC Success must complete without a response");
    }

    #[test]
    fn advanced_downlink_ignores_ack_blocks_for_unsent_tlsdus() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        llc.advanced_links.get_mut(&77_468).unwrap().window_size = 3;
        while queue.pop_front().is_some() {}
        let mut reporters = Vec::new();
        // The negotiated N.272 window is three in this test profile, so
        // N(S)=3 is the first TL-SDU that has not yet reached UMAC.
        for bit in ["0", "1", "0", "1"] {
            let reporter = TxReporter::new();
            reporters.push(reporter.clone());
            llc.rx_tla_tldata_req_al_message(SapMsg::new(
                Sap::TlaSap,
                TetraEntity::Mle,
                TetraEntity::Llc,
                SapMsgInner::TlaTlDataReqAl(tetra_saps::tla::TlaTlDataReqAl {
                    main_address: TetraAddress::issi(77_468),
                    link_id: 0,
                    endpoint_id: 7,
                    tl_sdu: BitBuffer::from_bitstr(&bit.repeat(64)),
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: true,
                    packet_data_flag: true,
                    air_interface_encryption: None,
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0,
                    graceful_degradation: None,
                    chan_alloc: None,
                    associated_channel: Llc::packet_route(&llc.config, 77_468, 2),
                    tx_reporter: Some(reporter),
                }),
            ));
        }
        llc.submit_advanced_link_messages(&mut queue);
        assert_eq!(llc.advanced_links[&77_468].tx.len(), 4);

        let mut ack = BitBuffer::new_autoexpand(32);
        AlAck {
            receiver_ready: true,
            blocks: vec![
                AlAckBlock {
                    nr: 0,
                    acknowledgement_length: 0,
                    first_missing_segment: None,
                    acknowledgement_bitmap: Vec::new(),
                },
                AlAckBlock {
                    nr: 3,
                    acknowledgement_length: 0,
                    first_missing_segment: None,
                    acknowledgement_bitmap: Vec::new(),
                },
            ],
        }
        .to_bitbuf(&mut ack)
        .unwrap();
        ack.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, ack));

        assert_eq!(llc.advanced_links[&77_468].tx.len(), 3);
        assert_eq!(reporters[0].get_state(), TxState::Acknowledged);
        assert_eq!(reporters[3].get_state(), TxState::Pending);

        while queue.pop_front().is_some() {}
        assert!(
            !llc.submit_advanced_link_messages(&mut queue),
            "an AR for the current N.272 window must complete before a new window begins"
        );
        let mut ack = BitBuffer::new_autoexpand(16);
        AlAck {
            receiver_ready: true,
            blocks: vec![AlAckBlock {
                nr: 2,
                acknowledgement_length: 0,
                first_missing_segment: None,
                acknowledgement_bitmap: Vec::new(),
            }],
        }
        .to_bitbuf(&mut ack)
        .unwrap();
        ack.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, ack));
        assert!(llc.submit_advanced_link_messages(&mut queue));
        assert!(queue.iter_mut().count() > 0);
        let mut ack = BitBuffer::new_autoexpand(16);
        AlAck {
            receiver_ready: true,
            blocks: vec![AlAckBlock {
                nr: 3,
                acknowledgement_length: 0,
                first_missing_segment: None,
                acknowledgement_bitmap: Vec::new(),
            }],
        }
        .to_bitbuf(&mut ack)
        .unwrap();
        ack.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, ack));
        assert_eq!(llc.advanced_links[&77_468].tx.len(), 1);
        assert_eq!(reporters[3].get_state(), TxState::Acknowledged);
    }

    #[test]
    fn advanced_downlink_does_not_slide_past_missing_window_base() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        llc.advanced_links.get_mut(&77_468).unwrap().window_size = 3;
        while queue.pop_front().is_some() {}

        // Queue far enough ahead for the three-bit N(S) to wrap. Only the
        // first N.272 window may be transmitted while its base remains
        // incomplete, even if the other two members are acknowledged.
        for index in 0..9 {
            queue_advanced_downlink(&mut llc, &mut queue, 77_468, &format!("{:08b}", index));
        }
        assert!(llc.submit_advanced_link_messages(&mut queue));
        while queue.pop_front().is_some() {}

        let mut ack = BitBuffer::new_autoexpand(32);
        AlAck {
            receiver_ready: true,
            blocks: vec![
                AlAckBlock {
                    nr: 0,
                    acknowledgement_length: 1,
                    first_missing_segment: Some(0),
                    acknowledgement_bitmap: Vec::new(),
                },
                AlAckBlock {
                    nr: 1,
                    acknowledgement_length: 0,
                    first_missing_segment: None,
                    acknowledgement_bitmap: Vec::new(),
                },
                AlAckBlock {
                    nr: 2,
                    acknowledgement_length: 0,
                    first_missing_segment: None,
                    acknowledgement_bitmap: Vec::new(),
                },
            ],
        }
        .to_bitbuf(&mut ack)
        .unwrap();
        ack.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, ack));

        let link = &llc.advanced_links[&77_468];
        assert_eq!(link.tx.front().unwrap().ns, 0);
        assert_eq!(link.tx.back().unwrap().ns, 0, "the queued N(S) has wrapped");
        let expected_payload = link.tx.front().unwrap().segments[0].to_bitstr();
        while queue.pop_front().is_some() {}

        assert!(llc.submit_advanced_link_messages(&mut queue));
        let retransmitted = queue
            .iter_mut()
            .filter_map(|message| {
                let SapMsgInner::TmaUnitdataReq(request) = &message.msg else {
                    return None;
                };
                let mut pdu = request.pdu.clone();
                AlDataHeader::from_bitbuf(&mut pdu)
                    .ok()
                    .map(|header| (header.ns, pdu.to_bitstr().ends_with(&expected_payload)))
            })
            .collect::<Vec<_>>();
        assert_eq!(retransmitted, vec![(0, true)]);
    }

    #[test]
    fn advanced_ack_retires_tlsdu_passed_by_peer_window() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        llc.advanced_links.get_mut(&77_468).unwrap().window_size = 3;
        while queue.pop_front().is_some() {}

        let reporters = (0..4)
            .map(|index| queue_advanced_downlink(&mut llc, &mut queue, 77_468, &format!("{:08b}", index)))
            .collect::<Vec<_>>();
        assert!(llc.submit_advanced_link_messages(&mut queue));
        while queue.pop_front().is_some() {}

        // N(S)=0 was completed by a selective retry. The peer now starts its
        // report at N(R)=1, rather than repeating a positive block for zero.
        let mut ack = BitBuffer::new_autoexpand(32);
        AlAck {
            receiver_ready: true,
            blocks: vec![
                AlAckBlock {
                    nr: 1,
                    acknowledgement_length: 0,
                    first_missing_segment: None,
                    acknowledgement_bitmap: Vec::new(),
                },
                AlAckBlock {
                    nr: 2,
                    acknowledgement_length: 0,
                    first_missing_segment: None,
                    acknowledgement_bitmap: Vec::new(),
                },
                AlAckBlock {
                    nr: 3,
                    acknowledgement_length: 1,
                    first_missing_segment: Some(0),
                    acknowledgement_bitmap: Vec::new(),
                },
            ],
        }
        .to_bitbuf(&mut ack)
        .unwrap();
        ack.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, ack));

        assert!(reporters[..3].iter().all(|reporter| reporter.get_state() == TxState::Acknowledged));
        assert_eq!(reporters[3].get_state(), TxState::Pending);
        let link = &llc.advanced_links[&77_468];
        assert_eq!(link.tx.len(), 1);
        assert_eq!(link.tx.front().unwrap().ns, 3);
    }

    #[test]
    fn established_advanced_link_in_standby_falls_back_to_basic_link() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}

        // TTR 001-05 section 6.5 keeps the AL established in STANDBY, while
        // section 7.1 performs PDP activation signalling on the CCCH.  Model
        // that state by withdrawing the assigned packet bearer only.
        llc.config.state_write().subscriber_packet_delivery_routes.remove(&77_468);

        llc.rx_tla_tldata_req_bl(
            &mut queue,
            SapMsg::new(
                Sap::TlaSap,
                TetraEntity::Mle,
                TetraEntity::Llc,
                SapMsgInner::TlaTlDataReqBl(tetra_saps::tla::TlaTlDataReqBl {
                    main_address: TetraAddress::issi(77_468),
                    link_id: 0,
                    endpoint_id: 7,
                    tl_sdu: BitBuffer::from_bitstr("1010001"),
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: true,
                    packet_data_flag: true,
                    air_interface_encryption: None,
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0,
                    graceful_degradation: None,
                    chan_alloc: None,
                    associated_channel: None,
                    tx_reporter: None,
                }),
            ),
        );

        let link = llc.advanced_links.get(&77_468).unwrap();
        assert!(link.tx.is_empty(), "STANDBY signalling must not enter the AL queue");
        assert_eq!(llc.outbound_messages.len(), 1, "STANDBY signalling must use BL-DATA");
        let SapMsgInner::TmaUnitdataReq(request) = &llc.outbound_messages[0].retransmission_buf.msg else {
            panic!("expected buffered basic-link request")
        };
        assert!(request.associated_channel.is_none());
    }

    #[test]
    fn packet_replace_assignment_bypasses_existing_advanced_link_and_pdch_routes() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}

        llc.rx_tla_tldata_req_bl(
            &mut queue,
            SapMsg::new(
                Sap::TlaSap,
                TetraEntity::Mle,
                TetraEntity::Llc,
                SapMsgInner::TlaTlDataReqBl(tetra_saps::tla::TlaTlDataReqBl {
                    main_address: TetraAddress::issi(77_468),
                    link_id: 0,
                    endpoint_id: 7,
                    tl_sdu: BitBuffer::from_bitstr("1000111000111100000000000001010"),
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: true,
                    packet_data_flag: true,
                    air_interface_encryption: None,
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0,
                    graceful_degradation: None,
                    chan_alloc: Some(CmceChanAllocReq {
                        usage: Some(54),
                        carrier: None,
                        timeslots: [false, true, true, true],
                        alloc_type: ChanAllocType::Replace,
                        cell_change_flag: false,
                        ul_dl_assigned: UlDlAssignment::Both,
                    }),
                    associated_channel: None,
                    tx_reporter: None,
                }),
            ),
        );

        assert!(llc.advanced_links[&77_468].tx.is_empty());
        assert_eq!(llc.outbound_messages.len(), 1);
        assert!(llc.outbound_messages[0].force_common_channel);
        assert!(llc.submit_free_messages_to_umac(&mut queue));
        let SapMsgInner::TmaUnitdataReq(request) = queue.pop_front().expect("MCCH assignment").msg else {
            panic!("expected TMA request")
        };
        assert!(request.associated_channel.is_none());
        assert_eq!(request.chan_alloc.unwrap().alloc_type, ChanAllocType::Replace);
        assert!(
            queue.pop_front().is_none(),
            "packet assignment must not be copied onto its old PDCH"
        );
    }

    #[test]
    fn basic_downlink_with_fcs_appends_a_valid_checksum() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        let payload = BitBuffer::from_bitstr("10100101100101101010010110010");
        let payload_len = payload.get_len_remaining();

        llc.rx_tla_tldata_req_bl(
            &mut queue,
            SapMsg::new(
                Sap::TlaSap,
                TetraEntity::Mle,
                TetraEntity::Llc,
                SapMsgInner::TlaTlDataReqBl(tetra_saps::tla::TlaTlDataReqBl {
                    main_address: TetraAddress::issi(77_468),
                    link_id: 0,
                    endpoint_id: 7,
                    tl_sdu: payload,
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: true,
                    packet_data_flag: false,
                    air_interface_encryption: None,
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0,
                    graceful_degradation: None,
                    chan_alloc: None,
                    associated_channel: None,
                    tx_reporter: None,
                }),
            ),
        );

        let SapMsgInner::TmaUnitdataReq(mut request) = llc.outbound_messages[0].retransmission_buf.msg.clone() else {
            panic!("expected buffered TMA request")
        };
        assert_eq!(request.pdu.get_len_remaining(), 5 + payload_len + 32);
        let header = BlData::from_bitbuf(&mut request.pdu).expect("BL-DATA header");
        assert!(header.has_fcs);
        assert!(fcs::check_fcs(&request.pdu));
    }

    #[test]
    fn sc2_bl_ack_keeps_the_received_aie_policy() {
        let mut llc = Llc::new(test_config());
        let addr = TetraAddress::issi(0x12_34_56);
        let request = AieRequest::sc2(AieSubject::Individual { issi: addr.ssi }, AieScope::MacData);
        llc.schedule_outgoing_ack(TdmaTime::default(), addr, 1, request);

        let mut queue = MessageQueue::new();
        assert!(llc.submit_ack_replies_to_umac(&mut queue));
        let message = queue.pop_front().expect("BL-ACK must be queued");
        let SapMsgInner::TmaUnitdataReq(request) = message.msg else {
            panic!("expected a TMA request")
        };
        assert!(matches!(
            request.air_interface_encryption,
            Some(AieRequest::Sc2 {
                subject: AieSubject::Individual { issi },
                scope: AieScope::MacResource,
            }) if issi == addr.ssi
        ));
    }

    #[test]
    fn packet_data_bl_ack_uses_assigned_schf_instead_of_facch() {
        let mut llc = Llc::new(test_config());
        let addr = TetraAddress::issi(77_468);
        let received = TdmaTime { h: 0, m: 1, f: 4, t: 3 };
        let aie = AieRequest::sc2(AieSubject::Individual { issi: addr.ssi }, AieScope::MacData);
        llc.schedule_outgoing_ack(received, addr, 1, aie);

        let mut queue = MessageQueue::new();
        assert!(llc.submit_ack_replies_to_umac(&mut queue));
        let SapMsgInner::TmaUnitdataReq(request) = queue.pop_front().expect("BL-ACK must be queued").msg else {
            panic!("expected a TMA request")
        };
        assert!(!request.stealing_permission, "an assigned PDCH is not a traffic channel");
        assert!(
            request.chan_alloc.is_none(),
            "the existing packet bearer does not need a replacement allocation"
        );
        assert_eq!(
            request.associated_channel.map(|route| (route.call_id, route.timeslot, route.usage)),
            Some((32, 3, 55))
        );
        assert!(queue.pop_front().is_none());
    }

    #[test]
    fn combined_bl_adata_never_mixes_clear_and_sc2_ack_status() {
        let mut llc = Llc::new(test_config());
        let addr = TetraAddress::issi(1234);
        let sc2 = AieRequest::sc2(AieSubject::Individual { issi: addr.ssi }, AieScope::MacData);
        let clear = AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource);
        llc.schedule_outgoing_ack(TdmaTime::default(), addr, 0, sc2);

        assert_eq!(llc.get_out_ack_seq_if_any(addr, 1, clear), None);
        assert_eq!(llc.scheduled_out_acks.len(), 1, "mismatched ACK remains separate");
        assert_eq!(llc.get_out_ack_seq_if_any(addr, 1, sc2), Some(0));
    }

    #[test]
    fn acknowledged_downlink_uses_live_call_route_on_first_attempt() {
        let config = test_config();
        let issi = 0x12_34_56;
        config.state_write().subscriber_delivery_routes.insert(
            issi,
            vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                call_id: 7,
                timeslot: 2,
                usage: 10,
            }],
        );

        let route = Llc::delivery_routes(&config, issi, TdmaTime::default())
            .into_iter()
            .next()
            .expect("active call route");
        assert_eq!(route.call_id, 7);
        assert_eq!(route.timeslot, 2);
        assert_eq!(route.usage, 10);
    }

    #[test]
    fn delivery_routes_treat_multislot_packet_context_as_one_bearer() {
        let config = test_config();
        let issi = 77_479;
        let mut state = config.state_write();
        state.subscriber_delivery_routes.insert(
            issi,
            vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                call_id: 7,
                timeslot: 4,
                usage: 10,
            }],
        );
        state.subscriber_packet_delivery_routes.insert(
            issi,
            vec![
                tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 11,
                    timeslot: 2,
                    usage: 52,
                },
                tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 11,
                    timeslot: 3,
                    usage: 52,
                },
                tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 11,
                    timeslot: 4,
                    usage: 52,
                },
            ],
        );
        drop(state);

        let routes = Llc::delivery_routes(&config, issi, TdmaTime::default());
        assert_eq!(
            routes
                .iter()
                .map(|route| (route.call_id, route.timeslot, route.usage))
                .collect::<Vec<_>>(),
            vec![(11, 2, 52), (7, 4, 10)]
        );
    }

    #[test]
    fn discarded_associated_downlink_retries_over_mcch() {
        let config = test_config();
        let issi = 77_468;
        let start = TdmaTime { t: 1, f: 1, m: 1, h: 0 };
        {
            let mut state = config.state_write();
            // This test exercises one circuit route plus the MCCH fallback.
            // test_config installs a three-slot PDCH for other routing tests,
            // so remove that unrelated route from this scenario.
            state.subscriber_packet_delivery_routes.remove(&issi);
            state.subscriber_delivery_routes.insert(
                issi,
                vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 7,
                    timeslot: 2,
                    usage: 10,
                }],
            );
        }

        let mut llc = Llc::new(config.clone());
        llc.dltime = start;
        let mut queue = MessageQueue::new();
        llc.rx_tla_tldata_req_bl(
            &mut queue,
            SapMsg::new(
                Sap::TlaSap,
                TetraEntity::Mle,
                TetraEntity::Llc,
                SapMsgInner::TlaTlDataReqBl(tetra_saps::tla::TlaTlDataReqBl {
                    main_address: TetraAddress::issi(issi),
                    link_id: 0,
                    endpoint_id: 0,
                    tl_sdu: BitBuffer::from_bitstr("1010"),
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: false,
                    packet_data_flag: false,
                    air_interface_encryption: Some(AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource)),
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0,
                    graceful_degradation: None,
                    chan_alloc: None,
                    associated_channel: None,
                    tx_reporter: None,
                }),
            ),
        );
        assert!(llc.submit_free_messages_to_umac(&mut queue));
        let first = queue.pop_front().expect("associated attempt queued");
        let SapMsgInner::TmaUnitdataReq(first) = first.msg else {
            panic!("expected TMA request")
        };
        assert_eq!(first.associated_channel.map(|route| route.timeslot), Some(2));

        let mcch = queue.pop_front().expect("concurrent MCCH attempt queued");
        let SapMsgInner::TmaUnitdataReq(mcch) = mcch.msg else {
            panic!("expected TMA request")
        };
        assert!(mcch.associated_channel.is_none());

        // UMAC removes both queued copies before transmission. Once the
        // traffic route disappears, the next attempt must contain MCCH only.
        llc.outbound_messages[0].attempt_reporters[0].mark_discarded();
        llc.outbound_messages[0].attempt_reporters[1].mark_discarded();
        config.state_write().subscriber_delivery_routes.remove(&issi);
        llc.dltime = start.add_timeslots(1);
        assert!(!llc.submit_retransmissions_to_umac(&mut queue));
        let retry_timer = Llc::basic_link_retry_timer(&llc.outbound_messages[0]);
        llc.dltime = llc.dltime.add_timeslots(retry_timer as i32);
        assert!(llc.submit_retransmissions_to_umac(&mut queue));

        let retry = queue.pop_front().expect("MCCH retry queued");
        let SapMsgInner::TmaUnitdataReq(retry) = retry.msg else {
            panic!("expected TMA retry")
        };
        assert!(retry.associated_channel.is_none());
        assert_eq!(llc.outbound_messages[0].retransmit_count, 1);
    }

    #[test]
    fn explicit_associated_downlink_survives_direct_response_window() {
        let config = test_config();
        let issi = 77_479;
        let start = TdmaTime { t: 1, f: 1, m: 1, h: 0 };
        {
            let mut state = config.state_write();
            state.subscribers.mark_direct_response_window(issi, start);
            state.subscriber_delivery_routes.insert(
                issi,
                vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 8,
                    timeslot: 3,
                    usage: 11,
                }],
            );
        }

        let mut llc = Llc::new(config.clone());
        llc.dltime = start;
        let mut queue = MessageQueue::new();
        llc.rx_tla_tldata_req_bl(
            &mut queue,
            SapMsg::new(
                Sap::TlaSap,
                TetraEntity::Mle,
                TetraEntity::Llc,
                SapMsgInner::TlaTlDataReqBl(tetra_saps::tla::TlaTlDataReqBl {
                    main_address: TetraAddress::issi(issi),
                    link_id: 0,
                    endpoint_id: 0,
                    tl_sdu: BitBuffer::from_bitstr("1010"),
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: false,
                    packet_data_flag: false,
                    air_interface_encryption: Some(AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource)),
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0,
                    graceful_degradation: None,
                    chan_alloc: None,
                    associated_channel: Some(tetra_saps::tma::AssociatedChannel {
                        call_id: 8,
                        timeslot: 3,
                        usage: 11,
                        best_effort_key: None,
                    }),
                    tx_reporter: None,
                }),
            ),
        );
        assert!(llc.submit_free_messages_to_umac(&mut queue));
        let first = queue.pop_front().expect("associated attempt queued");
        let SapMsgInner::TmaUnitdataReq(first) = first.msg else {
            panic!("expected TMA request")
        };
        assert_eq!(first.associated_channel.map(|route| route.timeslot), Some(3));
        let mcch = queue.pop_front().expect("concurrent MCCH attempt queued");
        let SapMsgInner::TmaUnitdataReq(mcch) = mcch.msg else {
            panic!("expected TMA request")
        };
        assert!(mcch.associated_channel.is_none());
        assert!(Llc::delivery_routes(&config, issi, start).is_empty());

        llc.outbound_messages[0].attempt_reporters[0].mark_transmitted();
        llc.dltime = start.add_timeslots(1);
        assert!(!llc.submit_retransmissions_to_umac(&mut queue));
        let retry_timer = Llc::basic_link_retry_timer(&llc.outbound_messages[0]);
        assert_eq!(retry_timer, T251_SENDER_RETRY_TIMER * 18);

        // One elapsed multiframe is only one downlink signalling frame on
        // SACCH. In particular, it must not reproduce the live premature
        // retry that used to add another fragmented SDS after this delay.
        let one_sacch_opportunity = tetra_core::frames!(18);
        llc.dltime = llc.dltime.add_timeslots(one_sacch_opportunity);
        assert!(!llc.submit_retransmissions_to_umac(&mut queue));

        llc.dltime = llc.dltime.add_timeslots((retry_timer - one_sacch_opportunity as u32) as i32);
        assert!(llc.submit_retransmissions_to_umac(&mut queue));

        let retry_route = queue.pop_front().expect("traffic retry queued");
        let SapMsgInner::TmaUnitdataReq(retry_route) = retry_route.msg else {
            panic!("expected TMA retry")
        };
        assert_eq!(retry_route.associated_channel.map(|route| route.timeslot), Some(3));
        let retry_mcch = queue.pop_front().expect("MCCH retry queued");
        let SapMsgInner::TmaUnitdataReq(retry_mcch) = retry_mcch.msg else {
            panic!("expected TMA retry")
        };
        assert!(retry_mcch.associated_channel.is_none());
    }

    #[test]
    fn packet_basic_link_uses_only_its_associated_pdch() {
        let config = test_config();
        let issi = 77_468;
        let start = TdmaTime { t: 1, f: 1, m: 1, h: 0 };
        let mut llc = Llc::new(config);
        llc.dltime = start;
        let mut queue = MessageQueue::new();
        llc.rx_tla_tldata_req_bl(
            &mut queue,
            SapMsg::new(
                Sap::TlaSap,
                TetraEntity::Mle,
                TetraEntity::Llc,
                SapMsgInner::TlaTlDataReqBl(tetra_saps::tla::TlaTlDataReqBl {
                    main_address: TetraAddress::issi(issi),
                    link_id: 0,
                    endpoint_id: 0,
                    tl_sdu: BitBuffer::from_bitstr("1010"),
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: false,
                    packet_data_flag: true,
                    air_interface_encryption: Some(AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource)),
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0,
                    graceful_degradation: None,
                    chan_alloc: None,
                    associated_channel: Some(tetra_saps::tma::AssociatedChannel {
                        call_id: 17,
                        timeslot: 2,
                        usage: 52,
                        best_effort_key: None,
                    }),
                    tx_reporter: None,
                }),
            ),
        );

        assert!(llc.submit_free_messages_to_umac(&mut queue));
        let first = queue.pop_front().expect("PDCH attempt queued");
        let SapMsgInner::TmaUnitdataReq(first) = first.msg else {
            panic!("expected TMA request")
        };
        assert_eq!(first.associated_channel.map(|route| route.timeslot), Some(2));
        assert!(queue.pop_front().is_none(), "packet signalling must not be duplicated on MCCH");
        assert_eq!(llc.outbound_messages[0].attempt_reporters.len(), 1);
        assert_eq!(llc.outbound_messages[0].attempt_timeslots, vec![2]);
    }

    #[test]
    fn acknowledged_downlink_fans_out_over_scan_list_routes_and_mcch() {
        let config = test_config();
        let issi = 77_468;
        let start = TdmaTime { t: 1, f: 1, m: 1, h: 0 };
        {
            let mut state = config.state_write();
            state.subscriber_packet_delivery_routes.remove(&issi);
            state.subscriber_delivery_routes.insert(
                issi,
                vec![
                    tetra_config::bluestation::SubscriberDeliveryRoute {
                        call_id: 9,
                        timeslot: 4,
                        usage: 12,
                    },
                    tetra_config::bluestation::SubscriberDeliveryRoute {
                        call_id: 8,
                        timeslot: 3,
                        usage: 11,
                    },
                    tetra_config::bluestation::SubscriberDeliveryRoute {
                        call_id: 7,
                        timeslot: 2,
                        usage: 10,
                    },
                ],
            );
        }

        let mut llc = Llc::new(config.clone());
        llc.dltime = start;
        let mut queue = MessageQueue::new();
        llc.rx_tla_tldata_req_bl(
            &mut queue,
            SapMsg::new(
                Sap::TlaSap,
                TetraEntity::Mle,
                TetraEntity::Llc,
                SapMsgInner::TlaTlDataReqBl(tetra_saps::tla::TlaTlDataReqBl {
                    main_address: TetraAddress::issi(issi),
                    link_id: 0,
                    endpoint_id: 0,
                    tl_sdu: BitBuffer::from_bitstr("1010"),
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: false,
                    packet_data_flag: false,
                    air_interface_encryption: Some(AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource)),
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0,
                    graceful_degradation: None,
                    chan_alloc: None,
                    associated_channel: None,
                    tx_reporter: None,
                }),
            ),
        );
        assert!(llc.submit_free_messages_to_umac(&mut queue));
        let mut initial_timeslots = Vec::new();
        while let Some(message) = queue.pop_front() {
            let SapMsgInner::TmaUnitdataReq(request) = message.msg else {
                panic!("expected TMA request")
            };
            initial_timeslots.push(request.associated_channel.map(|route| route.timeslot));
        }
        assert_eq!(initial_timeslots, vec![Some(4), Some(3), Some(2), None]);
        assert_eq!(llc.outbound_messages[0].attempt_reporters.len(), 4);
        assert!(
            llc.outbound_messages[0]
                .attempt_reporters
                .iter()
                .all(|reporter| reporter.get_state() == tetra_core::TxState::Pending)
        );

        // The first route starts T.251, but the other copies may still be
        // queued or fragmented on their own bearers.
        llc.outbound_messages[0].attempt_reporters[0].mark_transmitted();
        llc.dltime = start.add_timeslots(1);
        assert!(!llc.submit_retransmissions_to_umac(&mut queue));
        assert_eq!(llc.outbound_messages[0].t_umac_done, Some(llc.dltime));
        assert!(llc.outbound_messages[0].tx_reporter.is_transmitted());

        let first_completion = llc.dltime;
        let retry_timer = Llc::basic_link_retry_timer(&llc.outbound_messages[0]);
        llc.dltime = first_completion.add_timeslots(retry_timer as i32);
        assert!(
            !llc.submit_retransmissions_to_umac(&mut queue),
            "an unfinished concurrent route must not be cut off at the first copy's T.251 boundary"
        );

        // A later complete copy restarts T.251. Once all remaining copies are
        // done, a retry is allowed only after that fresh interval.
        llc.outbound_messages[0].attempt_reporters[1].mark_transmitted();
        llc.outbound_messages[0].attempt_reporters[2].mark_discarded();
        llc.outbound_messages[0].attempt_reporters[3].mark_discarded();
        llc.dltime = llc.dltime.add_timeslots(1);
        assert!(!llc.submit_retransmissions_to_umac(&mut queue));
        let latest_completion = llc.dltime;
        assert_eq!(llc.outbound_messages[0].t_umac_done, Some(latest_completion));

        let old_attempt_reporters = llc.outbound_messages[0].attempt_reporters.clone();
        llc.dltime = latest_completion.add_timeslots(retry_timer as i32);
        assert!(llc.submit_retransmissions_to_umac(&mut queue));
        assert_eq!(llc.outbound_messages[0].retransmit_count, 1);
        assert!(old_attempt_reporters[2..].iter().all(TxReporter::is_discarded));
        let mut retry_copies = 0;
        while queue.pop_front().is_some() {
            retry_copies += 1;
        }
        assert_eq!(retry_copies, 4);

        let ack = &mut llc.outbound_messages[0];
        ack.retransmit_count = 2;
        Llc::submit_for_acknowledged_transmission(&config, &mut queue, ack, start);
        let mut copies = 0;
        while queue.pop_front().is_some() {
            copies += 1;
        }
        assert_eq!(copies, 4, "every retry must cover all plausible bearers again");
    }

    #[test]
    fn delayed_ack_for_transmitted_attempt_survives_queued_retry() {
        let config = test_config();
        let issi = 77_479;
        let addr = TetraAddress::issi(issi);
        let start = TdmaTime { t: 1, f: 1, m: 1, h: 0 };
        config.state_write().subscriber_delivery_routes.insert(
            issi,
            vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                call_id: 8,
                timeslot: 2,
                usage: 11,
            }],
        );

        let reporter = TxReporter::new();
        let mut llc = Llc::new(config);
        llc.dltime = start;
        let mut queue = MessageQueue::new();
        llc.rx_tla_tldata_req_bl(
            &mut queue,
            SapMsg::new(
                Sap::TlaSap,
                TetraEntity::Mle,
                TetraEntity::Llc,
                SapMsgInner::TlaTlDataReqBl(tetra_saps::tla::TlaTlDataReqBl {
                    main_address: addr,
                    link_id: 0,
                    endpoint_id: 0,
                    tl_sdu: BitBuffer::from_bitstr("1010"),
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: false,
                    packet_data_flag: false,
                    air_interface_encryption: Some(AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource)),
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0,
                    graceful_degradation: None,
                    chan_alloc: None,
                    associated_channel: None,
                    tx_reporter: Some(reporter.clone()),
                }),
            ),
        );
        assert!(llc.submit_free_messages_to_umac(&mut queue));
        queue.pop_front().expect("first attempt queued");
        queue.pop_front().expect("concurrent MCCH attempt queued");

        llc.outbound_messages[0].attempt_reporters[0].mark_transmitted();
        llc.dltime = start.add_timeslots(1);
        assert!(!llc.submit_retransmissions_to_umac(&mut queue));
        assert!(llc.outbound_messages[0].has_transmitted_attempt);

        let retry_timer = Llc::basic_link_retry_timer(&llc.outbound_messages[0]);
        llc.dltime = llc.dltime.add_timeslots(retry_timer as i32);
        assert!(llc.submit_retransmissions_to_umac(&mut queue));
        assert_eq!(reporter.get_state(), tetra_core::TxState::Transmitted);

        let redundant_copies = llc.outbound_messages[0].attempt_reporters.clone();
        llc.process_incoming_ack(addr, 0, AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacData));
        assert!(llc.outbound_messages.is_empty());
        assert_eq!(reporter.get_state(), tetra_core::TxState::Acknowledged);
        assert!(redundant_copies.iter().all(TxReporter::is_discarded));
    }

    #[test]
    fn direct_mac_access_response_ignores_stale_call_route() {
        let config = test_config();
        let issi = 0x12_34_56;
        let now = TdmaTime::default();
        {
            let mut state = config.state_write();
            state.subscribers.mark_direct_response_window(issi, now);
            state.subscriber_delivery_routes.insert(
                issi,
                vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 7,
                    timeslot: 2,
                    usage: 10,
                }],
            );
        }

        assert!(Llc::delivery_routes(&config, issi, now).is_empty());
    }

    #[test]
    fn direct_response_window_preserves_assigned_packet_routes() {
        let config = test_config();
        let issi = 0x12_34_56;
        let now = TdmaTime::default();
        {
            let mut state = config.state_write();
            state.subscribers.mark_direct_response_window(issi, now);
            state.subscriber_delivery_routes.insert(
                issi,
                vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 7,
                    timeslot: 2,
                    usage: 10,
                }],
            );
            state.subscriber_packet_delivery_routes.insert(
                issi,
                vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 11,
                    timeslot: 3,
                    usage: 52,
                }],
            );
        }

        let routes = Llc::delivery_routes(&config, issi, now);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].call_id, 11);
        assert_eq!(routes[0].timeslot, 3);
        assert_eq!(routes[0].usage, 52);
    }

    #[test]
    fn registration_delivery_stays_on_mcch_after_direct_response_window() {
        let config = test_config();
        let issi = 0x12_34_56;
        let now = TdmaTime::default();
        {
            let mut state = config.state_write();
            state.subscribers.set_registration_delivery_pending(issi, true);
            state.subscriber_delivery_routes.insert(
                issi,
                vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 7,
                    timeslot: 2,
                    usage: 10,
                }],
            );
        }

        assert!(Llc::delivery_routes(&config, issi, now.add_timeslots(500)).is_empty());
    }

    #[test]
    fn final_common_channel_ack_gets_one_frame_of_grace_after_retry_exhaustion() {
        let retry_timer = T251_SENDER_RETRY_TIMER;
        assert!(!Llc::final_ack_grace_elapsed(retry_timer as i32, retry_timer, false));
        assert!(!Llc::final_ack_grace_elapsed(
            (retry_timer + COMMON_CHANNEL_FINAL_ACK_GRACE_TIMESLOTS - 1) as i32,
            retry_timer,
            false,
        ));
        assert!(Llc::final_ack_grace_elapsed(
            (retry_timer + COMMON_CHANNEL_FINAL_ACK_GRACE_TIMESLOTS) as i32,
            retry_timer,
            false,
        ));
    }

    #[test]
    fn final_assigned_channel_ack_survives_mcch_random_access_window() {
        let retry_timer = T251_SENDER_RETRY_TIMER * ASSIGNED_CHANNEL_ACK_RETRY_TIMER_MULTIPLIER;
        let observed_late_ack_age = retry_timer + 3 * 18 * 4;
        assert!(
            !Llc::final_ack_grace_elapsed(observed_late_ack_age as i32, retry_timer, true),
            "a BL-ACK returning through MCCH after a call edge must remain associated with its delivery"
        );
        assert!(Llc::final_ack_grace_elapsed(
            (retry_timer + ASSIGNED_CHANNEL_FINAL_ACK_GRACE_TIMESLOTS) as i32,
            retry_timer,
            true,
        ));
    }

    #[test]
    fn discarded_final_attempt_reports_lost_without_panicking() {
        let reporter = TxReporter::new();
        reporter.mark_discarded();

        Llc::mark_reporter_lost(&reporter);

        assert_eq!(reporter.get_state(), tetra_core::TxState::Lost);
    }
}
