mod common;

use tetra_config::bluestation::{StackMode, SubscriberDeliveryRoute};
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BitBuffer, Sap, SsiType, TdmaTime, TetraAddress, TxState, debug};
use tetra_pdus::cmce::enums::cmce_pdu_type_dl::CmcePduTypeDl;
use tetra_pdus::cmce::enums::party_type_identifier::PartyTypeIdentifier;
use tetra_pdus::cmce::fields::basic_service_information::BasicServiceInformation;
use tetra_pdus::cmce::pdus::u_setup::USetup;
use tetra_saps::control::brew::{BrewSubscriberAction, MmSubscriberUpdate};
use tetra_saps::control::call_control::CallControl;
use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;
use tetra_saps::control::enums::communication_type::CommunicationType;
use tetra_saps::lcmc::LcmcMleUnitdataInd;
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};

use crate::common::ComponentTest;

const TEST_GSSI: u32 = 91;
const TEST_ISSI: u32 = 1000001;

/// Helper: register a subscriber on a GSSI so CMCE accepts calls for that group.
fn register_subscriber(test: &mut ComponentTest, issi: u32, gssi: u32) {
    let register = SapMsg {
        sap: Sap::Control,
        src: TetraEntity::Mm,
        dest: TetraEntity::Cmce,
        msg: SapMsgInner::MmSubscriberUpdate(MmSubscriberUpdate {
            issi,
            groups: vec![],
            action: BrewSubscriberAction::Register,
            class_of_usage: vec![],
            scanning_enabled: None,
        }),
    };
    test.submit_message(register);
    test.run_stack(Some(1));

    let affiliate = SapMsg {
        sap: Sap::Control,
        src: TetraEntity::Mm,
        dest: TetraEntity::Cmce,
        msg: SapMsgInner::MmSubscriberUpdate(MmSubscriberUpdate {
            issi,
            groups: vec![gssi],
            action: BrewSubscriberAction::Affiliate,
            class_of_usage: vec![3],
            scanning_enabled: None,
        }),
    };
    test.submit_message(affiliate);
    test.run_stack(Some(1));
    test.dump_sinks();
}

/// Helper: build a U-SETUP SAP message for a group call.
fn build_u_setup_msg(calling_issi: u32, dest_gssi: u32) -> SapMsg {
    let u_setup = USetup {
        area_selection: 0,
        hook_method_selection: false,
        simplex_duplex_selection: false,
        basic_service_information: BasicServiceInformation {
            circuit_mode_type: CircuitModeType::TchS,
            encryption_flag: false,
            communication_type: CommunicationType::P2Mp,
            slots_per_frame: None,
            speech_service: Some(0),
        },
        request_to_transmit_send_data: false,
        call_priority: 0,
        clir_control: 0,
        called_party_type_identifier: PartyTypeIdentifier::Ssi,
        called_party_ssi: Some(dest_gssi as u64),
        called_party_short_number_address: None,
        called_party_extension: None,
        external_subscriber_number: None,
        facility: None,
        dm_ms_address: None,
        proprietary: None,
    };

    let mut sdu = BitBuffer::new_autoexpand(80);
    u_setup.to_bitbuf(&mut sdu).expect("Failed to serialize USetup");
    sdu.seek(0);

    SapMsg {
        sap: Sap::LcmcSap,
        src: TetraEntity::Mle,
        dest: TetraEntity::Cmce,
        msg: SapMsgInner::LcmcMleUnitdataInd(LcmcMleUnitdataInd {
            sdu,
            handle: 1,
            endpoint_id: 1,
            link_id: 1,
            received_tetra_address: TetraAddress::new(calling_issi, SsiType::Issi),
            chan_change_resp_req: false,
            chan_change_handle: None,
        }),
    }
}

/// Extract tx_reporters from D-SETUP messages in the sink output.
/// D-SETUPs are identified as LcmcMleUnitdataReq with a chan_alloc that has a usage field.
fn extract_d_setup_reporters(msgs: &mut Vec<SapMsg>) -> Vec<tetra_core::TxReporter> {
    let mut reporters = vec![];
    for msg in msgs.iter_mut() {
        if msg.dest == TetraEntity::Mle {
            if let SapMsgInner::LcmcMleUnitdataReq(ref mut prim) = msg.msg {
                if prim.chan_alloc.as_ref().is_some_and(|ca| ca.usage.is_some()) {
                    if let Some(reporter) = prim.tx_reporter.take() {
                        reporters.push(reporter);
                    }
                }
            }
        }
    }
    reporters
}

/// Count D-SETUP messages in sink output without taking reporters.
fn count_d_setups(msgs: &[SapMsg]) -> usize {
    msgs.iter()
        .filter(|msg| {
            msg.dest == TetraEntity::Mle
                && matches!(&msg.msg, SapMsgInner::LcmcMleUnitdataReq(prim)
                    if prim.chan_alloc.as_ref().is_some_and(|ca| ca.usage.is_some()))
        })
        .count()
}

fn count_circuit_opens(msgs: &[SapMsg]) -> usize {
    msgs.iter()
        .filter(|msg| matches!(&msg.msg, SapMsgInner::CmceCallControl(CallControl::Open(_))))
        .count()
}

fn count_group_d_setups(msgs: &[SapMsg], gssi: u32) -> usize {
    msgs.iter()
        .filter(|msg| {
            msg.dest == TetraEntity::Mle
                && matches!(&msg.msg, SapMsgInner::LcmcMleUnitdataReq(prim)
                    if prim.main_address.ssi == gssi
                        && prim.chan_alloc.as_ref().is_some_and(|ca| ca.usage.is_some()))
        })
        .count()
}

#[test]
fn test_group_setup_joins_existing_circuit() {
    debug::setup_logging_verbose();

    let dltime = TdmaTime { h: 0, m: 1, f: 1, t: 1 };
    let mut test = ComponentTest::new(StackMode::Bs, Some(dltime));
    test.populate_entities(
        vec![TetraEntity::Cmce],
        vec![TetraEntity::Mle, TetraEntity::Umac, TetraEntity::Brew],
    );

    register_subscriber(&mut test, TEST_ISSI, TEST_GSSI);

    // The first terminal creates the local group-call circuit.
    test.submit_message(build_u_setup_msg(TEST_ISSI, TEST_GSSI));
    test.run_stack(Some(1));
    let first_msgs = test.dump_sinks();
    assert_eq!(count_circuit_opens(&first_msgs), 1);

    // A second terminal joins the same group call.  It must receive an
    // individual D-CONNECT, but must not create another local circuit or
    // another group D-SETUP on a different traffic timeslot.
    test.submit_message(build_u_setup_msg(TEST_ISSI + 1, TEST_GSSI));
    test.run_stack(Some(1));
    let join_msgs = test.dump_sinks();
    assert_eq!(count_circuit_opens(&join_msgs), 0);
    assert_eq!(count_group_d_setups(&join_msgs, TEST_GSSI), 0);
    assert!(
        join_msgs.iter().any(|msg| {
            msg.dest == TetraEntity::Mle
                && matches!(&msg.msg, SapMsgInner::LcmcMleUnitdataReq(prim)
                    if prim.main_address.ssi == TEST_ISSI + 1
                        && prim.chan_alloc.as_ref().is_some_and(|ca| ca.usage.is_some()))
        }),
        "expected an individually addressed D-CONNECT for the joining terminal"
    );
}

#[test]
fn test_group_setup_from_pdch_returns_call_signalling_on_pdch() {
    let dltime = TdmaTime { h: 0, m: 1, f: 1, t: 1 };
    let mut test = ComponentTest::new(StackMode::Bs, Some(dltime));
    test.populate_entities(
        vec![TetraEntity::Cmce],
        vec![TetraEntity::Mle, TetraEntity::Umac, TetraEntity::Brew],
    );
    register_subscriber(&mut test, TEST_ISSI, TEST_GSSI);

    let packet_route = SubscriberDeliveryRoute {
        call_id: 1846,
        timeslot: 4,
        usage: 47,
    };
    test.config
        .state_write()
        .subscriber_packet_delivery_routes
        .insert(TEST_ISSI, vec![packet_route]);

    test.submit_message(build_u_setup_msg(TEST_ISSI, TEST_GSSI));
    test.run_stack(Some(1));
    let messages = test.dump_sinks();

    let mut proceeding_seen = false;
    let mut connect_seen = false;
    for message in messages {
        let SapMsgInner::LcmcMleUnitdataReq(prim) = message.msg else {
            continue;
        };
        if prim.main_address.ssi != TEST_ISSI || prim.main_address.ssi_type != SsiType::Issi {
            continue;
        }
        let Some(pdu_type) = prim.sdu.peek_bits(5) else {
            continue;
        };
        let associated = prim
            .associated_channel
            .expect("call setup response must remain on the originating PDCH");
        assert_eq!(associated.call_id, packet_route.call_id);
        assert_eq!(associated.timeslot, packet_route.timeslot);
        assert_eq!(associated.usage, packet_route.usage);
        if pdu_type == CmcePduTypeDl::DCallProceeding.into_raw() {
            proceeding_seen = true;
            assert!(prim.chan_alloc.is_none());
        } else if pdu_type == CmcePduTypeDl::DConnect.into_raw() {
            connect_seen = true;
            let allocation = prim.chan_alloc.expect("D-CONNECT must carry the new voice allocation");
            assert!(allocation.timeslots.iter().any(|assigned| *assigned));
            assert_ne!(
                allocation.timeslots[packet_route.timeslot as usize - 1],
                true,
                "the test voice circuit must not replace the PDCH source route before D-CONNECT is received"
            );
        }
    }
    assert!(proceeding_seen, "D-CALL-PROCEEDING was not emitted for the PDCH setup");
    assert!(connect_seen, "D-CONNECT was not emitted for the PDCH setup");
}

/// Test that late-entry D-SETUP re-sends are throttled when the previous
/// D-SETUP's TxReceipt is still in Pending state (UMAC hasn't transmitted it yet),
/// and that they resume once the receipt reaches a final state.
#[test]
fn test_dsetup_late_entry_throttle() {
    debug::setup_logging_verbose();

    // Start at timeslot 1 so circuit creation aligns cleanly with tick_start checks
    let dltime = TdmaTime { h: 0, m: 1, f: 1, t: 1 };
    let mut test = ComponentTest::new(StackMode::Bs, Some(dltime));

    let components = vec![TetraEntity::Cmce];
    let sinks = vec![TetraEntity::Mle, TetraEntity::Umac, TetraEntity::Brew];
    test.populate_entities(components, sinks);

    register_subscriber(&mut test, TEST_ISSI, TEST_GSSI);

    // Send U-SETUP to start a group call
    let u_setup_msg = build_u_setup_msg(TEST_ISSI, TEST_GSSI);
    test.submit_message(u_setup_msg);
    test.run_stack(Some(1));

    // Collect initial output — should contain D-SETUP (initial send with no tracked receipt)
    let initial_msgs = test.dump_sinks();
    let initial_setups = count_d_setups(&initial_msgs);
    assert!(initial_setups > 0, "Expected initial D-SETUP after U-SETUP");

    // The first late-entry D-SETUP follows one multiframe (about one second)
    // after the initial D-SETUP; there is no next-frame backup anymore.
    test.run_stack(Some(80));
    let mut late_entry_msgs = test.dump_sinks();
    let late_entry_reporters = extract_d_setup_reporters(&mut late_entry_msgs);

    // We should have at least one reporter from the first late-entry send.
    assert!(
        !late_entry_reporters.is_empty(),
        "Expected late-entry D-SETUP with tx_reporter after one second"
    );
    let last_reporter = &late_entry_reporters[late_entry_reporters.len() - 1];
    assert_eq!(last_reporter.get_state(), TxState::Pending);

    // Run for two one-second late-entry intervals. With the receipt still Pending,
    // ALL late-entry D-SETUPs should be suppressed.
    test.run_stack(Some(144));
    let throttled_msgs = test.dump_sinks();
    let throttled_count = count_d_setups(&throttled_msgs);
    assert_eq!(
        throttled_count, 0,
        "Late-entry D-SETUPs should be suppressed while receipt is Pending"
    );

    // Now mark the previous D-SETUP as transmitted (simulating UMAC sending it over the air)
    last_reporter.mark_transmitted();

    // Run for two more late-entry intervals. Now D-SETUPs should go through.
    test.run_stack(Some(144));
    let mut unthrottled_msgs = test.dump_sinks();
    let unthrottled_count = count_d_setups(&unthrottled_msgs);
    assert!(
        unthrottled_count > 0,
        "Late-entry D-SETUPs should resume once receipt reaches final state"
    );

    // Each re-send that went through should have created a fresh reporter
    let new_reporters = extract_d_setup_reporters(&mut unthrottled_msgs);
    assert_eq!(
        new_reporters.len(),
        unthrottled_count,
        "Each re-sent D-SETUP should carry a fresh tx_reporter"
    );
}
