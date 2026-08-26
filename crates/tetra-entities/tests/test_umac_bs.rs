mod common;

use tetra_config::bluestation::StackMode;
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{AieRequest, AieScope, AieSubject, BitBuffer, Layer2Service, PhyBlockNum, Sap, SsiType, TdmaTime, TetraAddress, debug};
use tetra_saps::lmm::LmmMleUnitdataReq;
use tetra_saps::sapmsg::{SapMsg, SapMsgInner};
use tetra_saps::tmv::TmvUnitdataReqSlot;
use tetra_saps::tmv::{TmvUnitdataInd, enums::logical_chans::LogicalChannel};

use crate::common::ComponentTest;

#[test]
fn test_in_fragmented_sch_hu_and_sch_f() {
    // Receive SCH/HU containing MAC-ACCESS with fragmentation start
    // Then receive SCH-F containing MAC-END (UL)
    debug::setup_logging_verbose();
    let test_vec1 = "00000000111111000001001111110111000100011001011100111000000011111100001000010000000000000000";
    let test_vec2 = "0110001110000000000010010000000000000000000000000100010000000000000000000000000110010000000000000000000000001000001000000111111000001001111110000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let dltime_vec1 = TdmaTime::default().add_timeslots(2); // Downlink time: 0/1/1/3
    // let ultime_vec1 = dltime_vec1.add_timeslots(-2); // Uplink time: 0/1/1/1
    let test_prim1 = TmvUnitdataInd {
        pdu: BitBuffer::from_bitstr(test_vec1),
        block_num: PhyBlockNum::Block1,
        logical_channel: LogicalChannel::SchHu,
        ul_time: dltime_vec1.add_timeslots(-2),
        crc_pass: true,
        scrambling_code: 864282631,
    };
    let test_sapmsg1 = SapMsg {
        sap: Sap::TmvSap,
        src: TetraEntity::Lmac,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::TmvUnitdataInd(test_prim1),
    };
    let test_prim2 = TmvUnitdataInd {
        pdu: BitBuffer::from_bitstr(test_vec2),
        block_num: PhyBlockNum::Both,
        logical_channel: LogicalChannel::SchF,
        ul_time: dltime_vec1.add_timeslots(-2),
        crc_pass: true,
        scrambling_code: 864282631,
    };
    let test_sapmsg2 = SapMsg {
        sap: Sap::TmvSap,
        src: TetraEntity::Lmac,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::TmvUnitdataInd(test_prim2),
    };

    // Setup testing stack
    let mut test = ComponentTest::new(StackMode::Bs, Some(dltime_vec1));
    let components = vec![TetraEntity::Umac, TetraEntity::Llc, TetraEntity::Mle];
    let sinks: Vec<TetraEntity> = vec![
        // TetraEntity::Lmac, // Simply discard
        TetraEntity::Mm,
    ];
    test.populate_entities(components, sinks);

    // Submit and process message
    test.submit_message(test_sapmsg1);
    test.run_stack(Some(4));
    test.submit_message(test_sapmsg2);
    test.run_stack(Some(1));
    let sink_msgs = test.dump_sinks();

    // Evaluate results. We should have an MM message in the sink
    assert_eq!(sink_msgs.len(), 1);
    tracing::info!("We have the expected MM message, but full validation of result not implemented");
}

#[test]
fn test_in_fragmented_sch_hu_and_sch_hu() {
    // Receive SCH/HU containing MAC-ACCESS with fragmentation start
    // Then receive SCH-HU containing MAC-END-HU
    // Message ultimately contains CMCE SDS message
    debug::setup_logging_verbose();
    let test_vec1 = "00000000111110010001111101110111000000010010011110000010000001100010001001001111100001010100";
    let test_vec2 = "10011000000101000110000000000000000000000000000000000000000000000000111111111111110100000010";
    let dltime_vec1 = TdmaTime::default().add_timeslots(2); // Downlink time: 0/1/1/3
    // let ultime_vec1 = dltime_vec1.add_timeslots(-2); // Uplink time: 0/1/1/1
    let test_prim1 = TmvUnitdataInd {
        pdu: BitBuffer::from_bitstr(test_vec1),
        block_num: PhyBlockNum::Block1,
        logical_channel: LogicalChannel::SchHu,
        ul_time: dltime_vec1.add_timeslots(-2),
        crc_pass: true,
        scrambling_code: 864282631,
    };
    let test_sapmsg1 = SapMsg {
        sap: Sap::TmvSap,
        src: TetraEntity::Lmac,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::TmvUnitdataInd(test_prim1),
    };
    let test_prim2 = TmvUnitdataInd {
        pdu: BitBuffer::from_bitstr(test_vec2),
        block_num: PhyBlockNum::Block1,
        logical_channel: LogicalChannel::SchHu,
        ul_time: dltime_vec1.add_timeslots(-2),
        crc_pass: true,
        scrambling_code: 864282631,
    };
    let test_sapmsg2 = SapMsg {
        sap: Sap::TmvSap,
        src: TetraEntity::Lmac,
        dest: TetraEntity::Umac,
        msg: SapMsgInner::TmvUnitdataInd(test_prim2),
    };

    // Setup testing stack
    let mut test = ComponentTest::new(StackMode::Bs, Some(dltime_vec1));
    let components = vec![TetraEntity::Umac, TetraEntity::Llc, TetraEntity::Mle];
    let sinks: Vec<TetraEntity> = vec![
        // TetraEntity::Lmac, // Simply discard
        TetraEntity::Cmce,
    ];
    test.populate_entities(components, sinks);

    // Submit and process message
    test.submit_message(test_sapmsg1);
    test.run_stack(Some(4));
    test.submit_message(test_sapmsg2);
    test.run_stack(Some(1));

    // Evaluate results. We should have an CMCE message in the sink
    let sink_msgs = test.dump_sinks();
    assert_eq!(sink_msgs.len(), 1);
    tracing::info!("We have the expected CMCE message, but full validation of result not implemented");
}

#[test]
fn test_out_fragmented_resource() {
    // Test for UMAC (and LLC/MLE)
    // The vector is an MM DAttachDetachGroupIdentityAcknowledgement which contains a lot of groups.
    // As it is very large, it needs to be fragmented at the MAC layer.
    debug::setup_logging_verbose();
    let test_vec = "10110011011100110100110001101011100000000000011101010011001110110100000000000111010100111111101101000000000001110101010000000011010000000000011101010100000010110100000000000111010101000001001101000000000001110101010000011011010000000000011101010100001000110100000000000111010101000010101101000000000001110101010000110011010000000000011101010100001110110100000000000111010101000100001101000000000001110101010001001011010000000000011101010100010100";
    let dltime_vec = TdmaTime::default().add_timeslots(2); // Downlink time: 0/1/1/3
    // let ultime_vec = dltime_vec.add_timeslots(-2); // Uplink time: 0/1/1/1
    let test_prim = LmmMleUnitdataReq {
        sdu: BitBuffer::from_bitstr(test_vec),
        handle: 0,
        address: TetraAddress {
            ssi_type: SsiType::Issi,
            ssi: 30128,
        },
        layer2service: Layer2Service::Acknowledged,
        stealing_permission: false,
        stealing_repeats_flag: false,
        encryption_flag: false,
        aie_request: AieRequest::clear(AieSubject::System, AieScope::MacResource),
        is_null_pdu: false,
        tx_reporter: None,
        seamless_handover: None,
    };
    let test_sapmsg = SapMsg {
        sap: Sap::LmmSap,
        src: TetraEntity::Mm,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::LmmMleUnitdataReq(test_prim),
    };

    // Setup testing stack
    let mut test = ComponentTest::new(StackMode::Bs, Some(dltime_vec));
    let components = vec![TetraEntity::Umac, TetraEntity::Llc, TetraEntity::Mle];
    let sinks: Vec<TetraEntity> = vec![TetraEntity::Lmac];
    test.populate_entities(components, sinks);

    // Submit and process message
    test.submit_message(test_sapmsg);
    test.run_stack(Some(8));

    tracing::info!("Validation of result not implemented");
}

#[test]
fn sc2_mm_downlink_sets_esi_mode_and_ciphers_only_the_payload() {
    let dltime = TdmaTime::default().add_timeslots(2);
    let issi = 30_128;
    let mut test = ComponentTest::new(StackMode::Bs, Some(dltime));
    let sc2 = tetra_config::bluestation::RuntimeSc2Aie::new(tetra_config::bluestation::RuntimeSc2TeaAlgorithm::Tea1, 3, 7, [0x5a; 10]);
    {
        let mut state = test.config.state_write();
        state.aie = tetra_config::bluestation::RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: Some(sc2.clone()),
        };
        state.aie_sessions.activate_terminal(issi, &sc2);
    }
    test.populate_entities(vec![TetraEntity::Umac, TetraEntity::Llc, TetraEntity::Mle], vec![TetraEntity::Lmac]);

    test.submit_message(SapMsg {
        sap: Sap::LmmSap,
        src: TetraEntity::Mm,
        dest: TetraEntity::Mle,
        msg: SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
            // The content is intentionally arbitrary for this MAC-boundary
            // regression test; LLC/MLE only transport it as an MM SDU.
            sdu: BitBuffer::from_bitstr("00000000"),
            handle: 0,
            address: TetraAddress::issi(issi),
            layer2service: Layer2Service::Acknowledged,
            stealing_permission: false,
            stealing_repeats_flag: false,
            encryption_flag: true,
            aie_request: AieRequest::sc2(AieSubject::Individual { issi }, AieScope::MacResource),
            is_null_pdu: false,
            tx_reporter: None,
            seamless_handover: None,
        }),
    });
    test.run_stack(Some(8));

    let mut output = test.dump_sinks();
    let mut slot = output
        .iter_mut()
        .find_map(|message| match &mut message.msg {
            SapMsgInner::TmvUnitdataReq(TmvUnitdataReqSlot { blk1: Some(block), .. }) => Some(block.mac_block.clone()),
            _ => None,
        })
        .expect("UMAC must submit a downlink MAC block to LMAC");
    slot.seek(0);
    let resource = tetra_pdus::umac::pdus::mac_resource::MacResource::from_bitbuf(&mut slot).expect("clear MAC header remains decodable");
    assert_eq!(resource.encryption_mode, 0b11, "odd SCK-VN selects SC2 encryption mode 11");
    assert_eq!(
        resource.addr.expect("address").ssi_type,
        SsiType::Ssi,
        "on-air ESI uses the SSI address form"
    );
    assert_ne!(
        resource.addr.expect("address").ssi,
        issi,
        "clear ISSI must not be emitted in an SC2 resource"
    );
}
