use tetra_config::bluestation::{SharedConfig, StackMode};
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{BurstType, PhyBlockNum, PhysicalChannel, Sap, TdmaTime, TrainingSequence};
use tetra_saps::tmv::enums::logical_chans::LogicalChannel;
use tetra_saps::tmv::{TmvCrcInd, TmvUnitdataInd};
use tetra_saps::tp::{TpUnitdataInd, TpUnitdataReqSlot};
use tetra_saps::{SapMsg, SapMsgInner};

use crate::lmac::components::{errorcontrol, scrambler};
use crate::{MessagePrio, MessageQueue, TetraEntityTrait};

#[derive(Debug, Clone, Copy)]
pub struct LmacTrafficChan {
    pub is_active: bool,
    pub logical_channel: LogicalChannel,
    // TODO FIXME: extend with all required fields
}

impl Default for LmacTrafficChan {
    fn default() -> Self {
        Self {
            is_active: false,
            logical_channel: LogicalChannel::TchS,
        }
    }
}

// #[derive(Default)]
// pub struct CurBurst {
//     pub is_traffic: bool,
//     pub usage: Option<u8>,
//     pub blk1_stolen: bool,
//     pub blk2_stolen: bool,
// }

pub struct LmacBs {
    /// Timeslot time, provided by upper layer and then maintained in sync here
    dltime: TdmaTime,
    config: SharedConfig,

    /// Cached from global config
    stack_mode: StackMode,
    scrambling_code: u32,

    /// Traffic channels and associated state
    // ul_circuits: [Option<LmacTrafficChan>; 4],
    // dl_circuits: [Option<LmacTrafficChan>; 4],

    /// Per-timeslot UL physical channel indicator from UMAC.
    /// UL bursts arrive 2 timeslots after the corresponding DL slot, so we must
    /// keep this keyed by timeslot rather than a single "latest" value.
    uplink_phy_chan: [PhysicalChannel; 4],

    /// Signalled by Umac per timeslot. Set to true when in a traffic burst, the 1st stolen block shows that the 2nd slot is also stolen
    blk2_stolen: bool,
    /// Common SCH/HU CRC failures already forwarded for a physical block.
    recent_common_crc_failures: VecDeque<(TdmaTime, PhyBlockNum)>,
    // Details about current burst, parsed from BBK broadcast block
    // cur_burst: CurBurst,
}

impl LmacBs {
    pub fn new(config: SharedConfig) -> Self {
        // Retrieve initial basic network params from config
        let (stack_mode, sc) = {
            let c = config.config();
            tracing::info!(
                "LmacBs: initialized with stack mode {:?}, mcc {} mnc {} cc {}",
                c.stack_mode,
                c.net.mcc,
                c.net.mnc,
                c.cell.colour_code
            );
            (
                c.stack_mode,
                scrambler::tetra_scramb_get_init(c.net.mcc, c.net.mnc, c.cell.colour_code),
            )
        };

        Self {
            config,
            stack_mode,
            scrambling_code: sc,

            dltime: TdmaTime::default(),
            uplink_phy_chan: [PhysicalChannel::Unallocated; 4],
            blk2_stolen: false,
            recent_common_crc_failures: VecDeque::with_capacity(32),
        }
    }

    // fn determine_phy_chan_ul(&self) -> PhysicalChannel {
    //     let ultime = self.dltime.add_timeslots(-2);
    //     // Frame 18 is always CP (I think)
    //     if ultime.f == 18 {
    //         return PhysicalChannel::Control;
    //     }
    //     if self.ul_circuits[ultime.t as usize - 1].is_some() {
    //         return PhysicalChannel::Traffic;
    //     }
    //     PhysicalChannel::Unallocated
    // }

    // fn determine_phy_chan_dl(&self) -> PhysicalChannel {

    //     // Frame 18 is always CP (I think)
    //     if self.dltime.f == 18 {
    //         return PhysicalChannel::Control;
    //     }
    //     // Slot 1 is primary control channel
    //     if self.dltime.t == 1 {
    //         return PhysicalChannel::Control;
    //     }
    //     // Slots 2-4 may contain traffic or are unallocated
    //     if self.dl_circuits[self.dltime.t as usize - 1].is_some() {
    //         return PhysicalChannel::Traffic;
    //     } else {
    //         PhysicalChannel::Unallocated
    //     }
    // }

    /// Yields logical channel for given block. Based on Clause 9.5.1
    fn determine_logical_channel_ul(
        blk: &TpUnitdataInd,
        burst_is_traffic: bool,
        is_sacch_frame: bool,
        block2_stolen: bool,
    ) -> LogicalChannel {
        match blk.burst_type {
            BurstType::CUB => {
                // CUB is always SCH/HU
                assert!(
                    blk.train_type == TrainingSequence::ExtendedTrainSeq,
                    "CUB must have extended training sequence"
                );
                LogicalChannel::SchHu
            }
            BurstType::NUB => {
                match blk.train_type {
                    TrainingSequence::NormalTrainSeq1 => {
                        // TCH or SCH/F
                        assert!(
                            blk.block_num == PhyBlockNum::Both,
                            "NUB with NormalTrainSeq1 must have one large block, got {:?}",
                            blk.block_num
                        );
                        // On an assigned traffic channel the 18th frame is
                        // SACCH: it is still carried on TP, but uses SCH/F
                        // coding rather than TCH coding (EN 300 392-2,
                        // table 9.27).  Treating this as TCH/S drops an
                        // MS's BL-ACK for an individually addressed SDS.
                        if burst_is_traffic && !is_sacch_frame {
                            // Only support TCH/S speech channel for now
                            LogicalChannel::TchS
                        } else {
                            // Full slot signalling
                            LogicalChannel::SchF
                        }
                    }
                    TrainingSequence::NormalTrainSeq2 => {
                        // Clause 9.4.4.3.2:
                        // STCH+TCH
                        // STCH+STCH (if blk1 has resource stating 2nd block stolen)
                        if !burst_is_traffic {
                            tracing::debug!("NUB with NormalTrainSeq2 but non-traffic burst");
                            // tracing::warn!("NUB with NormalTrainSeq2 but non-traffic burst, unexpected");
                        }

                        if blk.block_num == PhyBlockNum::Block1 {
                            LogicalChannel::Stch
                        } else if blk.block_num == PhyBlockNum::Block2 {
                            if !burst_is_traffic || block2_stolen {
                                // TODO FIXME remove !burst_is_traffic guard, temporary fix only
                                tracing::debug!("NUB blk2 in STCH?");
                                LogicalChannel::Stch
                            } else {
                                LogicalChannel::TchS
                            }
                        } else {
                            panic!("NUB with NormalTrainSeq2 must have two blocks, got {:?}", blk.block_num);
                        }
                    }
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }
    }

    fn rx_blk_traffic(&mut self, queue: &mut MessageQueue, blk: TpUnitdataInd, lchan: LogicalChannel, ul_time: TdmaTime) {
        // Only full-slot TCH/S supported for now
        if lchan != LogicalChannel::TchS || blk.block_num != PhyBlockNum::Both {
            tracing::trace!(
                "rx_blk_traffic: ignoring partial/unsupported lchan={:?} blk_num={:?}",
                lchan,
                blk.block_num
            );
            return;
        }

        let (decoded, crc_ok) = errorcontrol::decode_tp(lchan, blk.block, self.scrambling_code);
        let Some(acelp_bits) = decoded else {
            tracing::warn!("rx_blk_traffic: decode_tp returned None");
            return;
        };

        if !crc_ok {
            tracing::trace!("rx_blk_traffic: CRC fail (BFI), still forwarding for concealment");
        }

        // Convert ACELP BitBuffer to Vec<u8> (one bit per byte, 274 bytes)
        let mut data = vec![0u8; acelp_bits.get_len()];
        let mut bb = acelp_bits;
        bb.seek(0);
        bb.to_bitarr(&mut data);

        let msg = SapMsg {
            sap: Sap::TmdSap,
            src: TetraEntity::Lmac,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmdCircuitDataInd(tetra_saps::tmd::TmdCircuitDataInd { ts: ul_time.t, data }),
        };
        queue.push_back(msg);
    }

    fn rx_blk_control(
        &mut self,
        queue: &mut MessageQueue,
        blk: TpUnitdataInd,
        lchan: LogicalChannel,
        ul_time: TdmaTime,
        common_control: bool,
    ) {
        assert!(
            lchan.is_control_channel(),
            "rx_blk_cp: lchan {:?} is not a signalling channel",
            lchan
        );

        let block_num = blk.block_num;
        let (type1bits, crc_pass) = errorcontrol::decode_cp(lchan, blk, Some(self.scrambling_code));

        if ul_time.f == 18 && lchan == LogicalChannel::SchF {
            tracing::info!(
                ul_time = %ul_time,
                block = ?block_num,
                crc_pass,
                "decoded frame-18 SACCH/SCH-F uplink block"
            );
        }

        // tracing::debug!("rx_blk_cp {:?} CRC: {} type1 {:?}",
        //     lchan,
        //     if crc_pass { "ok" } else { "WRONG" },
        //     type1bits
        // );
        tracing::debug!("rx_blk_cp {:?} CRC: {}", lchan, if crc_pass { "ok" } else { "WRONG" });

        if !crc_pass && common_control && lchan == LogicalChannel::SchHu {
            let key = (ul_time, block_num);
            if self.recent_common_crc_failures.contains(&key) {
                tracing::debug!(
                    "rx_blk_control: suppressing duplicate common SCH/HU CRC failure at {} block={:?}",
                    ul_time,
                    block_num
                );
                return;
            }
            self.recent_common_crc_failures.push_back(key);
            if self.recent_common_crc_failures.len() > 32 {
                self.recent_common_crc_failures.pop_front();
            }
            queue.push_prio(
                SapMsg {
                    sap: Sap::TmvSap,
                    src: TetraEntity::Lmac,
                    dest: TetraEntity::Umac,
                    msg: SapMsgInner::TmvCrcInd(TmvCrcInd {
                        logical_channel: lchan,
                        block_num,
                        common_control,
                    }),
                },
                MessagePrio::Immediate,
            );
        }

        // CRC-failed blocks are intentionally not delivered as MAC PDUs.
        if !crc_pass {
            return;
        }
        let Some(type1bits) = type1bits else {
            tracing::warn!("rx_blk_control: decoder returned no type-1 bits for a CRC-valid block");
            return;
        };

        // Pass block to the upper mac
        let m = SapMsg {
            sap: Sap::TmvSap,
            src: TetraEntity::Lmac,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmvUnitdataInd(TmvUnitdataInd {
                pdu: type1bits,
                logical_channel: lchan,
                block_num,
                crc_pass,
                scrambling_code: self.scrambling_code,
            }),
        };

        // Suppose we've just parsed blk1 in a stolen traffic burst.
        // We then don't know whether blk2 is also stolen, as that will be shown by the Umac
        // We thus push this with prio, and the umac will signal with prio if blk2 is stolen too
        queue.push_prio(m, MessagePrio::Immediate);
    }

    fn rx_tp_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::debug!("rx_tp_prim: msg {:?}", message);

        let SapMsgInner::TpUnitdataInd(prim) = message.msg else { panic!() };

        // PHY captured this at reception.  Do not derive it again from the
        // LMAC clock: queue timing can advance that clock before this burst
        // is decoded, which would misclassify FN18 SACCH as TCH/S.
        let ul_time = prim.ul_time;
        let ts_idx = ul_time.t as usize - 1;
        let pchan = self.uplink_phy_chan[ts_idx];
        let lchan = Self::determine_logical_channel_ul(
            &prim,
            pchan == PhysicalChannel::Tp,
            ul_time.f == 18,
            self.blk2_stolen,
        );

        // FN18 on a TP channel is SACCH/SCH-F, not TCH/S. The physical
        // receiver reports only the training sequence, so record the LMAC
        // classification at info level while investigating associated SDS.
        if ul_time.f == 18 {
            tracing::info!(
                lmac_dltime = %self.dltime,
                ul_time = %ul_time,
                physical_channel = ?pchan,
                training_sequence = ?prim.train_type,
                burst_type = ?prim.burst_type,
                block = ?prim.block_num,
                logical_channel = ?lchan,
                "received frame-18 uplink burst"
            );
        }

        // Sanity checks
        assert!(
            prim.block_num != PhyBlockNum::Block1 || !self.blk2_stolen,
            "blk2_stolen must be false when receiving block1"
        );
        assert!(
            pchan == PhysicalChannel::Tp || !self.blk2_stolen,
            "blk2_stolen must be false when not in a traffic burst"
        );

        match lchan {
            LogicalChannel::Clch => {}
            LogicalChannel::TchS | LogicalChannel::Tch24 | LogicalChannel::Tch48 | LogicalChannel::Tch72 => {
                self.rx_blk_traffic(queue, prim, lchan, ul_time)
            }
            LogicalChannel::SchF | LogicalChannel::SchHu | LogicalChannel::Stch => {
                self.rx_blk_control(queue, prim, lchan, ul_time, pchan == PhysicalChannel::Cp && ul_time.t == 1);
            }
            _ => {
                panic!()
            }
        }
    }

    fn rx_tmv_configure_req(&mut self, _queue: &mut MessageQueue, message: SapMsg) {
        let SapMsgInner::TmvConfigureReq(prim) = &message.msg else {
            panic!()
        };
        if let Some(stolen) = prim.blk2_stolen {
            self.blk2_stolen = stolen;
        }
    }

    /// Request from Umac to transmit a message
    fn rx_tmv_unitdata_req_slot(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::debug!("rx_tmv_unitdata_req_slot");
        let SapMsgInner::TmvUnitdataReq(prim) = &mut message.msg else {
            panic!()
        };

        // Update per-timeslot UL physical channel indicator
        let ts_idx = prim.ts.t as usize - 1;
        self.uplink_phy_chan[ts_idx] = prim.ul_phy_chan;

        assert!(prim.bbk.is_some(), "rx_tmv_unitdata_req_slot: bbk must be present");
        assert!(prim.blk1.is_some(), "rx_tmv_unitdata_req_slot: blk1 must be present");

        let bbk = prim.bbk.take().unwrap(); // Guaranteed for BS stack
        let blk1 = prim.blk1.take().unwrap(); // Guaranteed for BS stack
        let blk2 = prim.blk2.take();

        // Determine train and burst type
        let (burst_type, train_type) = match blk1.logical_channel {
            LogicalChannel::Bsch => {
                // Synchronization Downlink Burst
                assert!(blk2.is_some());
                (BurstType::SDB, TrainingSequence::SyncTrainSeq)
            }

            LogicalChannel::SchF => {
                // Single full block
                assert!(blk2.is_none());
                (BurstType::NDB, TrainingSequence::NormalTrainSeq1)
            }
            LogicalChannel::TchS | LogicalChannel::Tch24 | LogicalChannel::Tch48 | LogicalChannel::Tch72 => {
                // Traffic burst
                // TODO FIXME: we could say, if blk2 is some, then it's traffic with the
                // first block stolen. Then, we still need to know if blk2 is also stolen
                assert!(blk2.is_none());
                (BurstType::NDB, TrainingSequence::NormalTrainSeq1)
            }
            LogicalChannel::SchHd | LogicalChannel::Stch | LogicalChannel::Bnch => {
                // Two half-blocks
                assert!(blk2.is_some());
                (BurstType::NDB, TrainingSequence::NormalTrainSeq2)
            }
            _ => panic!("rx_tmv_unitdata_req_slot: unsupported logical channel {:?}", blk1.logical_channel),
        };

        let mut prim_phy = TpUnitdataReqSlot {
            train_type,
            burst_type,
            bbk: None,
            blk1: None,
            blk2: None,
        };

        if prim.ts.f == 18 && (2..=4).contains(&prim.ts.t) {
            tracing::debug!(
                dltime = %prim.ts,
                logical_channel = ?blk1.logical_channel,
                burst_type = ?burst_type,
                training_sequence = ?train_type,
                ul_phy_channel = ?prim.ul_phy_chan,
                "encoding assigned frame-18 downlink burst"
            );
        }

        // Encode blk1 and optionally blk2
        prim_phy.bbk = Some(errorcontrol::encode_aach(bbk.mac_block, bbk.scrambling_code));
        if blk1.logical_channel.is_traffic() {
            prim_phy.blk1 = Some(errorcontrol::encode_tp(blk1, 1));
        } else {
            prim_phy.blk1 = Some(errorcontrol::encode_cp(blk1));
        }
        if let Some(blk2) = blk2 {
            if blk2.logical_channel.is_traffic() {
                prim_phy.blk2 = Some(errorcontrol::encode_tp(blk2, 2));
            } else {
                prim_phy.blk2 = Some(errorcontrol::encode_cp(blk2));
            }
        }

        // Pass timeslot worth of blocks to Phy
        let m = SapMsg {
            sap: Sap::TpSap,
            src: TetraEntity::Lmac,
            dest: TetraEntity::Phy,
            msg: SapMsgInner::TpUnitdataReq(prim_phy),
        };
        queue.push_back(m);
    }

    fn rx_tmv_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tmv_prim");

        match message.msg {
            SapMsgInner::TmvConfigureReq(_) => {
                self.rx_tmv_configure_req(queue, message);
            }
            SapMsgInner::TmvUnitdataReq(_) => {
                self.rx_tmv_unitdata_req_slot(queue, message);
            }
            // SapMsgInner::CmceCallControl(_) => {
            //     self.rx_control(queue, message);
            // }
            _ => {
                panic!();
            }
        }
    }

    // fn rx_control(&mut self, queue: &mut MessageQueue, message: SapMsg) {

    //     tracing::trace!("rx_control");
    //     let SapMsgInner::CmceCallControl(prim) = message.msg else {panic!()};

    //     match prim {
    //         CallControl::Open(_) => {
    //             self.rx_control_circuit_open(queue, prim);
    //         },
    //         CallControl::Close(_, _) => {
    //             self.rx_control_circuit_close(queue, prim);

    //         },
    //     }
    // }
}

impl TetraEntityTrait for LmacBs {
    fn entity(&self) -> TetraEntity {
        TetraEntity::Lmac
    }

    fn set_config(&mut self, config: SharedConfig) {
        self.config = config;
    }

    fn rx_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::debug!("rx_prim: {:?}", message);
        // tracing::debug!(ts=%message.dltime, "rx_prim: {:?}", message);

        match message.sap {
            Sap::TpSap => {
                self.rx_tp_prim(queue, message);
            }
            Sap::TmvSap => {
                self.rx_tmv_prim(queue, message);
            }
            // Sap::Control => {
            //     self.rx_control(queue, message);
            // }
            _ => panic!(),
        }
    }

    fn tick_start(&mut self, _queue: &mut MessageQueue, ts: TdmaTime) {
        self.dltime = ts;
        self.blk2_stolen = false; // reset in case it was set during this tick
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tetra_core::PhyBlockType;

    fn normal_uplink_burst() -> TpUnitdataInd {
        TpUnitdataInd {
            ul_time: TdmaTime::default(),
            train_type: TrainingSequence::NormalTrainSeq1,
            burst_type: BurstType::NUB,
            block_type: PhyBlockType::NUB,
            block_num: PhyBlockNum::Both,
            block: BitBuffer::new(0),
        }
    }

    #[test]
    fn decodes_associated_frame18_as_schf_on_tp() {
        assert_eq!(
            LmacBs::determine_logical_channel_ul(&normal_uplink_burst(), true, true, false),
            LogicalChannel::SchF,
        );
    }

    #[test]
    fn decodes_ordinary_traffic_frame_as_tchs_on_tp() {
        assert_eq!(
            LmacBs::determine_logical_channel_ul(&normal_uplink_burst(), true, false, false),
            LogicalChannel::TchS,
        );
    }
}
use std::collections::VecDeque;
