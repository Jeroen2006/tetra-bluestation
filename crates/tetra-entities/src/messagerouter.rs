use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tetra_config::bluestation::SharedConfig;
use tetra_core::{TdmaTime, tetra_entities::TetraEntity};
use tetra_saps::SapMsg;

use crate::TetraEntityTrait;
use crate::monitoring::{EntitySnapshot, RadioSnapshot, SharedMonitor, TerminalSnapshot, unix_ms};

#[derive(Default)]
pub enum MessagePrio {
    Immediate,
    #[default]
    Normal,
}

pub struct MessageQueue {
    messages: VecDeque<SapMsg>,
}

impl MessageQueue {
    pub fn new() -> Self {
        Self { messages: VecDeque::new() }
    }

    pub fn push_back(&mut self, message: SapMsg) {
        self.messages.push_back(message);
    }

    pub fn push_prio(&mut self, message: SapMsg, prio: MessagePrio) {
        match prio {
            MessagePrio::Immediate => {
                // Insert at the front for immediate processing
                self.messages.push_front(message);
            }
            MessagePrio::Normal => {
                // Insert at the back for normal processing
                self.messages.push_back(message);
            }
        }
    }

    pub fn pop_front(&mut self) -> Option<SapMsg> {
        self.messages.pop_front()
    }

    /// Lets a producing entity enrich messages that it just queued before the
    /// router hands them to the next layer.  Used by CMCE to attach the
    /// current probabilistic listening-channel context to SDS/STATUS.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut SapMsg> {
        self.messages.iter_mut()
    }
}

pub struct MessageRouter {
    /// While currently unused by the MessageRouter, this may change in the future
    /// As such, we provide the MessageRouter with a copy of the SharedConfig
    _config: SharedConfig,
    entities: HashMap<TetraEntity, Box<dyn TetraEntityTrait>>,
    msg_queue: MessageQueue,

    /// The current TDMA time, if applicable.
    /// For Bs mode, this is always available
    /// For Ms/Mon mode, it is recovered from a received SYNC frame and communicated in a different way
    ts: TdmaTime,
    monitor: Option<SharedMonitor>,
    last_monitor_sample: Instant,
}

impl MessageRouter {
    pub fn new(config: SharedConfig) -> Self {
        Self {
            entities: HashMap::new(),
            msg_queue: MessageQueue { messages: VecDeque::new() },
            _config: config,
            ts: TdmaTime::default(),
            monitor: None,
            last_monitor_sample: Instant::now(),
        }
    }

    /// For BS mode, sets global TDMA time
    /// Incremented each tick and passed to entities in tick() function
    pub fn set_dl_time(&mut self, ts: TdmaTime) {
        self.ts = ts;
    }

    pub fn register_entity(&mut self, entity: Box<dyn TetraEntityTrait>) {
        let comp_type = entity.entity();
        tracing::debug!("register_entity {:?}", comp_type);
        self.entities.insert(comp_type, entity);
    }

    pub fn set_monitor(&mut self, monitor: SharedMonitor) {
        self.monitor = Some(monitor);
        self.last_monitor_sample = Instant::now() - Duration::from_secs(1);
    }

    fn publish_monitor_snapshot(&mut self) {
        let Some(monitor) = self.monitor.as_ref() else { return };
        if self.last_monitor_sample.elapsed() < Duration::from_secs(1) { return; }
        self.last_monitor_sample = Instant::now();
        let mut ra = None;
        let mut cell = None;
        let mut rf = HashMap::new();
        let mut last_seen = HashMap::new();
        let mut pdp = HashMap::new();
        for entity in self.entities.values_mut() {
            match entity.monitoring_snapshot() {
                Some(EntitySnapshot::Umac { cell: current_cell, ra: current, rf: signals, last_seen: seen }) => {
                    cell = Some(current_cell);
                    ra = Some(current);
                    rf = signals;
                    last_seen = seen;
                }
                Some(EntitySnapshot::Sndcp(contexts)) => pdp = contexts,
                None => {}
            }
        }
        let state = self._config.state_read();
        let terminals = state.subscribers.monitor_subscribers().into_iter().map(|(issi, registered_at, active, pending, talkgroups)| TerminalSnapshot {
            issi,
            common_scch_supported: state.subscribers.common_control(issi).supported,
            ms_scch: state.subscribers.common_control(issi).ms_scch,
            control_timeslot: tetra_config::bluestation::common_control_slot(state.subscribers.common_control(issi).ms_scch, state.common_control.advertised_count),
            registration: if active { "Active" } else if pending { "Pending" } else { "Registered" }.to_owned(),
            talkgroups,
            last_seen_ms: last_seen.get(&issi).copied().filter(|seen| *seen >= registered_at),
            rf: rf.get(&issi).filter(|sample| sample.measured_at_ms >= registered_at).cloned(),
            pdp: pdp.get(&issi).filter(|context| context.created_at_ms >= registered_at).cloned(),
        }).collect();
        let mut timeslots = ["Control".to_owned(), "Free".to_owned(), "Free".to_owned(), "Free".to_owned()];
        for (index, slot) in (2..=4).enumerate() {
            if let Some(owner) = state.timeslot_alloc.owner(slot) {
                timeslots[index + 1] = match owner {
                    tetra_core::timeslot_alloc::TimeslotOwner::PacketData => "Packet data",
                    tetra_core::timeslot_alloc::TimeslotOwner::Cmce => "Voice",
                    tetra_core::timeslot_alloc::TimeslotOwner::Brew => "Network",
                    tetra_core::timeslot_alloc::TimeslotOwner::CommonControl => "Common SCCH",
                }.to_owned();
            }
        }
        let snapshot = RadioSnapshot {
            measured_at_ms: unix_ms(),
            common_scch_requested: state.operator_settings.common_scch_count,
            common_scch_active: state.common_control.advertised_count,
            common_scch_transition: state.common_control.drain_until.is_some() || state.operator_settings.common_scch_count != state.common_control.advertised_count,
            control_channel_loads: state.subscribers.common_control_loads(state.common_control.advertised_count),
            cell,
            ra: ra.unwrap_or_default(), terminals, timeslots,
            network_connected: state.network_connected,
            radio_tx_allowed: state.radio_transmit_enabled(),
            radio_tx_enabled: state.operator_tx_enabled,
            radio_tx_active: state.radio_tx_active,
            provisioned_once: state.provisioned_once,
            advertisement_accepted: state.advertisement_accepted,
            recovery_ready: state.recovery_ready,
        };
        drop(state);
        if let Ok(mut slot) = monitor.radio.try_write() { *slot = snapshot; }
    }

    /// Returns a mut ref to a component of the requested type
    pub fn get_entity(&mut self, comp: TetraEntity) -> Option<&mut dyn TetraEntityTrait> {
        self.entities.get_mut(&comp).map(|entity| entity.as_mut())
    }

    pub fn submit_message(&mut self, message: SapMsg) {
        tracing::debug!(
            "submit_message {:?}: {:?} -> {:?}",
            message.get_sap(),
            message.get_source(),
            message.get_dest()
        );
        self.msg_queue.push_back(message);
    }

    pub fn deliver_message(&mut self) {
        let message = self.msg_queue.pop_front();
        if let Some(message) = message {
            tracing::debug!(
                "deliver_message: got {:?}: {:?} -> {:?}",
                message.get_sap(),
                message.get_source(),
                message.get_dest()
            );

            // Determine the destination entity
            let dest = message.get_dest();

            // Check if the destination entity registered and deliver if found
            if let Some(entity) = self.entities.get_mut(dest) {
                entity.rx_prim(&mut self.msg_queue, message);
            } else {
                tracing::warn!(
                    "deliver_message: entity {:?} not found for {:?}: {:?} -> {:?}",
                    dest,
                    message.get_sap(),
                    message.get_source(),
                    message.get_dest()
                );
            }
        }
    }

    pub fn deliver_all_messages(&mut self) {
        while !self.msg_queue.messages.is_empty() {
            self.deliver_message();
        }
    }

    pub fn get_msgqueue_len(&self) -> usize {
        self.msg_queue.messages.len()
    }

    pub fn tick_start(&mut self) {
        // tracing::info!("--- tick dl {} ul {} txdl {} ----------------------------",
        //     self.ts, self.ts.add_timeslots(-2), self.ts.add_timeslots(MACSCHED_TX_AHEAD as i32));
        tracing::info!("--- tick dl {} ----------------------------", self.ts);

        // Call tick on all entities
        for entity in self.entities.values_mut() {
            entity.tick_start(&mut self.msg_queue, self.ts);
        }
    }

    /// Executes all end-of-tick functions:
    /// - LLC sends down all outstanding BL-ACKs
    /// - UMAC finalizes any resources for ts and sends down to LMAC
    ///
    pub fn tick_end(&mut self) {
        tracing::debug!("############################ end-of-tick ############################");

        // Llc should send down outstanding BL-ACKs
        let target = TetraEntity::Llc;
        if let Some(entity) = self.entities.get_mut(&target) {
            tracing::trace!("tick_end for entity {:?}", target);
            entity.tick_end(&mut self.msg_queue, self.ts);
        }
        self.deliver_all_messages();

        // Umac should finalize any resources and send down to Lmac
        let target = TetraEntity::Umac;
        if let Some(entity) = self.entities.get_mut(&target) {
            tracing::trace!("tick_end for entity {:?}", target);
            entity.tick_end(&mut self.msg_queue, self.ts);
        }
        self.deliver_all_messages();

        // Then call tick_end on all other entities
        for entity in self.entities.values_mut() {
            let entity_id = entity.entity();
            if entity_id == TetraEntity::Llc || entity_id == TetraEntity::Umac {
                continue;
            }
            entity.tick_end(&mut self.msg_queue, self.ts);
        }
        self.deliver_all_messages();

        // Increment the TDMA time if set
        self.ts = self.ts.add_timeslots(1);
    }

    /// Runs the full stack either forever or for a specified number of ticks.
    /// If `running` is provided, the loop will exit when the flag is set to false
    /// (e.g. by a Ctrl+C signal handler), allowing entities to be dropped cleanly.
    pub fn run_stack(&mut self, num_ticks: Option<usize>, running: Option<Arc<AtomicBool>>) {
        let mut ticks: usize = 0;

        loop {
            // Check if we've been asked to stop (e.g. Ctrl+C)
            if let Some(ref flag) = running {
                if !flag.load(Ordering::Relaxed) {
                    eprintln!("\n[INFO] Shutting down gracefully...");
                    break;
                }
            }

            // Send tick_start event
            self.tick_start();

            // Deliver messages until queue empty
            while self.get_msgqueue_len() > 0 {
                self.deliver_all_messages();
            }

            // Send tick_end event and process final messages
            self.tick_end();

            self.publish_monitor_snapshot();

            // Check if we should stop
            ticks += 1;
            if let Some(num_ticks) = num_ticks {
                if ticks >= num_ticks {
                    break;
                }
            }
        }
    }
}
