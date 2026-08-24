use crate::bluestation::RuntimeNetworkBroadcast;
use std::collections::{HashMap, HashSet};
use tetra_core::{TdmaTime, TimeslotAllocator};

/// Two multiframes cover the immediate call-control response to a received
/// MAC-ACCESS while remaining much shorter than an EE monitoring interval.
const DIRECT_RESPONSE_WINDOW_TIMESLOTS: i32 = 2 * 18 * 4;

#[derive(Debug, Clone)]
pub struct Subscriber {
    pub issi: u32,
    // Set of attached GSSIs
    pub attached_groups: HashSet<u32>,
    /// Authoritative EE assignment last accepted by the SwMI (or LST).
    /// Raw values avoid making config depend on the PDU crate.
    pub energy_economy_mode: u8,
    pub energy_economy_frame_number: Option<u8>,
    pub energy_economy_multiframe_number: Option<u8>,
    /// One control response establishes a new EE phase before ordinary MCCH
    /// traffic is gated. UMAC consumes this atomically for the addressed MS.
    pub energy_economy_activation_pending: bool,
    /// Group MCCH replay is relevant only while the terminal scans groups.
    pub scanning_enabled: bool,
    /// Last RUA state observed on the air interface.  This is deliberately
    /// optional: local-site trunking must not invent an RUA state for a radio
    /// that has not exchanged an RUA control PDU with this BS.
    pub rua_assigned: Option<bool>,
}

/// A live, per-terminal downlink listening opportunity.  Call control owns
/// the observations; LLC reads this small neutral representation again just
/// before every acknowledged transmission.  Keeping it in shared state is
/// what prevents a retry from inheriting a stale traffic timeslot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriberDeliveryRoute {
    pub call_id: u16,
    pub timeslot: u8,
    pub usage: u8,
}

/// A logical DM subscriber address reachable through a TMO gateway.  This is
/// deliberately separate from `SubscriberRegistry`: a DM-MS route is not a
/// direct TMO registration and must never replace one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DmMsRouteAddress {
    pub ssi: u32,
    pub mcc: Option<u16>,
    pub mnc: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmoCarrierState {
    pub carrier_number: u16,
    pub frequency_band: Option<u8>,
    pub offset: Option<u8>,
    pub duplex_spacing: Option<u8>,
    pub normal_reverse: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct DmGatewaySession {
    pub gateway_issi: u32,
    pub dmo_carrier: Option<DmoCarrierState>,
    pub dm_ms_addresses: HashSet<DmMsRouteAddress>,
    pub last_seen: TdmaTime,
}

#[derive(Debug, Clone, Default)]
pub struct DmGatewayRegistry {
    gateways: HashMap<u32, DmGatewaySession>,
    routes: HashMap<DmMsRouteAddress, HashSet<u32>>,
}

impl DmGatewayRegistry {
    pub fn activate(
        &mut self,
        gateway_issi: u32,
        dmo_carrier: Option<DmoCarrierState>,
        addresses: impl IntoIterator<Item = DmMsRouteAddress>,
        now: TdmaTime,
    ) {
        self.deactivate(gateway_issi);
        let dm_ms_addresses: HashSet<_> = addresses.into_iter().collect();
        for address in &dm_ms_addresses {
            self.routes.entry(*address).or_default().insert(gateway_issi);
        }
        self.gateways.insert(
            gateway_issi,
            DmGatewaySession {
                gateway_issi,
                dmo_carrier,
                dm_ms_addresses,
                last_seen: now,
            },
        );
    }
    pub fn deactivate(&mut self, gateway_issi: u32) {
        let Some(session) = self.gateways.remove(&gateway_issi) else {
            return;
        };
        for address in session.dm_ms_addresses {
            if let Some(gateways) = self.routes.get_mut(&address) {
                gateways.remove(&gateway_issi);
                if gateways.is_empty() {
                    self.routes.remove(&address);
                }
            }
        }
    }
    pub fn add_addresses(&mut self, gateway_issi: u32, addresses: impl IntoIterator<Item = DmMsRouteAddress>, now: TdmaTime) {
        let Some(session) = self.gateways.get_mut(&gateway_issi) else {
            return;
        };
        session.last_seen = now;
        for address in addresses {
            session.dm_ms_addresses.insert(address);
            self.routes.entry(address).or_default().insert(gateway_issi);
        }
    }
    pub fn remove_addresses(&mut self, gateway_issi: u32, addresses: impl IntoIterator<Item = DmMsRouteAddress>, now: TdmaTime) {
        let Some(session) = self.gateways.get_mut(&gateway_issi) else {
            return;
        };
        session.last_seen = now;
        for address in addresses {
            session.dm_ms_addresses.remove(&address);
            if let Some(gateways) = self.routes.get_mut(&address) {
                gateways.remove(&gateway_issi);
                if gateways.is_empty() {
                    self.routes.remove(&address);
                }
            }
        }
    }
    pub fn replace_addresses(&mut self, gateway_issi: u32, addresses: impl IntoIterator<Item = DmMsRouteAddress>, now: TdmaTime) {
        let carrier = self.gateways.get(&gateway_issi).and_then(|session| session.dmo_carrier);
        self.activate(gateway_issi, carrier, addresses, now);
    }
    pub fn touch(&mut self, gateway_issi: u32, now: TdmaTime) {
        if let Some(session) = self.gateways.get_mut(&gateway_issi) {
            session.last_seen = now;
        }
    }
    pub fn update_carrier(&mut self, gateway_issi: u32, dmo_carrier: Option<DmoCarrierState>, now: TdmaTime) {
        if let Some(session) = self.gateways.get_mut(&gateway_issi) {
            session.dmo_carrier = dmo_carrier;
            session.last_seen = now;
        }
    }
    pub fn is_active(&self, gateway_issi: u32) -> bool {
        self.gateways.contains_key(&gateway_issi)
    }
    pub fn gateways_for(&self, address: DmMsRouteAddress) -> Vec<u32> {
        self.routes
            .get(&address)
            .map(|value| value.iter().copied().collect())
            .unwrap_or_default()
    }
    /// Resolve a logical DM-MS address to one radio endpoint. The lowest
    /// gateway ISSI wins when overlapping DM areas are advertised.
    pub fn gateway_for_ssi(&self, ssi: u32) -> Option<(u32, DmMsRouteAddress)> {
        self.gateways
            .iter()
            .flat_map(|(gateway_issi, session)| session.dm_ms_addresses.iter().map(move |address| (*gateway_issi, *address)))
            .filter(|(_, address)| address.ssi == ssi)
            .min_by_key(|(gateway_issi, _)| *gateway_issi)
    }
    pub fn session(&self, gateway_issi: u32) -> Option<&DmGatewaySession> {
        self.gateways.get(&gateway_issi)
    }
}

/// Centralized subscriber registry tracking locally registered ISSIs and their group affiliations.
#[derive(Debug, Clone)]
pub struct SubscriberRegistry {
    /// Registered ISSIs → Subscriber information
    subscribers: HashMap<u32, Subscriber>,
    /// Registered ISSIs that have completed the location-update delivery path.
    active_subscribers: HashSet<u32>,
    /// Registrations waiting for their D-LOCATION UPDATE ACCEPT delivery.
    pending_registration_deliveries: HashSet<u32>,
    /// Failed registration deliveries consumed by UMAC once per RA window.
    registration_delivery_failures: u16,
    /// Set of all GSSIs with at least one local affiliate
    all_attached_groups: HashSet<u32>,
    /// Short-lived MS-initiated MAC-ACCESS contexts. These are deliberately
    /// independent of registration so a first location-update response also
    /// remains immediate.
    direct_response_deadlines: HashMap<u32, TdmaTime>,
}

impl SubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: HashMap::new(),
            active_subscribers: HashSet::new(),
            pending_registration_deliveries: HashSet::new(),
            registration_delivery_failures: 0,
            all_attached_groups: HashSet::new(),
            direct_response_deadlines: HashMap::new(),
        }
    }

    pub fn is_registered(&self, issi: u32) -> bool {
        self.subscribers.contains_key(&issi)
    }

    pub fn is_active(&self, issi: u32) -> bool {
        self.active_subscribers.contains(&issi)
    }

    pub fn mark_active(&mut self, issi: u32) {
        self.active_subscribers.insert(issi);
        self.pending_registration_deliveries.remove(&issi);
    }

    pub fn mark_inactive(&mut self, issi: u32) {
        self.active_subscribers.remove(&issi);
        self.pending_registration_deliveries.remove(&issi);
    }

    /// An MS that just used MAC-ACCESS is listening for the direct outcome of
    /// that procedure. The resulting call-control response must not wait for
    /// its ordinary EE MCCH monitoring phase.
    pub fn mark_direct_response_window(&mut self, issi: u32, now: TdmaTime) {
        self.direct_response_deadlines
            .insert(issi, now.add_timeslots(DIRECT_RESPONSE_WINDOW_TIMESLOTS));
    }

    pub fn direct_response_window_active(&mut self, issi: u32, now: TdmaTime) -> bool {
        self.direct_response_deadlines.retain(|_, deadline| deadline.age(now) <= 0);
        self.direct_response_deadlines
            .get(&issi)
            .is_some_and(|deadline| deadline.age(now) <= 0)
    }

    pub fn set_registration_delivery_pending(&mut self, issi: u32, pending: bool) {
        if pending {
            self.pending_registration_deliveries.insert(issi);
            self.active_subscribers.remove(&issi);
        } else {
            self.pending_registration_deliveries.remove(&issi);
        }
    }

    pub fn is_registration_pending(&self, issi: u32) -> bool {
        self.pending_registration_deliveries.contains(&issi)
    }

    pub fn pending_registration_count(&self) -> u16 {
        self.pending_registration_deliveries.len().min(u16::MAX as usize) as u16
    }

    pub fn note_registration_delivery_failure(&mut self) {
        self.registration_delivery_failures = self.registration_delivery_failures.saturating_add(1);
    }

    pub fn take_registration_delivery_failures(&mut self) -> u16 {
        std::mem::take(&mut self.registration_delivery_failures)
    }

    /// Tolerant registration; if ISSI already registered, we overwrite it with a fresh Subscriber struct
    pub fn register(&mut self, issi: u32) {
        self.deregister(issi); // Clean up any existing registration to prevent stale affiliations
        self.subscribers.insert(
            issi,
            Subscriber {
                issi,
                attached_groups: HashSet::new(),
                energy_economy_mode: 0,
                energy_economy_frame_number: None,
                energy_economy_multiframe_number: None,
                energy_economy_activation_pending: false,
                scanning_enabled: true,
                rua_assigned: None,
            },
        );
    }

    /// Gets mutable ref to subscriber. If not registered, a default Subscriber is inserted.
    pub fn get_subscriber_mut(&mut self, issi: u32) -> &mut Subscriber {
        self.subscribers.entry(issi).or_insert_with(|| Subscriber {
            issi,
            attached_groups: HashSet::new(),
            energy_economy_mode: 0,
            energy_economy_frame_number: None,
            energy_economy_multiframe_number: None,
            energy_economy_activation_pending: false,
            scanning_enabled: true,
            rua_assigned: None,
        })
    }

    /// Deregister an ISSI, removing it from the registry and cleaning up any group affiliations
    pub fn deregister(&mut self, issi: u32) {
        self.mark_inactive(issi);
        self.direct_response_deadlines.remove(&issi);
        if let Some(subscriber) = self.subscribers.remove(&issi) {
            // Clean up global group affiliations for this subscriber
            for gssi in &subscriber.attached_groups {
                // Check if any other subscriber is still affiliated with this group
                let still_has_members = self.subscribers.values().any(|s| s.attached_groups.contains(gssi));
                if !still_has_members {
                    self.all_attached_groups.remove(gssi);
                }
            }
        }
    }

    /// Add GSSI to subscriber's attached groups and global set
    pub fn affiliate(&mut self, issi: u32, gssi: u32) {
        let subscriber = self.get_subscriber_mut(issi);
        subscriber.attached_groups.insert(gssi);
        self.all_attached_groups.insert(gssi);
    }

    /// Remove GSSI from subscriber's attached groups. Update global set if no more subscribers are affiliated with this GSSI.
    pub fn deaffiliate(&mut self, issi: u32, gssi: u32) {
        let subscriber = self.get_subscriber_mut(issi);
        if subscriber.attached_groups.remove(&gssi) {
            // Check if any other subscriber is still affiliated with this group
            let still_has_members = self.subscribers.values().any(|s| s.attached_groups.contains(&gssi));
            if !still_has_members {
                self.all_attached_groups.remove(&gssi);
            }
        }
    }

    /// Check if any subscriber is affiliated with the given GSSI
    pub fn has_group_members(&self, gssi: u32) -> bool {
        self.all_attached_groups.contains(&gssi)
    }

    pub fn set_energy_economy(&mut self, issi: u32, mode: u8, frame_number: Option<u8>, multiframe_number: Option<u8>) -> bool {
        let Some(subscriber) = self.subscribers.get_mut(&issi) else {
            return false;
        };
        subscriber.energy_economy_mode = mode;
        subscriber.energy_economy_frame_number = frame_number;
        subscriber.energy_economy_multiframe_number = multiframe_number;
        true
    }

    pub fn set_energy_economy_activation_pending(&mut self, issi: u32, pending: bool) {
        if let Some(subscriber) = self.subscribers.get_mut(&issi) {
            subscriber.energy_economy_activation_pending = pending;
        }
    }

    pub fn take_energy_economy_activation_pending(&mut self, issi: u32) -> bool {
        let Some(subscriber) = self.subscribers.get_mut(&issi) else {
            return false;
        };
        std::mem::take(&mut subscriber.energy_economy_activation_pending)
    }

    pub fn set_scanning_enabled(&mut self, issi: u32, enabled: bool) {
        if let Some(subscriber) = self.subscribers.get_mut(&issi) {
            subscriber.scanning_enabled = enabled;
        }
    }

    pub fn set_rua_assignment_state(&mut self, issi: u32, assigned: Option<bool>) {
        if let Some(subscriber) = self.subscribers.get_mut(&issi) {
            subscriber.rua_assigned = assigned;
        }
    }

    pub fn rua_assignment_state(&self, issi: u32) -> Option<bool> {
        self.subscribers.get(&issi).and_then(|subscriber| subscriber.rua_assigned)
    }

    pub fn energy_economy(&self, issi: u32) -> Option<(u8, Option<u8>, Option<u8>)> {
        let subscriber = self.subscribers.get(&issi)?;
        Some((
            subscriber.energy_economy_mode,
            subscriber.energy_economy_frame_number,
            subscriber.energy_economy_multiframe_number,
        ))
    }

    pub fn group_energy_economies(&self, gssi: u32) -> Vec<(u32, u8, Option<u8>, Option<u8>)> {
        self.subscribers
            .values()
            .filter(|subscriber| {
                subscriber.attached_groups.contains(&gssi)
                    && subscriber.scanning_enabled
                    && self.active_subscribers.contains(&subscriber.issi)
            })
            .map(|subscriber| {
                (
                    subscriber.issi,
                    subscriber.energy_economy_mode,
                    subscriber.energy_economy_frame_number,
                    subscriber.energy_economy_multiframe_number,
                )
            })
            .collect()
    }
}

/// Mutable, stack-editable state (mutex-protected).
#[derive(Debug, Clone)]
pub struct StackState {
    pub timeslot_alloc: TimeslotAllocator,
    /// Backhaul/network connection to SwMI (e.g., Brew/TetraPack). False -> fallback mode.
    pub network_connected: bool,
    /// Authentication policy advertised by the currently connected SwMI cell.
    /// This is mutable because the central SwMI sends it after the BS starts.
    pub authentication_required: bool,
    /// Centralized subscriber registry for local-first routing decisions.
    pub subscribers: SubscriberRegistry,
    /// Active external DMO gateways served by this BS.
    pub dm_gateways: DmGatewayRegistry,
    /// Ordered, currently valid traffic-channel opportunities for individual
    /// downlink signalling.  Empty means that LLC must use MCCH/EE delivery.
    pub subscriber_delivery_routes: HashMap<u32, Vec<SubscriberDeliveryRoute>>,
    /// Mutable D-NWRK-BROADCAST configuration controlled by the local control
    /// API. The worker reports each version to the SwMI.
    pub network_broadcast: RuntimeNetworkBroadcast,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_deregister() {
        let mut reg = SubscriberRegistry::new();
        assert!(!reg.is_registered(1001));
        reg.register(1001);
        assert!(reg.is_registered(1001));
        reg.deregister(1001);
        assert!(!reg.is_registered(1001));
    }

    #[test]
    fn direct_response_window_expires() {
        let mut reg = SubscriberRegistry::new();
        let now = TdmaTime::default();
        reg.mark_direct_response_window(1001, now);
        assert!(reg.direct_response_window_active(1001, now.add_timeslots(143)));
        assert!(!reg.direct_response_window_active(1001, now.add_timeslots(145)));
    }

    #[test]
    fn test_affiliate_deaffiliate() {
        let mut reg = SubscriberRegistry::new();
        reg.register(1001);
        reg.affiliate(1001, 91);
        assert!(reg.has_group_members(91));
        reg.deaffiliate(1001, 91);
        assert!(!reg.has_group_members(91));
    }

    #[test]
    fn test_has_group_members() {
        let mut reg = SubscriberRegistry::new();
        reg.register(1001);
        reg.register(1002);
        reg.register(1003);
        reg.affiliate(1001, 100);
        reg.affiliate(1002, 100);
        reg.affiliate(1003, 100);
        assert!(reg.has_group_members(100));

        // Deaffiliate one, should still have members
        reg.deaffiliate(1001, 100);
        assert!(reg.has_group_members(100));

        // Deregister a user, should still have members
        reg.deregister(1002);
        assert!(reg.has_group_members(100));

        // Deregister last user, should have no members
        reg.deregister(1003);
        assert!(!reg.has_group_members(100));
    }

    #[test]
    fn test_has_group_members_empty() {
        let reg = SubscriberRegistry::new();
        assert!(!reg.has_group_members(999));
    }

    #[test]
    fn test_register_overwrites_existing_subscriber() {
        let mut reg = SubscriberRegistry::new();
        reg.register(1001);
        reg.affiliate(1001, 91);
        assert!(reg.has_group_members(91));

        reg.register(1001);

        assert!(reg.is_registered(1001));
        reg.deaffiliate(1001, 91);
        assert!(!reg.has_group_members(91));
    }
}

impl Default for StackState {
    fn default() -> Self {
        Self {
            timeslot_alloc: TimeslotAllocator::default(),
            network_connected: false,
            authentication_required: false,
            subscribers: SubscriberRegistry::new(),
            dm_gateways: DmGatewayRegistry::default(),
            subscriber_delivery_routes: HashMap::new(),
            network_broadcast: RuntimeNetworkBroadcast {
                version: 0,
                neighbours: Default::default(),
                broadcast: Default::default(),
            },
        }
    }
}
