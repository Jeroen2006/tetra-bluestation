use crate::bluestation::RuntimeNetworkBroadcast;
use std::collections::{HashMap, HashSet};
use tetra_core::TimeslotAllocator;

#[derive(Debug, Clone)]
pub struct Subscriber {
    pub issi: u32,
    // Set of attached GSSIs
    pub attached_groups: HashSet<u32>,
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
}

impl SubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: HashMap::new(),
            active_subscribers: HashSet::new(),
            pending_registration_deliveries: HashSet::new(),
            registration_delivery_failures: 0,
            all_attached_groups: HashSet::new(),
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
            },
        );
    }

    /// Gets mutable ref to subscriber. If not registered, a default Subscriber is inserted.
    pub fn get_subscriber_mut(&mut self, issi: u32) -> &mut Subscriber {
        self.subscribers.entry(issi).or_insert_with(|| Subscriber {
            issi,
            attached_groups: HashSet::new(),
        })
    }

    /// Deregister an ISSI, removing it from the registry and cleaning up any group affiliations
    pub fn deregister(&mut self, issi: u32) {
        self.mark_inactive(issi);
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
            network_broadcast: RuntimeNetworkBroadcast {
                version: 0,
                neighbours: Default::default(),
                broadcast: Default::default(),
            },
        }
    }
}
