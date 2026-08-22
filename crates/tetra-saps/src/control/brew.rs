#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrewSubscriberAction {
    Register,
    Deregister,
    Affiliate,
    Deaffiliate,
    /// MM-only state notification.  Brew deliberately ignores it; CMCE uses
    /// it to apply the group-scanning reception set.
    ScanningState,
}

#[derive(Debug, Clone)]
pub struct MmSubscriberUpdate {
    pub issi: u32,
    pub groups: Vec<u32>,
    pub action: BrewSubscriberAction,
    /// Parallel to `groups` for Affiliate updates.  Deaffiliate updates use
    /// zero because the class is no longer locally present.
    pub class_of_usage: Vec<u8>,
    /// Present only for ScanningState.  `None` keeps legacy updates neutral.
    pub scanning_enabled: Option<bool>,
}
