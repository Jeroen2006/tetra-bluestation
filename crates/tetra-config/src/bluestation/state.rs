use crate::bluestation::{RuntimeNetworkBroadcast, SharedConfig};
use std::collections::{HashMap, HashSet};
use tetra_core::{AieAlgorithm, AieContext, AieDirection, AieSubject, BitBuffer, Sc2KeyIdentifier, SoftBit, TdmaTime, TimeslotAllocator};

/// The TEA variant selected by the SwMI for SC2 AIE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSc2TeaAlgorithm {
    Tea1,
    Tea3,
}

/// The currently authoritative SC2 key received from the SwMI. This stays in
/// mutable runtime state because it can change while a BS is running. Its
/// custom Debug implementation deliberately never exposes key material.
#[derive(Clone, PartialEq, Eq)]
pub struct RuntimeSc2Aie {
    pub algorithm: RuntimeSc2TeaAlgorithm,
    pub sckn: u8,
    pub sck_vn: u16,
    key: [u8; 10],
}

impl RuntimeSc2Aie {
    /// Accept SCK material only at the authenticated SwMI configuration
    /// boundary. Callers can subsequently use the central provider, but
    /// cannot extract the key from a runtime configuration snapshot.
    pub fn new(algorithm: RuntimeSc2TeaAlgorithm, sckn: u8, sck_vn: u16, key: [u8; 10]) -> Self {
        Self {
            algorithm,
            sckn,
            sck_vn,
            key,
        }
    }
}

impl std::fmt::Debug for RuntimeSc2Aie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeSc2Aie")
            .field("algorithm", &self.algorithm)
            .field("sckn", &self.sckn)
            .field("sck_vn", &self.sck_vn)
            .field("key_present", &true)
            .finish()
    }
}

/// AIE policy cached from the authenticated SwMI. `sc1_allowed` maps to the
/// SC1-supported bit and a present SC2 record maps to the SC2/SCKN fields in
/// SYSINFO. SCK-VN and the SCK itself are intentionally not broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAieConfig {
    pub enabled: bool,
    pub sc1_allowed: bool,
    pub sc2: Option<RuntimeSc2Aie>,
}

/// Key-free SC2 identity bound to a registered terminal or active call. The
/// corresponding SCK remains exclusively in `RuntimeAieConfig` and is never
/// duplicated into per-subscriber/call state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeSc2Binding {
    pub key: Sc2KeyIdentifier,
}

impl RuntimeSc2Binding {
    pub fn from_sc2(sc2: &RuntimeSc2Aie) -> Self {
        let algorithm = match sc2.algorithm {
            RuntimeSc2TeaAlgorithm::Tea1 => AieAlgorithm::Tea1,
            RuntimeSc2TeaAlgorithm::Tea3 => AieAlgorithm::Tea3,
        };
        Self {
            key: Sc2KeyIdentifier::new(algorithm, sc2.sckn, sc2.sck_vn).expect("runtime SC2 SCKN is validated by SwMI protocol"),
        }
    }
}

/// Central, key-free SC2 state. UMAC may bind a terminal provisionally after
/// inverse-TA61 has decoded an encrypted initial registration; MM still owns
/// registration approval and CMCE binds call state when AIE reaches the
/// traffic/FACCH implementation. This lets UMAC resolve one consistent
/// context without making protocol layers carry key bytes.
#[derive(Debug, Clone, Default)]
pub struct RuntimeAieSessions {
    terminals: HashMap<u32, RuntimeSc2Binding>,
    /// A call can legitimately have several individually protected legs
    /// (e.g. each party of a private call, or successive floor holders).
    /// Keep every subject separately instead of letting the last update
    /// overwrite the prior binding.
    calls: HashMap<u32, HashMap<AieSubject, RuntimeSc2Binding>>,
}

impl RuntimeAieSessions {
    pub fn activate_terminal(&mut self, issi: u32, sc2: &RuntimeSc2Aie) {
        self.terminals.insert(issi, RuntimeSc2Binding::from_sc2(sc2));
    }

    pub fn deactivate_terminal(&mut self, issi: u32) {
        self.terminals.remove(&issi);
        self.calls.retain(|_, bindings| {
            bindings.retain(|subject, _| !matches!(subject, AieSubject::Call { issi: Some(value), .. } if *value == issi));
            !bindings.is_empty()
        });
    }

    pub fn terminal(&self, issi: u32) -> Option<RuntimeSc2Binding> {
        self.terminals.get(&issi).copied()
    }

    pub fn bind_call(&mut self, call_id: u32, subject: AieSubject, sc2: &RuntimeSc2Aie) {
        assert!(matches!(subject, AieSubject::Call { call_id: id, .. } if id == call_id));
        self.calls
            .entry(call_id)
            .or_default()
            .insert(subject, RuntimeSc2Binding::from_sc2(sc2));
    }

    pub fn unbind_call(&mut self, call_id: u32) {
        self.calls.remove(&call_id);
    }

    pub fn call(&self, call_id: u32, subject: AieSubject) -> Option<RuntimeSc2Binding> {
        self.calls.get(&call_id)?.get(&subject).copied()
    }

    /// Drops bindings that refer to a former SwMI key identity. This must run
    /// atomically with a runtime AIE config replacement.
    pub fn retain_current_key(&mut self, sc2: Option<&RuntimeSc2Aie>) {
        let Some(sc2) = sc2 else {
            self.terminals.clear();
            self.calls.clear();
            return;
        };
        let current = RuntimeSc2Binding::from_sc2(sc2);
        self.terminals.retain(|_, binding| *binding == current);
        self.calls.retain(|_, bindings| {
            bindings.retain(|_, binding| *binding == current);
            !bindings.is_empty()
        });
    }
}

impl Default for RuntimeAieConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sc1_allowed: true,
            sc2: None,
        }
    }
}

/// Errors from the one BS-local SC2 context/key provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AieContextError {
    Sc2Disabled,
    SubjectNotProvisioned,
    UnsupportedSubject,
    StaleKeyIdentity,
    InvalidContext,
    CryptoInput,
}

/// Central BS SC2 provider. It is the sole public API that can use SCK
/// material after the SwMI configuration boundary. [`tetra_core::AieContext`]
/// contains only the non-secret SC2 identity and is safe for SAP metadata.
#[derive(Clone)]
pub struct BsAieKeyProvider {
    config: SharedConfig,
}

impl BsAieKeyProvider {
    pub fn new(config: SharedConfig) -> Self {
        Self { config }
    }

    /// Bind a key-free policy to direction and exact TDMA time.
    pub fn resolve(
        &self,
        request: tetra_core::AieRequest,
        direction: tetra_core::AieDirection,
        time: TdmaTime,
    ) -> Result<tetra_core::AieContext, AieContextError> {
        match request {
            tetra_core::AieRequest::Clear { subject, scope } => Ok(tetra_core::AieContext::clear(subject, direction, time, scope)),
            tetra_core::AieRequest::Sc2 { subject, scope } => {
                let state = self.config.state_read();
                let sc2 = active_sc2(&state.aie)?;
                let binding = binding_for_subject(&state, subject, sc2)?;
                let current = RuntimeSc2Binding::from_sc2(sc2);
                if binding != current {
                    return Err(AieContextError::StaleKeyIdentity);
                }
                Ok(tetra_core::AieContext::sc2(subject, direction, time, scope, binding.key))
            }
        }
    }

    /// Transform a short identity into its encrypted form (IESI/GESI) for
    /// an SC2-protected MAC resource. The SCK never crosses this API.
    pub fn encrypted_short_identity(&self, context: AieContext, ssi: u32) -> Result<u32, AieContextError> {
        let (_, sc2) = self.current_sc2_for_context(context, AieDirection::Downlink)?;
        if ssi > 0x00ff_ffff {
            return Err(AieContextError::InvalidContext);
        }
        let esi = tetra_crypto::ta61(&sc2.key, &[(ssi >> 16) as u8, (ssi >> 8) as u8, ssi as u8]);
        Ok(u32::from_be_bytes([0, esi[0], esi[1], esi[2]]))
    }

    /// Resolve the clear on-air ESI of an uplink SC2 MAC PDU to its ISSI and
    /// active individual SC2 session. TA61 is a reversible identity
    /// transformation, so the BS must decrypt the ESI directly rather than
    /// searching a list of already registered subscribers. This is required
    /// for the first encrypted location update after a BS restart.
    pub fn resolve_uplink_esi(&self, esi: u32, time: TdmaTime, scope: tetra_core::AieScope) -> Result<(u32, AieContext), AieContextError> {
        if esi > 0x00ff_ffff {
            return Err(AieContextError::InvalidContext);
        }

        let state = self.config.state_read();
        let sc2 = active_sc2(&state.aie)?;
        let current = RuntimeSc2Binding::from_sc2(sc2);
        let raw = tetra_crypto::ta61_inverse(&sc2.key, &[(esi >> 16) as u8, (esi >> 8) as u8, esi as u8]);
        let issi = u32::from_be_bytes([0, raw[0], raw[1], raw[2]]);
        if state.aie_sessions.terminal(issi) != Some(current) {
            return Err(AieContextError::SubjectNotProvisioned);
        }
        Ok((
            issi,
            AieContext::sc2(AieSubject::Individual { issi }, AieDirection::Uplink, time, scope, current.key),
        ))
    }

    /// Decode an SC2 ESI and create the key-free terminal binding needed for
    /// the encrypted registration exchange.  Possession of the SCK protects
    /// the encrypted payload; SwMI authentication and registration policy
    /// still decide whether the decoded ISSI is admitted.
    pub fn bind_unbound_uplink_esi(
        &self,
        esi: u32,
        time: TdmaTime,
        scope: tetra_core::AieScope,
    ) -> Result<(u32, AieContext), AieContextError> {
        if esi > 0x00ff_ffff {
            return Err(AieContextError::InvalidContext);
        }
        let mut state = self.config.state_write();
        let sc2 = active_sc2(&state.aie)?.clone();
        let raw = tetra_crypto::ta61_inverse(&sc2.key, &[(esi >> 16) as u8, (esi >> 8) as u8, esi as u8]);
        let issi = u32::from_be_bytes([0, raw[0], raw[1], raw[2]]);
        let binding = RuntimeSc2Binding::from_sc2(&sc2);
        state.aie_sessions.activate_terminal(issi, &sc2);
        Ok((
            issi,
            AieContext::sc2(AieSubject::Individual { issi }, AieDirection::Uplink, time, scope, binding.key),
        ))
    }

    /// Decrypt an SC2 MAC payload before its ESI can be bound to a local
    /// terminal session. Kept for callers that only need payload recovery;
    /// registration must use [`bind_unbound_uplink_esi`] to decode the ESI
    /// before scheduling MAC fragments and layer-2 acknowledgements.
    pub fn decrypt_unbound_uplink_mac(
        &self,
        time: TdmaTime,
        mac_block: &mut BitBuffer,
        start: usize,
        len: usize,
    ) -> Result<(), AieContextError> {
        let state = self.config.state_read();
        let sc2 = active_sc2(&state.aie)?.clone();
        drop(state);
        self.cipher_mac_with_sc2(time, &sc2, mac_block, start, len, 0, AieDirection::Uplink)
    }

    /// Check that the ISSI carried by a decrypted bootstrap PDU maps to the
    /// clear ESI in its MAC header. This is the SC2 identity proof; no ISSI
    /// candidate list is required.
    pub fn verify_uplink_esi(&self, esi: u32, issi: u32) -> Result<(), AieContextError> {
        if esi > 0x00ff_ffff || issi == 0 || issi > 0x00ff_ffff {
            return Err(AieContextError::InvalidContext);
        }
        let state = self.config.state_read();
        let sc2 = active_sc2(&state.aie)?;
        let expected = tetra_crypto::ta61(&sc2.key, &[(issi >> 16) as u8, (issi >> 8) as u8, issi as u8]);
        (u32::from_be_bytes([0, expected[0], expected[1], expected[2]]) == esi)
            .then_some(())
            .ok_or(AieContextError::InvalidContext)
    }

    /// A clear MAC-DATA from an already SC2-bound terminal is not a valid
    /// fallback when SC1 is forbidden.  MAC-ACCESS remains outside this
    /// check so an unbound terminal can still perform the clear bootstrap.
    pub fn clear_uplink_allowed(&self, issi: u32) -> bool {
        let state = self.config.state_read();
        !state.aie.enabled || state.aie.sc1_allowed || state.aie_sessions.terminal(issi).is_none()
    }

    /// Cipher exactly one phase-modulation MAC region.  `start` and `len`
    /// are relative to the supplied MAC block; clear header and fill bits are
    /// intentionally outside that range.  The provider validates the
    /// key-free context against live runtime state before touching the SCK.
    pub fn cipher_downlink_mac(
        &self,
        context: AieContext,
        mac_block: &mut BitBuffer,
        start: usize,
        len: usize,
    ) -> Result<(), AieContextError> {
        self.cipher_mac(context, mac_block, start, len, 0, AieDirection::Downlink)
    }

    /// Decrypt (the same XOR operation) exactly one uplink MAC payload
    /// region.  Header/fill ranges are selected by UMAC and remain clear.
    pub fn cipher_uplink_mac(
        &self,
        context: AieContext,
        mac_block: &mut BitBuffer,
        start: usize,
        len: usize,
    ) -> Result<(), AieContextError> {
        self.cipher_mac(context, mac_block, start, len, 0, AieDirection::Uplink)
    }

    /// Cipher a decoded traffic type-1 region.  The key stays inside this
    /// provider; LMAC supplies only the exact burst time through `context`.
    pub fn cipher_downlink_traffic(
        &self,
        context: AieContext,
        block: &mut BitBuffer,
        start: usize,
        len: usize,
    ) -> Result<(), AieContextError> {
        self.cipher_mac(context, block, start, len, 0, AieDirection::Downlink)
    }

    /// Decrypt a decoded uplink traffic type-1 region.
    pub fn cipher_uplink_traffic(
        &self,
        context: AieContext,
        block: &mut BitBuffer,
        start: usize,
        len: usize,
    ) -> Result<(), AieContextError> {
        self.cipher_mac(context, block, start, len, 0, AieDirection::Uplink)
    }

    /// Cipher a type-5 traffic range using its explicitly assigned KSS bit
    /// offset. The currently supported TCH/S stolen-half offset is 216,
    /// which is byte-aligned; unaligned future mappings need a dedicated API.
    pub fn cipher_downlink_traffic_at_kss_offset(
        &self,
        context: AieContext,
        block: &mut BitBuffer,
        start: usize,
        len: usize,
        kss_offset: usize,
    ) -> Result<(), AieContextError> {
        self.cipher_mac(context, block, start, len, kss_offset, AieDirection::Downlink)
    }

    /// Apply the same cipher mask to demodulator soft decisions.  An XOR with
    /// one reverses the expected bit, which is a sign inversion in the LLR
    /// representation.  This keeps FEC on the encrypted TCH/S path instead
    /// of silently falling back to hard decisions.
    pub fn cipher_uplink_traffic_soft(
        &self,
        context: AieContext,
        soft_bits: &mut [SoftBit],
        kss_offset: usize,
    ) -> Result<(), AieContextError> {
        let mut mask = BitBuffer::new(soft_bits.len());
        self.cipher_mac(context, &mut mask, 0, soft_bits.len(), kss_offset, AieDirection::Uplink)?;
        let mut bits = vec![0u8; soft_bits.len()];
        mask.seek(0);
        mask.to_bitarr(&mut bits);
        for (soft, bit) in soft_bits.iter_mut().zip(bits) {
            if bit != 0 {
                *soft = soft.saturating_neg();
            }
        }
        Ok(())
    }

    fn cipher_mac(
        &self,
        context: AieContext,
        mac_block: &mut BitBuffer,
        start: usize,
        len: usize,
        kss_offset: usize,
        direction: AieDirection,
    ) -> Result<(), AieContextError> {
        if len == 0 {
            return Ok(());
        }
        let (time, sc2) = self.current_sc2_for_context(context, direction)?;
        self.cipher_mac_with_sc2(time, &sc2, mac_block, start, len, kss_offset, direction)
    }

    fn cipher_mac_with_sc2(
        &self,
        time: TdmaTime,
        sc2: &RuntimeSc2Aie,
        mac_block: &mut BitBuffer,
        start: usize,
        len: usize,
        kss_offset: usize,
        direction: AieDirection,
    ) -> Result<(), AieContextError> {
        if len == 0 {
            return Ok(());
        }
        let config = self.config.config();
        let eck = tetra_crypto::tb5(
            config.cell.main_carrier,
            config.cell.location_area,
            config.cell.colour_code,
            &sc2.key,
        )
        .map_err(|_| AieContextError::CryptoInput)?;
        if kss_offset % 8 != 0 {
            return Err(AieContextError::CryptoInput);
        }
        let mut key_stream = vec![0_u8; (kss_offset + len).div_ceil(8)];
        let iv = tetra_crypto::FrameNumbers {
            timeslot: time.t,
            frame: time.f,
            multiframe: time.m,
            hyperframe: time.h,
            uplink: direction == AieDirection::Uplink,
        }
        .iv();
        match sc2.algorithm {
            RuntimeSc2TeaAlgorithm::Tea1 => tetra_crypto::tea1(iv, &eck, &mut key_stream),
            RuntimeSc2TeaAlgorithm::Tea3 => tetra_crypto::tea3(iv, &eck, &mut key_stream),
        }
        let cursor = mac_block.get_pos();
        mac_block.seek(start);
        mac_block
            .xor_bytearr(&key_stream[kss_offset / 8..], len)
            .ok_or(AieContextError::InvalidContext)?;
        mac_block.seek(cursor);
        Ok(())
    }

    fn current_sc2_for_context(
        &self,
        context: AieContext,
        expected_direction: AieDirection,
    ) -> Result<(TdmaTime, RuntimeSc2Aie), AieContextError> {
        let AieContext::Sc2 {
            subject,
            direction,
            time,
            key,
            ..
        } = context
        else {
            return Err(AieContextError::InvalidContext);
        };
        if direction != expected_direction {
            return Err(AieContextError::InvalidContext);
        }
        let state = self.config.state_read();
        let sc2 = active_sc2(&state.aie)?.clone();
        if RuntimeSc2Binding::from_sc2(&sc2).key != key || binding_for_subject(&state, subject, &sc2)?.key != key {
            return Err(AieContextError::StaleKeyIdentity);
        }
        Ok((time, sc2))
    }
}

fn active_sc2(aie: &RuntimeAieConfig) -> Result<&RuntimeSc2Aie, AieContextError> {
    aie.enabled
        .then_some(())
        .and_then(|()| aie.sc2.as_ref())
        .ok_or(AieContextError::Sc2Disabled)
}

/// In TMO SC2 the active SCK is also the cipher context for a group-addressed
/// traffic leg.  This is not a GCK/GSKO implementation: those remain needed
/// for their own OTAR/provisioning flows, but they are not a precondition for
/// using an already active SCK on a group traffic burst.
fn binding_for_subject(state: &StackState, subject: AieSubject, active_sc2: &RuntimeSc2Aie) -> Result<RuntimeSc2Binding, AieContextError> {
    match subject {
        AieSubject::Individual { issi } => state.aie_sessions.terminal(issi).ok_or(AieContextError::SubjectNotProvisioned),
        AieSubject::Call { call_id, .. } => state
            .aie_sessions
            .call(call_id, subject)
            .ok_or(AieContextError::SubjectNotProvisioned),
        AieSubject::Group { .. } => Ok(RuntimeSc2Binding::from_sc2(active_sc2)),
        AieSubject::System => Err(AieContextError::UnsupportedSubject),
    }
}

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
    /// AIE settings and SC2 key supplied by the authenticated SwMI.
    pub aie: RuntimeAieConfig,
    /// Key-free active SC2 sessions. The SCK itself stays only in `aie`.
    pub aie_sessions: RuntimeAieSessions,
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
    use tetra_core::{AieRequest, AieScope};

    fn test_shared_config() -> SharedConfig {
        let config = crate::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        SharedConfig::from_parts(config, None)
    }

    fn test_sc2(sckn: u8, sck_vn: u16) -> RuntimeSc2Aie {
        RuntimeSc2Aie::new(RuntimeSc2TeaAlgorithm::Tea3, sckn, sck_vn, [0x5a; 10])
    }

    #[test]
    fn aie_sessions_keep_each_private_call_leg() {
        let sc2 = test_sc2(3, 42);
        let mut sessions = RuntimeAieSessions::default();
        let alice = AieSubject::Call {
            call_id: 17,
            issi: Some(1001),
            gssi: None,
        };
        let bob = AieSubject::Call {
            call_id: 17,
            issi: Some(1002),
            gssi: None,
        };

        sessions.bind_call(17, alice, &sc2);
        sessions.bind_call(17, bob, &sc2);

        assert_eq!(sessions.call(17, alice), Some(RuntimeSc2Binding::from_sc2(&sc2)));
        assert_eq!(sessions.call(17, bob), Some(RuntimeSc2Binding::from_sc2(&sc2)));
    }

    #[test]
    fn aie_key_rotation_discards_old_terminal_and_call_bindings() {
        let old = test_sc2(3, 42);
        let new = test_sc2(4, 43);
        let mut sessions = RuntimeAieSessions::default();
        let call = AieSubject::Call {
            call_id: 17,
            issi: Some(1001),
            gssi: None,
        };
        sessions.activate_terminal(1001, &old);
        sessions.bind_call(17, call, &old);

        sessions.retain_current_key(Some(&new));

        assert_eq!(sessions.terminal(1001), None);
        assert_eq!(sessions.call(17, call), None);
    }

    #[test]
    fn sc2_provider_resolves_esi_and_uses_the_uplink_iv() {
        let config = test_shared_config();
        let issi = 0x12_34_56;
        let sc2 = RuntimeSc2Aie::new(RuntimeSc2TeaAlgorithm::Tea1, 3, 7, [0x5a; 10]);
        {
            let mut state = config.state_write();
            state.aie = RuntimeAieConfig {
                enabled: true,
                sc1_allowed: false,
                sc2: Some(sc2.clone()),
            };
            state.aie_sessions.activate_terminal(issi, &sc2);
        }
        let provider = BsAieKeyProvider::new(config);
        let time = TdmaTime::default().add_timeslots(37);
        let downlink = provider
            .resolve(
                AieRequest::sc2(AieSubject::Individual { issi }, AieScope::MacData),
                AieDirection::Downlink,
                time,
            )
            .expect("active SC2 terminal resolves");
        let esi = provider
            .encrypted_short_identity(downlink, issi)
            .expect("ESI is derived inside provider");
        let (resolved_issi, uplink) = provider
            .resolve_uplink_esi(esi, time, AieScope::MacData)
            .expect("uplink ESI resolves to active ISSI");
        assert_eq!(resolved_issi, issi);
        assert!(uplink.is_encrypted());

        let mut encrypted = BitBuffer::from_bitstr("1011001110001110");
        let plaintext = encrypted.clone();
        let payload_len = encrypted.get_len();
        provider
            .cipher_uplink_mac(uplink, &mut encrypted, 0, payload_len)
            .expect("uplink cipher succeeds");
        assert_ne!(encrypted.to_bitstr(), plaintext.to_bitstr(), "uplink KSS changes payload");
        provider
            .cipher_uplink_mac(uplink, &mut encrypted, 0, payload_len)
            .expect("XOR decrypt succeeds");
        assert_eq!(encrypted.to_bitstr(), plaintext.to_bitstr());
        assert!(!provider.clear_uplink_allowed(issi), "SC2-bound terminal cannot downgrade to clear");
        assert!(provider.clear_uplink_allowed(issi + 1), "unbound terminal may use clear bootstrap");
    }

    #[test]
    fn sc2_provider_decodes_and_binds_an_unbound_registration_esi() {
        let config = test_shared_config();
        let issi = 0x12_34_56;
        let key = [0x5a; 10];
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: Some(RuntimeSc2Aie::new(RuntimeSc2TeaAlgorithm::Tea3, 3, 7, key)),
        };
        let provider = BsAieKeyProvider::new(config);
        let esi_bytes = tetra_crypto::ta61(&key, &[(issi >> 16) as u8, (issi >> 8) as u8, issi as u8]);
        let esi = u32::from_be_bytes([0, esi_bytes[0], esi_bytes[1], esi_bytes[2]]);
        let mut payload = BitBuffer::from_bitstr("1011001110001110");
        let plaintext = payload.clone();
        let time = TdmaTime::default().add_timeslots(37);
        let payload_len = payload.get_len();

        let (decoded_issi, context) = provider
            .bind_unbound_uplink_esi(esi, time, AieScope::MacData)
            .expect("inverse TA61 binds an initial encrypted registration");
        assert_eq!(decoded_issi, issi);
        assert!(context.is_encrypted());
        assert!(
            provider.resolve_uplink_esi(esi, time, AieScope::MacData).is_ok(),
            "the bound ISSI resolves without a subscriber candidate list"
        );

        provider
            .decrypt_unbound_uplink_mac(time, &mut payload, 0, payload_len)
            .expect("unbound SC2 registration decrypts with the active SCK");
        provider
            .decrypt_unbound_uplink_mac(time, &mut payload, 0, payload_len)
            .expect("SC2 XOR restores the bootstrap payload");
        assert_eq!(payload.to_bitstr(), plaintext.to_bitstr());
        assert!(provider.verify_uplink_esi(esi, issi).is_ok());
        assert!(provider.verify_uplink_esi(esi, issi + 1).is_err());
    }

    #[test]
    fn sc2_provider_applies_the_stolen_tchs_kss_offset() {
        let config = test_shared_config();
        let issi = 0x12_34_56;
        let sc2 = RuntimeSc2Aie::new(RuntimeSc2TeaAlgorithm::Tea3, 3, 8, [0x5a; 10]);
        {
            let mut state = config.state_write();
            state.aie = RuntimeAieConfig {
                enabled: true,
                sc1_allowed: false,
                sc2: Some(sc2.clone()),
            };
            state.aie_sessions.activate_terminal(issi, &sc2);
        }
        let provider = BsAieKeyProvider::new(config);
        let context = provider
            .resolve(
                AieRequest::sc2(AieSubject::Individual { issi }, AieScope::Traffic),
                AieDirection::Downlink,
                TdmaTime::default().add_timeslots(19),
            )
            .expect("active SC2 terminal resolves");
        let mut second_half = BitBuffer::new(216);
        provider
            .cipher_downlink_traffic_at_kss_offset(context, &mut second_half, 0, 216, 216)
            .expect("TCH/S stolen-half offset is supported");
        assert_ne!(second_half.to_bitstr(), "0".repeat(216));
        provider
            .cipher_downlink_traffic_at_kss_offset(context, &mut second_half, 0, 216, 216)
            .expect("XOR decrypt succeeds at the same offset");
        assert_eq!(second_half.to_bitstr(), "0".repeat(216));
    }

    #[test]
    fn sc2_provider_resolves_group_traffic_and_derives_a_gesi_with_the_active_sck() {
        let config = test_shared_config();
        let sc2 = test_sc2(3, 9);
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: Some(sc2),
        };
        let provider = BsAieKeyProvider::new(config);
        let context = provider
            .resolve(
                AieRequest::sc2(AieSubject::Group { gssi: 101 }, AieScope::Traffic),
                AieDirection::Downlink,
                TdmaTime::default(),
            )
            .expect("an active SC2 SCK protects group traffic as well");
        assert!(context.is_encrypted());
        let gesi = provider
            .encrypted_short_identity(context, 101)
            .expect("group ESI is derived inside the provider");
        assert_ne!(gesi, 101);
    }

    #[test]
    fn sc2_soft_traffic_cipher_inverts_exactly_the_ciphered_llrs() {
        let config = test_shared_config();
        let issi = 0x12_34_56;
        let sc2 = test_sc2(3, 10);
        {
            let mut state = config.state_write();
            state.aie = RuntimeAieConfig {
                enabled: true,
                sc1_allowed: false,
                sc2: Some(sc2.clone()),
            };
            state.aie_sessions.activate_terminal(issi, &sc2);
        }
        let provider = BsAieKeyProvider::new(config);
        let context = provider
            .resolve(
                AieRequest::sc2(AieSubject::Individual { issi }, AieScope::Traffic),
                AieDirection::Uplink,
                TdmaTime::default().add_timeslots(23),
            )
            .expect("active SC2 terminal resolves");
        let mut ciphertext = BitBuffer::new(32);
        provider
            .cipher_uplink_traffic(context, &mut ciphertext, 0, 32)
            .expect("hard traffic mask succeeds");
        let mut expected = vec![0u8; 32];
        ciphertext.seek(0);
        ciphertext.to_bitarr(&mut expected);

        let mut soft = vec![-48i8; 32];
        provider
            .cipher_uplink_traffic_soft(context, &mut soft, 0)
            .expect("soft traffic mask succeeds");
        for (mask, llr) in expected.into_iter().zip(soft) {
            assert_eq!(llr, if mask == 0 { -48 } else { 48 });
        }
    }

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
            aie: RuntimeAieConfig::default(),
            aie_sessions: RuntimeAieSessions::default(),
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
