use crate::bluestation::{RuntimeNetworkBroadcast, SharedConfig};
use std::collections::{HashMap, HashSet, VecDeque};
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
/// SYSINFO. SCK-VN is advertised in the SYSINFO cipher-key field; the SCK
/// material itself never leaves this private runtime boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeAieConfig {
    pub enabled: bool,
    pub sc1_allowed: bool,
    pub sc2: Option<RuntimeSc2Aie>,
    /// A single prepared network-wide SC2 rollover. The future/retired SCKs
    /// never leave this private runtime boundary.
    pub rollover: Option<RuntimeSc2Rollover>,
}

/// BS-local state for a SwMI-announced SCK rollover. The target Network Time
/// is common across cells; the actual application is the first local DL slot
/// at or after it, so cells may differ by a bounded slot phase.
#[derive(Clone, PartialEq)]
pub struct RuntimeSc2Rollover {
    pub rollover_id: u64,
    pub activation_network_time: u64,
    /// The serving cell's exact, locally chosen downlink slot for this
    /// rollover. It is sent to MSs as Absolute IV and is deliberately not a
    /// network-global value: neighbouring cells may have another TDMA phase.
    local_activation_tdma: Option<TdmaTime>,
    activated: bool,
    future: RuntimeSc2Aie,
    retired_rx: Option<(RuntimeSc2Aie, TdmaTime)>,
}

impl std::fmt::Debug for RuntimeSc2Rollover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeSc2Rollover")
            .field("rollover_id", &self.rollover_id)
            .field("activation_network_time", &self.activation_network_time)
            .field("local_activation_tdma", &self.local_activation_tdma)
            .field("activated", &self.activated)
            .field("future", &self.future)
            .field("retired_rx", &self.retired_rx.as_ref().map(|(key, until)| (key, until)))
            .finish()
    }
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

    /// Move all existing terminal and call contexts to the newly active
    /// network SCK without discarding registrations or calls at cutover.
    pub fn rebind_all_to(&mut self, sc2: &RuntimeSc2Aie) {
        let binding = RuntimeSc2Binding::from_sc2(sc2);
        self.terminals.values_mut().for_each(|value| *value = binding);
        self.calls
            .values_mut()
            .for_each(|bindings| bindings.values_mut().for_each(|value| *value = binding));
    }
}

impl Default for RuntimeAieConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sc1_allowed: true,
            sc2: None,
            rollover: None,
        }
    }
}

impl RuntimeAieConfig {
    /// Return the key-free SC2 identity which must be advertised for an
    /// exact downlink air slot.  Downlink is prepared one slot ahead, so
    /// callers cannot safely use only the software-current `sc2` field at a
    /// rollover boundary.
    pub fn downlink_sc2_identity_at(&self, time: TdmaTime) -> Option<Sc2KeyIdentifier> {
        if !self.enabled {
            return None;
        }
        self.sc2_for_air_time(AieDirection::Downlink, time)
            .ok()
            .map(|sc2| RuntimeSc2Binding::from_sc2(sc2).key)
    }

    /// Stage a future key from an authenticated SwMI command. The fixed
    /// parity rule makes the MAC encryption-mode selector unambiguous during
    /// the old-key uplink grace interval.
    pub fn stage_rollover(
        &mut self,
        rollover_id: u64,
        active: RuntimeSc2Binding,
        future: RuntimeSc2Aie,
        activation_network_time: u64,
    ) -> Result<(), &'static str> {
        if activation_network_time >= (1_u64 << 48) {
            return Err("rollover network time exceeds 48 bits");
        }
        let current = active_sc2(self).map_err(|_| "SC2 is not enabled")?;
        if RuntimeSc2Binding::from_sc2(current) != active {
            return Err("rollover active identity does not match local SC2 state");
        }
        if let Some(existing) = &self.rollover {
            if existing.rollover_id == rollover_id {
                if existing.activation_network_time != activation_network_time || existing.future != future {
                    return Err("repeated SC2 rollover command does not match staged key");
                }
                // The SwMI deliberately replays a prepare after WSS reconnect.
                // Never reset an already activated local state back to staged.
                return Ok(());
            }
            // A cancel can be lost while the SwMI connection is down. A new
            // prepare which names the locally active identity proves that this
            // old, unactivated target never became active in this cell, so it
            // is safe to replace the stale staged state.
            //
            // The same proof also identifies the next, sequential rollover
            // after this cell has activated the previous one: `current` is
            // now the prior target. Its new Network-Time must be later than
            // the retained transition, which is at least a full two seconds
            // past the two-slot old-uplink grace period.
            if existing.activated
                && !tetra_network_time_units(activation_network_time)
                    .zip(tetra_network_time_units(existing.activation_network_time))
                    .is_some_and(|(new, old)| new > old)
            {
                return Err("new SC2 rollover overlaps the activated rollover");
            }
        }
        if current.algorithm != future.algorithm {
            return Err("rollover may not change the SC2 TEA algorithm");
        }
        if current.sckn == future.sckn {
            return Err("rollover future SCK must use a different SCKN");
        }
        if future.sck_vn != current.sck_vn.wrapping_add(1) {
            return Err("rollover SCK-VN must increment by exactly one");
        }
        self.rollover = Some(RuntimeSc2Rollover {
            rollover_id,
            activation_network_time,
            local_activation_tdma: None,
            activated: false,
            future,
            retired_rx: None,
        });
        Ok(())
    }

    pub fn rollover_is_activated(&self, rollover_id: u64) -> bool {
        self.rollover
            .as_ref()
            .is_some_and(|rollover| rollover.rollover_id == rollover_id && rollover.activated)
    }

    pub fn staged_rollover_id(&self) -> Option<u64> {
        self.rollover
            .as_ref()
            .filter(|rollover| !rollover.activated)
            .map(|rollover| rollover.rollover_id)
    }

    /// Cancelling is valid only before this BS has crossed the target. The
    /// future key may remain on terminals, but it is no longer a candidate
    /// for activation in this cell.
    pub fn cancel_staged_rollover(&mut self, rollover_id: u64) -> bool {
        if self
            .rollover
            .as_ref()
            .is_some_and(|rollover| rollover.rollover_id == rollover_id && !rollover.activated)
        {
            self.rollover = None;
            true
        } else {
            false
        }
    }

    /// Derive the serving cell's Absolute IV before announcing the rollover.
    /// Network Time has a two-second unit and must not remain the on-air
    /// cutover selector for a running traffic call: the MS and BS need one
    /// identical TDMA slot, not two independently sampled wall clocks.
    pub fn schedule_rollover_absolute_iv(&mut self, current_network_time: u64, current_tdma_time: TdmaTime) -> Option<(u64, TdmaTime)> {
        let rollover = self.rollover.as_mut()?;
        if rollover.activated {
            return None;
        }
        if rollover.local_activation_tdma.is_some() {
            return None;
        }
        let current = tetra_network_time_units(current_network_time)?;
        let target = tetra_network_time_units(rollover.activation_network_time)?;
        // 1 TDMA slot = 17/1200 s; round a Network-Time target upward to a
        // downlink slot as required by EN 300 392-7 clause 4.5.5.6.
        let slots = (target - current).max(0).saturating_mul(2400).saturating_add(16) / 17;
        let slots = i32::try_from(slots).ok()?;
        // EN 300 392-7 section 4.5.5.6 also requires the security information
        // in MAC-SYSINFO to be synchronized with the key change. This stack's
        // Extended Services SYSINFO (containing SCKN and SCK-VN) is sent on
        // TS1 in frames 4, 8, 12 and 16. Use exactly such a BNCH boundary, not
        // merely an arbitrary TS1 where SYSINFO1 may advertise no key
        // identity. TS1 is reserved for cell control, so all voice channels
        // start using the new key only after the matching identity was aired.
        // The cell-local Absolute IV is authoritative; neighbouring cells may
        // select a nearby opportunity independently.
        let time = current_tdma_time.add_timeslots(slots).forward_to_sc2_security_sysinfo();
        rollover.local_activation_tdma = Some(time);
        Some((rollover.rollover_id, time))
    }

    /// Promote a staged key exactly once at its announced local Absolute IV.
    /// The old key is receive-only for
    /// two following UL slots mandated by EN 300 392-7 §4.5.5.4.
    pub fn activate_rollover_if_due(&mut self, current_tdma_time: TdmaTime, sessions: &mut RuntimeAieSessions) -> Option<u64> {
        let (rollover_id, future) = {
            let rollover = self.rollover.as_ref()?;
            if rollover.activated
                || rollover
                    .local_activation_tdma
                    .is_none_or(|activation| activation.age(current_tdma_time) < 0)
            {
                return None;
            }
            (rollover.rollover_id, rollover.future.clone())
        };
        let old = self.sc2.replace(future)?;
        let new_active = self.sc2.as_ref().expect("future key promoted");
        sessions.rebind_all_to(new_active);
        let rollover = self.rollover.as_mut().expect("rollover checked above");
        // A concurrent state change is not possible while this method owns
        // the configuration, but retaining the ID check keeps this update
        // fail-closed if its calling model is ever changed.
        if rollover.rollover_id != rollover_id {
            return None;
        }
        rollover.retired_rx = Some((old, current_tdma_time.add_timeslots(2)));
        rollover.activated = true;
        Some(rollover_id)
    }

    /// Select the key for the actual on-air slot rather than for the software
    /// instant at which the block happens to be constructed. UMAC/LMAC build
    /// downlink one slot ahead, while TMO SCK changeover retains the old key
    /// for exactly two uplink slots (EN 300 392-7 §4.5.5.4).
    fn sc2_for_air_time(&self, direction: AieDirection, time: TdmaTime) -> Result<&RuntimeSc2Aie, AieContextError> {
        let active = active_sc2(self)?;
        let Some(rollover) = self.rollover.as_ref() else {
            return Ok(active);
        };
        let Some(activation) = rollover.local_activation_tdma else {
            return Ok(active);
        };
        let slots_after_activation = activation.age(time);
        // Promotion changes `self.sc2` to the new key, but LMAC may still be
        // draining a burst whose explicit air time precedes the Absolute IV.
        // Such a burst must remain encrypted with the retired key.  Falling
        // through to `active` here produces a short, scheduler-latency-sized
        // patch of undecipherable downlink traffic at rollover.
        if slots_after_activation < 0 && rollover.activated {
            return rollover
                .retired_rx
                .as_ref()
                .map(|(key, _)| key)
                .ok_or(AieContextError::StaleKeyIdentity);
        }
        match direction {
            // An on-air downlink at the Absolute IV must use the target SCK,
            // even if it was assembled during the preceding scheduler tick.
            AieDirection::Downlink if slots_after_activation >= 0 => Ok(&rollover.future),
            // The old SCK is still expected for two uplink slots. Before
            // state promotion `active` is old; afterwards it is retained as
            // the bounded receive-only key.
            AieDirection::Uplink if (0..2).contains(&slots_after_activation) => {
                if rollover.activated {
                    rollover
                        .retired_rx
                        .as_ref()
                        .map(|(key, _)| key)
                        .ok_or(AieContextError::StaleKeyIdentity)
                } else {
                    Ok(active)
                }
            }
            // Entity tick order must not create a third key state. If an
            // uplink is handled after the grace window but before MLE's local
            // promotion turn, select the scheduled target directly.
            AieDirection::Uplink if slots_after_activation >= 2 && !rollover.activated => Ok(&rollover.future),
            _ => Ok(active),
        }
    }

    /// The notification a newly registered or roamed MS must receive. Before
    /// local cutover it repeats this cell's scheduled Absolute IV; after it
    /// reports the new key as currently in use instead of replaying an
    /// expired schedule.
    pub fn rollover_notification(&self) -> Option<(RuntimeSc2Binding, Option<TdmaTime>)> {
        let rollover = self.rollover.as_ref()?;
        if rollover.activated {
            Some((RuntimeSc2Binding::from_sc2(self.sc2.as_ref()?), None))
        } else {
            Some((RuntimeSc2Binding::from_sc2(&rollover.future), Some(rollover.local_activation_tdma?)))
        }
    }
}

/// Compare packed ETSI Network Time values chronologically by their UTC
/// seconds-of-year and year fields. Offset/reserved fields do not determine
/// the instant and may legitimately differ around DST transitions.
fn tetra_network_time_units(value: u64) -> Option<i64> {
    (value < (1_u64 << 48)).then_some(())?;
    let year = 2000_i64 + i64::try_from((value >> 11) & 0x3f).ok()?;
    let days_before_year = (2000..year)
        .map(|year| {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                366
            } else {
                365
            }
        })
        .sum::<i64>();
    Some(days_before_year * 43_200 + i64::try_from(value >> 24).ok()?)
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
                let sc2 = state.aie.sc2_for_air_time(direction, time)?;
                let binding = binding_for_subject(&state, subject, sc2)?;
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
        let sc2 = state.aie.sc2_for_air_time(AieDirection::Uplink, time)?;
        let raw = tetra_crypto::ta61_inverse(&sc2.key, &[(esi >> 16) as u8, (esi >> 8) as u8, esi as u8]);
        let issi = u32::from_be_bytes([0, raw[0], raw[1], raw[2]]);
        if state.aie_sessions.terminal(issi).is_some() {
            let key = RuntimeSc2Binding::from_sc2(sc2).key;
            return Ok((
                issi,
                AieContext::sc2(AieSubject::Individual { issi }, AieDirection::Uplink, time, scope, key),
            ));
        }
        Err(AieContextError::SubjectNotProvisioned)
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
        let sc2 = state.aie.sc2_for_air_time(AieDirection::Uplink, time)?.clone();
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
        let sc2 = state.aie.sc2_for_air_time(AieDirection::Uplink, time)?.clone();
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
        // This compatibility verifier has no TDMA timestamp in its API. The
        // time-aware paths (`resolve_uplink_esi` and MAC/TCH decrypt) make
        // the actual on-air key decision.
        let sc2 = active_sc2(&state.aie)?;
        (tetra_crypto::ta61(&sc2.key, &[(issi >> 16) as u8, (issi >> 8) as u8, issi as u8])
            == [(esi >> 16) as u8, (esi >> 8) as u8, esi as u8])
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

    /// Cipher a traffic plaintext range using its explicitly assigned KSS bit
    /// offset. For STCH+TCH/S, the 137 bits of speech frame B use KSS bits
    /// 216 through 352 (EN 300 392-7, table 6.4).
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
        let sc2 = state.aie.sc2_for_air_time(expected_direction, time)?.clone();
        if RuntimeSc2Binding::from_sc2(&sc2).key == key && binding_for_subject(&state, subject, &sc2)?.key == key {
            return Ok((time, sc2));
        }
        Err(AieContextError::StaleKeyIdentity)
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
fn binding_for_subject(state: &StackState, subject: AieSubject, sc2: &RuntimeSc2Aie) -> Result<RuntimeSc2Binding, AieContextError> {
    match subject {
        // Session state authorizes the subject. Its key identity deliberately
        // follows the target air slot, because the cutover downlink slot is
        // built before `rebind_all_to` promotes future sessions.
        AieSubject::Individual { issi } => state
            .aie_sessions
            .terminal(issi)
            .map(|_| RuntimeSc2Binding::from_sc2(sc2))
            .ok_or(AieContextError::SubjectNotProvisioned),
        AieSubject::Call { call_id, .. } => state
            .aie_sessions
            .call(call_id, subject)
            .map(|_| RuntimeSc2Binding::from_sc2(sc2))
            .ok_or(AieContextError::SubjectNotProvisioned),
        AieSubject::Group { .. } => Ok(RuntimeSc2Binding::from_sc2(sc2)),
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

    /// Snapshot the terminals that completed registration delivery in this
    /// cell.  Rollover MM uses the snapshot to send one cell-specific
    /// Absolute-IV demand to every known listener without holding the shared
    /// state lock while it queues radio messages.
    pub fn active_issis(&self) -> Vec<u32> {
        self.active_subscribers.iter().copied().collect()
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
    /// Key-free rollover lifecycle reports waiting for the authenticated
    /// SwMI worker. Keeping them in shared state lets the TDMA-owned MLE
    /// activate at a slot boundary without putting secrets on a SAP.
    pub sc2_rollover_events: VecDeque<RuntimeSc2RolloverEvent>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeSc2RolloverEvent {
    pub rollover_id: u64,
    pub activated: bool,
    pub local_network_time: u64,
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

    fn rollover_aie(sckn: u8, sck_vn: u16) -> RuntimeAieConfig {
        RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: Some(test_sc2(sckn, sck_vn)),
            rollover: None,
        }
    }

    #[test]
    fn staged_rollover_requires_a_different_sckn_and_the_next_sck_vn() {
        let mut aie = rollover_aie(3, 4);
        let active = RuntimeSc2Binding::from_sc2(aie.sc2.as_ref().expect("active SC2"));
        aie.stage_rollover(1, active, test_sc2(4, 5), 1)
            .expect("a different SCKN with the next SCK-VN is valid");

        let mut aie = rollover_aie(3, 4);
        let active = RuntimeSc2Binding::from_sc2(aie.sc2.as_ref().expect("active SC2"));
        assert_eq!(
            aie.stage_rollover(1, active, test_sc2(4, 17), 1),
            Err("rollover SCK-VN must increment by exactly one")
        );

        let mut aie = rollover_aie(3, 4);
        let active = RuntimeSc2Binding::from_sc2(aie.sc2.as_ref().expect("active SC2"));
        assert_eq!(
            aie.stage_rollover(1, active, test_sc2(3, 5), 1),
            Err("rollover future SCK must use a different SCKN")
        );
    }

    #[test]
    fn staged_rollover_wraps_sck_vn_after_the_16_bit_maximum() {
        let mut aie = rollover_aie(30, u16::MAX);
        let active = RuntimeSc2Binding::from_sc2(aie.sc2.as_ref().expect("active SC2"));
        aie.stage_rollover(1, active, test_sc2(0, 0), 1)
            .expect("SCK-VN wraps modulo 16 bits");
    }

    #[test]
    fn staged_rollover_accepts_sckn_31() {
        let mut aie = rollover_aie(30, 4);
        let active = RuntimeSc2Binding::from_sc2(aie.sc2.as_ref().expect("active SC2"));
        aie.stage_rollover(1, active, test_sc2(31, 5), 1)
            .expect("SCKN 31 is a valid rollover target");
    }

    #[test]
    fn new_prepare_replaces_an_unactivated_rollover_after_a_missed_cancel() {
        let mut aie = rollover_aie(3, 4);
        let active = RuntimeSc2Binding::from_sc2(aie.sc2.as_ref().expect("active SC2"));
        aie.stage_rollover(10, active, test_sc2(4, 5), 1)
            .expect("stage rollover that will be cancelled centrally");

        // The cancel was missed while this BS was disconnected. The new
        // preparation repeats the real active identity and must recover the
        // local staged state rather than reject the new rollover ID.
        aie.stage_rollover(11, active, test_sc2(5, 17), 2)
            .expect("replace stale unactivated rollover");
        assert_eq!(aie.staged_rollover_id(), Some(11));
    }

    #[test]
    fn next_prepare_replaces_an_activated_rollover_after_its_uplink_grace() {
        let mut aie = rollover_aie(3, 4);
        let active = RuntimeSc2Binding::from_sc2(aie.sc2.as_ref().expect("active SC2"));
        aie.stage_rollover(10, active, test_sc2(4, 5), 1 << 24).expect("stage rollover");
        let activation = TdmaTime::default().add_timeslots(1);
        aie.rollover.as_mut().expect("staged rollover").local_activation_tdma = Some(activation);
        aie.activate_rollover_if_due(activation, &mut RuntimeAieSessions::default())
            .expect("activate rollover");

        let new_active = RuntimeSc2Binding::from_sc2(aie.sc2.as_ref().expect("active SC2"));
        aie.stage_rollover(11, new_active, test_sc2(5, 16), 2 << 24)
            .expect("a later rollover may follow an activated rollover");
        assert_eq!(aie.staged_rollover_id(), Some(11));
    }

    #[test]
    fn rollover_selects_keys_by_air_slot_for_tx_ahead_and_uplink_grace() {
        let mut aie = rollover_aie(3, 4);
        let active = RuntimeSc2Binding::from_sc2(aie.sc2.as_ref().expect("active SC2"));
        let activation = TdmaTime::default().add_timeslots(20);
        aie.stage_rollover(1, active, test_sc2(4, 5), 1).expect("stage rollover");
        aie.rollover.as_mut().expect("staged rollover").local_activation_tdma = Some(activation);

        // The scheduler prepares this downlink one tick before it goes on
        // air, but its real slot is the cutover slot and must use the future
        // SCK. The paired two uplink slots still use the old SCK.
        assert_eq!(
            aie.sc2_for_air_time(AieDirection::Downlink, activation)
                .expect("downlink key")
                .sck_vn,
            5
        );
        assert_eq!(
            aie.downlink_sc2_identity_at(activation.add_timeslots(-1))
                .expect("pre-cutover SYSINFO identity")
                .sck_vn,
            4
        );
        assert_eq!(
            aie.downlink_sc2_identity_at(activation).expect("cutover SYSINFO identity").sck_vn,
            5
        );
        assert_eq!(
            aie.sc2_for_air_time(AieDirection::Uplink, activation)
                .expect("first uplink grace key")
                .sck_vn,
            4
        );
        assert_eq!(
            aie.sc2_for_air_time(AieDirection::Uplink, activation.add_timeslots(1))
                .expect("second uplink grace key")
                .sck_vn,
            4
        );

        let mut sessions = RuntimeAieSessions::default();
        aie.activate_rollover_if_due(activation, &mut sessions).expect("activate rollover");
        assert_eq!(
            aie.sc2_for_air_time(AieDirection::Downlink, activation.add_timeslots(-1))
                .expect("retired key for a delayed pre-cutover downlink")
                .sck_vn,
            4
        );
        assert_eq!(
            aie.sc2_for_air_time(AieDirection::Uplink, activation.add_timeslots(1))
                .expect("retired uplink grace key")
                .sck_vn,
            4
        );
        assert_eq!(
            aie.sc2_for_air_time(AieDirection::Uplink, activation.add_timeslots(2))
                .expect("new uplink key after grace")
                .sck_vn,
            5
        );
    }

    #[test]
    fn rollover_absolute_iv_uses_security_sysinfo_before_voice_slots() {
        let mut aie = rollover_aie(3, 4);
        let active = RuntimeSc2Binding::from_sc2(aie.sc2.as_ref().expect("active SC2"));
        aie.stage_rollover(1, active, test_sc2(4, 5), 0).expect("stage rollover");
        let current = TdmaTime { h: 7, m: 8, f: 9, t: 2 };
        let (_, activation) = aie.schedule_rollover_absolute_iv(0, current).expect("schedule local Absolute IV");
        assert_eq!(activation, TdmaTime { h: 7, m: 8, f: 12, t: 1 });
        assert!(activation.is_sc2_security_sysinfo_opportunity());
    }

    #[test]
    fn rollover_absolute_iv_keeps_an_exact_security_sysinfo_boundary() {
        let mut aie = rollover_aie(3, 4);
        let active = RuntimeSc2Binding::from_sc2(aie.sc2.as_ref().expect("active SC2"));
        aie.stage_rollover(1, active, test_sc2(4, 5), 0).expect("stage rollover");
        let current = TdmaTime { h: 7, m: 8, f: 12, t: 1 };
        let (_, activation) = aie.schedule_rollover_absolute_iv(0, current).expect("schedule local Absolute IV");
        assert_eq!(activation, current);
    }

    #[test]
    fn rollover_absolute_iv_advances_to_next_multiframe_after_frame_16() {
        let mut aie = rollover_aie(3, 4);
        let active = RuntimeSc2Binding::from_sc2(aie.sc2.as_ref().expect("active SC2"));
        aie.stage_rollover(1, active, test_sc2(4, 5), 0).expect("stage rollover");
        let current = TdmaTime { h: 7, m: 8, f: 16, t: 2 };
        let (_, activation) = aie.schedule_rollover_absolute_iv(0, current).expect("schedule local Absolute IV");
        assert_eq!(activation, TdmaTime { h: 7, m: 9, f: 4, t: 1 });
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
                rollover: None,
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
            rollover: None,
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
                rollover: None,
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
        let mut second_half = BitBuffer::new(137);
        provider
            .cipher_downlink_traffic_at_kss_offset(context, &mut second_half, 0, 137, 216)
            .expect("TCH/S stolen-half offset is supported");
        assert_ne!(second_half.to_bitstr(), "0".repeat(137));
        provider
            .cipher_downlink_traffic_at_kss_offset(context, &mut second_half, 0, 137, 216)
            .expect("XOR decrypt succeeds at the same offset");
        assert_eq!(second_half.to_bitstr(), "0".repeat(137));
    }

    #[test]
    fn sc2_provider_resolves_group_traffic_and_derives_a_gesi_with_the_active_sck() {
        let config = test_shared_config();
        let sc2 = test_sc2(3, 9);
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: Some(sc2),
            rollover: None,
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
                rollover: None,
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
            sc2_rollover_events: VecDeque::new(),
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
