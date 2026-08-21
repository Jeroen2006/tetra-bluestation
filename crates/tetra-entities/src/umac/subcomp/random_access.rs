use std::collections::HashMap;

use tetra_config::bluestation::CfgRandomAccess;
use tetra_core::TdmaTime;

/// Common-channel access-code A parameters advertised in ACCESS-DEFINE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomAccessParameters {
    pub imm: u8,
    pub wt: u8,
    pub nu: u8,
    pub frame_len_factor: bool,
    pub ts_pointer: u8,
    pub min_pdu_prio: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomAccessUpdate {
    pub parameters: RandomAccessParameters,
    /// Raw Base Frame Length value encoded in the AACH access field.
    pub frame_len: u8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RandomAccessWindowStats {
    pub first_attempts: u16,
    pub retry_attempts: u16,
    pub followup_attempts: u16,
    pub invalid_mac_access: u16,
    pub crc_failures: u16,
    pub pending_registrations: u16,
    pub registration_delivery_failures: u16,
    pub sample_score: u32,
    pub ewma_score_hundredths: u32,
}

pub struct RandomAccessController {
    config: CfgRandomAccess,
    current: RandomAccessUpdate,
    first_attempts: u16,
    retry_attempts: u16,
    followup_attempts: u16,
    invalid_mac_access: u16,
    crc_failures: u16,
    recent_accesses: HashMap<u32, TdmaTime>,
    ewma_score_hundredths: u32,
    ewma_initialized: bool,
    last_window_stats: Option<RandomAccessWindowStats>,
    last_update: Option<(u16, u8)>,
    startup_grace_updates_remaining: u8,
    low_load_recovery_progress: u8,
    high_load_progress: u8,
    frame_factor_release_progress: u8,
    pending_registrations: u16,
    registration_delivery_failures: u16,
}

const NOMINAL_IMM: u8 = 8;
const NOMINAL_WT: u8 = 5;
const NOMINAL_NU: u8 = 5;
const NOMINAL_FRAME_LEN: u8 = 4;
const CONTENTION_IMM: u8 = 6;
const CONTENTION_WT: u8 = 6;
const CONTENTION_FRAME_LEN: u8 = 6;
const HEAVY_IMM: u8 = 2;
const HEAVY_WT: u8 = 8;
const HEAVY_FRAME_LEN: u8 = 8;

impl RandomAccessController {
    pub fn new(config: CfgRandomAccess) -> Self {
        let current = RandomAccessUpdate {
            parameters: RandomAccessParameters {
                imm: NOMINAL_IMM,
                wt: NOMINAL_WT,
                nu: NOMINAL_NU,
                frame_len_factor: false,
                ts_pointer: 0,
                min_pdu_prio: 0,
            },
            frame_len: NOMINAL_FRAME_LEN,
        };
        let mut controller = Self {
            startup_grace_updates_remaining: config.startup_grace_multiframes,
            config,
            current,
            first_attempts: 0,
            retry_attempts: 0,
            followup_attempts: 0,
            invalid_mac_access: 0,
            crc_failures: 0,
            recent_accesses: HashMap::new(),
            ewma_score_hundredths: 0,
            ewma_initialized: false,
            last_window_stats: None,
            last_update: None,
            low_load_recovery_progress: 0,
            high_load_progress: 0,
            frame_factor_release_progress: 0,
            pending_registrations: 0,
            registration_delivery_failures: 0,
        };
        controller.current = controller.clamp_update(current);
        controller
    }

    pub fn current(&self) -> RandomAccessUpdate {
        self.current
    }

    pub fn last_window_stats(&self) -> Option<RandomAccessWindowStats> {
        self.last_window_stats
    }

    pub fn observe_access(&mut self, issi: Option<u32>, ts: TdmaTime, active: bool, registration_pending: bool) {
        if active && !registration_pending {
            self.followup_attempts = self.followup_attempts.saturating_add(1);
            return;
        }

        let retry_window_slots = self.config.retry_window_multiframes as i32 * 18 * 4;
        let retry = issi.and_then(|id| self.recent_accesses.get(&id).copied()).is_some_and(|last| {
            let age = ts.diff(last);
            (0..=retry_window_slots).contains(&age)
        });
        if retry {
            self.retry_attempts = self.retry_attempts.saturating_add(1);
        } else {
            self.first_attempts = self.first_attempts.saturating_add(1);
        }
        if let Some(id) = issi {
            self.recent_accesses.retain(|_, last| {
                let age = ts.diff(*last);
                (0..=retry_window_slots).contains(&age)
            });
            self.recent_accesses.insert(id, ts);
        }
    }

    pub fn observe_invalid_mac_access(&mut self) {
        self.invalid_mac_access = self.invalid_mac_access.saturating_add(1);
    }

    pub fn observe_crc_failure(&mut self) {
        self.crc_failures = self.crc_failures.saturating_add(1);
    }

    pub fn set_pending_registrations(&mut self, pending: u16) {
        self.pending_registrations = pending;
    }

    pub fn observe_registration_delivery_failures(&mut self, failures: u16) {
        self.registration_delivery_failures = self.registration_delivery_failures.saturating_add(failures);
    }

    /// Evaluate at one stable MCCH broadcast position per configured interval.
    pub fn maybe_update(&mut self, ts: TdmaTime) -> Option<RandomAccessUpdate> {
        if !self.config.enabled || ts.t != 1 || ts.f != 2 {
            return None;
        }
        let interval = self.config.update_interval_multiframes.max(1);
        if (ts.m - 1) % interval != 0 || self.last_update == Some((ts.h, ts.m)) {
            return None;
        }
        self.last_update = Some((ts.h, ts.m));

        let collision_indications = self
            .retry_attempts
            .saturating_add(self.invalid_mac_access)
            .saturating_add(self.crc_failures);
        let urgent_contention = collision_indications >= 2 || self.pending_registrations >= 2 || self.registration_delivery_failures > 0;
        if self.startup_grace_updates_remaining > 0 && !urgent_contention {
            self.startup_grace_updates_remaining -= 1;
            return None;
        }
        if urgent_contention {
            self.startup_grace_updates_remaining = 0;
        }

        let retry_score = (self.retry_attempts as u32 * self.config.retry_weight_percent as u32 + 99) / 100;
        let sample_score = self.first_attempts as u32
            + retry_score
            + self.invalid_mac_access as u32 * 2
            + self.crc_failures as u32 * 2
            + self.pending_registrations as u32
            + self.registration_delivery_failures as u32 * 4;
        let alpha = self.config.ewma_alpha_percent as u32;
        if self.ewma_initialized {
            self.ewma_score_hundredths = (self.ewma_score_hundredths * (100 - alpha) + sample_score * 100 * alpha) / 100;
        } else {
            self.ewma_score_hundredths = sample_score * 100;
            self.ewma_initialized = true;
        }

        let stats = RandomAccessWindowStats {
            first_attempts: self.first_attempts,
            retry_attempts: self.retry_attempts,
            followup_attempts: self.followup_attempts,
            invalid_mac_access: self.invalid_mac_access,
            crc_failures: self.crc_failures,
            pending_registrations: self.pending_registrations,
            registration_delivery_failures: self.registration_delivery_failures,
            sample_score,
            ewma_score_hundredths: self.ewma_score_hundredths,
        };
        self.last_window_stats = Some(stats);
        let high = self.config.high_load_threshold as u32;
        let low = self.config.low_load_threshold as u32;
        let heavy_load = sample_score >= high || self.ewma_score_hundredths >= high * 100 || stats.registration_delivery_failures > 0;
        let contention = heavy_load || collision_indications >= 2 || stats.pending_registrations >= 2;
        let registration_backlog = stats.pending_registrations > 0
            || stats.retry_attempts > 0
            || stats.invalid_mac_access > 0
            || stats.crc_failures > 0
            || stats.registration_delivery_failures > 0;
        let low_load = !contention && !registration_backlog && sample_score <= low && self.ewma_score_hundredths <= low * 100;

        let previous = self.current;
        if heavy_load {
            self.high_load_progress = if sample_score >= high || stats.registration_delivery_failures > 0 {
                self.high_load_progress.saturating_add(1)
            } else {
                0
            };
            self.low_load_recovery_progress = 0;
            self.frame_factor_release_progress = 0;
            self.apply_contention_target(HEAVY_IMM, HEAVY_WT, HEAVY_FRAME_LEN);
            if self.high_load_progress >= self.config.frame_factor_activation_windows && self.current.frame_len >= self.config.frame_len_max
            {
                self.current.parameters.frame_len_factor = true;
            }
        } else if contention {
            self.high_load_progress = 0;
            self.low_load_recovery_progress = 0;
            self.frame_factor_release_progress = 0;
            self.apply_contention_target(CONTENTION_IMM, CONTENTION_WT, CONTENTION_FRAME_LEN);
        } else if low_load {
            self.high_load_progress = 0;
            self.low_load_recovery_progress = self.low_load_recovery_progress.saturating_add(1);
            if self.low_load_recovery_progress >= self.config.recovery_step_multiframes {
                self.low_load_recovery_progress = 0;
                let nominal = self.nominal_update();
                self.current.parameters.imm = self.current.parameters.imm.saturating_add(1).min(nominal.parameters.imm);
                self.current.parameters.wt = self.current.parameters.wt.saturating_sub(1).max(nominal.parameters.wt);
                self.current.parameters.nu = nominal.parameters.nu;
                self.current.frame_len = self.current.frame_len.saturating_sub(1).max(nominal.frame_len);
            }
            self.frame_factor_release_progress = self.frame_factor_release_progress.saturating_add(1);
            if self.frame_factor_release_progress >= self.config.frame_factor_release_windows {
                self.current.parameters.frame_len_factor = false;
            }
        } else {
            self.high_load_progress = 0;
            self.low_load_recovery_progress = 0;
            self.frame_factor_release_progress = 0;
        }

        self.current = self.clamp_update(self.current);
        self.first_attempts = 0;
        self.retry_attempts = 0;
        self.followup_attempts = 0;
        self.invalid_mac_access = 0;
        self.crc_failures = 0;
        self.registration_delivery_failures = 0;
        (self.current != previous).then_some(self.current)
    }

    fn nominal_update(&self) -> RandomAccessUpdate {
        self.clamp_update(RandomAccessUpdate {
            parameters: RandomAccessParameters {
                imm: NOMINAL_IMM,
                wt: NOMINAL_WT,
                nu: NOMINAL_NU,
                frame_len_factor: false,
                ts_pointer: 0,
                min_pdu_prio: 0,
            },
            frame_len: NOMINAL_FRAME_LEN,
        })
    }

    fn apply_contention_target(&mut self, imm: u8, wt: u8, frame_len: u8) {
        let target = self.clamp_update(RandomAccessUpdate {
            parameters: RandomAccessParameters {
                imm,
                wt,
                nu: NOMINAL_NU,
                frame_len_factor: self.current.parameters.frame_len_factor,
                ts_pointer: self.current.parameters.ts_pointer,
                min_pdu_prio: self.current.parameters.min_pdu_prio,
            },
            frame_len,
        });
        self.current.parameters.imm = self.current.parameters.imm.min(target.parameters.imm);
        self.current.parameters.wt = self.current.parameters.wt.max(target.parameters.wt);
        self.current.parameters.nu = target.parameters.nu;
        self.current.frame_len = self.current.frame_len.max(target.frame_len);
    }

    fn clamp_update(&self, mut update: RandomAccessUpdate) -> RandomAccessUpdate {
        update.parameters.imm = update.parameters.imm.clamp(self.config.imm_min, self.config.imm_max);
        update.parameters.wt = update.parameters.wt.clamp(self.config.wt_min, self.config.wt_max);
        update.parameters.nu = update.parameters.nu.clamp(self.config.nu_min, self.config.nu_max);
        update.frame_len = update.frame_len.clamp(self.config.frame_len_min, self.config.frame_len_max);
        update
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time(m: u8) -> TdmaTime {
        TdmaTime { h: 0, m, f: 2, t: 1 }
    }

    #[test]
    fn heavy_load_jumps_directly_without_lowering_nu() {
        let mut config = CfgRandomAccess::default();
        config.startup_grace_multiframes = 0;
        let mut controller = RandomAccessController::new(config);
        for id in 0..16 {
            controller.observe_access(Some(id), time(1), false, false);
        }
        let update = controller.maybe_update(time(1)).expect("high-load update");
        assert_eq!(update.parameters.imm, HEAVY_IMM);
        assert_eq!(update.parameters.wt, HEAVY_WT);
        assert_eq!(update.parameters.nu, NOMINAL_NU);
        assert_eq!(update.frame_len, HEAVY_FRAME_LEN);
    }

    #[test]
    fn retries_have_lighter_weight_and_followups_do_not_score() {
        let mut config = CfgRandomAccess::default();
        config.startup_grace_multiframes = 0;
        let mut controller = RandomAccessController::new(config);
        controller.observe_access(Some(1234), time(1), false, false);
        controller.observe_access(Some(1234), time(2), false, false);
        controller.observe_access(Some(1234), time(3), true, false);
        controller.maybe_update(time(4));
        let stats = controller.last_window_stats().expect("window stats");
        assert_eq!(stats.first_attempts, 1);
        assert_eq!(stats.retry_attempts, 1);
        assert_eq!(stats.followup_attempts, 1);
        assert_eq!(stats.sample_score, 2);
    }

    #[test]
    fn two_collision_indications_override_startup_grace() {
        let mut config = CfgRandomAccess::default();
        config.startup_grace_multiframes = 5;
        let mut controller = RandomAccessController::new(config);
        controller.observe_invalid_mac_access();
        controller.observe_crc_failure();
        let update = controller.maybe_update(time(1)).expect("contention update");
        assert!(update.parameters.imm <= CONTENTION_IMM);
        assert!(update.parameters.wt >= CONTENTION_WT);
        assert!(update.frame_len >= CONTENTION_FRAME_LEN);
    }

    #[test]
    fn pending_registration_blocks_low_load_recovery() {
        let mut config = CfgRandomAccess::default();
        config.startup_grace_multiframes = 0;
        config.recovery_step_multiframes = 1;
        let mut controller = RandomAccessController::new(config);
        controller.observe_registration_delivery_failures(1);
        controller.maybe_update(time(1)).expect("heavy-load update");
        controller.set_pending_registrations(1);
        assert!(controller.maybe_update(time(2)).is_none());
        assert_eq!(controller.current().parameters.imm, HEAVY_IMM);
    }

    #[test]
    fn frame_factor_requires_sustained_high_load() {
        let mut config = CfgRandomAccess::default();
        config.startup_grace_multiframes = 0;
        config.frame_factor_activation_windows = 3;
        let mut controller = RandomAccessController::new(config);
        for m in 1..=3 {
            for id in 0..16 {
                controller.observe_access(Some(id + u32::from(m) * 100), time(m), false, false);
            }
            controller.maybe_update(time(m));
        }
        assert!(controller.current().parameters.frame_len_factor);
    }

    #[test]
    fn quiet_windows_recover_one_step_at_a_time() {
        let mut config = CfgRandomAccess::default();
        config.startup_grace_multiframes = 0;
        config.recovery_step_multiframes = 1;
        config.ewma_alpha_percent = 100;
        let mut controller = RandomAccessController::new(config);
        for id in 0..16 {
            controller.observe_access(Some(id), time(1), false, false);
        }
        controller.maybe_update(time(1));
        controller.maybe_update(time(2));
        assert_eq!(controller.current().parameters.imm, HEAVY_IMM + 1);
        assert_eq!(controller.current().parameters.wt, HEAVY_WT - 1);
    }
}
