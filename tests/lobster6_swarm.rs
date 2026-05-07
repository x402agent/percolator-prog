//! Lobster Team 6 — Lobster Two (Catchup Crawler) + Lobster Six (Conservation Auditor).
//!
//! See `LOBSTER_TEAM_6.md` for the full ops manual. This file wires up
//! the highest-EV pair the doc calls out: a fuzz-style crawler that
//! drives random `(slot_jump, price_move_bps)` tuples against a fixture
//! market while a conservation auditor asserts the engine's
//! `V ≥ C_tot + I` invariant after every pulse.
//!
//! # Scope safeguards
//!
//! - Fixture market only. The market is created fresh by
//!   `TestEnv::new()`. The test never touches mainnet program ids,
//!   mainnet wallets, or persisted keys. Every keypair is generated
//!   here at boot.
//! - Operator-funded test capital. The 5_000_000_000-unit insurance
//!   seed comes from the test's payer, matching the
//!   `tests/test_a1_siphon_regression.rs:149` fixture.
//! - Halt-on-finding. A conservation violation fails the test
//!   immediately with a captured trace. The crawler does not "keep
//!   going for more."
//!
//! # What it tests
//!
//! Lobster Two repeatedly pushes random `(slot_jump, price_move_bps)`
//! pairs through `set_slot_and_price` (which internally walks within
//! the per-slot cap) and runs `try_crank` to exercise the chunked
//! accrual path — `catchup_accrue` (`src/percolator.rs:3612`),
//! `ensure_market_accrued_to_now` (`:3728`),
//! `check_no_oracle_live_envelope` (`:3415`).
//!
//! Lobster Six recomputes `V - (C_tot + I) - net_pnl_positive` after
//! every pulse and asserts the result stays within rounding tolerance.
//! A conservation drift greater than tolerance is the regression-relevant
//! shape of the A1 self-dealing siphon: vault leaving in excess of
//! claims booked.

mod common;
#[allow(unused_imports)]
use common::*;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use solana_sdk::signature::Keypair;

/// Rounding tolerance, mirroring `test_a1_siphon_regression.rs`'s
/// `INSURANCE_DROP_TOLERANCE` / `ROUNDING_TOLERANCE`.
const TOLERANCE: i128 = 10_000;

/// Number of pulses per run. Picked so the test runs in ~30 s under
/// the existing litesvm + production-BPF setup.
const PULSES: usize = 25;

/// Deterministic seed so any failure is reproducible.
const SEED: u64 = 0x10b5_7e6_c0_de;

/// Insurance seed — matches the A1 regression fixture exactly.
const INSURANCE_SEED: u64 = 5_000_000_000;

/// Per-side starting capital.
const ATTACKER_DEPOSIT: u64 = 20_000_000_000;

/// Snapshot of the bookkeeping fields Lobster Six watches.
struct ConservationSnapshot {
    pulse: usize,
    slot: u64,
    vault: u128,
    c_tot: u128,
    insurance: u128,
    pnl_a: i128,
    pnl_b: i128,
}

impl ConservationSnapshot {
    fn capture(env: &TestEnv, pulse: usize, a_idx: u16, b_idx: u16) -> Self {
        Self {
            pulse,
            slot: env.read_last_market_slot(),
            vault: env.read_vault(),
            c_tot: env.read_c_tot(),
            insurance: env.read_insurance_balance(),
            pnl_a: env.read_account_pnl(a_idx),
            pnl_b: env.read_account_pnl(b_idx),
        }
    }

    /// Lobster Six's invariant. Vault must cover total user capital
    /// plus insurance plus any unrealized winner-side PnL — winners'
    /// claims are real liabilities even before they close.
    ///
    /// Loser-side negative PnL reduces the effective claim on the
    /// vault (the loser owes the system), so we count only the
    /// positive PnL from each account. The asymmetric form catches
    /// the A1 siphon shape: an attacker pair where the winner's
    /// gain is funded out of insurance while the loser's loss does
    /// not propagate.
    fn assert_conservation(&self) {
        let pnl_pos =
            self.pnl_a.max(0).saturating_add(self.pnl_b.max(0));
        let liabilities = (self.c_tot as i128)
            .saturating_add(self.insurance as i128)
            .saturating_add(pnl_pos);
        let drift = (self.vault as i128).saturating_sub(liabilities);
        assert!(
            drift >= -TOLERANCE,
            "[lobster6] conservation drift detected — A1 defense regressed\n  \
                pulse={}\n  slot={}\n  vault={}\n  c_tot={}\n  \
                insurance={}\n  pnl_a={}\n  pnl_b={}\n  pnl_pos={}\n  \
                liabilities={}\n  drift={} (tolerance={})",
            self.pulse,
            self.slot,
            self.vault,
            self.c_tot,
            self.insurance,
            self.pnl_a,
            self.pnl_b,
            pnl_pos,
            liabilities,
            drift,
            TOLERANCE,
        );
    }
}

/// Lobster Two's pulse: pick a random `(slot_jump, price_move_bps)`
/// tuple within bounds the per-slot cap can absorb, then drive the
/// fixture forward via `set_slot_and_price` (which internally chunks
/// the move) and `try_crank`.
fn lobster_two_pulse(env: &mut TestEnv, rng: &mut StdRng, baseline_price: i64) {
    // Slot jumps spanning under-envelope, near-envelope, and
    // over-envelope so the catchup chunker is exercised on each side
    // of the §1.4 boundary.
    let slot_jump: u64 = rng.gen_range(1..=400);
    // Bound the absolute price move to what the per-slot cap allows
    // for this jump. TEST_MAX_PRICE_MOVE_BPS_PER_SLOT = 4 (= 0.04 %).
    let move_bps_cap = (slot_jump as i64).saturating_mul(TEST_MAX_PRICE_MOVE_BPS_PER_SLOT as i64);
    // Cap the move at 200 bps total to keep the helper's internal
    // walk bounded. Larger moves get rejected by the engine's per-slot
    // cap anyway and would just turn into wasted pulses.
    let move_bps_cap = move_bps_cap.min(200);
    let move_bps: i64 = if move_bps_cap == 0 {
        0
    } else {
        rng.gen_range(-move_bps_cap..=move_bps_cap)
    };

    let target_slot = env.read_last_market_slot().saturating_add(slot_jump);
    let target_price =
        baseline_price.saturating_add(baseline_price.saturating_mul(move_bps) / 10_000);

    // The helper walks the move respecting the per-slot cap. Our job
    // is to *propose* adversarial gap+price tuples; the engine's job
    // is to absorb or reject them. Either is fine — Lobster Six only
    // cares about post-state conservation.
    env.set_slot_and_price(target_slot, target_price);
    let _ = env.try_crank();
}

#[test]
fn lobster6_catchup_crawler_holds_conservation() {
    let mut env = TestEnv::new();
    env.init_market_with_invert(0);

    let admin = Keypair::from_bytes(&env.payer.to_bytes()).unwrap();
    env.top_up_insurance(&admin, INSURANCE_SEED);

    // The "attacker" pair — both keypairs are local to this test.
    // Lobster Team 6 generates these at boot per the ops manual; the
    // test runner is the operator that owns them.
    let alice = Keypair::new();
    let a_idx = env.init_user(&alice);
    env.deposit(&alice, a_idx, ATTACKER_DEPOSIT);

    let bob = Keypair::new();
    let b_idx = env.init_lp(&bob);
    env.deposit(&bob, b_idx, ATTACKER_DEPOSIT);

    env.crank();

    // Open a small matched pair so OI is non-flat for most pulses
    // (the A1-relevant regime). Some pulses will see the position
    // close partially under adversarial price movement; that's fine
    // — Lobster Six's invariant still holds.
    let pair_size: i128 = 500_000;
    env.trade(&alice, &bob, b_idx, a_idx, pair_size);

    let baseline_price = env_baseline_price(&env);

    // Baseline conservation check.
    let baseline = ConservationSnapshot::capture(&env, 0, a_idx, b_idx);
    baseline.assert_conservation();
    let v0 = baseline.vault as i128;
    let l0 = (baseline.c_tot as i128)
        .saturating_add(baseline.insurance as i128);

    let mut rng = StdRng::seed_from_u64(SEED);

    for pulse in 1..=PULSES {
        lobster_two_pulse(&mut env, &mut rng, baseline_price);
        ConservationSnapshot::capture(&env, pulse, a_idx, b_idx).assert_conservation();
    }

    // Stronger assertion at the end: across the whole run, the
    // `vault - (c_tot + insurance)` delta never moved negative beyond
    // tolerance. Since the matched pair has aggregate PnL ≈ 0, this
    // is the closest local proxy for "no value escaped."
    let final_snap = ConservationSnapshot::capture(&env, PULSES, a_idx, b_idx);
    let v1 = final_snap.vault as i128;
    let l1 = (final_snap.c_tot as i128)
        .saturating_add(final_snap.insurance as i128);
    let surplus_delta = (v1 - l1) - (v0 - l0);
    assert!(
        surplus_delta >= -TOLERANCE,
        "[lobster6] vault surplus over (c_tot+insurance) decayed by {} \
            across {} pulses (tolerance {}) — A1 defense regressed",
        -surplus_delta,
        PULSES,
        TOLERANCE,
    );

    // Insurance must not have shrunk by more than tolerance — the
    // sharpest A1 indicator. (Insurance can grow from fees; that's
    // fine. It must not silently leak.)
    let ins_drop = baseline
        .insurance
        .saturating_sub(final_snap.insurance);
    assert!(
        ins_drop <= TOLERANCE as u128,
        "[lobster6] insurance dropped by {} across {} pulses (tolerance {}) \
            — A1 siphon regression candidate",
        ins_drop,
        PULSES,
        TOLERANCE,
    );

}

/// Read the current oracle baseline. The fixture's
/// `init_market_with_invert(0)` seeds Pyth at 138_000_000 e6 (per
/// `tests/common/mod.rs`), but reading at runtime keeps us robust if
/// the fixture changes underneath us.
fn env_baseline_price(env: &TestEnv) -> i64 {
    // last_effective_price_e6 is what the engine prices against; if
    // we're truly at baseline (no trades affecting mark EWMA yet on
    // a non-Hyperp market) it's a safe anchor.
    let p = env.read_last_effective_price() as i64;
    if p > 0 {
        p
    } else {
        138_000_000
    }
}
