//! Public-path stale-market gates (security.md seventh pass).
//!
//! `TopUpInsurance` and `InitUser` are permissionless public paths that
//! mutate slab state. Under v12.19 they must reject before any token
//! movement when the market has matured into the permissionless-resolve
//! window (`permissionless_stale_matured`). Otherwise an attacker (or
//! confused honest user) could move tokens into a market that has
//! already exited the live regime, leaving funds stranded behind the
//! resolution flow.
//!
//! These tests fire the matured-gate path. The §9.2 `CatchupRequired`
//! backstop is structurally only reachable after a partial CatchupAccrue
//! advances `last_good_oracle_slot` ahead of `engine.last_market_slot`
//! (covered indirectly by the F1 partial-catchup regression).

mod common;
#[allow(unused_imports)]
use common::*;

use solana_sdk::signature::{Keypair, Signer};

/// Custom error code for `PercolatorError::OracleStale`.
const ORACLE_STALE: u32 = 6;

#[test]
fn test_attack_top_up_insurance_rejected_after_stale_matured() {
    let mut env = TestEnv::new();
    // perm_resolve = 80 (test default, < MAX_ACCRUAL_DT_SLOTS = 100).
    env.init_market_with_invert(0);

    let admin = Keypair::from_bytes(&env.payer.to_bytes()).unwrap();
    env.top_up_insurance(&admin, 1_000_000_000);

    let lp = Keypair::new();
    let lp_idx = env.init_lp(&lp);
    env.deposit(&lp, lp_idx, 50_000_000_000);

    let user = Keypair::new();
    let user_idx = env.init_user(&user);
    env.deposit(&user, user_idx, 10_000_000_000);

    env.trade(&user, &lp, lp_idx, user_idx, 1_000_000);
    env.crank();

    let insurance_before = env.read_insurance_balance();
    let last_slot = env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;

    // Jump well past perm_resolve (80) without cranking. Oracle account is
    // also re-stamped at the new slot, but `last_good_oracle_slot` is the
    // stored cursor; without a wrapper read it stays at the pre-jump value.
    env.set_slot_and_price_raw_no_walk(last_slot + 200, 138_000_000);

    let payer = Keypair::new();
    env.svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();
    let result = env.try_top_up_insurance(&payer, 1_000_000);
    assert!(
        result.is_err(),
        "TopUpInsurance must reject on a stale-matured market: result={:?}",
        result
    );
    let err_str = result.unwrap_err();
    assert!(
        err_str.contains(&format!("Custom({})", ORACLE_STALE)),
        "expected OracleStale (Custom({})), got: {}",
        ORACLE_STALE,
        err_str
    );

    // Atomicity: rejected TopUp must not move tokens or insurance.
    assert_eq!(
        env.read_insurance_balance(),
        insurance_before,
        "rejected TopUp must not move insurance balance"
    );
}

#[test]
fn test_attack_init_user_rejected_after_stale_matured() {
    let mut env = TestEnv::new();
    env.init_market_with_invert(0);

    let admin = Keypair::from_bytes(&env.payer.to_bytes()).unwrap();
    env.top_up_insurance(&admin, 1_000_000_000);

    let lp = Keypair::new();
    let lp_idx = env.init_lp(&lp);
    env.deposit(&lp, lp_idx, 50_000_000_000);

    let user = Keypair::new();
    let user_idx = env.init_user(&user);
    env.deposit(&user, user_idx, 10_000_000_000);

    env.trade(&user, &lp, lp_idx, user_idx, 1_000_000);
    env.crank();

    let last_slot = env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    env.set_slot_and_price_raw_no_walk(last_slot + 200, 138_000_000);

    let new_user = Keypair::new();
    let result = env.try_init_user(&new_user);
    assert!(
        result.is_err(),
        "InitUser must reject on a stale-matured market: result={:?}",
        result
    );
    let err_str = result.unwrap_err();
    assert!(
        err_str.contains(&format!("Custom({})", ORACLE_STALE)),
        "expected OracleStale (Custom({})), got: {}",
        ORACLE_STALE,
        err_str
    );
}
