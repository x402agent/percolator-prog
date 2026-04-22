# Security findings — 2026-04-22 deep sweep

Whitehat deep-dive after the `d19a712` fixes landed. All four findings
below were verified against the actual code at that commit. Each cites
file:line, describes the concrete attack, severity, and fix.

## F1 — CatchupAccrue partial mode rolls back `last_oracle_publish_time` (HIGH, conditional)

**Location:** `src/percolator.rs:8385-8387` (partial-catchup branch of
`Instruction::CatchupAccrue`).

**Code:**
```rust
let mut restored = config_pre;
restored.last_good_oracle_slot = config.last_good_oracle_slot;
state::write_config(&mut data, &restored);
```

**Bug.** The partial branch rolls back `config` to its pre-read value
(`config_pre`) but preserves only `last_good_oracle_slot`. It does NOT
preserve `last_oracle_publish_time`.

After commit `168cc0b`, `clamp_external_price` enforces:
`publish_time > last_oracle_publish_time` for advance. The test
invariant "a single Pyth observation refreshes liveness at most once"
holds in the normal path.

In partial catchup:
1. `read_price_and_stamp` called with publish_time = T. Config sees
   `last_oracle_publish_time → T`, `last_good_oracle_slot → clock.slot`.
2. Engine catches up partially (can't finish because funding-active
   and `gap > max_step_per_call`).
3. Selective rollback: `last_good_oracle_slot` preserved (stamp
   survives), but `last_oracle_publish_time` rolls back to its
   pre-read value.
4. **Next** CatchupAccrue call, same Pyth account: publish_time = T
   is still `> config.last_oracle_publish_time` (rolled back) →
   passes the "fresh observation" gate → advances
   `last_good_oracle_slot` AGAIN.

Invariant break: one observation can refresh liveness multiple times
across partial catchups. An attacker holding a single fresh Pyth
account can keep issuing partial catchups to stamp liveness on every
call, even without ever presenting a genuinely newer observation.

**Severity conditional.** Under the init constraint that
`permissionless_resolve_stale_slots <= max_accrual_dt_slots`, partial
catchup in a perm-resolve market should be hard to reach before
stale maturity — the gap that forces PARTIAL also forces stale
maturity. But the code-level invariant is broken and the fix is
trivial.

**Fix.** Preserve the timestamp atomically with the liveness stamp:
```rust
let mut restored = config_pre;
restored.last_good_oracle_slot = config.last_good_oracle_slot;
restored.last_oracle_publish_time = config.last_oracle_publish_time;
state::write_config(&mut data, &restored);
```

---

## F2 — Hyperp liveness spoofable via cheap self-trades when `mark_min_fee == 0` (HIGH)

**Location:** `src/percolator.rs:6205-6209` (TradeCpi Hyperp branch).

**Code:**
```rust
let full_weight = config.mark_min_fee == 0
    || fee_paid_hyperp >= config.mark_min_fee;
if full_weight {
    config.last_mark_push_slot = clock.slot as u128;
}
```

**Bug.** When `mark_min_fee == 0`, the short-circuit OR makes every
successful Hyperp trade "full-weight" — advances
`last_mark_push_slot`, which is the ONLY hard-timeout liveness
signal for Hyperp (see `permissionless_stale_matured`).

Default Hyperp init (`encode_init_market_hyperp` → `encode_init_market_full_v2`)
sets `mark_min_fee = 0`. A permissionless attacker with their own
LP + matcher can round-trip tiny self-trades (even `trading_fee_bps=0`
markets work) to refresh `last_mark_push_slot` every slot, blocking
`permissionless_stale_matured` from ever tripping.

**Impact.** `ResolvePermissionless` is the terminal exit for users
after admin burns the mark authority. Attacker-blocked resolve =
users stuck in a zombie market.

**Severity HIGH** because:
- Permissionless attack (any user can deploy their own matcher).
- Real bricking vector, not dust accumulation.
- Default config ships with the hole open.

**Fix.** Require a nonzero `mark_min_fee` at InitMarket when the
market is Hyperp AND `permissionless_resolve_stale_slots > 0`. This
is the config-time gate — simpler than decoupling the trade path,
operator-visible, doesn't change the EWMA/trade semantics honest
users rely on. Hyperp markets without perm-resolve (admin-resolve
only) can keep `mark_min_fee = 0` since there's no bricking vector.

---

## F3 — Account-slot exhaustion when `new_account_fee == 0 AND maintenance_fee_per_slot == 0` (documented config-risk, NOT enforced)

**Location:** `src/percolator.rs:4660-4672` (InitUser),
`src/percolator.rs:4774-4785` (InitLP).

**Bug.** Wrapper InitUser/InitLP only require `capital_units > 0`.
With `new_account_fee = 0`, a 1-base-unit deposit materializes a
permanent account slot. Attacker fills `max_accounts` slots for
near-zero cost.

The dust-reclaim fix in commit `b5ddaeb` mitigates this IF
`maintenance_fee_per_slot > 0` (accounts drain → reclaim in the fee
sweep). But with BOTH `new_account_fee = 0` AND
`maintenance_fee_per_slot = 0`, no drain mechanism exists → slots
stay filled indefinitely.

**Decision: documentation-only, not enforced.** Trusted-admin /
KYC'd / demo / test deployments may legitimately want neither gate
on (e.g., admin reviews account creations out-of-band, or the
market is short-lived test infrastructure). Enforcing the
"must-pick-one" rule at init was tried — it broke 84 existing
tests that use both-zero for legitimate test simplicity. Operator
policy instead:

- **Permissionless production markets MUST set at least one gate**
  (`new_account_fee > 0` or `maintenance_fee_per_slot > 0`).
- Otherwise an attacker fills `max_accounts` with 1-unit dust and
  bricks onboarding.

A comment pointing at this doc is placed at the InitMarket validation
site.

---

## F4 — `ForceCloseResolved` payout accepts any owner token account, not the canonical ATA (LOW, doc drift)

**Location:** `src/percolator.rs:7746` (code);
`src/percolator.rs:1402` (stale doc).

**Code:**
```rust
verify_token_account(a_owner_ata, &owner_pubkey, &mint)?;
```

**Bug.** The doc comment at `src/percolator.rs:1402` says "Sends
capital to stored owner ATA." In reality, `verify_token_account`
only checks (a) the account is a valid SPL token account, (b) its
token-owner field equals the stored owner pubkey, (c) its mint
matches. It does NOT derive the canonical Associated Token Address
and compare.

**Impact.** Admin-only op (gated by `require_admin`). An admin can
route payouts to any token account owned by the victim — not just the
ATA. Not a theft vector (the victim owns it), but:
- Payout goes to a non-canonical account the victim may not expect
  or monitor.
- Violates the documented contract.

**Severity LOW.** Low-privilege attacker doesn't have this capability;
admin is already trusted. Documentation/contract-drift issue.

**Fix.** Update the doc to match reality. The flexibility is
operationally useful (victim's canonical ATA might be closed or
broken); the doc is the right place to restore truth.

---

## Confirmed closed from prior review

All the previously-raised oracle-path issues, re-checked against
`d19a712`, are closed in the normal path:

- **Same-publish_time replay** — `clamp_external_price` requires
  `publish_time > last` (strict `<=` short-circuit). Cap-walk
  attempts return the stored baseline.
- **`last_good_oracle_slot` stamped on stale reads** —
  `read_price_and_stamp` snapshots `last_oracle_publish_time` before
  the call and only stamps the liveness cursor when it advanced.
- **Zero-fill TradeCpi ratchet** — rollback preserves
  `last_oracle_publish_time` atomically with `last_effective_price_e6`.
- **`new_account_fee` scale alignment** — InitMarket rejects
  misaligned fee so the InitUser/InitLP split can't create
  unavoidable dust.
- **Dust account slot reclamation** — wrapper's
  `sweep_maintenance_fees` reclaims flat zero-capital accounts in
  the same pass, so crank-only reclamation works when fees are
  enabled.
- **Hyperp EWMA clock on sub-threshold trades** — both TradeCpi
  and TradeNoCpi now gate clock bump on full-weight observation.

That leaves F1–F4 as new findings from this pass. F1/F2/F3 are
actionable fixes; F4 is a doc correction.

## Fix order (TDD)

Each fix lands with a failing regression test first, then the fix,
then test passes, one commit per finding.

1. **F1**: preserve `last_oracle_publish_time` in the partial
   CatchupAccrue rollback. Test: two successive partial-catchup
   calls with the same Pyth account → `last_good_oracle_slot`
   advances only once.
2. **F2**: reject Hyperp init when
   `permissionless_resolve_stale_slots > 0 AND mark_min_fee == 0`.
   Test: init with that combo → rejection.
3. **F3**: reject InitMarket when `new_account_fee == 0 AND
   maintenance_fee_per_slot == 0`. Test: init with both zero →
   rejection.
4. **F4**: update the `ForceCloseResolved` doc to match reality.

---

## Additional surfaces traced in this sweep (no new findings)

To justify stopping the sweep at F1–F4, these high-value surfaces
were also traced and confirmed safe at `1795eba`:

### TradeCpi adversarial matcher

The matcher program is an arbitrary caller-chosen CPI target. In
principle it could try to mutate state mid-instruction.
Defense-in-depth is solid:

- **Solana ownership rule**: the slab is owned by percolator; a
  matcher (different program) cannot write to the slab's data
  buffer directly, regardless of whether the slab is passed as
  writable in the outer tx.
- **Reentrancy guard**: `set_cpi_in_progress` is set before the
  CPI at `src/percolator.rs:5952-5955`; every instruction handler
  calls `slab_guard` which rejects if the flag is set
  (`src/percolator.rs:3746-3748`). A matcher trying to re-enter
  percolator from inside the CPI fails immediately.
- **LP PDA validation**: `find_program_address` against
  `["lp", slab_key, lp_idx]` — PDA key match implies only
  percolator can sign for it, so it's always system-owned with
  zero data. Can't be spoofed.
- **Matcher identity binding**: `matcher_program` and
  `matcher_context` are stored at InitLP and checked against the
  CPI args. Can't swap matcher mid-flight.
- **ABI echo**: the matcher must echo `req_id`, `lp_account_id`,
  and `oracle_price_e6` back — forgery requires the matcher to
  guess the caller's pre-CPI-computed values, which are fresh
  per-call (`req_nonce`).

### Funding rate boundary arithmetic

`compute_current_funding_rate_e9` at `src/percolator.rs:3628-3652`
was traced numerically. All intermediate products fit i128 easily
given the configured bounds:

- `diff.saturating_mul(1e9)` at worst `1.8e19 * 1e9 = 1.8e28` (fits
  i128 = ~1.7e38).
- `premium_e9 * funding_k_bps` post-clamp bounded at ~9.2e28.
- Final `.clamp(-max_rate_e9, max_rate_e9)` — `max_rate_e9 ≥ 0`
  enforced at InitMarket (`src/percolator.rs:4325-4338`) and
  UpdateConfig (`src/percolator.rs:6797-6803`), so the clamp
  invariant `min ≤ max` holds and `.clamp()` never panics.
- Engine envelope (`max_abs_funding_e9_per_slot *
  max_accrual_dt_slots`) is validated at InitMarket per
  `validate_params` in the engine crate.

### `is_resolved()` coverage across instructions

Every instruction handler was checked for post-resolution gating.
Coverage map:

- **Blocks post-resolution**: `InitUser`, `InitLP`,
  `DepositCollateral`, `WithdrawCollateral`, `KeeperCrank`,
  `TradeNoCpi`, `TradeCpi`, `LiquidateAtOracle`, `TopUpInsurance`,
  `UpdateConfig`, `PushHyperpMark`, `SetOraclePriceCap`,
  `ResolveMarket` (re-resolve), `WithdrawInsuranceLimited`,
  `ReclaimEmptyAccount`, `SettleAccount`, `DepositFeeCredits`,
  `ConvertReleasedPnl`, `ResolvePermissionless` (re-resolve),
  `CatchupAccrue` (confirmed at `src/percolator.rs:8314`).
- **Requires resolved**: `WithdrawInsurance`,
  `AdminForceCloseAccount`, `ForceCloseResolved`.
- **Mode-aware**: `CloseAccount` (both modes, different paths).
- **No explicit check (correct)**: `UpdateAuthority` — rotating
  insurance_authority post-resolution is a legitimate operational
  pattern; admin-burn has its own kind-specific invariant check.
- **No explicit check (correct)**: `CloseSlab` — requires all
  accounts freed + vault zero, which is only achievable in
  Resolved mode anyway.

### Vault / token account hygiene

- `verify_vault_empty` at `src/percolator.rs:3816-3849` enforces
  mint + owner + initialized + no delegate + no close_authority +
  zero balance. Can't smuggle pre-loaded vault at init.
- `verify_vault` at `src/percolator.rs:3777+` mirrors the checks
  for live-market validation.
- `verify_token_account` checks owner + mint only (doesn't derive
  ATA) — documented as F4.

### Crank reward economics

`CRANK_REWARD_BPS = 5000` (50% of swept fees). Traced possible
farming attacks:

- Self-cranker receives up to 50% of all swept fees in a single
  crank. Comes from insurance (zero-sum: insurance pays out what
  it just collected).
- Attacker filling dust accounts to farm rewards: nets a LOSS
  because they paid 100% of the dust capital (which becomes the
  fee source) but only recoup 50%. Economically unfavorable.
- Reward is capped at post-crank insurance balance, so drain is
  bounded. Conservation invariant (vault ≥ c_tot + insurance +
  net_pnl) is explicitly preserved with `checked_add`.

### Generation counter wrap

`next_mat_counter` at `src/percolator.rs:2246-2251` uses
`checked_add` — u64 overflow returns None → error propagates. At
~226 billion years to overflow at 1 init/slot, not a real concern
even ignoring the overflow check.

---

## Second pass — 2026-04-22 late (post F1-F4 commit)

Revisiting surfaces after F1/F2/F4 landed, plus an explicit
small/medium tier test run (655/655 each). No new actionable
findings. Surfaces traced:

### Matcher ABI return validation

`matcher_abi::validate_matcher_return` at
`src/percolator.rs:1084-1150` is thorough:

- Echoes (`req_id`, `lp_account_id`, `oracle_price_e6`) must match
  the wrapper's pre-CPI values. Any forgery rejects.
- `abi_version == MATCHER_ABI_VERSION` — prevents future matchers
  with new flag semantics being silently accepted.
- Flag bits outside `{VALID, PARTIAL_OK, REJECTED}` rejected.
- `VALID` required, `REJECTED` forbidden.
- `reserved == 0` required.
- `exec_price_e6 != 0` required (disambiguates "all zeros + valid flag").
- `exec_size == 0` requires `PARTIAL_OK`.
- `|exec_size| <= |req_size|`.
- `sign(exec_size) == sign(req_size)` when `req_size != 0`.
- `req_size == 0` is rejected at the entry (line 5770), so the
  sign check can safely skip that case.
- `exec_size == i128::MIN` with a negative req_size would pass the
  sign/abs check, but the engine's `checked_neg()` at trade
  execution (src/percolator.rs:3684) returns None → `Overflow`.
  Safely rejected downstream.

### Matcher identity immutability

`matcher_program` and `matcher_context` on an LP account are set
only at `InitLP` (`src/percolator.rs:4837-4838`) and never mutated
elsewhere. No instruction offers to change them after registration.
A registered LP is bound to its matcher for life. The only
operator consideration is that the MATCHER PROGRAM itself may be
upgradeable — operators deploying LPs should prefer matchers with
burned upgrade_authority (out of percolator's control, documented
as operator hygiene).

### Panic surface

21 uses of `.unwrap()` / `.expect()` in the wrapper, all in fixed-
width `slice.try_into()` calls after preceding length guards. Each
was traced — no unguarded panic reachable from caller input.
Notable sites:
- `matcher_abi::read_matcher_return` at line 1059: length guard
  `ctx.len() < 64` at line 1060, each slice is a fixed subrange of
  [0, 64). Safe.
- `read_chainlink_price_e6` at line 2645/2652: length guard
  `data.len() < CL_MIN_LEN (232)` upstream, both slices are within
  [138, 232). Safe.
- Wrapper's `read_u64/u128/pubkey/bytes32` all have per-call
  `input.len() < N` guards before each `try_into().unwrap()`. Safe.

### `ensure_market_accrued_to_now` idempotency

`src/percolator.rs:3500-3513`. The helper:
1. Calls `catchup_accrue(engine, now_slot, price, rate)` — returns
   early when `now_slot <= engine.last_market_slot`, when
   `max_dt == 0`, when engine never observed a real price, or when
   funding is inactive. Safe no-op in all edge cases.
2. Calls `accrue_market_to` only if `price > 0 && now_slot >
   engine.last_market_slot`. Idempotent: a second call in the same
   slot with the same price is a no-op inside the engine (§5.4
   early return on same-slot + same-price).

So instructions that call `ensure_market_accrued_to_now` AFTER
their own internal accrue-bearing engine call (which also advances
last_market_slot) don't double-accrue.

### `cluster_restarted_since_init` false-positive analysis

`src/percolator.rs:2914-2921`. The init-time sysvar read uses
`.unwrap_or(0)` as a fallback:

```rust
init_restart_slot: LastRestartSlot::get()
    .map(|lrs| lrs.last_restart_slot)
    .unwrap_or(0),
```

Theoretical false positive: sysvar fails at init (→
`init_restart_slot = 0`), then succeeds at a later read returning
any `R > 0`. `restart_detected(0, R) = true` → market
incorrectly frozen even without a real restart happening after
init.

Unreachable in practice: `LastRestartSlot` sysvar is always
available on production Solana (SIMD-0047 landed in v1.18). The
fallback exists only to avoid panicking in test environments with
stubbed runtimes. Not a mainnet concern.

### `SetOraclePriceCap` disable path

`src/percolator.rs:7037+`. Admin can reduce `oracle_price_cap_e2bps`
to 0 only when `min_oracle_price_cap_e2bps == 0` (init-time
constraint). With cap=0, the circuit breaker is effectively off —
a fresh Pyth read that lifts the price by ≥100% is passed through
clamped-to-identity. Admin-only op; explicit operator choice. Not
a protocol bug.

### Max cap (100%) semantics

`MAX_ORACLE_PRICE_CAP_E2BPS = 1_000_000` (100% per update). At
this ceiling, `clamp_oracle_price(last=X, raw=Y, cap=MAX)` allows
`Y ∈ [0, 2X]`. Prices can approach zero (rejected downstream by
`if price == 0` checks in engine/wrapper). Effectively the same
as "no cap" — documented as operator choice.

### Negative `publish_time` handling

Pyth's `publish_time` is `i64`, nominally a unix timestamp.
Theoretical negative values (pre-1970, crafted, or i64::MIN):
- `clamp_external_price` at `src/percolator.rs:2814+`: strict
  `publish_time <= last_oracle_publish_time` gate. Any negative
  publish_time with `last = 0` (init fresh market) is ≤ 0 →
  graceful fallback, no advance. Safe.
- `read_pyth_price_e6` staleness check: `age = now - publish_time`
  with saturating sub. `publish_time = i64::MIN` → `now.sat_sub(MIN)`
  saturates at `i64::MAX` → age > max_staleness_secs → reject.
  Safe.

### Reclaim forgives fee debt: loss-to-insurance analysis

When `reclaim_empty_account_not_atomic` fires on a flat zero-
capital account with `fee_credits < 0`, the debt is forgiven
(`src/percolator.rs:5346-5348` in engine). Insurance loses the
uncollected dust (shortfall = capital-drained-before-zeroing minus
fees-already-collected).

Attacker economics: they funded the account with some capital X,
which flowed to insurance as fees. Unreclaimed debt is bounded by
one max-interval's fee charge (capped at per-sync rate * dt_max).
Net protocol loss is at most one slot's fee rate per dust account,
per reclaim cycle. Attacker's net position: -X (capital lost to
insurance), so they can't profit by forcing forgiveness.

### Tier coverage

All findings re-verified against three build tiers after the F1-F4
commits:
- default (`MAX_ACCOUNTS = 4096`): 655/655 pass.
- `--features small` (`MAX_ACCOUNTS = 256`): 655/655 pass.
- `--features medium` (`MAX_ACCOUNTS = 1024`): 655/655 pass.

The SLAB_LEN cascade (RiskParams field removals in earlier
commits) was verified against all three BPF binary sizes.
