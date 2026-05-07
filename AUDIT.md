# Audit log — `claude/analyze-unlock-vectors-NXuHA`

This branch adds four discards (D76–D79) to `security.md`. No source
changes. Read this if you've landed on the branch cold and want to
know what's here without scrolling 1600 lines of audit log.

## What we were looking for

The 5_000_000_000-unit insurance seed in
`tests/test_a1_siphon_regression.rs:149` (≈ 5 SOL of wrapped collateral)
is the only pool of value in this codebase that an attacker could
plausibly extract without owning a matching deposit. Every other
vault balance belongs to a specific user/LP whose owner-binding
signer is required to release it.

So: **can someone walk away with the insurance fund?**

## The attack class — A1 self-dealing siphon

Pre-v12.19, the answer was yes, with the following recipe:

1. Attacker controls two keypairs on one market — keypair **A** (user,
   long) and keypair **B** (LP, matched short).
2. They open a matched pair at the entry price.
3. They drive the oracle ~25 % adverse in one shot.
4. The §4.17 settlement waterfall over-pays B's gain from insurance
   while A's loss doesn't propagate cleanly.
5. `(A_cap + A_pnl) + (B_cap + B_pnl) > A_dep + B_dep`. The surplus
   came from the insurance fund.

`tests/test_a1_siphon_regression.rs` is the regression guard.

## The three v12.19 defense layers

1. **Per-slot oracle-move cap** — `max_price_move_bps_per_slot`,
   immutable RiskParam, enforced by `accrue_market_to`.
2. **§1.4 solvency envelope** —
   `max_price_move·max_accrual_dt + funding + liq_fee ≤ maint_margin`,
   prevalidated wrapper-side.
3. **§12.21 admission-threshold gate** —
   `admit_h_max_consumption_threshold_bps`, blocks position admit /
   ADL enqueue against a depleted price-move generation.

Each layer is independent. Break one, the attack still fails on the
other two.

## What this branch adds

Four numbered priors in `security.md`, walking the four highest-leverage
angles where a recent fix could plausibly have left a regression:

| #   | Vector                                                  | Status     |
| --- | ------------------------------------------------------- | ---------- |
| D76 | `c447686` same-slot catchup leaves a stale-engine read window | Discarded |
| D77 | `UpdateConfig` fast-forward bypasses §1.4 envelope      | Discarded |
| D78 | Sibling no-oracle paths missed by `7e82eb0`'s §9.2 gate | Discarded |
| D79 | `ResolveMarket` Degenerate-arm forced on healthy market | Discarded |

Each entry has hypothesis, why-discarded reasoning, and `file:line`
references to every gate cited.

## How to keep auditing

`security.md` is a working R&D loop, not a static doc. The convention:

- Every probe gets a numbered prior — D80, D81, D82, … — even if
  discarded.
- A bug-find lands as a failing test in the relevant `tests/` file
  AND a numbered prior pointing at it.
- Discards keep the line references tight enough that a future
  auditor can reproduce the walk.

The residual surface that wasn't probed this session:

- Funding rate at envelope boundary with bilateral OI at
  `MAX_VAULT_TVL`.
- Multi-block keeper-timing collusion across tx boundaries.
- Future cross-market / multi-slab deployment (current design is
  single-market).

For continuous adversarial pressure on the A1 defenses against a
fixture market, see [`LOBSTER_TEAM_6.md`](./LOBSTER_TEAM_6.md).
