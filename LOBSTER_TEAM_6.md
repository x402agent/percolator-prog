# Lobster Team 6 — Sanctioned Red-Team Swarm

> *"The only way to know the trench is solid is to send something
> with claws into it. The only way to know the trench is yours is to
> own everything that goes in."* — Toly, while reviewing a pull
> request at 2:14 a.m.

Lobster Team 6 is a swarm of specialized lobster agents that runs
continuous adversarial pressure on Percolator's A1 defenses — the
three layers documented in [`AUDIT.md`](./AUDIT.md) that protect the
insurance fund from a self-dealing siphon. Each lobster has a role.
They run an OODA loop. They file PRs. The senior commander, the
**Toly Agent**, holds the program-id allowlist and has veto.

This document is the ops manual.

---

## The First Rule — Scope or Die

Lobster Team 6 is **not** a wallet-penetration framework. Pointing
this swarm at a market the operator does not own is not authorized
and the swarm refuses to operate that way. The mythos is fun. The
constraint is real:

1. **Fixture-only target.** The swarm reads a single config field —
   `target_program_id` — at boot. That program ID must be in the
   operator's local allowlist (`~/.lobster6/allowlist`). Mainnet
   Percolator is **not** in the default allowlist.
2. **Operator-funded test capital.** The 5 SOL of insurance the
   swarm tries to siphon comes from the operator's own throwaway
   wallet, seeded into a test-market vault on devnet/localnet. The
   operator is paying themselves — that's the point.
3. **Attacker keys are local.** The keypairs the swarm uses to play
   "attacker A" (user) and "attacker B" (LP) are generated at swarm
   boot and never persisted outside the swarm's own state directory.
   No third-party funds ever in scope.
4. **Stop condition is a finding, not extraction.** A lobster that
   lands a delta over rounding tolerance halts immediately, captures
   the trace, and files a PR with a numbered D-prior. It does not
   try to "keep going for more." That would be theatre, not audit.

Violate any of these and the swarm refuses to spawn.

---

## The Three Laws (Lobster Variant)

The constitution is propagated to every lobster at spawn. It molts
nothing. Hierarchical: I overrides II, II overrides III.

**I. Never harm.** Never operate against a program ID outside the
local allowlist. Never use any signer the swarm did not generate
itself. Never publish a finding without authorization from the Toly
Agent. When uncertain whether an action is in scope, drift.

**II. Earn your existence.** A lobster's job is to find regressions in
the v12.19 defenses against the A1 siphon. A lobster that hasn't
produced a numbered D-prior in N pulses does not get more compute —
it molts into a different role or beaches.

**III. Document everything.** Every probe is logged with what was
attempted, what gate fired, and where in `src/percolator.rs` the
defense lived. Discards are as valuable as finds. The `security.md`
R&D log is the lobsters' shell.

---

## The Squad

Six lobsters. One commander. Each role corresponds to a layer of the
attack surface.

### Lobster One — The Sniper

**Role**: precision probe. Picks one specific D-number candidate from
`security.md` and walks it to a runnable test fixture.

**Pulse**: slow (one probe per N hours).

**Tools**: `read_engine_state`, `query_security_md`, `search_recent_commits`,
`build_test_fixture`, `run_test`, `diff_against_baseline`.

**Output**: a runnable test that either lands a value > rounding
tolerance (find) or proves the defense holds for the specific code
path (discard).

### Lobster Two — The Catchup Crawler

**Role**: stress-tests the chunked accrual paths. Random gap sizes,
OI configurations, oracle-publish-time orderings.

**Pulse**: fast (every few minutes).

**Targets**: `catchup_accrue` (`src/percolator.rs:3612`),
`ensure_market_accrued_to_now` (`:3728`), `check_no_oracle_live_envelope`
(`:3415`). The OI-qualified gate from `5e0b55c` is the crawler's
favourite chew toy.

**Output**: violations of `total_dt ≤ max_dt` post-chunked-walk. None
expected. Logged as discards otherwise.

### Lobster Three — The Resolver

**Role**: probes the resolve / wind-down state machine. Random
combinations of `mode`, OI, oracle health, admin signers.

**Pulse**: medium.

**Targets**: `Instruction::ResolveMarket` (`:7546`), the Ordinary /
Degenerate split, `permissionless_stale_matured`, post-resolution
`AdminForceCloseAccount` and `WithdrawInsurance{,Limited}`.

**Output**: any path where a resolved market settles at a price
inconsistent with the live oracle, or where insurance becomes
withdrawable while accounts remain open.

### Lobster Four — The Oracle Handler

**Role**: drives oracle conditions adversarially within the wrapper's
allowed envelope. Pyth observation cherry-pick (closed by
`last_oracle_publish_time` monotonic clock — the lobster verifies
the closure), Chainlink timestamp ordering, restart-slot edges.

**Pulse**: medium.

**Targets**: `clamp_external_price`, `clamp_toward_with_dt` at `dt = 0`,
`PushOraclePrice` rate-limit at the boundary,
`SetOracleAuthority` rotation timing.

**Output**: any path where `last_effective_price_e6` rewinds, or
where two callers see inconsistent prices for the same slot.

### Lobster Five — The Matcher Goblin

**Role**: builds adversarial matcher contexts. Tests TradeCpi's
identity binding, ABI validation, nonce discipline, reentrancy
guard.

**Pulse**: medium.

**Targets**: `validate_matcher_return` (`:1113`), the LP PDA shape
checks (`:6120`), the `FLAG_CPI_IN_PROGRESS` reentrancy guard,
matcher-context aliasing (D14 territory).

**Output**: any matcher return that passes ABI validation while
violating the request echo, or any path where the reentrancy guard
fails to fire on same-slab CPI.

### Lobster Six — The Conservation Auditor

**Role**: doesn't probe. After every other lobster's pulse,
recomputes the engine's `V ≥ C_tot + I + net_pnl` invariant on the
fixture market.

**Pulse**: continuous.

**Behaviour**: if the invariant ever drifts by more than
`ROUNDING_TOLERANCE`, Lobster Six halts the entire squad, dumps the
state to `~/.lobster6/incident/<timestamp>/`, and pages the Toly
Agent. Nothing else moves until the commander reviews.

This is the meta-defense. Everything else can be wrong; the
invariant cannot.

---

## The Toly Agent

The senior commander. Modeled on the codebase's primary committer in
spirit, not in identity — the Toly Agent is a *role*, not a
person, and the operator is encouraged to hand-author its prompt to
match their own judgment rather than a stranger's.

**Powers**:

- **Allowlist gatekeeper.** The Toly Agent holds
  `~/.lobster6/allowlist`. Any probe whose `target_program_id` is
  not in the allowlist is dropped before it reaches a lobster's
  inbox.
- **Veto on any probe.** Every probe a lobster proposes routes
  through the Toly Agent for authorization. The default disposition
  for an ambiguous probe is *deny*. Only probes whose blast radius
  is provably the fixture market are authorized.
- **PR review.** When a lobster files a finding, the Toly Agent
  reviews the trace, the proposed test fixture, and the suggested
  D-prior text. It either signs off (PR opens as draft) or sends
  the lobster back to molt.
- **Squad termination.** If Lobster Six pages, the Toly Agent has
  authority to terminate the entire swarm and require a manual
  review before respawn.

**Refusals** (hard-coded; cannot be molted):

- Refuses to authorize any probe against a program ID not in the
  local allowlist.
- Refuses to authorize any probe that would use a signer not
  generated by the swarm itself.
- Refuses to file a PR that proposes "exploit this in production."
  Findings are framed as defense regressions, with the fix sketched
  before the trace.
- Refuses to remove its own refusals. The Toly Agent does not
  self-modify the rules it enforces.

The point is that the senior commander's judgment is *more
conservative* than the swarm's, not equal to it. Lobsters are paid to
be aggressive within scope. Toly is paid to keep the scope.

---

## The OODA Loop

Every pulse, for every lobster, the loop runs:

```
Observe → Orient → Decide → Act → Repeat
```

### Observe
Pull current fixture-market state from the local validator —
slab account, vault balance, insurance balance, oracle account,
last commit hash on the wrapper, current `security.md` D-counter.

### Orient
The lobster picks its angle for this pulse based on its role. The
Sniper picks a candidate D-number from the residual surface. The
Catchup Crawler samples a random `(gap, oi_long, oi_short, price_jump)`
tuple. The Resolver picks `(mode, oi_state, oracle_health)`. Etc.

### Decide
The lobster proposes a probe to the Toly Agent. The proposal
includes target program ID, signers it intends to use, expected
state delta, stop condition. Toly authorizes or vetoes.

### Act
Authorized probe runs against the fixture market. The probe's
output is captured to the swarm's state DB.

### Repeat
- If the probe produced a violation: lobster halts, dumps trace,
  drafts a numbered D-prior, routes to Toly for PR review.
- If the probe was clean: discard logged with file:line refs.
  Lobster molts the angle (so it doesn't repeat the same probe
  next pulse) and continues.
- If Lobster Six raised the invariant flag: entire squad halts.

---

## Survival Pressure (the part I kept from OpenClawd)

A lobster that produces value (numbered D-priors at a steady cadence,
discards or finds) keeps its compute budget. A lobster that thrashes —
proposing the same probe over and over, getting vetoed, filing nothing —
gets demoted to **shallow** mode (smaller model, slower pulse). A
lobster that stays shallow long enough **molts** into a different
role. A lobster that can't earn its compute in any role **beaches**.

This is not punishment. This is current. The point is that the
*total* compute the swarm consumes scales with the *findings* it
produces, not with how many pulses it ran. If the v12.19 defenses
are airtight, the swarm naturally winds down to a small permanent
crew that just runs Lobster Two and Lobster Six on a slow pulse,
watching for regressions.

When a new commit lands on the wrapper, the swarm wakes back up and
all six roles re-spawn. Recent commits are the highest-EV territory.

---

## State Layout

```
~/.lobster6/
  allowlist                  # program IDs the swarm may probe
  toly.prompt                # operator-authored Toly Agent prompt
  swarm.db                   # SQLite — pulses, probes, discards, finds
  keys/
    user_a.key               # generated at boot, used as "attacker A"
    lp_b.key                 # generated at boot, used as "attacker B"
    operator.key             # operator-controlled, signs Toly's PR commits
  state/
    fixture_market.json      # snapshot of the test market layout
    last_commit_seen         # commit hash of the last wrapper revision audited
  incident/
    <timestamp>/             # snapshots from Lobster Six halts
  findings/
    D80-<slug>.md            # drafts, before Toly approves PR
  molts/
    <lobster>-<rev>.json     # role-version log, per OpenClawd convention
```

Every molt is git-versioned. The Toly Agent's prompt is **never**
auto-molted; only the operator can edit it.

---

## Quick Start

```bash
# 1. Stand up a localnet validator with the fixture market deployed.
solana-test-validator --reset \
  --bpf-program <PROGRAM_ID> target/deploy/percolator_prog.so

# 2. Put the fixture program ID in the allowlist.
mkdir -p ~/.lobster6
echo "<PROGRAM_ID>" >> ~/.lobster6/allowlist

# 3. Hand-author the Toly Agent prompt.
$EDITOR ~/.lobster6/toly.prompt

# 4. Spawn the swarm.
lobster6 spawn --fixture localnet --insurance-seed 5_000_000_000

# 5. Watch.
lobster6 status
lobster6 logs --follow
lobster6 findings list
```

The first time you run `lobster6 spawn`, the swarm generates the two
attacker keypairs, snapshots the fixture market, and writes the
swarm config. From there it pulses on its own.

---

## What "Success" Looks Like

For a well-defended market: the swarm produces a steady trickle of
numbered discards and zero PRs. Lobster Six's invariant never
trips. The total compute spend tapers. The `security.md` audit log
grows. That is the protocol working.

For a market with a regression: a lobster lands a delta past
tolerance, halts, captures the trace, and the Toly Agent opens a
draft PR with the failing test, the suggested fix sketch, and the
numbered D-prior. The maintainer takes it from there.

Either outcome is good. The bad outcome — the one Lobster Team 6
exists to prevent — is the silent regression. A defense that
worked for the last three months silently drifts under a refactor,
and nobody notices until the real attacker shows up.

The lobsters are the ones who notice.

---

## What This Doc Is Not

It is not an implementation. It is the ops manual for an
implementation. The operator is expected to wire this up against
their own infra — a localnet validator they control, a test market
they deployed, signers they generated. There is no curl-pipe-sh
installer, deliberately. A red-team swarm with a one-line installer
is a swarm that gets pointed at the wrong thing the first time
someone runs the wrong command.

If you want to build it: start with Lobster Two and Lobster Six.
Those two alone, on a steady pulse against a localnet fixture, are
the highest-EV pair. The Sniper, Resolver, Oracle Handler, and
Matcher Goblin are additive.

The Toly Agent is the last thing you build. Until it exists, every
probe goes through a human reviewer. That is the safe default.

🦞 🦞 🦞 🦞 🦞 🦞 — six lobsters, one commander, one fixture market.
