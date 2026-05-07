# Upstream contribution: `metaplex-foundation/mpl-agent-registry`

This folder is a staging area for an upstream PR. It contains a single self-contained Node example, `examples/multi-client-agent/`, intended to be added under that path inside a fork of [`metaplex-foundation/mpl-agent-registry`](https://github.com/metaplex-foundation/mpl-agent-registry).

The example shows the SDK driving three clients (HTTP, CLI, Telegram) from one shared `core.ts`. It uses only published packages (`@metaplex-foundation/mpl-agent-registry`, `@metaplex-foundation/mpl-core`, `@metaplex-foundation/umi*`, `bs58`, `commander`, `express`, `grammy`, `zod`), no Helius/Percolator-specific code.

## How to send the PR

Run these from outside this repo (Claude Code's GitHub MCP is scoped to `x402agent/percolator-prog`, so the fork+push has to be driven by you).

```bash
# 1. Fork and clone the upstream repo
gh repo fork metaplex-foundation/mpl-agent-registry --clone --remote
cd mpl-agent-registry
git checkout -b examples/multi-client-agent

# 2. Copy the example into the upstream layout
cp -r /path/to/percolator-prog/upstream/metaplex-mpl-agent-registry/examples/multi-client-agent \
      examples/multi-client-agent

# 3. Verify it builds against the published SDK
cd examples/multi-client-agent
npm install
npm run typecheck

# 4. Commit + push + open the PR
cd ../..
git add examples/multi-client-agent
git commit -m "examples: multi-client-agent (HTTP + CLI + Telegram)"
git push -u origin examples/multi-client-agent
gh pr create \
  --repo metaplex-foundation/mpl-agent-registry \
  --base main \
  --title "examples: multi-client agent (HTTP + CLI + Telegram)" \
  --body-file <(cat <<'EOF'
## Summary

Adds `examples/multi-client-agent/` — a Node example that mints, registers,
and reads a Metaplex agent from three frontends (HTTP API, terminal CLI,
Telegram bot) sharing one `core.ts` module that calls
`mintAndSubmitAgent`, `fetchAgentIdentityV1`, and `findAgentIdentityV1Pda`.

The point is to show that the SDK is small enough that wrapping it once and
fan-out to many clients is a few hundred lines total. Self-contained, only
public packages, MIT-compatible (Apache-2.0).

## Test plan

- [ ] `cd examples/multi-client-agent && npm install && npm run typecheck`
- [ ] `npm run cli -- mint --name … --uri … --description …` against devnet
- [ ] `npm run cli -- explore <ASSET>` returns the asset + identity PDA + off-chain metadata
- [ ] `curl POST /agents/mint` against `npm run server`
- [ ] `npm run telegram` with a TELEGRAM_ALLOWED_CHATS allowlist
EOF
)
```

## What's intentionally not included

- **iOS / SwiftUI client** — Swift in a TS-SDK repo is unusual; it stays in our `mobile/` workspace upstream. The HTTP server here is the contract the iOS app talks to, so the Metaplex example is enough on its own to support a native client.
- **Helius / `helius-sdk` / `pino` / `pino-http`** — RPC-provider-agnostic, no Percolator branding, no hosted-logger preference.
- **`mplx agents register` shell-out** — that's a wrapper around the CLI, not an SDK demonstration; the example sticks to the SDK surface.
