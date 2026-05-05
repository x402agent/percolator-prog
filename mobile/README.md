# Percolator mobile DApp routing layer

Three clients — **iOS (SwiftUI)**, **terminal**, and **Telegram** — connecting to one backend that registers, mints, and explores Solana agents through [Metaplex](https://www.metaplex.com/docs/agents/mint-agent) over [Helius](https://helius.dev) RPC.

> Educational scaffold. The host program (`percolator-prog`) is unaudited. Don't point this at mainnet with real funds.

## Topology

```
                       ┌────────────────────────────────────────┐
                       │            mobile/src/core             │
                       │  agents.ts · helius.ts · registerCli   │
                       │  ───────────────────────────────────   │
                       │  mintAndSubmitAgent  (SDK + Helius)    │
                       │  mplx agents register  (CLI)           │
                       │  fetchAssetV1 + AgentIdentity (RPC)    │
                       └────────────────┬───────────────────────┘
                                        │
                ┌───────────────────────┼────────────────────────┐
                │                       │                        │
        HTTP /agents/*           CLI (commander)         Telegram (grammy)
                │                       │                        │
        ┌───────┴───────┐                                ┌───────┴───────┐
        │ iOS SwiftUI   │  `npm run dev:cli …`           │ /register      │
        │ APIClient     │                                │ /mint /explore │
        └───────────────┘                                └────────────────┘
```

All three clients hit the same code path. To add a new agent operation, implement it once in `src/core/agents.ts` and wire it into the adapters.

## Backend setup

```bash
cd mobile
cp .env.example .env
# Fill in HELIUS_RPC_URL, OPERATOR_SECRET_KEY, API_KEY (≥24 chars), TELEGRAM_BOT_TOKEN, …

npm install
npm run dev:server     # HTTP API on :8787 (used by iOS)
npm run dev:cli  -- mint --name "My Agent" --uri https://… --description "…"
npm run dev:telegram   # long-poll Telegram bot
```

The Metaplex CLI is required for `register` to actually run (the SDK only exposes `mintAgent`/`mintAndSubmitAgent`):

```bash
npm i -g @metaplex-foundation/cli
mplx config set rpc "$HELIUS_RPC_URL"
mplx config set keypair ./operator.json
```

## HTTP API

All routes require `x-api-key: $API_KEY` (except `/health`).

| Method | Path                | Body / Params                                   | Action                                             |
| ------ | ------------------- | ----------------------------------------------- | -------------------------------------------------- |
| GET    | `/health`           | —                                               | liveness probe                                     |
| POST   | `/agents/register`  | `{name, description?, image?, services?, dryRun?}` | shells out to `mplx agents register`            |
| POST   | `/agents/mint`      | `{name, uri, metadata, owner?}`                 | calls `mintAndSubmitAgent` via Umi/Helius          |
| GET    | `/agents/:address`  | —                                               | reads MPL Core asset + Agent Identity PDA          |

`metadata` matches the Metaplex shape: `{type:'agent', name, description, services[], registrations[], supportedTrust[]}`.

## Terminal CLI

```bash
npm run dev:cli -- register --name "My Agent" --description "…" --image ./avatar.png
npm run dev:cli -- mint --name "My Agent" --uri https://example.com/agent.json --description "…"
npm run dev:cli -- explore <ASSET_ADDRESS>
```

After `npm run build` the bin is exposed as `percolator-agent`.

## Telegram bot

Set `TELEGRAM_BOT_TOKEN` and a comma-separated `TELEGRAM_ALLOWED_CHATS` allowlist. Then:

```
/register MyAgent | An autonomous trading agent | ./avatar.png
/mint MyAgent | https://example.com/agent.json | An autonomous trading agent
/explore <ASSET_ADDRESS>
```

Pipe (`|`) is the field separator, matching the order of the underlying request bodies.

## iOS app

`ios/PercolatorAgent/` contains the SwiftUI sources (`PercolatorAgentApp.swift`, `Models/`, `Services/`, `Views/`). To run:

1. In Xcode: **File → New → Project → iOS App** (SwiftUI, Swift, no Core Data).
2. Add the files from `ios/PercolatorAgent/` to the target (drag in or **Add Files to…**).
3. In **Signing & Capabilities**, allow arbitrary loads only if you're hitting `http://` during dev — prefer running the backend behind Tailscale or ngrok with TLS.
4. Build to a device/simulator. On first launch, open the **Settings** tab and set the server URL + API key.

The app has four tabs: **Register**, **Mint**, **Explore**, **Settings**. Each tab posts to the routes above; the explorer tab fetches the agent and links out to the Solana explorer.

## Where this connects to `percolator-prog`

The Rust on-chain program lives in `src/percolator.rs`. Once a market is deployed, set `PERCOLATOR_PROGRAM_ID` and extend `src/core/` with helpers that read slab state via Helius (e.g. `getAccountInfo` against the slab pubkey, then decode using the same layout as `tests/`). The current scaffold deliberately leaves that integration out — it's a separate task once the agent flow is wired end-to-end.

## File map

```
mobile/
├── package.json · tsconfig.json · .env.example
├── src/
│   ├── core/        agents.ts · helius.ts · registerCli.ts · config.ts
│   ├── server/      index.ts (express) · routes.ts
│   ├── cli/         index.ts (commander)
│   └── telegram/    bot.ts (grammy long-poll)
└── ios/PercolatorAgent/
    ├── PercolatorAgentApp.swift
    ├── Models/Agent.swift
    ├── Services/Settings.swift · APIClient.swift
    └── Views/Root · Register · Mint · Explorer · Settings
```
