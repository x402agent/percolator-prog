# multi-client-agent

Mint, register, and read a Metaplex agent from three clients — **HTTP API**, **terminal CLI**, and **Telegram bot** — all sharing a single `core.ts` module that calls [`mintAndSubmitAgent`](https://www.metaplex.com/docs/agents/mint-agent) and [`fetchAgentIdentityV1`](https://www.metaplex.com/docs/agents) from `@metaplex-foundation/mpl-agent-registry`.

The point of this example is to show that the SDK is small enough that wrapping it once and calling it from any number of frontends is a few hundred lines of code total. To add a new client (Discord, REPL, native mobile), implement it once on top of `core.ts` — the on-chain side stays unchanged.

## Layout

```
src/
├── core.ts      buildUmi() + mintAgent() + getAgent() — the only file that imports the SDK
├── server.ts    Express HTTP API
├── cli.ts       Commander terminal CLI
└── telegram.ts  Grammy long-poll bot
```

## Setup

```bash
cd examples/multi-client-agent
npm install
cp .env.example .env
# Fill RPC_URL, NETWORK, OPERATOR_SECRET_KEY, and (optionally) API_KEY / TELEGRAM_*.
```

`OPERATOR_SECRET_KEY` accepts either the raw JSON byte array from `solana-keygen` (`[12,34,…]`) or a base58-encoded secret.

## Run a client

```bash
# HTTP
npm run server                       # listens on :8787
curl -X POST http://localhost:8787/agents/mint \
  -H "x-api-key: $API_KEY" -H "content-type: application/json" \
  -d '{"name":"My Agent","uri":"https://example.com/agent.json","metadata":{"name":"My Agent","description":"…"}}'

# Terminal
npm run cli -- mint --name "My Agent" --uri https://example.com/agent.json --description "…"
npm run cli -- explore <ASSET_ADDRESS>

# Telegram
npm run telegram     # then in the bot:
# /mint My Agent | https://example.com/agent.json | An autonomous trading agent
# /explore <ASSET_ADDRESS>
```

## What `getAgent` returns

```ts
{
  asset: string,                     // MPL Core asset address
  owner: string,
  name: string,                      // from the on-chain asset
  uri: string,
  identity: { pda: string, registered: boolean },   // AgentIdentityV1 PDA + whether it exists
  metadata?: AgentMetadata,          // best-effort parse of the off-chain JSON at `uri`
  explorer: string,
}
```

`AgentIdentityV1` only stores `{ key, bump, padding, asset }` on-chain — the rich fields (services, supportedTrust, registrations) live in the JSON pointed to by the asset's `uri`, so this example fetches that JSON and re-validates it through the same `AgentMetadataSchema` used at mint time.

## Notes

- `network` goes in the **input** to `mintAndSubmitAgent`, not in the `AgentApiConfig`. The default is `solana-mainnet`; override with `solana-devnet` for devnet runs.
- `mintAndSubmitAgent` returns `{ signature: Uint8Array, assetAddress: string }` — base58-encode the signature for explorer URLs.
- Plugins required on the Umi instance: `mplCore()` for the asset, `mplAgentIdentity()` for the registry PDA.
