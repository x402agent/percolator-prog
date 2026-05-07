import { mintAndSubmitAgent, fetchAgentIdentityV1, findAgentIdentityV1Pda } from '@metaplex-foundation/mpl-agent-registry';
import { fetchAssetV1 } from '@metaplex-foundation/mpl-core';
import { publicKey, type Umi, type PublicKey } from '@metaplex-foundation/umi';
import bs58 from 'bs58';
import { z } from 'zod';
import { explorerUrl, networkFor } from './helius.js';
import type { Config } from './config.js';

export const ServiceSchema = z.object({
  name: z.string().min(1),
  endpoint: z.string().url(),
});

export const RegistrationSchema = z.object({
  agentId: z.string().min(1),
  agentRegistry: z.string().min(1),
});

export const AgentMetadataSchema = z.object({
  type: z.literal('agent').default('agent'),
  name: z.string().min(1),
  description: z.string().min(1),
  services: z.array(ServiceSchema).default([]),
  registrations: z.array(RegistrationSchema).default([]),
  supportedTrust: z.array(z.string()).default([]),
});
export type AgentMetadata = z.infer<typeof AgentMetadataSchema>;

export const MintRequestSchema = z.object({
  name: z.string().min(1),
  uri: z.string().url(),
  metadata: AgentMetadataSchema,
  owner: z.string().optional(),
});
export type MintRequest = z.infer<typeof MintRequestSchema>;

export interface MintResult {
  asset: string;
  identityPda: string;
  signature: string;
  explorer: string;
}

/**
 * Mints a Metaplex agent (MPL Core asset + Agent Identity PDA in one tx) and
 * submits it through the Umi (Helius) connection.
 *
 * Mirrors the documented `mintAndSubmitAgent` flow at
 * https://www.metaplex.com/docs/agents/mint-agent.
 */
export async function mintAgent(umi: Umi, cfg: Config, req: MintRequest): Promise<MintResult> {
  const wallet: PublicKey = req.owner ? publicKey(req.owner) : umi.identity.publicKey;
  // The Metaplex hosted mint API defaults to solana-mainnet; pass the network
  // derived from SOLANA_CLUSTER so devnet runs go through the matching backend
  // instead of registering against mainnet while Umi is connected to devnet.
  const result = await mintAndSubmitAgent(umi, null, {
    wallet,
    network: networkFor(cfg.SOLANA_CLUSTER),
    name: req.name,
    uri: req.uri,
    agentMetadata: req.metadata,
  });
  const asset = result.assetAddress;
  const [identityPda] = findAgentIdentityV1Pda(umi, { asset: publicKey(asset) });
  return {
    asset,
    identityPda: String(identityPda),
    signature: bs58.encode(result.signature),
    explorer: explorerUrl(cfg.SOLANA_CLUSTER, asset),
  };
}

export interface AgentView {
  asset: string;
  owner: string;
  name: string;
  uri: string;
  identity: {
    pda: string;
    registered: boolean;
  };
  metadata?: AgentMetadata;
  explorer: string;
}

/**
 * Reads an agent's MPL Core asset and Agent Identity PDA via Helius RPC, then
 * pulls the off-chain metadata JSON pointed to by the asset's `uri` (where the
 * services / trust mechanisms actually live — the on-chain identity PDA only
 * stores the binding back to the asset).
 */
export async function getAgent(umi: Umi, cfg: Config, address: string): Promise<AgentView> {
  const asset = await fetchAssetV1(umi, publicKey(address));
  const [identityPda] = findAgentIdentityV1Pda(umi, { asset: publicKey(address) });
  let registered = true;
  try {
    await fetchAgentIdentityV1(umi, identityPda);
  } catch {
    registered = false;
  }
  let metadata: AgentMetadata | undefined;
  try {
    const r = await fetch(asset.uri);
    if (r.ok) {
      const parsed = AgentMetadataSchema.safeParse(await r.json());
      if (parsed.success) metadata = parsed.data;
    }
  } catch {
    // off-chain metadata is best-effort
  }
  return {
    asset: address,
    owner: String(asset.owner),
    name: asset.name,
    uri: asset.uri,
    identity: { pda: String(identityPda), registered },
    metadata,
    explorer: explorerUrl(cfg.SOLANA_CLUSTER, address),
  };
}

export interface RegisterCliRequest {
  name: string;
  description?: string;
  image?: string;
  services?: { name: string; endpoint: string }[];
  supportedTrust?: string[];
  useIx?: boolean;
}

/**
 * Builds the argv for `mplx agents register`, matching
 * https://www.metaplex.com/docs/dev-tools/cli/agents/register.
 *
 * The CLI itself runs out-of-process; this helper exists so the HTTP/CLI/Telegram
 * adapters all produce the same canonical command (and so a future implementation
 * can pipe it through `child_process.spawn` without restating the flag mapping).
 */
export function buildRegisterArgv(req: RegisterCliRequest): string[] {
  const argv = ['agents', 'register', '--name', req.name];
  if (req.description) argv.push('--description', req.description);
  if (req.image) argv.push('--image', req.image);
  if (req.services && req.services.length > 0) {
    argv.push('--services', JSON.stringify(req.services));
  }
  if (req.supportedTrust && req.supportedTrust.length > 0) {
    argv.push('--supported-trust', JSON.stringify(req.supportedTrust));
  }
  if (req.useIx) argv.push('--use-ix');
  return argv;
}
