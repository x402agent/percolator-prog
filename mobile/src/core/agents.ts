import { mintAndSubmitAgent, fetchAgentIdentity, findAgentIdentityPda } from '@metaplex-foundation/mpl-agent-registry';
import { fetchAssetV1 } from '@metaplex-foundation/mpl-core';
import { publicKey, type Umi, type PublicKey } from '@metaplex-foundation/umi';
import { z } from 'zod';
import { explorerUrl } from './helius.js';
import type { Config } from './config.js';

export const ServiceSchema = z.object({
  name: z.string().min(1),
  endpoint: z.string().url(),
});

export const AgentMetadataSchema = z.object({
  type: z.literal('agent').default('agent'),
  name: z.string().min(1),
  description: z.string().min(1),
  services: z.array(ServiceSchema).default([]),
  registrations: z.array(z.string()).default([]),
  supportedTrust: z.array(z.enum(['tee', 'attestation', 'none'])).default([]),
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
  const result = await mintAndSubmitAgent(umi, {}, {
    wallet,
    name: req.name,
    uri: req.uri,
    agentMetadata: req.metadata,
  });
  const asset = String(result.asset ?? result.assetAddress ?? '');
  const signature = String(result.signature ?? '');
  const identityPda = findAgentIdentityPda(umi, { asset: publicKey(asset) })[0];
  return {
    asset,
    identityPda: String(identityPda),
    signature,
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
    services: { name: string; endpoint: string }[];
    supportedTrust: string[];
  };
  explorer: string;
}

/**
 * Reads an agent's MPL Core asset and Agent Identity PDA via Helius RPC.
 */
export async function getAgent(umi: Umi, cfg: Config, address: string): Promise<AgentView> {
  const asset = await fetchAssetV1(umi, publicKey(address));
  const [identityPda] = findAgentIdentityPda(umi, { asset: publicKey(address) });
  const identity = await fetchAgentIdentity(umi, identityPda);
  return {
    asset: address,
    owner: String(asset.owner),
    name: asset.name,
    uri: asset.uri,
    identity: {
      pda: String(identityPda),
      services: identity.services.map((s) => ({ name: s.name, endpoint: s.endpoint })),
      supportedTrust: identity.supportedTrust.map((t) => String(t)),
    },
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
