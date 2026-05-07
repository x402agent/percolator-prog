import 'dotenv/config';
import {
  mintAndSubmitAgent,
  fetchAgentIdentityV1,
  findAgentIdentityV1Pda,
  mplAgentIdentity,
  type SvmNetwork,
} from '@metaplex-foundation/mpl-agent-registry';
import { fetchAssetV1, mplCore } from '@metaplex-foundation/mpl-core';
import { createUmi } from '@metaplex-foundation/umi-bundle-defaults';
import { keypairIdentity, publicKey, type Umi, type PublicKey } from '@metaplex-foundation/umi';
import bs58 from 'bs58';
import { z } from 'zod';

const Env = z.object({
  RPC_URL: z.string().url(),
  NETWORK: z.enum(['solana-mainnet', 'solana-devnet']).default('solana-devnet'),
  OPERATOR_SECRET_KEY: z.string().min(1),
  PORT: z.coerce.number().int().positive().default(8787),
  API_KEY: z.string().optional(),
  TELEGRAM_BOT_TOKEN: z.string().optional(),
  TELEGRAM_ALLOWED_CHATS: z.string().optional(),
});
export type Env = z.infer<typeof Env>;

let cachedEnv: Env | null = null;
export function loadEnv(): Env {
  if (cachedEnv) return cachedEnv;
  const r = Env.safeParse(process.env);
  if (!r.success) {
    throw new Error(`Invalid env:\n${r.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n')}`);
  }
  cachedEnv = r.data;
  return cachedEnv;
}

export function buildUmi(env: Env): Umi {
  const umi = createUmi(env.RPC_URL);
  const kp = umi.eddsa.createKeypairFromSecretKey(decodeSecretKey(env.OPERATOR_SECRET_KEY));
  return umi.use(keypairIdentity(kp)).use(mplCore()).use(mplAgentIdentity());
}

export function decodeSecretKey(raw: string): Uint8Array {
  const trimmed = raw.trim();
  if (trimmed.startsWith('[')) return Uint8Array.from(JSON.parse(trimmed) as number[]);
  return bs58.decode(trimmed);
}

export const ServiceSchema = z.object({ name: z.string().min(1), endpoint: z.string().url() });
export const RegistrationSchema = z.object({ agentId: z.string().min(1), agentRegistry: z.string().min(1) });
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

export async function mintAgent(umi: Umi, env: Env, req: MintRequest): Promise<MintResult> {
  const wallet: PublicKey = req.owner ? publicKey(req.owner) : umi.identity.publicKey;
  const result = await mintAndSubmitAgent(umi, null, {
    wallet,
    network: env.NETWORK as SvmNetwork,
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
    explorer: explorerUrl(env.NETWORK, asset),
  };
}

export interface AgentView {
  asset: string;
  owner: string;
  name: string;
  uri: string;
  identity: { pda: string; registered: boolean };
  metadata?: AgentMetadata;
  explorer: string;
}

export async function getAgent(umi: Umi, env: Env, address: string): Promise<AgentView> {
  const asset = await fetchAssetV1(umi, publicKey(address));
  const [pda] = findAgentIdentityV1Pda(umi, { asset: publicKey(address) });
  let registered = true;
  try { await fetchAgentIdentityV1(umi, pda); } catch { registered = false; }
  let metadata: AgentMetadata | undefined;
  try {
    const r = await fetch(asset.uri);
    if (r.ok) {
      const parsed = AgentMetadataSchema.safeParse(await r.json());
      if (parsed.success) metadata = parsed.data;
    }
  } catch { /* off-chain metadata is best-effort */ }
  return {
    asset: address,
    owner: String(asset.owner),
    name: asset.name,
    uri: asset.uri,
    identity: { pda: String(pda), registered },
    metadata,
    explorer: explorerUrl(env.NETWORK, address),
  };
}

function explorerUrl(network: SvmNetwork, address: string): string {
  const cluster = network === 'solana-mainnet' ? '' : '?cluster=devnet';
  return `https://explorer.solana.com/address/${address}${cluster}`;
}
