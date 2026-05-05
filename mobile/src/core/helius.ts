import { createUmi } from '@metaplex-foundation/umi-bundle-defaults';
import { keypairIdentity, publicKey, type Umi } from '@metaplex-foundation/umi';
import bs58 from 'bs58';
import type { Config } from './config.js';

export function buildUmi(cfg: Config): Umi {
  const umi = createUmi(cfg.HELIUS_RPC_URL);
  const secret = decodeSecretKey(cfg.OPERATOR_SECRET_KEY);
  const kp = umi.eddsa.createKeypairFromSecretKey(secret);
  return umi.use(keypairIdentity(kp));
}

function decodeSecretKey(raw: string): Uint8Array {
  const trimmed = raw.trim();
  if (trimmed.startsWith('[')) {
    const arr = JSON.parse(trimmed) as number[];
    return Uint8Array.from(arr);
  }
  return bs58.decode(trimmed);
}

export function explorerUrl(cluster: string, address: string): string {
  const suffix = cluster === 'mainnet-beta' ? '' : `?cluster=${cluster}`;
  return `https://explorer.solana.com/address/${address}${suffix}`;
}

export { publicKey };
