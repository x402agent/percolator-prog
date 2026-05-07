import 'dotenv/config';
import { z } from 'zod';

const Schema = z.object({
  HELIUS_RPC_URL: z.string().url(),
  // Solana testnet isn't supported by the Metaplex Agent API (its SvmNetwork
  // covers solana-mainnet/solana-devnet plus eclipse/sonic/fogo); restrict to
  // the two clusters the agent flow actually works on.
  SOLANA_CLUSTER: z.enum(['mainnet-beta', 'devnet']).default('devnet'),
  OPERATOR_SECRET_KEY: z.string().min(1),
  PORT: z.coerce.number().int().positive().default(8787),
  API_KEY: z.string().min(24),
  TELEGRAM_BOT_TOKEN: z.string().optional(),
  TELEGRAM_ALLOWED_CHATS: z.string().optional(),
  PERCOLATOR_PROGRAM_ID: z.string().optional(),
});

export type Config = z.infer<typeof Schema>;

let cached: Config | null = null;

export function loadConfig(): Config {
  if (cached) return cached;
  const parsed = Schema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid environment:\n${issues}`);
  }
  cached = parsed.data;
  return cached;
}

export function allowedTelegramChats(cfg: Config): Set<number> {
  if (!cfg.TELEGRAM_ALLOWED_CHATS) return new Set();
  return new Set(
    cfg.TELEGRAM_ALLOWED_CHATS.split(',')
      .map((s) => Number(s.trim()))
      .filter((n) => Number.isFinite(n)),
  );
}
