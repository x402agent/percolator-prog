import type { Express, Request, Response, NextFunction } from 'express';
import type { Umi } from '@metaplex-foundation/umi';
import { z } from 'zod';
import {
  MintRequestSchema,
  mintAgent,
  getAgent,
  buildRegisterArgv,
} from '../core/agents.js';
import { runRegister } from '../core/registerCli.js';
import type { Config } from '../core/config.js';

const RegisterBody = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  image: z.string().optional(),
  services: z.array(z.object({ name: z.string(), endpoint: z.string().url() })).optional(),
  supportedTrust: z.array(z.string()).optional(),
  useIx: z.boolean().optional(),
  dryRun: z.boolean().optional(),
});

export function mountRoutes(app: Express, deps: { umi: Umi; cfg: Config }) {
  const { umi, cfg } = deps;

  app.post('/agents/register', asyncHandler(async (req, res) => {
    const body = RegisterBody.parse(req.body);
    if (body.dryRun) {
      res.json({ command: ['mplx', ...buildRegisterArgv(body)].join(' ') });
      return;
    }
    const out = await runRegister(body);
    res.json(out);
  }));

  app.post('/agents/mint', asyncHandler(async (req, res) => {
    const body = MintRequestSchema.parse(req.body);
    const out = await mintAgent(umi, cfg, body);
    res.json(out);
  }));

  app.get('/agents/:address', asyncHandler(async (req, res) => {
    const address = z.string().min(32).max(44).parse(req.params.address);
    const out = await getAgent(umi, cfg, address);
    res.json(out);
  }));

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'bad_request', issues: err.issues });
      return;
    }
    const msg = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: 'internal', message: msg });
  });
}

function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void>,
) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, next).catch(next);
  };
}
