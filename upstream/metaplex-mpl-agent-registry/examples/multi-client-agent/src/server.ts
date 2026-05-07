import express from 'express';
import { z } from 'zod';
import { buildUmi, getAgent, loadEnv, mintAgent, MintRequestSchema } from './core.js';

const env = loadEnv();
const umi = buildUmi(env);
const app = express();
app.use(express.json({ limit: '256kb' }));

if (env.API_KEY) {
  app.use((req, res, next) => {
    if (req.path === '/health') return next();
    if (req.header('x-api-key') !== env.API_KEY) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }
    next();
  });
}

app.get('/health', (_req, res) => res.json({ ok: true, network: env.NETWORK }));

app.post('/agents/mint', async (req, res, next) => {
  try {
    res.json(await mintAgent(umi, env, MintRequestSchema.parse(req.body)));
  } catch (e) { next(e); }
});

app.get('/agents/:address', async (req, res, next) => {
  try {
    const address = z.string().min(32).max(44).parse(req.params.address);
    res.json(await getAgent(umi, env, address));
  } catch (e) { next(e); }
});

app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (err instanceof z.ZodError) { res.status(400).json({ error: 'bad_request', issues: err.issues }); return; }
  res.status(500).json({ error: 'internal', message: err instanceof Error ? err.message : String(err) });
});

app.listen(env.PORT, () => console.log(`server listening on :${env.PORT} (${env.NETWORK})`));
