import express from 'express';
import pinoHttp from 'pino-http';
import pino from 'pino';
import { loadConfig } from '../core/config.js';
import { buildUmi } from '../core/helius.js';
import { mountRoutes } from './routes.js';

const cfg = loadConfig();
const logger = pino({ name: 'percolator-mobile' });
const umi = buildUmi(cfg);
const app = express();

app.use(express.json({ limit: '256kb' }));
app.use(pinoHttp({ logger }));

app.use((req, res, next) => {
  if (req.path === '/health') return next();
  const provided = req.header('x-api-key');
  if (provided !== cfg.API_KEY) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }
  next();
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, cluster: cfg.SOLANA_CLUSTER });
});

mountRoutes(app, { umi, cfg });

app.listen(cfg.PORT, () => {
  logger.info({ port: cfg.PORT, cluster: cfg.SOLANA_CLUSTER }, 'server listening');
});
