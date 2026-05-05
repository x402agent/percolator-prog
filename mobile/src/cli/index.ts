#!/usr/bin/env node
import { Command } from 'commander';
import { loadConfig } from '../core/config.js';
import { buildUmi } from '../core/helius.js';
import { mintAgent, getAgent, MintRequestSchema } from '../core/agents.js';
import { runRegister } from '../core/registerCli.js';

const program = new Command();
program
  .name('percolator-agent')
  .description('Terminal client for Percolator mobile DApp routing layer.')
  .version('0.1.0');

program
  .command('register')
  .description('Register an agent via the Metaplex CLI (`mplx agents register`).')
  .requiredOption('-n, --name <name>')
  .option('-d, --description <desc>')
  .option('-i, --image <path>')
  .option('-s, --services <json>', 'JSON array of {name,endpoint}')
  .option('-t, --supported-trust <json>', 'JSON array of trust mechanisms')
  .option('--use-ix', 'send instruction directly instead of via API')
  .action(async (opts) => {
    const services = opts.services ? JSON.parse(opts.services) : undefined;
    const supportedTrust = opts.supportedTrust ? JSON.parse(opts.supportedTrust) : undefined;
    const out = await runRegister({
      name: opts.name,
      description: opts.description,
      image: opts.image,
      services,
      supportedTrust,
      useIx: !!opts.useIx,
    });
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  });

program
  .command('mint')
  .description('Mint an agent on-chain via the Metaplex SDK and Helius RPC.')
  .requiredOption('-n, --name <name>')
  .requiredOption('-u, --uri <uri>', 'metadata JSON URI')
  .requiredOption('-D, --description <desc>')
  .option('-s, --services <json>', 'JSON array of {name,endpoint}')
  .option('-t, --supported-trust <json>', 'JSON array of trust mechanisms')
  .option('-o, --owner <pubkey>')
  .action(async (opts) => {
    const cfg = loadConfig();
    const umi = buildUmi(cfg);
    const req = MintRequestSchema.parse({
      name: opts.name,
      uri: opts.uri,
      owner: opts.owner,
      metadata: {
        type: 'agent',
        name: opts.name,
        description: opts.description,
        services: opts.services ? JSON.parse(opts.services) : [],
        registrations: [],
        supportedTrust: opts.supportedTrust ? JSON.parse(opts.supportedTrust) : [],
      },
    });
    const out = await mintAgent(umi, cfg, req);
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  });

program
  .command('explore <address>')
  .description('Fetch an agent (MPL Core asset + Agent Identity PDA) via Helius RPC.')
  .action(async (address: string) => {
    const cfg = loadConfig();
    const umi = buildUmi(cfg);
    const out = await getAgent(umi, cfg, address);
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  });

program.parseAsync(process.argv).catch((e) => {
  process.stderr.write(`error: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(1);
});
