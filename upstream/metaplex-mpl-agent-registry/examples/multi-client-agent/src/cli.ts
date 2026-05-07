import { Command } from 'commander';
import { buildUmi, getAgent, loadEnv, mintAgent, MintRequestSchema } from './core.js';

const program = new Command();
program
  .name('multi-client-agent')
  .description('Mint or read a Metaplex agent from the terminal.')
  .version('0.0.1');

program
  .command('mint')
  .requiredOption('-n, --name <name>')
  .requiredOption('-u, --uri <uri>', 'metadata JSON URI')
  .requiredOption('-D, --description <desc>')
  .option('-s, --services <json>', 'JSON array of {name, endpoint}')
  .option('-t, --supported-trust <json>', 'JSON array of trust mechanisms')
  .option('-o, --owner <pubkey>')
  .action(async (opts) => {
    const env = loadEnv();
    const umi = buildUmi(env);
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
    process.stdout.write(JSON.stringify(await mintAgent(umi, env, req), null, 2) + '\n');
  });

program
  .command('explore <address>')
  .description('Read an agent (MPL Core asset + Agent Identity PDA + off-chain metadata).')
  .action(async (address: string) => {
    const env = loadEnv();
    const umi = buildUmi(env);
    process.stdout.write(JSON.stringify(await getAgent(umi, env, address), null, 2) + '\n');
  });

program.parseAsync(process.argv).catch((e) => {
  process.stderr.write(`error: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(1);
});
