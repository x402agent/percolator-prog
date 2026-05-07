import { Bot, GrammyError, HttpError } from 'grammy';
import { allowedTelegramChats, loadConfig } from '../core/config.js';
import { buildUmi } from '../core/helius.js';
import { mintAgent, getAgent, MintRequestSchema } from '../core/agents.js';
import { runRegister } from '../core/registerCli.js';

const cfg = loadConfig();
if (!cfg.TELEGRAM_BOT_TOKEN) {
  throw new Error('TELEGRAM_BOT_TOKEN is required to run the Telegram bot');
}
const allowed = allowedTelegramChats(cfg);
const umi = buildUmi(cfg);
const bot = new Bot(cfg.TELEGRAM_BOT_TOKEN);

bot.use(async (ctx, next) => {
  const id = ctx.chat?.id;
  if (id == null || !allowed.has(id)) {
    await ctx.reply('unauthorized chat');
    return;
  }
  await next();
});

bot.command('start', (ctx) =>
  ctx.reply(
    [
      'Percolator agent bot.',
      '',
      'Commands:',
      '  /register <name>|<description>|<image?>',
      '  /mint <name>|<uri>|<description>',
      '  /explore <address>',
      '',
      `Cluster: ${cfg.SOLANA_CLUSTER}`,
    ].join('\n'),
  ),
);

bot.command('register', async (ctx) => {
  const args = parsePipeArgs(ctx.match);
  if (args.length < 2) {
    await ctx.reply('usage: /register <name>|<description>|<image?>');
    return;
  }
  await ctx.reply(`registering "${args[0]}"…`);
  const out = await runRegister({
    name: args[0]!,
    description: args[1],
    image: args[2],
  });
  await ctx.reply(formatJson(out));
});

bot.command('mint', async (ctx) => {
  const args = parsePipeArgs(ctx.match);
  if (args.length < 3) {
    await ctx.reply('usage: /mint <name>|<uri>|<description>');
    return;
  }
  const [name, uri, description] = args as [string, string, string];
  await ctx.reply(`minting "${name}"…`);
  const req = MintRequestSchema.parse({
    name,
    uri,
    metadata: {
      type: 'agent',
      name,
      description,
      services: [],
      registrations: [],
      supportedTrust: [],
    },
  });
  const out = await mintAgent(umi, cfg, req);
  await ctx.reply(formatJson(out));
});

bot.command('explore', async (ctx) => {
  const address = ctx.match.trim();
  if (!address) {
    await ctx.reply('usage: /explore <address>');
    return;
  }
  const out = await getAgent(umi, cfg, address);
  await ctx.reply(formatJson(out));
});

bot.catch((err) => {
  const e = err.error;
  if (e instanceof GrammyError) console.error('grammy error', e.description);
  else if (e instanceof HttpError) console.error('http error', e);
  else console.error('bot error', e);
});

function parsePipeArgs(raw: string): string[] {
  return raw
    .split('|')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function formatJson(obj: unknown): string {
  const s = JSON.stringify(obj, null, 2);
  return s.length > 3500 ? s.slice(0, 3500) + '\n…(truncated)' : '```\n' + s + '\n```';
}

bot.start({ onStart: (info) => console.log(`bot @${info.username} started`) });
