import { Bot } from 'grammy';
import { buildUmi, getAgent, loadEnv, mintAgent, MintRequestSchema } from './core.js';

const env = loadEnv();
if (!env.TELEGRAM_BOT_TOKEN) throw new Error('TELEGRAM_BOT_TOKEN is required');
const allowed = new Set((env.TELEGRAM_ALLOWED_CHATS ?? '').split(',').map((s) => Number(s.trim())).filter(Number.isFinite));
const umi = buildUmi(env);
const bot = new Bot(env.TELEGRAM_BOT_TOKEN);

bot.use(async (ctx, next) => {
  if (ctx.chat?.id == null || !allowed.has(ctx.chat.id)) {
    await ctx.reply('unauthorized chat');
    return;
  }
  await next();
});

bot.command('start', (ctx) =>
  ctx.reply([
    'Metaplex agent bot.',
    '',
    '/mint <name>|<uri>|<description>',
    '/explore <address>',
    '',
    `Network: ${env.NETWORK}`,
  ].join('\n')),
);

bot.command('mint', async (ctx) => {
  const args = ctx.match.split('|').map((s) => s.trim()).filter(Boolean);
  if (args.length < 3) { await ctx.reply('usage: /mint <name>|<uri>|<description>'); return; }
  const [name, uri, description] = args as [string, string, string];
  await ctx.reply(`minting "${name}"…`);
  const req = MintRequestSchema.parse({
    name, uri,
    metadata: { type: 'agent', name, description, services: [], registrations: [], supportedTrust: [] },
  });
  await ctx.reply('```\n' + JSON.stringify(await mintAgent(umi, env, req), null, 2) + '\n```');
});

bot.command('explore', async (ctx) => {
  const address = ctx.match.trim();
  if (!address) { await ctx.reply('usage: /explore <address>'); return; }
  await ctx.reply('```\n' + JSON.stringify(await getAgent(umi, env, address), null, 2) + '\n```');
});

bot.start({ onStart: (info) => console.log(`bot @${info.username} started (${env.NETWORK})`) });
