import { spawn } from 'node:child_process';
import { buildRegisterArgv, type RegisterCliRequest } from './agents.js';

export interface RegisterResult {
  asset?: string;
  signature?: string;
  explorer?: string;
  stdout: string;
  stderr: string;
  command: string;
}

/**
 * Invokes `mplx agents register` with the given parameters. Requires the
 * Metaplex CLI to be installed and on PATH (`npm i -g @metaplex-foundation/cli`).
 */
export function runRegister(req: RegisterCliRequest, opts: { cwd?: string; timeoutMs?: number } = {}): Promise<RegisterResult> {
  const argv = buildRegisterArgv(req);
  const timeoutMs = opts.timeoutMs ?? 60_000;
  return new Promise((resolve, reject) => {
    const child = spawn('mplx', argv, { cwd: opts.cwd, env: process.env });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`mplx agents register timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.on('data', (b) => (stdout += b.toString()));
    child.stderr.on('data', (b) => (stderr += b.toString()));
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(`mplx exited ${code}: ${stderr || stdout}`));
        return;
      }
      resolve({
        ...parseCliOutput(stdout),
        stdout,
        stderr,
        command: ['mplx', ...argv].join(' '),
      });
    });
  });
}

function parseCliOutput(out: string): { asset?: string; signature?: string; explorer?: string } {
  const asset = /(?:asset|address)[:\s]+([1-9A-HJ-NP-Za-km-z]{32,44})/i.exec(out)?.[1];
  const signature = /signature[:\s]+([1-9A-HJ-NP-Za-km-z]{60,90})/i.exec(out)?.[1];
  const explorer = /(https:\/\/explorer\.solana\.com\/\S+)/.exec(out)?.[1];
  return { asset, signature, explorer };
}
