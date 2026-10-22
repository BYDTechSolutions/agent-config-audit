#!/usr/bin/env node
import { main } from './cli-main.js';

main(process.argv.slice(2), {
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
  env: process.env,
  stdoutIsTTY: Boolean(process.stdout.isTTY),
  columns: process.stdout.columns,
}).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(`agent-config-audit: ${(error as Error).stack ?? String(error)}\n`);
    process.exitCode = 2;
  },
);
