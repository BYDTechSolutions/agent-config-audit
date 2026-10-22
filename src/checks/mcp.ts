/**
 * MCP server hygiene across Claude Code, Cursor, VS Code, Gemini CLI and Codex:
 * pinning, transport, credentials, filesystem scope, container privileges,
 * shell launches and trust overrides. Servers are read as config, never started.
 */
import { referencedPaths } from '../discover.js';
import type { McpServer, Model } from '../model.js';
import { formatPath, type JsonPath } from '../parse/json.js';
import { isLocalHost } from '../text/patterns.js';
import { code } from '../text/safe.js';
import { findTokens, looksLikeLiteralSecret, redact, SECRET_KEY } from '../text/secrets.js';
import type { Emit } from './emit.js';

const bin = (cmd: string) => cmd.replace(/\\/g, '/').split('/').pop()?.replace(/\.(?:exe|cmd|bat)$/i, '').toLowerCase() ?? '';

/** Splits a launch into program and arguments; a `command` string with spaces is split on whitespace. */
export function argv(s: McpServer): string[] {
  const cmd = (s.command ?? '').trim();
  const parts = s.args.length ? [cmd] : cmd.split(/\s+/);
  return [...parts, ...s.args].filter((x) => x !== '');
}

const NPX_VALUE_FLAGS = new Set(['-p', '--package', '-c', '--call', '--registry', '--cache', '--userconfig', '-w', '--workspace']);
const SEMVER_EXACT = /^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/;

/** The package spec an npx-style launcher installs, and whether it is pinned to an exact version. */
export function launcherSpec(a: string[]): { launcher: string; spec: string; pinned: boolean; autoYes: boolean } | null {
  const b = bin(a[0] ?? '');
  let rest: string[];
  let launcher: string;
  if (b === 'npx' || b === 'bunx' || b === 'pnpx') {
    launcher = b;
    rest = a.slice(1);
  } else if ((b === 'pnpm' || b === 'yarn') && a[1] === 'dlx') {
    launcher = `${b} dlx`;
    rest = a.slice(2);
  } else if (b === 'npm' && (a[1] === 'exec' || a[1] === 'x')) {
    launcher = `npm ${a[1]}`;
    rest = a.slice(2);
  } else if (b === 'uvx' || (b === 'uv' && a[1] === 'tool' && a[2] === 'run')) {
    launcher = 'uvx';
    rest = b === 'uv' ? a.slice(3) : a.slice(1);
    const from = rest.findIndex((x) => x === '--from' || x.startsWith('--from='));
    const fromSpec = from >= 0 ? (rest[from]?.includes('=') ? rest[from]?.split('=').slice(1).join('=') : rest[from + 1]) : undefined;
    const tool = rest.find((x, i) => !x.startsWith('-') && !(from >= 0 && i === from + 1));
    const spec = fromSpec ?? tool ?? '';
    if (!spec) return null;
    if (/^[./~]|^git\+|^https?:/.test(spec)) return null;
    const pinned = /==\s*\d+(?:\.\d+)*/.test(spec) || (/@/.test(spec) && SEMVER_EXACT.test(spec.split('@').pop() ?? '') ) || /@\d+(?:\.\d+)+$/.test(spec);
    return { launcher, spec, pinned, autoYes: false };
  } else if (b === 'pipx' && a[1] === 'run') {
    launcher = 'pipx run';
    rest = a.slice(2);
    const specIdx = rest.findIndex((x) => x === '--spec');
    const spec = specIdx >= 0 ? (rest[specIdx + 1] ?? '') : (rest.find((x) => !x.startsWith('-')) ?? '');
    if (!spec || /^[./~]/.test(spec)) return null;
    return { launcher, spec, pinned: /==\s*\d+(?:\.\d+)*/.test(spec), autoYes: false };
  } else return null;

  let autoYes = false;
  let spec = '';
  for (let i = 0; i < rest.length; i++) {
    const x = rest[i] as string;
    if (x === '-y' || x === '--yes') {
      autoYes = true;
      continue;
    }
    if (x === '--package' || x === '-p') {
      spec = rest[i + 1] ?? '';
      break;
    }
    if (x.startsWith('--package=')) {
      spec = x.slice('--package='.length);
      break;
    }
    if (NPX_VALUE_FLAGS.has(x)) {
      i++;
      continue;
    }
    if (x.startsWith('-')) continue;
    spec = x;
    break;
  }
  if (!spec || /^[./~]|^file:|^git\+|^https?:|^github:/.test(spec)) return null;
  const at = spec.lastIndexOf('@');
  const version = at > 0 ? spec.slice(at + 1) : '';
  return { launcher, spec, pinned: SEMVER_EXACT.test(version), autoYes };
}

const DOCKER_VALUE_FLAGS = new Set(['-e', '--env', '-v', '--volume', '--name', '-p', '--publish', '--network', '--net', '--mount', '-w', '--workdir', '-u', '--user', '--entrypoint', '--env-file', '--platform', '--pull', '--cap-add', '--cap-drop', '-l', '--label', '--add-host', '--device', '--pid', '--ipc', '--security-opt', '-m', '--memory', '--cpus', '--restart', '-h', '--hostname', '--dns', '--tmpfs', '--ulimit', '--log-driver', '--uts', '--userns', '--runtime', '--gpus', '--shm-size', '--stop-signal', '--cidfile', '--group-add']);

/** The image a `docker run` launches and the risky flags it passes. */
export function dockerRun(a: string[]): { image: string; risky: string[] } | null {
  const b = bin(a[0] ?? '');
  if (b !== 'docker' && b !== 'podman') return null;
  const runAt = a.findIndex((x, i) => i > 0 && (x === 'run' || x === 'create'));
  if (runAt < 0) return null;
  const risky: string[] = [];
  let image = '';
  const rest = a.slice(runAt + 1);
  for (let i = 0; i < rest.length; i++) {
    const x = rest[i] as string;
    const [flag, inline] = x.includes('=') && x.startsWith('-') ? [x.slice(0, x.indexOf('=')), x.slice(x.indexOf('=') + 1)] : [x, undefined];
    const value = inline ?? (DOCKER_VALUE_FLAGS.has(flag) ? rest[i + 1] : undefined);
    if (flag === '--privileged') risky.push('--privileged');
    if ((flag === '--network' || flag === '--net' || flag === '--pid' || flag === '--ipc' || flag === '--uts' || flag === '--userns') && value === 'host') risky.push(`${flag} host`);
    if (flag === '--cap-add' && value && /^(?:ALL|SYS_ADMIN|SYS_PTRACE|SYS_MODULE|NET_ADMIN|DAC_READ_SEARCH)$/i.test(value)) risky.push(`--cap-add ${value}`);
    if (flag === '--security-opt' && value && /unconfined/.test(value)) risky.push(`--security-opt ${value}`);
    if ((flag === '-v' || flag === '--volume') && value) {
      const src = value.split(':')[0] ?? '';
      if (src === '/' || src === '/var/run/docker.sock' || src === '/run/docker.sock' || src === '~' || src === '$HOME' || src === '${HOME}' || /^\/(?:etc|root|home|Users)\/?$/.test(src)) risky.push(`-v ${value}`);
    }
    if (flag === '--mount' && value && /(?:source|src)=(?:\/|\/var\/run\/docker\.sock)(?:,|$)/.test(value)) risky.push(`--mount ${value}`);
    if (DOCKER_VALUE_FLAGS.has(flag) && inline === undefined) {
      i++;
      continue;
    }
    if (x.startsWith('-')) continue;
    image = x;
    break;
  }
  return image ? { image, risky } : null;
}

const BROAD_ROOTS = new Set(['/', '~', '~/', '$HOME', '${HOME}', '${userHome}', '${env:HOME}', 'C:\\', 'C:/', '/Users', '/home', '%USERPROFILE%']);
const TOKEN_QUERY = /[?&](?:token|access_token|api[_-]?key|key|apikey|auth|secret|password)=([^&#\s]+)/i;

export function mcpChecks(model: Model, emit: Emit): void {
  for (const s of model.servers) {
    const lineOf = (...p: JsonPath) => s.doc?.lineOf([...s.path, ...p]) ?? s.line;
    const keyOf = (...p: JsonPath) => formatPath([...s.path, ...p]);
    const label = `${s.tool} MCP server ${code(s.name, 40)}`;
    const a = argv(s);
    const launch = a.join(' ');

    const spec = launcherSpec(a);
    if (spec && !spec.pinned) {
      emit('mcp/unpinned-package', {
        file: s.file,
        line: lineOf(s.args.length ? 'args' : 'command'),
        key: keyOf(s.args.length ? 'args' : 'command'),
        title: `${label} runs ${code(spec.spec, 50)} without a pinned version`,
        observed: `\`${spec.launcher}${spec.autoYes ? ' -y' : ''}\` installs ${code(spec.spec, 80)} at launch; command: ${code(launch, 140)}`,
        evidence: `${s.name}:${spec.spec}`,
        fix: `Pin the exact version you reviewed, e.g. ${code(`${spec.spec.replace(/(.)@[^@/]*$/, '$1').replace(/==.*$/, '')}${spec.launcher === 'pipx run' ? '==X.Y.Z' : '@X.Y.Z'}`, 60)}, and update it on purpose.`,
        ...(spec.launcher.startsWith('uvx') ? { source: { title: 'uv: Using tools (uvx)', url: 'https://docs.astral.sh/uv/guides/tools/' } } : {}),
      });
    }

    const dock = dockerRun(a);
    if (dock) {
      if (!/@sha256:[0-9a-f]{64}$/.test(dock.image)) {
        emit('mcp/docker-unpinned', { file: s.file, line: lineOf('args'), key: keyOf('args'), title: `${label} runs image ${code(dock.image, 50)} without a digest`, observed: `docker image ${code(dock.image, 80)}${dock.image.includes(':') ? '' : ' (no tag: Docker uses :latest)'}`, evidence: `${s.name}:${dock.image}` });
      }
      if (dock.risky.length) {
        emit('mcp/docker-privileged', { file: s.file, line: lineOf('args'), key: keyOf('args'), title: `${label} container gets host access: ${dock.risky.join(', ')}`, observed: `docker run with ${dock.risky.map((r) => code(r, 60)).join(', ')}`, evidence: `${s.name}:${dock.risky.join(',')}` });
      }
    }

    if (s.url && /^http:\/\//i.test(s.url)) {
      let host = '';
      try {
        host = new URL(s.url).hostname;
      } catch {
        host = '';
      }
      if (host && !isLocalHost(host)) {
        emit('mcp/plain-http', { file: s.file, line: lineOf('url') ?? lineOf('httpUrl'), key: keyOf('url'), title: `${label} uses plain HTTP`, observed: `url = ${code(s.url, 120)}`, evidence: `${s.name}:${host}` });
      }
    }

    // Credentials written into the config.
    const secretHits: { key: string; line?: number; shown: string }[] = [];
    for (const [k, v] of Object.entries(s.env)) {
      const tok = findTokens(v)[0];
      if (tok || (SECRET_KEY.test(k) && looksLikeLiteralSecret(v))) secretHits.push({ key: keyOf('env', k), line: lineOf('env', k), shown: `env.${k} = ${redact(tok?.value ?? v)}` });
    }
    for (const [k, v] of Object.entries(s.headers)) {
      const tok = findTokens(v)[0];
      if (tok || (SECRET_KEY.test(k) && looksLikeLiteralSecret(v))) secretHits.push({ key: keyOf('headers', k), line: lineOf('headers', k), shown: `headers.${k} = ${redact((tok?.value ?? v).replace(/^\s*(?:Bearer|Basic|Token)\s+/i, ''))}` });
    }
    if (s.url) {
      const q = TOKEN_QUERY.exec(s.url);
      if (q && looksLikeLiteralSecret(q[1] as string)) secretHits.push({ key: keyOf('url'), line: lineOf('url'), shown: `url query parameter = ${redact(q[1] as string)}` });
      const userinfo = /^[a-z]+:\/\/[^/@\s:]+:([^/@\s]+)@/i.exec(s.url);
      if (userinfo && looksLikeLiteralSecret(userinfo[1] as string)) secretHits.push({ key: keyOf('url'), line: lineOf('url'), shown: `password in url = ${redact(userinfo[1] as string)}` });
    }
    s.args.forEach((arg, i) => {
      const tok = findTokens(arg)[0];
      const flag = /^--?(?:token|api[-_]?key|access[-_]?token|password|secret|auth)(?:=(.+))?$/i.exec(arg);
      const next = flag && flag[1] === undefined ? s.args[i + 1] : undefined;
      const literal = flag?.[1] ?? next;
      if (tok) secretHits.push({ key: keyOf('args', i), line: lineOf('args', i), shown: `args[${i}] contains a ${tok.name}: ${redact(tok.value)}` });
      else if (literal && looksLikeLiteralSecret(literal)) secretHits.push({ key: keyOf('args', flag?.[1] !== undefined ? i : i + 1), line: lineOf('args', i), shown: `args ${code(arg.split('=')[0] as string, 30)} = ${redact(literal)}` });
    });
    for (const hit of secretHits) {
      emit('mcp/inline-secret', { file: s.file, line: hit.line, key: hit.key, title: `${label} has a credential in its config`, observed: hit.shown, evidence: hit.key });
    }

    const broad = s.args.map((x, i) => ({ x, i })).filter(({ x }) => BROAD_ROOTS.has(x.trim()) || /^--?(?:root|dir|directory|path|allowed[-_]?dir(?:ectories)?)=(?:\/|~\/?|\$HOME)$/.test(x.trim()));
    if (broad.length && !dock) {
      emit('mcp/broad-filesystem', { file: s.file, line: lineOf('args', (broad[0] as { i: number }).i), key: keyOf('args'), title: `${label} gets ${code((broad[0] as { x: string }).x, 20)} as a path`, observed: `args include ${broad.map(({ x }) => code(x, 30)).join(', ')}; command: ${code(launch, 120)}`, evidence: `${s.name}:${broad.map(({ x }) => x).join(',')}` });
    }

    const b = bin(a[0] ?? '');
    if (['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'cmd', 'powershell', 'pwsh'].includes(b)) {
      const ci = a.findIndex((x, i) => i > 0 && /^(?:-c|\/c|\/C|-Command|-command|-EncodedCommand|-e)$/.test(x));
      if (ci > 0) {
        emit('mcp/shell-wrapper', { file: s.file, line: lineOf('args') ?? lineOf('command'), key: keyOf(s.args.length ? 'args' : 'command'), title: `${label} is launched through ${b} ${a[ci]}`, observed: `${code(launch, 160)}`, evidence: `${s.name}:${a.slice(ci + 1).join(' ')}` });
      }
    }

    if (s.trust === true) {
      emit('mcp/trust-all', { file: s.file, line: lineOf('trust'), key: keyOf('trust'), title: `${label} has "trust": true`, observed: `${keyOf('trust')} = true` });
    }
    if (s.headersHelper) {
      emit('mcp/headers-helper', { file: s.file, line: lineOf('headersHelper'), key: keyOf('headersHelper'), title: `${label} runs a headersHelper command`, observed: `headersHelper = ${code(s.headersHelper, 140)}`, evidence: `${s.name}:${s.headersHelper}` });
    }
    const scripts = referencedPaths(launch).filter((p) => model.paths.has(p));
    if (scripts.length) {
      emit('mcp/repo-script', { file: s.file, line: s.line, key: keyOf(), title: `${label} runs ${code(scripts[0] as string, 60)} from this repository`, observed: `command: ${code(launch, 140)}`, evidence: `${s.name}:${scripts.join(',')}`, details: scripts.map((p) => `runs ${p}`) });
    }
  }
}
