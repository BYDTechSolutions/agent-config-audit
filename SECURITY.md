# Security policy

## Reporting a vulnerability

Please email **sales.bydtech@gmail.com** with the details, instead of opening a
public issue. We will acknowledge the report and keep you posted on the fix.

## Scope

`agent-config-audit` reads files in the directory you give it. It lists
directories without following symlinks, opens only files that belong to an
agent surface (with `O_NOFOLLOW` where the platform has it), and reads them as
bytes. It never executes, imports or fetches anything it finds, makes no network
requests, and writes only the report or lockfile you ask for.

Especially welcome:

- any way to make it execute, import or fetch something from a scanned
  repository;
- output that carries a raw secret or a raw invisible or control character
  (every output format is meant to redact and escape them);
- a crafted file that makes it crash, hang or skip a file without listing it
  as "needs human review".

It is not a malware scanner. A way to write a malicious skill that its pattern
rules miss is expected, not a vulnerability, but an issue with the example is
still useful.
