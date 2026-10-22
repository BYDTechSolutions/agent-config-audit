import { createHash } from 'node:crypto';
import { flatTags, rule } from '../rules.js';
import { scrubSecrets } from '../text/secrets.js';
import { escapeHidden } from '../text/unicode.js';
import type { Finding, Source } from '../types.js';
import type { Model } from '../model.js';

/** What a check passes to {@link Emit}. Missing `why` and `fix` come from the rule. */
export interface FindingInput {
  file: string;
  line?: number;
  key?: string;
  /** Overrides the rule's title, usually to name the file or key. */
  title?: string;
  observed: string;
  why?: string;
  fix?: string;
  /** What makes this finding unique within the file, for the fingerprint. Defaults to `key`, then `observed`. */
  evidence?: string;
  details?: string[];
  /** A more specific page than the rule's (e.g. the hook docs of the tool that reads this file). */
  source?: Source;
}

export type Emit = (ruleId: string, input: FindingInput) => void;

/** A check: reads the model, emits findings. */
export type Check = (model: Model, emit: Emit) => void;

/** Defense in depth: whatever a check passes, output never carries a secret or an invisible character. */
const clean = (s: string) => escapeHidden(scrubSecrets(s));

/** Builds a finding from a rule and a check's input. */
export function makeFinding(ruleId: string, input: FindingInput): Finding {
  const r = rule(ruleId);
  const evidence = input.evidence ?? input.key ?? input.observed;
  const fingerprint = createHash('sha256').update(`${ruleId}\0${input.file}\0${clean(evidence)}`).digest('hex').slice(0, 32);
  return {
    id: r.id,
    family: r.family,
    priority: r.priority,
    title: clean(input.title ?? r.title),
    file: input.file,
    ...(input.line ? { line: input.line } : {}),
    ...(input.key ? { key: clean(input.key) } : {}),
    observed: clean(input.observed),
    why: input.why ?? r.why,
    fix: clean(input.fix ?? r.fix),
    source: input.source ?? r.source,
    tags: flatTags(r),
    fingerprint,
    ...(input.details?.length ? { details: input.details.slice(0, 20).map(clean) } : {}),
  };
}
