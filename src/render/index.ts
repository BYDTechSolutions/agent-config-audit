import type { Report } from '../types.js';
import { formatMarkdown } from './markdown.js';
import { formatSarif } from './sarif.js';
import { formatText, type TextOptions } from './text.js';

/** Output formats. */
export type ReportFormat = 'text' | 'json' | 'md' | 'sarif';
export const FORMATS: readonly ReportFormat[] = ['text', 'json', 'md', 'sarif'];

/** Renders a report in any format. */
export function formatReport(report: Report, format: ReportFormat, options: TextOptions = {}): string {
  switch (format) {
    case 'json':
      return `${JSON.stringify(report, null, 2)}\n`;
    case 'md':
      return formatMarkdown(report);
    case 'sarif':
      return formatSarif(report);
    default:
      return formatText(report, options);
  }
}

export { formatMarkdown, formatSarif, formatText };
export type { TextOptions };
