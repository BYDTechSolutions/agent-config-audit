/** A problem with the input (a missing directory, an unreadable lockfile), as opposed to a finding. */
export class AuditError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditError';
  }
}
