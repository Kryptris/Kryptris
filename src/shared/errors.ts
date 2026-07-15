export type VaultaErrorCode =
  | 'AUTH_FAILED'
  | 'AUTH_FACTOR_REQUIRED'
  | 'AUTH_RATE_LIMITED'
  | 'CORRUPT_DATA'
  | 'INVALID_INPUT'
  | 'LOCKED'
  | 'NOT_FOUND'
  | 'CANCELLED'
  | 'CONFLICT'
  | 'FILE_TOO_LARGE'
  | 'UNSUPPORTED_FORMAT'
  | 'UNSAFE_PATH'
  | 'INTERNAL';

export interface SerializedVaultaError {
  code: VaultaErrorCode;
  message: string;
  action: string | null;
}

export class VaultaError extends Error {
  public constructor(
    public readonly code: VaultaErrorCode,
    message: string,
    public readonly action: string | null = null,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'VaultaError';
  }

  public serialize(): SerializedVaultaError {
    return { code: this.code, message: this.message, action: this.action };
  }
}

export function toVaultaError(error: unknown): VaultaError {
  if (error instanceof VaultaError) return error;
  return new VaultaError(
    'INTERNAL',
    'Vaulta konnte die Aktion nicht abschließen.',
    'Versuche es erneut. Falls der Fehler bleibt, prüfe die lokale Diagnose.',
    { cause: error },
  );
}
