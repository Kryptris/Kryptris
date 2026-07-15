import { describe, expect, it } from 'vitest';

import { AuthenticationSession } from '../../src/main/services/authentication-session';

describe('AuthenticationSession', () => {
  it('blockiert Fachzugriffe waehrend ein Profil nur vorlaeufig entsperrt ist', () => {
    const session = new AuthenticationSession();
    const epoch = session.begin();

    expect(() => session.requireAuthenticated(true)).toThrowError(
      expect.objectContaining({ code: 'LOCKED' }),
    );

    session.complete(true, epoch);
    expect(session.requireAuthenticated(true)).toBe(epoch);
  });

  it('kann nach einer Sperre nicht durch einen alten asynchronen Vorgang entsperrt werden', () => {
    const session = new AuthenticationSession();
    const staleEpoch = session.begin();

    session.reset();

    expect(() => session.complete(true, staleEpoch)).toThrowError(
      expect.objectContaining({ code: 'LOCKED' }),
    );
    expect(session.getState()).toBe('locked');
    expect(() => session.requireAuthenticated(true)).toThrowError(
      expect.objectContaining({ code: 'LOCKED' }),
    );
  });

  it('bindet den zweiten WebAuthn-Schritt an genau die aktive Challenge', () => {
    const session = new AuthenticationSession();
    const epoch = session.begin();
    session.awaitChallenge('challenge-1', epoch);

    expect(() => session.assertChallenge('challenge-2')).toThrowError(
      expect.objectContaining({ code: 'AUTH_FAILED' }),
    );
    expect(session.assertChallenge('challenge-1')).toBe(epoch);
    expect(session.cancelChallenge('challenge-1')).toBe(true);
    expect(session.cancelChallenge('challenge-1')).toBe(false);
    expect(session.getState()).toBe('locked');
  });
});
