import { describe, expect, it } from 'vitest';
import { base64DecodeTolerantPadding, parseArgon2idPrefix, parsePayload } from './crypto';

const decoder = new TextDecoder();

describe('base64DecodeTolerantPadding', () => {
  it('décodage avec padding manquant', () => {
    const bytes = base64DecodeTolerantPadding('YWI');
    expect(decoder.decode(bytes)).toBe('ab');
  });

  it('normalise le base64 url-safe', () => {
    const bytes = base64DecodeTolerantPadding('YWJjZA');
    expect(decoder.decode(bytes)).toBe('abcd');
  });
});

describe('parseArgon2idPrefix', () => {
  it('parse les paramètres attendus', () => {
    const params = parseArgon2idPrefix('$argon2id$v=19$m=131072,t=3,p=2$YWJj');
    expect(params.memoryCost).toBe(131072);
    expect(params.timeCost).toBe(3);
    expect(params.parallelism).toBe(2);
    expect(params.salt.length).toBe(3);
  });

  it('rejette un kdf différent', () => {
    expect(() => parseArgon2idPrefix('$argon2i$v=19$m=1,t=1,p=1$YWJj')).toThrow();
  });

  it('accepte IV en majuscule dans le payload', () => {
    const payload = `{
      "v": 1,
      "kdf": "$argon2id$v=19$m=1,t=1,p=1$YWJj",
      "c": "aes-256-gcm",
      "IV": "YWJjZGVmZ2hpamtsbW5vcA==",
      "ctxt": "YWJjZGVmZ2hpamtsbW5vcHFy",
      "t": 128
    }`;
    expect(() => parsePayload(payload)).not.toThrow();
  });
});
