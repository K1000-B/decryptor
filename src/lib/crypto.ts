import { argon2id as argon2idHash } from 'hash-wasm';

export type DisplayMode = 'utf8' | 'hex' | 'base64';

type ErrorStep = 'parse' | 'kdf' | 'decrypt' | 'validation';

export class PayloadError extends Error {
  step?: ErrorStep;

  constructor(message: string, step: ErrorStep = 'validation') {
    super(message);
    this.name = 'PayloadError';
    this.step = step;
  }
}

export interface Argon2Params {
  type: 'argon2id';
  version: number;
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  salt: Uint8Array;
}

export interface ParsedPayload {
  version: 1;
  cipher: 'aes-256-gcm';
  tagBits: 128;
  argonParams: Argon2Params;
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

const utf8FatalDecoder = new TextDecoder('utf-8', { fatal: true });
const utf8Decoder = new TextDecoder('utf-8');

export function base64DecodeTolerantPadding(input: string): Uint8Array {
  const normalized = input.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + '='.repeat(padLength);

  if (typeof atob === 'function') {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  if (typeof Buffer !== 'undefined') {
    return Uint8Array.from(Buffer.from(padded, 'base64'));
  }

  throw new PayloadError('Base64 non supporté dans cet environnement.', 'parse');
}

export function base64Encode(bytes: Uint8Array): string {
  if (typeof btoa === 'function') {
    let binary = '';
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }

  throw new PayloadError('Base64 non supporté dans cet environnement.', 'parse');
}

function parsePositiveInt(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new PayloadError(`${label} doit être un entier positif`, 'parse');
  }
  return parsed;
}

export function parseArgon2idPrefix(prefix: string): Argon2Params {
  if (!prefix.startsWith('$')) {
    throw new PayloadError('Préfixe Argon2 invalide (doit commencer par "$")', 'parse');
  }

  const parts = prefix.split('$');
  // ['', 'argon2id', 'v=19', 'm=...,t=...,p=...', 'salt']
  if (parts[1] !== 'argon2id') {
    throw new PayloadError('KDF attendu: argon2id', 'parse');
  }

  if (!parts[2]?.startsWith('v=')) {
    throw new PayloadError('Version Argon2 manquante', 'parse');
  }
  const version = parsePositiveInt(parts[2].slice(2), 'Version Argon2');
  if (version !== 19) {
    throw new PayloadError('Version Argon2 non supportée (v=19 uniquement)', 'parse');
  }

  const paramPart = parts[3];
  if (!paramPart) {
    throw new PayloadError('Paramètres Argon2 manquants', 'parse');
  }

  const params = new Map<string, string>();
  paramPart.split(',').forEach((pair) => {
    const [k, v] = pair.split('=');
    if (k && v) params.set(k.trim(), v.trim());
  });

  const memoryCost = parsePositiveInt(params.get('m') ?? '', 'm (memory_cost)');
  const timeCost = parsePositiveInt(params.get('t') ?? '', 't (time_cost)');
  const parallelism = parsePositiveInt(params.get('p') ?? '', 'p (parallelism)');

  const saltB64 = parts[4];
  if (!saltB64) {
    throw new PayloadError('Sel (salt) manquant dans le préfixe Argon2', 'parse');
  }
  const salt = base64DecodeTolerantPadding(saltB64);
  if (salt.length === 0) {
    throw new PayloadError('Sel décodé vide', 'parse');
  }

  return {
    type: 'argon2id',
    version,
    memoryCost,
    timeCost,
    parallelism,
    salt,
  };
}

export function parsePayload(jsonInput: string): ParsedPayload {
  let raw: unknown;
  try {
    raw = JSON.parse(jsonInput);
  } catch (err) {
    throw new PayloadError('JSON invalide: impossible de parser le texte fourni', 'parse');
  }

  if (typeof raw !== 'object' || raw === null) {
    throw new PayloadError('JSON attendu au format objet', 'parse');
  }

  const obj = raw as Record<string, unknown>;

  if (obj.v !== 1) {
    throw new PayloadError('Champ v doit valoir 1', 'parse');
  }

  if (obj.c !== 'aes-256-gcm') {
    throw new PayloadError('Champ c doit valoir "aes-256-gcm"', 'parse');
  }

  const tagBits = typeof obj.t === 'string' ? Number(obj.t) : obj.t;
  if (tagBits !== 128) {
    throw new PayloadError('Champ t doit valoir 128 (tag 16 octets)', 'parse');
  }

  if (typeof obj.kdf !== 'string') {
    throw new PayloadError('Champ kdf manquant ou invalide', 'parse');
  }

  const argonParams = parseArgon2idPrefix(obj.kdf);

  const ivField = (obj as Record<string, unknown>).iv ?? (obj as Record<string, unknown>).IV;
  if (typeof ivField !== 'string') {
    throw new PayloadError('Champ iv doit être une chaîne base64', 'parse');
  }
  const iv = base64DecodeTolerantPadding(ivField);
  if (iv.length !== 16) {
    throw new PayloadError('IV doit décoder en exactement 16 octets', 'parse');
  }

  if (typeof obj.ctxt !== 'string') {
    throw new PayloadError('Champ ctxt doit être une chaîne base64', 'parse');
  }
  const ciphertext = base64DecodeTolerantPadding(obj.ctxt);
  if (ciphertext.length < 16) {
    throw new PayloadError('Ciphertext trop court (le tag GCM de 16 octets est requis)', 'parse');
  }

  return {
    version: 1,
    cipher: 'aes-256-gcm',
    tagBits: 128,
    argonParams,
    iv,
    ciphertext,
  };
}

export async function deriveKeyArgon2id(secret: string, params: Argon2Params): Promise<Uint8Array> {
  const secretBytes = new TextEncoder().encode(secret);
  try {
    const hash = await argon2idHash({
      password: secretBytes,
      salt: params.salt,
      parallelism: params.parallelism,
      iterations: params.timeCost,
      memorySize: params.memoryCost,
      hashLength: 32,
      outputType: 'binary',
    });

    // hash-wasm returns Uint8Array in binary mode
    if (hash instanceof Uint8Array) {
      return hash;
    }

    return new Uint8Array(hash as ArrayBufferLike);
  } catch (err) {
    throw new PayloadError(`Échec Argon2id: ${(err as Error).message}`, 'kdf');
  } finally {
    secretBytes.fill(0);
  }
}

export async function decryptAesGcm(keyBytes: Uint8Array, payload: ParsedPayload): Promise<Uint8Array> {
  try {
    const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: payload.iv,
        tagLength: payload.tagBits,
      },
      cryptoKey,
      payload.ciphertext,
    );
    return new Uint8Array(decrypted);
  } catch (err) {
    throw new PayloadError(`Échec du déchiffrement AES-GCM: ${(err as Error).message}`, 'decrypt');
  } finally {
    keyBytes.fill(0);
  }
}

export function utf8Decode(bytes: Uint8Array): string | null {
  try {
    return utf8FatalDecoder.decode(bytes);
  } catch (err) {
    console.warn('UTF-8 invalide, bascule vers hex/base64');
    return null;
  }
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function toBase64(bytes: Uint8Array): string {
  return base64Encode(bytes);
}

export function pickBestDisplay(bytes: Uint8Array): { mode: DisplayMode; text: string } {
  const utf8 = utf8Decode(bytes);
  if (utf8 !== null) {
    return { mode: 'utf8', text: utf8 };
  }
  return { mode: 'hex', text: toHex(bytes) };
}
