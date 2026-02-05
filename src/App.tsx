import React, { useMemo, useState } from 'react';
import {
  DisplayMode,
  PayloadError,
  parsePayload,
  deriveKeyArgon2id,
  decryptAesGcm,
  pickBestDisplay,
  utf8Decode,
  toHex,
  toBase64,
} from './lib/crypto';

const examplePayload = `{
  "v": 1,
  "c": "aes-256-gcm",
  "t": 128,
  "kdf": "$argon2id$v=19$m=131072,t=3,p=2$<salt_base64>",
  "iv": "AAAAAAAAAAAAAAAAAAAAAA==",
  "ctxt": "<ciphertext_base64_incl_tag>"
}`;

function prettyError(err: unknown): string {
  if (err instanceof PayloadError) {
    return `${err.message} (étape: ${err.step})`;
  }
  if (err instanceof Error) return err.message;
  return 'Erreur inconnue';
}

function App() {
  const [secret, setSecret] = useState('');
  const [jsonInput, setJsonInput] = useState('');
  const [resultBytes, setResultBytes] = useState<Uint8Array | null>(null);
  const [displayMode, setDisplayMode] = useState<DisplayMode>('utf8');
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string>('');
  const [isBusy, setIsBusy] = useState(false);
  const [showSecret, setShowSecret] = useState(false);

  const utf8Candidate = useMemo(() => {
    if (!resultBytes) return null;
    return utf8Decode(resultBytes);
  }, [resultBytes]);

  const displayedResult = useMemo(() => {
    if (!resultBytes) return '';
    switch (displayMode) {
      case 'utf8':
        return utf8Candidate ?? '[UTF-8 invalide]';
      case 'hex':
        return toHex(resultBytes);
      case 'base64':
        return toBase64(resultBytes);
      default:
        return '';
    }
  }, [displayMode, resultBytes, utf8Candidate]);

  const canSubmit = secret.trim().length > 0 && jsonInput.trim().length > 0 && !isBusy;

  async function handleDecrypt() {
    setError(null);
    setResultBytes(null);
    setStatus('');
    try {
      setIsBusy(true);
      setStatus('Dérivation Argon2id…');
      const payload = parsePayload(jsonInput);
      const key = await deriveKeyArgon2id(secret, payload.argonParams);
      setStatus('Déchiffrement AES-GCM…');
      const plaintext = await decryptAesGcm(key, payload);
      const { mode } = pickBestDisplay(plaintext);
      setDisplayMode(mode);
      setResultBytes(plaintext);
      setStatus('Terminé');
    } catch (err) {
      setError(prettyError(err));
      setStatus('');
    } finally {
      setIsBusy(false);
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (canSubmit) {
      void handleDecrypt();
    }
  };

  const copyToClipboard = async () => {
    if (!displayedResult) return;
    try {
      await navigator.clipboard.writeText(displayedResult);
      setStatus('Résultat copié');
    } catch (err) {
      setError('Impossible de copier dans le presse-papiers');
    }
  };

  const pasteExample = () => {
    setJsonInput(examplePayload);
    setStatus('Exemple collé');
  };

  const toggleSecretVisibility = () => setShowSecret((prev) => !prev);

  return (
    <div className="page">
      <header className="header">
        <div>
          <p className="eyebrow">Argon2id + AES-256-GCM</p>
          <h1>Déchiffrer un JSON chiffré</h1>
          <p className="lead">
            Tout se passe dans votre navigateur : aucune donnée n’est envoyée. Compatible avec le script Python
            (Argon2id v=19, m/t/p paramétrables, IV 16 octets, AES-GCM tag 128 bits).
          </p>
        </div>
        <div className="status-block">
          {isBusy ? (
            <div className="spinner" aria-live="polite" aria-busy="true" />
          ) : (
            <div className="dot" aria-hidden />
          )}
          <span className="status-text">{status || 'Prêt'}</span>
        </div>
      </header>

      <main className="card" aria-live="polite">
        <form onSubmit={handleSubmit} className="form-grid">
          <div className="field">
            <label htmlFor="secret">Phrase secrète</label>
            <div className="secret-input">
              <input
                id="secret"
                type={showSecret ? 'text' : 'password'}
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                placeholder="Saisir la phrase secrète"
                autoComplete="off"
                spellCheck={false}
              />
              <button type="button" className="ghost" onClick={toggleSecretVisibility} aria-label="Afficher/masquer">
                {showSecret ? 'Masquer' : 'Afficher'}
              </button>
            </div>
          </div>

          <div className="field">
            <label htmlFor="json">JSON à déchiffrer</label>
            <textarea
              id="json"
              value={jsonInput}
              onChange={(e) => setJsonInput(e.target.value)}
              placeholder="Collez le JSON chiffré ici"
              rows={8}
            />
            <div className="actions-row">
              <button type="button" className="ghost" onClick={pasteExample} disabled={isBusy}>
                Coller un exemple
              </button>
              <button type="submit" className="primary" disabled={!canSubmit}>
                {isBusy ? 'En cours…' : 'Déchiffrer'}
              </button>
            </div>
          </div>

          {error && (
            <div className="alert" role="alert">
              <strong>Erreur :</strong> {error}
            </div>
          )}

          <div className="field">
            <div className="result-header">
              <label htmlFor="result">Résultat</label>
              <div className="mode-toggle" role="group" aria-label="Format du résultat">
                <button
                  type="button"
                  className={displayMode === 'utf8' ? 'chip active' : 'chip'}
                  onClick={() => setDisplayMode('utf8')}
                  disabled={!utf8Candidate}
                >
                  UTF-8
                </button>
                <button
                  type="button"
                  className={displayMode === 'hex' ? 'chip active' : 'chip'}
                  onClick={() => setDisplayMode('hex')}
                >
                  Hex
                </button>
                <button
                  type="button"
                  className={displayMode === 'base64' ? 'chip active' : 'chip'}
                  onClick={() => setDisplayMode('base64')}
                >
                  Base64
                </button>
              </div>
            </div>
            <textarea
              id="result"
              value={displayedResult}
              readOnly
              rows={8}
              placeholder="Le texte déchiffré apparaîtra ici"
            />
            <div className="actions-row">
              <button type="button" className="ghost" onClick={copyToClipboard} disabled={!displayedResult}>
                Copier
              </button>
              <span className="muted">Aucune donnée n’est conservée.</span>
            </div>
          </div>
        </form>
      </main>
    </div>
  );
}

export default App;
