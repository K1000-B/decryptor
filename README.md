# Déchiffreur JSON (Argon2id + AES-256-GCM)

Application web statique (React + Vite + TypeScript) qui déchiffre côté navigateur un JSON chiffré avec Argon2id (v=19) et AES-256-GCM, compatible avec le script Python de référence.

## Caractéristiques
- 100% client : aucune requête réseau, aucun stockage local.
- Prend en charge le payload JSON: `v=1`, `c="aes-256-gcm"`, `t=128`, `kdf="$argon2id$v=19$m=...,t=...,p=...$<salt_b64>"`, `iv` base64 (16 octets), `ctxt` base64 (ciphertext + tag 16o).
- Dérivation Argon2id paramétrable (m/t/p), clé 32 octets, déchiffrement AES-GCM (AAD vide).
- UI minimale avec affichage/masquage du secret, bouton « Coller un exemple », indicateur de progression Argon2, erreurs explicites.
- Affichage du résultat en UTF-8 quand possible, sinon hex/base64 (toggle).

## Démarrage local
```bash
npm install
npm run dev
```

## Build & tests
```bash
npm run build   # génère dist/
npm run test    # vitest (parsing base64 + préfixe Argon2)
```

## Déploiement Cloudflare Pages
- Build command : `npm run build`
- Output directory : `dist`
- Framework preset : Vite (optionnel) 
- Aucune variable d’environnement requise.

## Format attendu du payload
```json
{
  "v": 1,
  "c": "aes-256-gcm",
  "t": 128,
  "kdf": "$argon2id$v=19$m=131072,t=3,p=2$<salt_base64>",
  "iv": "<base64 iv 16 octets>",
  "ctxt": "<base64 ciphertext||tag>"
}
```

## Sécurité / UX
- Phrase secrète jamais persistée ni envoyée; effacement des buffers intermédiaires quand possible.
- Bouton « Déchiffrer » désactivé si champs vides.
- Indicateur visuel pendant Argon2.
- Zone résultat en lecture seule avec bouton « Copier ».

## Stack
- React 18, Vite 5, TypeScript strict.
- Argon2id via `hash-wasm` (WASM, compatible Pages).
- Tests unitaires avec Vitest.
