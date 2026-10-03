# Running & recovery dashboard

Static dashboard served by GitHub Pages. The data file `data/dashboard.enc.json` is encrypted
(AES-256-GCM, key derived with PBKDF2-SHA256, 600 000 iterations) and is decrypted only in the
viewer's browser after entering the passphrase. No unencrypted personal data is stored in this
repository.
