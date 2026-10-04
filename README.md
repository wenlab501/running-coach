# 我的個人化 AI 跑步教練

Static site served by GitHub Pages with four tabs: dashboard, data interpretation, coach
advice, and methods. The data file `data/dashboard.enc.json` is encrypted (AES-256-GCM, key
derived with PBKDF2-SHA256, 600 000 iterations) and is decrypted only in the viewer's browser
after entering the passphrase. No unencrypted personal data is stored in this repository.
