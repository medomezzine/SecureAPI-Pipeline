# Data protection

## Data stored

SQLite stores each username, a bcrypt password hash, and each note's numeric ID, owner ID, title, and encrypted content. The database file is `data/notes.db` by default (or the path in `DB_FILE`). The example Docker Compose setup persists it in the `notes-data` volume.

## How it is protected

- Passwords are hashed with bcrypt (cost 12). The original password is not stored.
- Note `content` is encrypted with AES-256-GCM before it reaches SQLite. A fresh random 12-byte nonce is used per note; the nonce, authentication tag, and ciphertext are stored together. The encryption key is read from `NOTES_ENCRYPTION_KEY` and must be 32 random bytes represented as 64 hexadecimal characters.
- Login issues a signed JWT that expires after one hour. `JWT_SECRET` signs the token. Both keys are configuration and must not be committed; `.env` is ignored by Git.
- SQL statements use placeholders, and each note query is scoped to the authenticated owner. The app does not log passwords, tokens, or note contents.

The title and identifying metadata are not encrypted. Anyone who can read the database can see usernames, note titles, IDs, and ownership. Anyone who obtains the encryption key can decrypt note content. Protect the host, database volume, and keys, and keep a secure backup of the key separate from the database. Losing the key makes encrypted notes unreadable.

## HTTPS in production

This learning app serves plain HTTP locally. A production deployment needs HTTPS terminated by a trusted reverse proxy or load balancer, a valid certificate with automated renewal, and secure forwarding configuration so the app recognizes the proxy correctly. Add HSTS after confirming HTTPS works everywhere. Keep secrets in a managed secret store, restrict database and network access, rotate keys with a planned data re-encryption process, and use encrypted backups. Do not expose this sample deployment directly to the public internet.
