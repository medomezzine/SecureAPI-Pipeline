# SecureAPI-Pipeline

A small notes API for learning how OWASP risk analysis, a local security audit, and a DevSecOps pipeline fit together. It uses Node.js, Express, SQLite, and one plain HTML page.

> **Warning:** The `vulnerable` branch intentionally contains security flaws. Run it only on your own computer with local test data. Never deploy it, expose it to a network, or use real passwords or notes.

## Quick start (`main`)

Use Node.js 22 or later and Docker Compose. Make a local environment file and replace both example values:

```sh
cp .env.example .env
node -e "const c=require('node:crypto'); console.log('JWT_SECRET='+c.randomBytes(32).toString('hex')); console.log('NOTES_ENCRYPTION_KEY='+c.randomBytes(32).toString('hex'))"
```

On PowerShell, use `Copy-Item .env.example .env` for the first command. Copy each generated line into `.env`, replacing its matching placeholder. The encryption key must be 64 hexadecimal characters.

Run with Docker:

```sh
docker compose up --build
```

Or run with Node:

```sh
npm install
npm start
```

Open <http://localhost:3000>. The API listens on port 3000. Register and log in using curl (the returned token is used as a bearer token):

```sh
curl -i -H 'Content-Type: application/json' -d '{"username":"alice","password":"a-long-demo-password"}' http://localhost:3000/register
curl -s -H 'Content-Type: application/json' -d '{"username":"alice","password":"a-long-demo-password"}' http://localhost:3000/login
curl -i -H 'Authorization: Bearer PASTE_TOKEN' -H 'Content-Type: application/json' -d '{"title":"first","content":"private text"}' http://localhost:3000/notes # gitleaks:allow (placeholder only)
curl -i -H 'Authorization: Bearer PASTE_TOKEN' http://localhost:3000/notes # gitleaks:allow (placeholder only)
curl -i -H 'Authorization: Bearer PASTE_TOKEN' 'http://localhost:3000/search?q=first' # gitleaks:allow (placeholder only)
```

Use `GET /notes/:id` to read one note and `DELETE /notes/:id` to delete it. Every note route requires `Authorization: Bearer <token>` and scopes access to the logged-in user.

## Branches

- `main` is the fixed version: JWTs, bcrypt password hashes, ownership checks, input validation, parameterized queries, output-safe page rendering, and encrypted note content.
- `vulnerable` is a deliberately flawed local training version with the four findings in the audit report. It also uses JWT authentication so the access-control exercise stays focused on checking note ownership. It is not an alternate deployable app.

Switch versions with `git switch main` or `git switch vulnerable`. Each branch contains the CI workflow. The CI tests and security rules are expected to fail on `vulnerable`; that failure is the teaching demo. They should pass on `main` (tool databases and third-party service availability can affect external scanners).

## DevSecOps checks

GitHub Actions runs on every push and pull request. See [docs/devsecops.md](docs/devsecops.md) for the diagram and artifact details.

- Lint and Jest/supertest checks catch broken syntax and regressions in login, ownership, and SQL injection handling.
- Gitleaks looks for committed credentials.
- Semgrep checks JavaScript against community Node.js and OWASP Top 10 rules.
- `npm audit` checks packages, while Trivy scans the built Docker image for high and critical findings.
- OWASP ZAP baseline crawls the locally started app for common web security signals.

Each stage uploads a report artifact where the scanner produces one. CI uses only free community rules and tunes dependency/image severity to high and critical to avoid failing on low-impact advisory noise. The regression tests still exercise the search injection payload.

## What I learned

- TODO: What did I learn about access control?
- TODO: Which pipeline finding was most useful?
- TODO: What would I improve before a real deployment?

More detail: [threat model](docs/threat-model.md), [security audit](docs/security-audit.md), and [data protection](docs/data-protection.md).
