# Security audit: `vulnerable` branch

This is a deliberately small, local-only training audit. Use two dummy users and dummy notes. Do not expose the app to a network or use real credentials. Commands below assume the app is running at `http://localhost:3000`; the `vulnerable` branch has no JWT and accepts the login-returned `X-User-Id` header.

## 1. SQL injection in search

- **OWASP:** A03 Injection
- **Severity:** High
- **Affected endpoint:** `GET /search?q=`
- **Reproduce:** Log in as a dummy user and copy its `userId`. Create notes for two users. Then request `curl -i -H 'X-User-Id: 1' 'http://localhost:3000/search?q=%27%20OR%201%3D1%20--'`. The concatenated condition can return rows outside the intended title match and owner scope.
- **Impact:** A caller can alter the SQL condition and expose notes belonging to other users.
- **Fix on `main`:** Bind the search phrase and owner ID as SQL parameters.

Before:

```js
db.prepare(`SELECT ... WHERE owner_id = ${req.userId} AND title LIKE '%${req.query.q}%'`).all();
```

After:

```js
db.prepare('SELECT ... WHERE owner_id = ? AND title LIKE ?')
  .all(req.user.id, `%${req.validatedQuery.q}%`);
```

## 2. Note ID access without ownership check

- **OWASP:** A01 Broken Access Control
- **Severity:** High
- **Affected endpoints:** `GET /notes/:id`, `DELETE /notes/:id`
- **Reproduce:** User A creates a note and records its ID. Log in as user B, then run `curl -i -H 'X-User-Id: 2' http://localhost:3000/notes/1`. The vulnerable route returns user A's note. `curl -i -X DELETE -H 'X-User-Id: 2' http://localhost:3000/notes/1` can delete it.
- **Impact:** Any logged-in user who guesses an ID can read or remove another user's private note.
- **Fix on `main`:** Include the authenticated owner ID in both read and delete conditions; return 404 when no owned record matches.

Before:

```js
db.prepare('SELECT ... FROM notes WHERE id = ?').get(req.params.id);
db.prepare('DELETE FROM notes WHERE id = ?').run(req.params.id);
```

After:

```js
db.prepare('SELECT ... FROM notes WHERE id = ? AND owner_id = ?').get(req.params.id, req.user.id);
db.prepare('DELETE FROM notes WHERE id = ? AND owner_id = ?').run(req.params.id, req.user.id);
```

## 3. Unsalted MD5 password hashes

- **OWASP:** A02 Cryptographic Failures
- **Severity:** High
- **Affected endpoints:** `POST /register`, `POST /login`
- **Reproduce:** Register a dummy user with `curl -i -H 'Content-Type: application/json' -d '{"username":"alice","password":"demo-password"}' http://localhost:3000/register`, then log in with the same dummy credentials using `curl -i -H 'Content-Type: application/json' -d '{"username":"alice","password":"demo-password"}' http://localhost:3000/login`. The HTTP flow confirms password-based authentication; the vulnerable registration code stores the password as a fast, unsalted MD5 digest. The API intentionally does not reveal its stored hash.
- **Impact:** A copied database permits fast offline guessing; identical passwords create identical stored digests.
- **Fix on `main`:** Store and verify bcrypt hashes with a work factor.

Before:

```js
crypto.createHash('md5').update(password).digest('hex');
```

After:

```js
bcrypt.hashSync(password, 12);
bcrypt.compareSync(password, user.password_hash);
```

## 4. Stored cross-site scripting in the demo page

- **OWASP:** A03 Injection
- **Severity:** High
- **Affected endpoint:** `POST /notes` (stored value); browser view at `/`
- **Reproduce:** Create a dummy note with `curl -i -H 'X-User-Id: 1' -H 'Content-Type: application/json' -d '{"title":"demo","content":"<img src=x onerror=alert(1)>"}' http://localhost:3000/notes`. Open `http://localhost:3000`, enter user ID `1`, and load notes. The vulnerable page puts stored content into `innerHTML`, so the browser interprets it as markup.
- **Impact:** A malicious note can run script in another viewer's browser context when shown.
- **Fix on `main`:** Render user-controlled text with DOM `textContent`; Helmet supplies a Content-Security-Policy as an additional layer.

Before:

```js
list.innerHTML = notes.map(note => `<li>${note.content}</li>`).join('');
```

After:

```js
item.textContent = `${note.title}: ${note.content}`;
list.append(item);
```

