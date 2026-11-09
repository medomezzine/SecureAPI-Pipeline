process.env.JWT_SECRET = 'test-only-jwt-secret-that-is-long-enough';
process.env.NOTES_ENCRYPTION_KEY = require('node:crypto').randomBytes(32).toString('hex');
process.env.DB_FILE = ':memory:';

const request = require('supertest');
const app = require('../src/app');
const db = require('../src/db');

async function makeUser(username) {
  const password = 'correct-horse-battery';
  await request(app).post('/register').send({ username, password }).expect(201);
  const login = await request(app).post('/login').send({ username, password });
  return login.body;
}
function as(identity) {
  return identity.token ? { Authorization: `Bearer ${identity.token}` } : { 'X-User-Id': String(identity.userId) };
}

afterAll(() => db.close());

test('login returns a signed bearer token', async () => {
  const identity = await makeUser('login-user');
  expect(identity.token).toEqual(expect.any(String));
});

test('one user cannot read another user\'s note', async () => {
  const owner = await makeUser('owner-user');
  const stranger = await makeUser('stranger-user');
  const note = await request(app).post('/notes').set(as(owner)).send({ title: 'private', content: 'secret' }).expect(201);
  await request(app).get(`/notes/${note.body.id}`).set(as(stranger)).expect(404);
});

test('search treats SQL injection text as plain search text', async () => {
  const first = await makeUser('search-user');
  const second = await makeUser('other-search');
  await request(app).post('/notes').set(as(first)).send({ title: 'mine', content: 'one' }).expect(201);
  await request(app).post('/notes').set(as(second)).send({ title: 'theirs', content: 'two' }).expect(201);
  const response = await request(app).get('/search').query({ q: "' OR 1=1 --" }).set(as(first)).expect(200);
  expect(response.body).toEqual([]);
});
