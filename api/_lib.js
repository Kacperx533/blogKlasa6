const crypto = require('node:crypto');
const { neon } = require('@neondatabase/serverless');

const SESSION_COOKIE = 'class_session';
const SESSION_DAYS = 7;
const LOGIN_PATTERN = /^[A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż0-9._-]+$/;
let schemaPromise;

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function fail(status, message) { throw new HttpError(status, message); }
function text(value, max = 5000) { return String(value || '').trim().slice(0, max); }
function id(prefix) { return `${prefix}_${crypto.randomBytes(12).toString('hex')}`; }
function code() { return `KLASA-${crypto.randomBytes(5).toString('hex').toUpperCase()}`; }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.pbkdf2Sync(password, salt, 180000, 32, 'sha256').toString('hex') };
}
function matchesPassword(password, user) {
  const salt = user?.password_salt || '4e87b89e20344bf3a753df8b12ea62ef';
  const actual = crypto.pbkdf2Sync(String(password || ''), salt, 180000, 32, 'sha256');
  if (!user) return false;
  const expected = Buffer.from(user.password_hash, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
function sqlClient() {
  if (!process.env.DATABASE_URL) fail(503, 'Dodaj DATABASE_URL po podłączeniu bazy Neon w Vercel.');
  return neon(process.env.DATABASE_URL);
}

async function initialize(sql) {
  await sql`CREATE TABLE IF NOT EXISTS kz_users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    login TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'teacher', 'student')),
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'pending')),
    invite_code TEXT UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ
  )`;
  await sql`CREATE TABLE IF NOT EXISTS kz_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES kz_users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
  )`;
  await sql`CREATE TABLE IF NOT EXISTS kz_invites (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    login TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('teacher', 'student')),
    code TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS kz_posts (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    author TEXT NOT NULL,
    tag TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS kz_events (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    event_date DATE NOT NULL,
    event_time TEXT NOT NULL DEFAULT '',
    place TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT ''
  )`;
  await sql`CREATE TABLE IF NOT EXISTS kz_materials (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    icon TEXT NOT NULL DEFAULT '📄',
    url TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;
  await sql`ALTER TABLE kz_materials ADD COLUMN IF NOT EXISTS file_name TEXT`;
  await sql`ALTER TABLE kz_materials ADD COLUMN IF NOT EXISTS file_type TEXT`;
  await sql`ALTER TABLE kz_materials ADD COLUMN IF NOT EXISTS file_data TEXT`;

  const admins = await sql`SELECT id FROM kz_users WHERE role = 'admin' LIMIT 1`;
  if (admins.length) return;
  const login = text(process.env.ADMIN_LOGIN || 'admin', 40).toLowerCase();
  const password = process.env.ADMIN_PASSWORD || '';
  if (!LOGIN_PATTERN.test(login)) fail(500, 'ADMIN_LOGIN może zawierać litery (także polskie), cyfry, kropkę, myślnik i podkreślenie.');
  if (password.length < 12) fail(503, 'Ustaw ADMIN_PASSWORD (co najmniej 12 znaków) w ustawieniach projektu Vercel.');
  const existing = await sql`SELECT id FROM kz_users WHERE lower(login) = ${login} LIMIT 1`;
  if (existing.length) fail(409, 'ADMIN_LOGIN jest już używany w bazie. Ustaw inny login administratora.');
  const { salt, hash } = hashPassword(password);
  await sql`INSERT INTO kz_users (id, name, login, role, password_salt, password_hash, status)
    VALUES ('admin', 'Administrator klasy', ${login}, 'admin', ${salt}, ${hash}, 'active')
    ON CONFLICT (login) DO NOTHING`;
}

async function database() {
  const sql = sqlClient();
  if (!schemaPromise) schemaPromise = initialize(sql);
  try { await schemaPromise; }
  catch (error) { schemaPromise = null; throw error; }
  return sql;
}

function send(res, status, body, headers = {}) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  for (const [key, value] of Object.entries(headers)) res.setHeader(key, value);
  res.end(JSON.stringify(body));
}

function readBody(req) {
  if (req.body && typeof req.body === 'object') return Promise.resolve(req.body);
  if (typeof req.body === 'string') {
    try { return Promise.resolve(JSON.parse(req.body)); } catch { return Promise.resolve({}); }
  }
  return new Promise(resolve => {
    let raw = '';
    req.on('data', part => { raw += part; });
    req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}

function sessionToken(req) {
  const cookie = req.headers.cookie || '';
  const entry = cookie.split(';').map(value => value.trim()).find(value => value.startsWith(`${SESSION_COOKIE}=`));
  return entry ? entry.slice(SESSION_COOKIE.length + 1) : '';
}

async function getUser(sql, req) {
  const token = sessionToken(req);
  if (!token || !/^[A-Za-z0-9_-]{40,60}$/.test(token)) return null;
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const rows = await sql`SELECT u.id, u.name, u.login, u.role
    FROM kz_sessions s JOIN kz_users u ON u.id = s.user_id
    WHERE s.token_hash = ${tokenHash} AND s.expires_at > now() AND u.status = 'active'
    LIMIT 1`;
  return rows[0] || null;
}

async function setSession(sql, user, res) {
  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const expiry = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  await sql`INSERT INTO kz_sessions (token_hash, user_id, expires_at) VALUES (${tokenHash}, ${user.id}, ${expiry})`;
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_DAYS * 24 * 60 * 60}`);
}

async function state(sql, user) {
  if (!user) return { users: [], posts: [], events: [], materials: [], invites: [] };
  const inviteQuery = user.role === 'admin'
    ? sql`SELECT i.name, i.login, i.role, i.code, i.status, i.created_at AS "createdAt", u.id AS "userId"
      FROM kz_invites i LEFT JOIN kz_users u ON lower(u.login) = lower(i.login) ORDER BY i.created_at DESC`
    : Promise.resolve([]);
  const [users, posts, events, materials, invites] = await Promise.all([
    sql`SELECT id, name, login, role, status FROM kz_users ORDER BY name`,
    sql`SELECT id, title, body, author, tag, to_char(created_at AT TIME ZONE 'Europe/Warsaw', 'YYYY-MM-DD') AS date FROM kz_posts ORDER BY created_at DESC`,
    sql`SELECT id, title, to_char(event_date, 'YYYY-MM-DD') AS date, event_time AS time, place, description AS desc FROM kz_events ORDER BY event_date, event_time`,
    sql`SELECT id, title, description, icon, url, file_name AS "fileName", file_type AS "fileType" FROM kz_materials ORDER BY created_at DESC`,
    inviteQuery
  ]);
  return { users, posts, events, materials, invites };
}

async function handle(action, req, res) {
  try {
    const sql = await database();
    if (action === 'state') {
      if (req.method !== 'GET') return send(res, 405, { error: 'Ta czynność nie jest dostępna.' });
      const user = await getUser(sql, req);
      return send(res, 200, { db: await state(sql, user), user });
    }
    if (action === 'material-file') {
      if (req.method !== 'GET') return send(res, 405, { error: 'Ta czynność nie jest dostępna.' });
      const user = await getUser(sql, req);
      if (!user) fail(401, 'Zaloguj się, aby pobrać materiał.');
      const fileId = text(req.query?.id || new URL(req.url, 'https://app.invalid').searchParams.get('id'), 80);
      if (!fileId) fail(400, 'Nie wskazano pliku.');
      const rows = await sql`SELECT file_name, file_type, file_data FROM kz_materials WHERE id = ${fileId} LIMIT 1`;
      const file = rows[0];
      if (!file?.file_data) fail(404, 'Nie znaleziono pliku.');
      const bytes = Buffer.from(file.file_data, 'base64');
      const filename = String(file.file_name || 'material').replace(/[\r\n"\\]/g, '_');
      res.statusCode = 200;
      res.setHeader('Content-Type', file.file_type || 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
      res.setHeader('Content-Length', String(bytes.length));
      res.setHeader('Cache-Control', 'private, no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      return res.end(bytes);
    }
    if (req.method !== 'POST') return send(res, 405, { error: 'Ta czynność nie jest dostępna.' });
    const body = await readBody(req);

    if (action === 'login') {
      const login = text(body.login, 40).toLowerCase();
      const rows = LOGIN_PATTERN.test(login)
        ? await sql`SELECT * FROM kz_users WHERE lower(login) = ${login} AND status = 'active' LIMIT 1`
        : [];
      if (!matchesPassword(body.password, rows[0])) fail(401, 'Niepoprawny login lub hasło. Sprawdź dane i spróbuj ponownie.');
      await setSession(sql, rows[0], res);
      return send(res, 200, { user: { id: rows[0].id, name: rows[0].name, login: rows[0].login, role: rows[0].role } });
    }

    if (action === 'activate') {
      const login = text(body.login, 40).toLowerCase();
      const activationCode = text(body.code, 32).toUpperCase();
      const rows = await sql`SELECT * FROM kz_users WHERE lower(login) = ${login} AND invite_code = ${activationCode} AND status = 'pending' LIMIT 1`;
      const user = rows[0];
      if (!user) fail(400, 'Nie znaleźliśmy takiego zaproszenia. Sprawdź login i kod.');
      if (typeof body.password !== 'string' || body.password.length < 8) fail(400, 'Hasło musi mieć co najmniej 8 znaków.');
      const { salt, hash } = hashPassword(body.password);
      await sql`UPDATE kz_users SET password_salt = ${salt}, password_hash = ${hash}, status = 'active', invite_code = NULL, activated_at = now() WHERE id = ${user.id}`;
      await sql`UPDATE kz_invites SET status = 'used' WHERE code = ${activationCode}`;
      await setSession(sql, user, res);
      return send(res, 200, { user: { id: user.id, name: user.name, login: user.login, role: user.role } });
    }

    if (action === 'logout') {
      const token = sessionToken(req);
      if (token) {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        await sql`DELETE FROM kz_sessions WHERE token_hash = ${tokenHash}`;
      }
      return send(res, 200, { ok: true }, { 'Set-Cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0` });
    }

    const user = await getUser(sql, req);
    if (!user) fail(401, 'Zaloguj się, aby wykonać tę czynność.');

    if (action === 'change-password') {
      const rows = await sql`SELECT * FROM kz_users WHERE id = ${user.id} LIMIT 1`;
      if (!matchesPassword(body.currentPassword, rows[0])) fail(400, 'Obecne hasło jest nieprawidłowe.');
      if (typeof body.newPassword !== 'string' || body.newPassword.length < 8) fail(400, 'Nowe hasło musi mieć co najmniej 8 znaków.');
      const { salt, hash } = hashPassword(body.newPassword);
      await sql`UPDATE kz_users SET password_salt = ${salt}, password_hash = ${hash} WHERE id = ${user.id}`;
      return send(res, 200, { ok: true });
    }

    if (action === 'accounts') {
      if (user.role !== 'admin') fail(403, 'Tylko administrator może tworzyć konta.');
      const name = text(body.name, 100);
      const login = text(body.login, 40).toLowerCase();
      const role = body.role;
      if (!name || !LOGIN_PATTERN.test(login) || !['teacher', 'student'].includes(role)) fail(400, 'Sprawdź imię, login i rolę. Login może zawierać litery (także polskie), cyfry, kropkę, myślnik i podkreślenie.');
      const collision = await sql`SELECT id FROM kz_users WHERE lower(login) = ${login} LIMIT 1`;
      if (collision.length) fail(409, 'Konto z tym loginem już istnieje.');
      const activationCode = code();
      const { salt, hash } = hashPassword(crypto.randomBytes(32).toString('hex'));
      const userId = id('user');
      const inviteId = id('invite');
      await sql`INSERT INTO kz_users (id, name, login, role, password_salt, password_hash, status, invite_code)
        VALUES (${userId}, ${name}, ${login}, ${role}, ${salt}, ${hash}, 'pending', ${activationCode})`;
      await sql`INSERT INTO kz_invites (id, name, login, role, code, status) VALUES (${inviteId}, ${name}, ${login}, ${role}, ${activationCode}, 'pending')`;
      return send(res, 201, { code: activationCode });
    }

    if (action === 'update-account') {
      if (user.role !== 'admin') fail(403, 'Tylko administrator może edytować konta.');
      const userId = text(body.userId, 80);
      const name = text(body.name, 100);
      const login = text(body.login, 40).toLowerCase();
      if (!userId || !name || !LOGIN_PATTERN.test(login)) fail(400, 'Sprawdź imię i login. Login może zawierać litery (także polskie), cyfry, kropkę, myślnik i podkreślenie.');
      const targetRows = await sql`SELECT id, login, role FROM kz_users WHERE id = ${userId} LIMIT 1`;
      const target = targetRows[0];
      if (!target || target.role === 'admin') fail(404, 'Nie znaleziono konta do edycji.');
      const collision = await sql`SELECT id FROM kz_users WHERE lower(login) = ${login} AND id <> ${userId} LIMIT 1`;
      if (collision.length) fail(409, 'Konto z tym loginem już istnieje.');
      await sql`UPDATE kz_users SET name = ${name}, login = ${login} WHERE id = ${userId}`;
      await sql`UPDATE kz_invites SET name = ${name}, login = ${login} WHERE lower(login) = ${target.login}`;
      return send(res, 200, { ok: true });
    }

    if (action === 'delete-account') {
      if (user.role !== 'admin') fail(403, 'Tylko administrator może usuwać konta.');
      const userId = text(body.userId, 80);
      if (!userId) fail(400, 'Nie wskazano konta do usunięcia.');
      const targetRows = await sql`SELECT id, login, role FROM kz_users WHERE id = ${userId} LIMIT 1`;
      const target = targetRows[0];
      if (!target || target.role === 'admin') fail(404, 'Nie znaleziono konta do usunięcia.');
      const deleted = await sql`WITH target AS (
          SELECT id, login FROM kz_users WHERE id = ${userId} AND role IN ('student', 'teacher')
        ), deleted_invites AS (
          DELETE FROM kz_invites i USING target t WHERE lower(i.login) = lower(t.login) RETURNING i.id
        )
        DELETE FROM kz_users u USING target t WHERE u.id = t.id RETURNING u.id`;
      if (!deleted.length) fail(404, 'Nie znaleziono konta do usunięcia.');
      return send(res, 200, { ok: true });
    }

    if (action === 'delete-post') {
      if (!['admin', 'teacher'].includes(user.role)) fail(403, 'Tylko nauczyciele i administrator mogą usuwać ogłoszenia.');
      const postId = text(body.id, 80);
      if (!postId) fail(400, 'Nie wskazano ogłoszenia do usunięcia.');
      const deleted = await sql`DELETE FROM kz_posts WHERE id = ${postId} RETURNING id`;
      if (!deleted.length) fail(404, 'Nie znaleziono ogłoszenia.');
      return send(res, 200, { ok: true });
    }

    if (action === 'delete-material') {
      if (!['admin', 'teacher'].includes(user.role)) fail(403, 'Tylko nauczyciele i administrator mogą usuwać materiały.');
      const materialId = text(body.id, 80);
      if (!materialId) fail(400, 'Nie wskazano materiału do usunięcia.');
      const deleted = await sql`DELETE FROM kz_materials WHERE id = ${materialId} RETURNING id`;
      if (!deleted.length) fail(404, 'Nie znaleziono materiału.');
      return send(res, 200, { ok: true });
    }

    if (action === 'delete-event') {
      if (!['admin', 'teacher'].includes(user.role)) fail(403, 'Tylko nauczyciele i administrator mogą usuwać wydarzenia.');
      const eventId = text(body.id, 80);
      if (!eventId) fail(400, 'Nie wskazano wydarzenia do usunięcia.');
      const deleted = await sql`DELETE FROM kz_events WHERE id = ${eventId} RETURNING id`;
      if (!deleted.length) fail(404, 'Nie znaleziono wydarzenia.');
      return send(res, 200, { ok: true });
    }

    if (!['admin', 'teacher'].includes(user.role)) fail(403, 'Tylko nauczyciele mogą publikować treści.');
    if (action === 'posts') {
      const title = text(body.title, 160), content = text(body.body, 5000), tag = text(body.tag, 40) || 'Aktualność';
      if (!title || !content) fail(400, 'Wpisz tytuł i treść ogłoszenia.');
      await sql`INSERT INTO kz_posts (id, title, body, author, tag) VALUES (${id('post')}, ${title}, ${content}, ${user.name}, ${tag})`;
      return send(res, 201, { ok: true });
    }
    if (action === 'events') {
      const title = text(body.title, 160), eventDate = text(body.date, 10);
      if (!title || !/^\d{4}-\d{2}-\d{2}$/.test(eventDate)) fail(400, 'Wpisz nazwę i prawidłową datę wydarzenia.');
      await sql`INSERT INTO kz_events (id, title, event_date, event_time, place) VALUES (${id('event')}, ${title}, ${eventDate}, ${text(body.time, 10)}, ${text(body.place, 100)})`;
      return send(res, 201, { ok: true });
    }
    if (action === 'update-event') {
      if (!['admin', 'teacher'].includes(user.role)) fail(403, 'Tylko nauczyciele i administrator mogą edytować wydarzenia.');
      const eventId = text(body.id, 80), title = text(body.title, 160), eventDate = text(body.date, 10);
      const parsedDate = new Date(`${eventDate}T00:00:00Z`);
      if (!eventId || !title || !/^\d{4}-\d{2}-\d{2}$/.test(eventDate) || Number.isNaN(parsedDate.valueOf()) || parsedDate.toISOString().slice(0, 10) !== eventDate) fail(400, 'Wpisz nazwę i prawidłową datę wydarzenia.');
      const updated = await sql`UPDATE kz_events SET title = ${title}, event_date = ${eventDate}, event_time = ${text(body.time, 10)}, place = ${text(body.place, 100)} WHERE id = ${eventId} RETURNING id`;
      if (!updated.length) fail(404, 'Nie znaleziono wydarzenia.');
      return send(res, 200, { ok: true });
    }
    if (action === 'materials') {
      const title = text(body.title, 160), description = text(body.description, 300), materialUrl = text(body.url, 2000);
      const fileName = text(body.fileName, 180), fileType = text(body.fileType, 120), fileData = typeof body.fileData === 'string' ? body.fileData : '';
      let validUrl = false;
      try { const parsed = new URL(materialUrl); validUrl = ['http:', 'https:'].includes(parsed.protocol); } catch {}
      const hasFile = Boolean(fileData || fileName || fileType);
      if (!title || (validUrl === hasFile)) fail(400, 'Dodaj link albo wybierz plik.');
      let bytes = null;
      if (hasFile) {
        const allowedTypes = new Set(['application/pdf','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','application/vnd.ms-powerpoint','application/vnd.openxmlformats-officedocument.presentationml.presentation','text/plain','text/csv','image/jpeg','image/png','image/gif','image/webp']);
        if (!fileName || !fileData || !allowedTypes.has(fileType) || fileData.length > 2800000 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(fileData)) fail(400, 'Wybierz obsługiwany plik (PDF, dokument, arkusz, prezentacja, tekst lub obraz) do 2 MB.');
        bytes = Buffer.from(fileData, 'base64');
        if (!bytes.length || bytes.length > 2 * 1024 * 1024 || bytes.toString('base64') !== fileData) fail(400, 'Plik jest pusty, uszkodzony lub przekracza limit 2 MB.');
      }
      await sql`INSERT INTO kz_materials (id, title, description, icon, url, file_name, file_type, file_data) VALUES (${id('material')}, ${title}, ${description}, ${text(body.icon, 8) || '📄'}, ${validUrl ? materialUrl : ''}, ${hasFile ? fileName : null}, ${hasFile ? fileType : null}, ${hasFile ? fileData : null})`;
      return send(res, 201, { ok: true });
    }
    return send(res, 404, { error: 'Nie znaleziono tej funkcji.' });
  } catch (error) {
    return send(res, error.status || 500, { error: error.status ? error.message : 'Błąd serwera. Sprawdź konfigurację bazy danych w Vercel.' });
  }
}

function createHandler(action) { return (req, res) => handle(action, req, res); }
module.exports = { createHandler };
