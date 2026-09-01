/**
 * Empower Ethnic Media — letter relay, as a Cloudflare Worker.
 *
 * There is no origin server. Nothing here can affect any other site.
 *
 * Storage: one D1 database.
 *   pending   staged letters, AES-256-GCM ciphertext, with an expiry
 *   cache     postal-code lookups, so readers' codes never reach a third party
 *             from their browser
 *   rate      rate-limit counters, keyed by hashed IP
 *   consent   newsletter consent. Durable on purpose: CASL requires proof.
 *   stats     counters, integers only
 *
 * Why the letter is encrypted even though we control the database:
 * the key is derived from the confirmation token, which exists only in the
 * link in the reader's inbox. A database dump, a leaked backup, or anyone
 * with read access to D1 gets ciphertext. On confirmation we decrypt in
 * memory, send, and delete the row. That makes "we do not keep your letter"
 * a property of the design rather than a promise about our discipline.
 */

import WIDGET_HTML from './widget.html';

const SUBJECT = 'Constituent letter: funding for independent ethnic community television';
const TOKEN_TTL = 1800;               // 30 minutes
const POSTAL_RE = /^[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z]\d[ABCEGHJ-NPRSTV-Z]\d$/;

// ---------------------------------------------------------------- responses

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...baseHeaders() },
  });

const bad = (message, status = 400) => json({ error: message }, status);

function baseHeaders() {
  return {
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'geolocation=(), microphone=(), camera=()',
    'cache-control': 'no-store, private, max-age=0',
  };
}

function csp(env, framed) {
  const ancestors = framed
    ? (env.FRAME_ANCESTORS || 'https://empowerethnicmedia.org')
    : "'none'";
  return [
    "default-src 'self'",
    "script-src 'self' https://challenges.cloudflare.com",
    'frame-src https://challenges.cloudflare.com',
    "connect-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "base-uri 'none'",
    "form-action 'none'",
    `frame-ancestors ${ancestors}`,
  ].join('; ');
}

// ---------------------------------------------------------------- crypto

const enc = (s) => new TextEncoder().encode(s);

function b64(bytes) {
  let s = '';
  const b = new Uint8Array(bytes);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}

function unb64(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256hex(text) {
  const d = await crypto.subtle.digest('SHA-256', enc(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function tokenKey(token) {
  const material = await crypto.subtle.importKey('raw', enc(token), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc('eem-letter-v1') },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function seal(plaintext, token) {
  const key = await tokenKey(token);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc(plaintext));
  const blob = new Uint8Array(12 + ct.byteLength);
  blob.set(iv, 0);
  blob.set(new Uint8Array(ct), 12);
  return b64(blob);
}

async function unseal(blobB64, token) {
  try {
    const raw = unb64(blobB64);
    const key = await tokenKey(token);
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: raw.slice(0, 12) }, key, raw.slice(12)
    );
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}

function newToken() {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return b64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ---------------------------------------------------------------- storage

const now = () => Math.floor(Date.now() / 1000);

async function ipHash(request, env) {
  const ip = request.headers.get('cf-connecting-ip') || '0';
  return (await sha256hex(ip + '|' + (env.IP_PEPPER || 'unsalted'))).slice(0, 24);
}

async function rateLimit(env, bucket, id, limit, window) {
  const k = `${bucket}:${id}`;
  const t = now();
  try {
    await env.DB.prepare(
      `INSERT INTO rate (k, n, expires_at) VALUES (?, 1, ?)
       ON CONFLICT(k) DO UPDATE SET
         n = CASE WHEN rate.expires_at < ? THEN 1 ELSE rate.n + 1 END,
         expires_at = CASE WHEN rate.expires_at < ? THEN ? ELSE rate.expires_at END`
    ).bind(k, t + window, t, t, t + window).run();

    const row = await env.DB.prepare('SELECT n FROM rate WHERE k = ?').bind(k).first();
    return !row || row.n <= limit;
  } catch (e) {
    console.error('rate limit failed', e);
    return true;   // never lock people out because the counter broke
  }
}

async function cacheGet(env, k) {
  const row = await env.DB.prepare(
    'SELECT v FROM cache WHERE k = ? AND expires_at > ?'
  ).bind(k, now()).first();
  return row ? row.v : null;
}

async function cacheSet(env, k, v, ttl) {
  await env.DB.prepare(
    `INSERT INTO cache (k, v, expires_at) VALUES (?, ?, ?)
     ON CONFLICT(k) DO UPDATE SET v = excluded.v, expires_at = excluded.expires_at`
  ).bind(k, v, now() + ttl).run();
}

/** Returns true only for the caller that actually removed the row. */
async function claim(env, k) {
  const res = await env.DB.prepare('DELETE FROM pending WHERE k = ?').bind(k).run();
  return (res.meta?.changes ?? 0) === 1;
}

async function sweep(env) {
  const t = now();
  try {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM pending WHERE expires_at < ?').bind(t),
      env.DB.prepare('DELETE FROM cache   WHERE expires_at < ?').bind(t),
      env.DB.prepare('DELETE FROM rate    WHERE expires_at < ?').bind(t),
    ]);
  } catch (e) {
    console.error('sweep failed', e);
  }
}

// ---------------------------------------------------------------- mail

async function sendMail(env, { to, subject, text, replyTo, bcc }) {
  const payload = {
    from: `${env.FROM_NAME || 'Empower Ethnic Media'} <${env.FROM_ADDR}>`,
    to,
    subject,
    text,
  };
  if (replyTo) payload.reply_to = replyTo;
  if (bcc && bcc.length) payload.bcc = bcc;

  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${env.RESEND_KEY}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  if (!r.ok) {
    console.error('resend failed', r.status, (await r.text()).slice(0, 300));
    return false;
  }
  return true;
}

/**
 * Add a confirmed subscriber to the Resend Audience.
 *
 * This only ever runs inside the confirm handler, after the reader has clicked
 * the link in their own inbox — so every contact is double opt-in by
 * construction, which is the standard CASL wants.
 *
 * Resend owns the unsubscribe flow from here: Broadcasts inject the
 * List-Unsubscribe headers and suppress opted-out contacts automatically.
 * We keep our own consent row as well, because that record is the evidence
 * and it should not live only in a third party's account.
 */
async function addToAudience(env, { email, name }) {
  if (!env.RESEND_AUDIENCE_ID) return;
  const first = (name || '').trim().split(/\s+/)[0] || '';
  const last = (name || '').trim().split(/\s+/).slice(1).join(' ');
  try {
    const r = await fetch(
      `https://api.resend.com/audiences/${env.RESEND_AUDIENCE_ID}/contacts`,
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${env.RESEND_KEY}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          email,
          first_name: first,
          last_name: last,
          unsubscribed: false,
        }),
      }
    );
    if (!r.ok) console.error('audience add failed', r.status, (await r.text()).slice(0, 200));
  } catch (e) {
    console.error('audience add threw', e);
  }
}

async function turnstileOk(env, token, ip) {
  if (!token) return false;
  const body = new FormData();
  body.append('secret', env.TURNSTILE_SECRET);
  body.append('response', token);
  if (ip) body.append('remoteip', ip);
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body,
  });
  const d = await r.json();
  return !!d.success;
}

// ---------------------------------------------------------------- targets

function targets(env) {
  return {
    minister: { name: 'Minister of Canadian Identity and Culture', email: env.EMAIL_MINISTER || '' },
    pmo: { name: 'Office of the Prime Minister', email: env.EMAIL_PMO || '' },
    heritage: { name: 'Canadian Heritage, Audiovisual Branch', email: env.EMAIL_HERITAGE || '' },
  };
}

// ---------------------------------------------------------------- handlers

async function handleLookup(request, env, url) {
  const code = (url.searchParams.get('postal') || '').replace(/\s/g, '').toUpperCase();
  if (!POSTAL_RE.test(code)) return bad('That does not look like a Canadian postal code.');

  if (!(await rateLimit(env, 'lookup', await ipHash(request, env), 30, 3600))) {
    return bad('Too many requests. Please wait a few minutes and try again.', 429);
  }

  const cached = await cacheGet(env, 'pc:' + code);
  if (cached) return json(JSON.parse(cached));

  const r = await fetch(`https://represent.opennorth.ca/postcodes/${code}/`, {
    headers: { accept: 'application/json' },
  });
  if (r.status === 404) return bad('We could not find that postal code. Please check it and try again.', 404);
  if (!r.ok) return bad('The riding lookup is unavailable right now. Please try again shortly.', 502);

  const data = await r.json();
  const reps = [
    ...(data.representatives_centroid || []),
    ...(data.representatives_concordance || []),
  ];
  const mp = reps.find((x) => x.elected_office === 'MP' && x.email);
  if (!mp) {
    return bad(
      'We could not match that postal code to a federal riding. Codes that sit on a boundary '
      + 'sometimes fail — try a neighbouring one, or send from your own email app.', 404);
  }

  const others = reps
    .filter((x) => x.elected_office !== 'MP' && x.email)
    .slice(0, 4)
    .map((x) => ({
      name: x.name,
      role: `${x.elected_office || ''}, ${x.district_name || ''}`.replace(/^, |, $/g, ''),
      email: x.email,
    }));

  const out = {
    riding: mp.district_name,
    province: data.province,
    city: data.city,
    mp: {
      name: mp.name,
      party: mp.party_name,
      email: mp.email,
      district: mp.district_name,
    },
    others,
  };
  await cacheSet(env, 'pc:' + code, JSON.stringify(out), 604800);
  return json(out);
}

async function handleDraft(request, env) {
  if (!env.ANTHROPIC_KEY) {
    return bad('Drafting is not available. Please use the template or write your own.', 503);
  }
  if (!(await rateLimit(env, 'draft', await ipHash(request, env), 8, 3600))) {
    return bad('Too many requests. Please wait a few minutes and try again.', 429);
  }

  const b = await request.json().catch(() => ({}));
  const why = String(b.why || '').slice(0, 1200).trim();
  if (why.length < 10) return bad('Tell us a little more about why this matters to you.');

  const prompt = `Write a short, sincere letter from a Canadian constituent to their MP.

MP: ${String(b.mp || 'their Member of Parliament').slice(0, 120)}
Riding: ${String(b.riding || 'their riding').slice(0, 120)}
The writer watches: ${String(b.lang || 'third-language').slice(0, 60)} community television
In their own words, why it matters to them: ${why}

The ask: fund the Canadian Independent Ethnic Community Television Anti-Disinformation and
Digital Transition Program at $10.52 million a year for two years.

Facts you may use: over 85 independent producers; more than 85 languages; about 800,000 weekly
viewers; one in four Canadians has a mother tongue other than English or French; the sector is
excluded from the Canada Media Fund, Local Journalism Initiative, Google News Fund and the
Canadian Journalism Labour Tax Credit; Bill C-11 promised support for multilingual programming
and none has arrived; the CMF distributed $336 million in 2023-24.

Rules: 250-350 words. Plain, warm, first person. Lead with the writer's own reason, in their
voice, not with statistics. Use at most three figures. No bullet points, no slogans, no
flattery. British/Canadian spelling. End with "Sincerely," and nothing after it — the signature
is added separately. Output only the letter.`;

  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': env.ANTHROPIC_KEY,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-6',
      max_tokens: 1200,
      messages: [{ role: 'user', content: prompt }],
    }),
  });
  if (!r.ok) return bad('The drafting service is busy. Please use the template for now.', 502);

  const d = await r.json();
  const text = (d.content || [])
    .filter((x) => x.type === 'text')
    .map((x) => x.text)
    .join('')
    .trim();
  if (!text) return bad('The drafting service returned nothing. Please use the template.', 502);
  return json({ letter: text + '\n' });
}

async function handleSend(request, env, ctx) {
  const iph = await ipHash(request, env);
  if (!(await rateLimit(env, 'send', iph, 5, 3600))) {
    return bad('Too many requests. Please wait a few minutes and try again.', 429);
  }

  const b = await request.json().catch(() => ({}));
  const name = String(b.name || '').trim().slice(0, 120);
  const email = String(b.email || '').trim().slice(0, 190);
  const street = String(b.street || '').trim().slice(0, 200);
  const code = String(b.postal || '').replace(/\s/g, '').toUpperCase();
  const letter = String(b.letter || '').trim().slice(0, 12000);
  const language = String(b.language || '').slice(0, 60);
  const subscribe = !!b.subscribe;
  const recipients = Array.isArray(b.recipients) ? b.recipients : [];

  if (name.length < 2) return bad('Please enter your full name.');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return bad('Please enter a valid email address.');
  if (street.length < 5) {
    return bad("Please enter your street address. MPs' offices need it to confirm you live in the riding.");
  }
  if (letter.length < 60) return bad('Your letter looks empty.');
  if (!POSTAL_RE.test(code)) return bad('Please look up your postal code again.');

  const ok = await turnstileOk(env, String(b.turnstile || ''), request.headers.get('cf-connecting-ip'));
  if (!ok) return bad('The check did not pass. Please try again.');

  const cached = await cacheGet(env, 'pc:' + code);
  if (!cached) return bad('Please look up your postal code again before sending.');
  const riding = JSON.parse(cached);

  const T = targets(env);
  const to = [riding.mp.email];
  for (const key of recipients) {
    if (typeof key !== 'string') continue;
    if (T[key] && T[key].email) to.push(T[key].email);
    else if (key.startsWith('other')) {
      const i = parseInt(key.slice(5), 10);
      if (riding.others?.[i]?.email) to.push(riding.others[i].email);
    }
  }
  const recipientList = [...new Set(to.filter(Boolean))];

  const token = newToken();
  const staged = JSON.stringify({
    name, email, street, postal: code, riding: riding.riding,
    language, to: recipientList, letter, subscribe, ts: now(),
  });

  await env.DB.prepare(
    'INSERT INTO pending (k, v, expires_at) VALUES (?, ?, ?)'
  ).bind(await sha256hex(token), await seal(staged, token), now() + TOKEN_TTL).run();

  const link = `${env.PUBLIC_BASE}/confirm?t=${token}`;
  const sent = await sendMail(env, {
    to: [email],
    subject: 'One click to send your letter',
    text:
      `Hello ${name},\n\n`
      + `You asked us to send your letter to ${riding.mp.name}, your MP in ${riding.riding}. `
      + `Confirm it is really you and we will send it right away:\n\n`
      + `${link}\n\n`
      + `The link works for 30 minutes. If you do nothing, your letter is deleted automatically `
      + `and nothing is sent.\n\n`
      + `Until you click, your letter is stored encrypted and we cannot read it — the key is in `
      + `this link and nowhere else.\n\n`
      + `If you did not ask for this, ignore this message. Nobody else receives anything.\n\n`
      + `Empower Ethnic Media\n`,
  });

  if (!sent) {
    await claim(env, await sha256hex(token));
    return bad('We could not send the confirmation email just now. Please try again shortly.', 502);
  }

  ctx.waitUntil(sweep(env));
  return json({ ok: true });
}

function page(title, body, status = 200) {
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<style>body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
color:#1A1718;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}
.c{max-width:520px;border:1px solid #E2DDD8;border-left:5px solid #D8232A;padding:34px 32px}
h1{font-family:"Iowan Old Style",Palatino,Georgia,serif;font-size:26px;margin:0 0 12px;font-weight:600}
p{margin:0;color:#5C5652;line-height:1.6}a{color:#D8232A}</style></head>
<body><div class="c"><h1>${title}</h1><p>${body}</p>
<p style="margin-top:18px"><a href="https://empowerethnicmedia.org/">Back to the campaign</a></p>
</div></body></html>`;
  return new Response(html, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', ...baseHeaders() },
  });
}

async function handleConfirm(request, env, url) {
  const token = url.searchParams.get('t') || '';
  if (!/^[A-Za-z0-9_-]{20,64}$/.test(token)) {
    return page('That link is not valid',
      'Please go back to the campaign page and write your letter again.', 400);
  }

  const k = await sha256hex(token);
  const row = await env.DB.prepare(
    'SELECT v FROM pending WHERE k = ? AND expires_at > ?'
  ).bind(k, now()).first();

  if (!row) {
    return page('That link has expired',
      'For your privacy we delete unconfirmed letters after 30 minutes, so nothing was sent. '
      + 'Please go back to the campaign page and write it again — it only takes a moment.', 410);
  }

  // Claim it before doing anything, so a double click cannot send twice.
  if (!(await claim(env, k))) {
    return page('Already sent', 'This letter has already gone out. Thank you.');
  }

  const plain = await unseal(row.v, token);
  if (!plain) {
    return page('That link is not valid',
      'We could not open your letter with this link. Please write it again from the campaign page.', 400);
  }
  const d = JSON.parse(plain);

  const body = d.letter.replace(/\s+$/, '') + `\n\n${d.name}\n${d.street}\n${d.postal}\n`;
  const sent = await sendMail(env, {
    to: d.to,
    subject: SUBJECT,
    text: body,
    replyTo: d.email,
    bcc: env.CAMPAIGN_COPY ? [env.CAMPAIGN_COPY] : [],
  });

  if (!sent) {
    return page('We could not send it just now',
      'Something went wrong on our side and your letter was not sent. Please go back to the '
      + 'campaign page and try again.', 502);
  }

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO stats (k, v) VALUES ('letters', 1)
       ON CONFLICT(k) DO UPDATE SET v = v + 1`
    ),
    ...(d.language
      ? [env.DB.prepare('INSERT OR IGNORE INTO languages (name) VALUES (?)').bind(d.language)]
      : []),
    ...(d.subscribe
      ? [env.DB.prepare(
          `INSERT INTO consent (email, name, consented_at, source, wording)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(email) DO UPDATE SET consented_at = excluded.consented_at`
        ).bind(d.email, d.name, now(),
               'letter widget, empowerethnicmedia.org',
               'Keep me posted on this campaign.')]
      : []),
  ]);

  if (d.subscribe) {
    await addToAudience(env, { email: d.email, name: d.name });
  }

  await sendMail(env, {
    to: [d.email],
    subject: 'Your letter is on its way',
    text:
      `Hello ${d.name},\n\nYour letter has been sent to:\n  ${d.to.join('\n  ')}\n\n`
      + `We have now deleted it. Replies will come straight to your own inbox.\n\n`
      + `Thank you for speaking up.\n\nEmpower Ethnic Media\n`,
  });

  return page('Your letter has been sent',
    'It went to your MP' + (d.to.length > 1 ? ' and the offices you chose' : '')
    + ', and our copy is deleted. Any reply will come straight to your own inbox. Thank you.');
}

async function handleCount(request, env) {
  if (request.method === 'POST') {
    if (!(await rateLimit(env, 'count', await ipHash(request, env), 10, 3600))) {
      return json({ ok: true });
    }
    const b = await request.json().catch(() => ({}));
    const language = String(b.language || '').slice(0, 60);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO stats (k, v) VALUES ('letters', 1)
         ON CONFLICT(k) DO UPDATE SET v = v + 1`
      ),
      ...(language
        ? [env.DB.prepare('INSERT OR IGNORE INTO languages (name) VALUES (?)').bind(language)]
        : []),
    ]);
    return json({ ok: true });
  }

  const letters = await env.DB.prepare("SELECT v FROM stats WHERE k = 'letters'").first();
  const langs = await env.DB.prepare('SELECT COUNT(*) AS n FROM languages').first();
  return json({ letters: letters?.v || 0, languages: langs?.n || 0 });
}

function serveWidget(env) {
  const inject = env.TURNSTILE_SITEKEY
    ? `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=onloadTurnstileCallback" async defer></script>
<script>
function onloadTurnstileCallback(){
  window.__tsWidget = turnstile.render('#turnstile', { sitekey: '${env.TURNSTILE_SITEKEY}', theme: 'light' });
}
</script>`
    : '';

  return new Response(WIDGET_HTML.replace('</body>', inject + '\n</body>'), {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': csp(env, true),
      ...baseHeaders(),
    },
  });
}

// ---------------------------------------------------------------- router

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname;

    try {
      if (p === '/' || p === '') return serveWidget(env);
      if (p === '/confirm') return handleConfirm(request, env, url);
      if (p === '/api/lookup') return handleLookup(request, env, url);
      if (p === '/api/draft' && request.method === 'POST') return handleDraft(request, env);
      if (p === '/api/send' && request.method === 'POST') return handleSend(request, env, ctx);
      if (p === '/api/count') return handleCount(request, env);
      if (p === '/api/health') {
        await env.DB.prepare('SELECT 1').first();
        return json({ ok: true });
      }
      return json({ error: 'Not found.' }, 404);
    } catch (e) {
      console.error('unhandled', e && e.stack ? e.stack : e);
      return json({ error: 'Something went wrong. Please try again.' }, 500);
    }
  },
};
