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
import LOGO_SVG from './assets/eem-logo.svg';

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

function csp(env, framed, nonce) {
  const ancestors = framed
    ? (env.FRAME_ANCESTORS || 'https://empowerethnicmedia.org')
    : "'none'";
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' https://hcaptcha.com https://*.hcaptcha.com`,
    'frame-src https://hcaptcha.com https://*.hcaptcha.com',
    "connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com",
    "style-src 'self' 'unsafe-inline' https://hcaptcha.com https://*.hcaptcha.com",
    "img-src 'self' data: https://hcaptcha.com https://*.hcaptcha.com",
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

async function sendMail(env, { to, subject, text, html, replyTo, bcc }) {
  const payload = {
    from: `${env.FROM_NAME || 'Empower Ethnic Media'} <${env.FROM_ADDR}>`,
    to,
    subject,
    text,
  };
  if (html) payload.html = html;
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

async function hcaptchaOk(env, token, ip) {
  if (!token) return false;
  const body = new FormData();
  body.append('secret', env.HCAPTCHA_SECRET);
  body.append('response', token);
  if (ip) body.append('remoteip', ip);
  const r = await fetch('https://api.hcaptcha.com/siteverify', {
    method: 'POST',
    body,
  });
  const d = await r.json();
  return !!d.success;
}

/**
 * Post one row to the campaign's Google Sheet, via an Apps Script Web App
 * deployed on that sheet (SHEETS_WEBHOOK_URL). `sheet` picks the tab
 * ("Letters" or "Consent") on the Apps Script side. Best-effort: a failure
 * here must never block or fail the send itself.
 */
async function logToSheet(env, sheet, row) {
  if (!env.SHEETS_WEBHOOK_URL) return;
  try {
    const r = await fetch(env.SHEETS_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sheet, ...row }),
    });
    if (!r.ok) console.error('sheet log failed', sheet, r.status, (await r.text()).slice(0, 300));
  } catch (e) {
    console.error('sheet log threw', sheet, e);
  }
}

// ---------------------------------------------------------------- targets

/**
 * Fixed government recipients. Every confirmed letter goes to these,
 * always, in addition to the visitor's own MP — each as a separate,
 * individually-addressed email. Not user-selectable in the widget.
 */
const FIXED_TARGETS = [
  { key: 'miller', name: 'Minister Marc Miller', salutation: 'Minister Miller', salutationFr: 'le ministre Miller', email: 'hon.marc.miller@pch.gc.ca' },
  { key: 'champagne', name: 'Minister François-Philippe Champagne', salutation: 'Minister Champagne', salutationFr: 'le ministre Champagne', email: 'francois-philippe.champagne@parl.gc.ca' },
  { key: 'budget', name: 'Department of Finance — Budget Consultations', salutation: 'Canadian Heritage and Department of Finance Officials', salutationFr: 'les responsables de Patrimoine canadien et du ministère des Finances', email: 'yourbudget-votrebudget@fin.gc.ca' },
  { key: 'finmin', name: 'Office of the Minister of Finance', salutation: 'Canadian Heritage and Department of Finance Officials', salutationFr: 'les responsables de Patrimoine canadien et du ministère des Finances', email: 'minister-ministre@fin.gc.ca' },
  { key: 'chpc', name: 'Standing Committee on Canadian Heritage', salutation: 'Canadian Heritage and Department of Finance Officials', salutationFr: 'les responsables de Patrimoine canadien et du ministère des Finances', email: 'CHPC@parl.gc.ca' },
  { key: 'fisher', name: 'Connor Fisher, Office of the Minister of Canadian Identity and Culture, Policy Advisor', salutation: 'Canadian Heritage and Department of Finance Officials', salutationFr: 'les responsables de Patrimoine canadien et du ministère des Finances', email: 'connor.fisher@pch.gc.ca' },
  { key: 'awad', name: 'Amy Awad, the Department of Canadian Heritage, Digital and Creative Marketplace Frameworks Branch, Director General', salutation: 'Canadian Heritage and Department of Finance Officials', salutationFr: 'les responsables de Patrimoine canadien et du ministère des Finances', email: 'amy.awad@pch.gc.ca' },
  { key: 'sabbagh', name: 'Michel Sabbagh, the Department of Canadian Heritage, Audiovisual Branch, Director General', salutation: 'Canadian Heritage and Department of Finance Officials', salutationFr: 'les responsables de Patrimoine canadien et du ministère des Finances', email: 'michel.sabbagh@pch.gc.ca' },
  { key: 'tao', name: 'Erica Tao, the Department of Canadian Heritage, Acting Assistant Deputy Minister of Multiculturalism and Anti-Racism', salutation: 'Canadian Heritage and Department of Finance Officials', salutationFr: 'les responsables de Patrimoine canadien et du ministère des Finances', email: 'erica.tao@pch.gc.ca' },
];

const FIXED_BCC = ['clevelbrief@gmail.com', 'empowerethnicmedia@gmail.com'];

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
  if (!env.ANTHROPIC_KEY || env.DISABLE_ASSIST) {
    return bad('Drafting is not available. Please use the template or write your own.', 503);
  }
  if (!(await rateLimit(env, 'draft', await ipHash(request, env), 8, 3600))) {
    return bad('Too many requests. Please wait a few minutes and try again.', 429);
  }

  const b = await request.json().catch(() => ({}));
  const why = String(b.why || '').slice(0, 1200).trim();
  if (why.length < 10) return bad('Tell us a little more about why this matters to you.');

  const isFrench = request.headers.get('X-Lang') === 'fr' || b.lang === 'fr';
  const languageRule = isFrench
    ? 'Write the entire letter in Canadian French (français canadien) — use Canadian French '
      + 'conventions and vocabulary (e.g. "courriel" not "email", Quebec/Canadian French usage), '
      + 'not France French. End with "Cordialement," instead of "Sincerely,". Output only the '
      + 'letter, entirely in French.'
    : 'Write the letter in English. End with "Sincerely," and nothing after it — the signature '
      + 'is added separately. Output only the letter.';

  const prompt = `Write a short letter from a Canadian constituent to the federal government.

The writer's community: ${String(b.lang || 'third-language').slice(0, 60)}
In their own words, why it matters to them: ${why}

The ask: a dedicated, temporary federal funding stream for independent third-language TV
producers in Budget 2026, to protect local news sovereignty and ensure all Canadians have
access to reliable civic reporting in their own language. Finance and Canadian Heritage are
the departments responsible.

Rules: 80-130 words total. Short, plain, direct sentences — no more than one idea per
sentence, no run-ons. Do not open with a salutation ("Dear ...") or a signature line — both
are added separately, so start directly with the first sentence of the letter body and end
right after the final sentence, no "Sincerely," or name. Lead with the writer's own reason for
caring, in their own voice, in one or two sentences, then the ask in one or two more. Use at
most one statistic. No bullet points, no slogans, no flattery. Write like an ordinary person
speaking plainly, not like a press release or an advocacy campaign: avoid grand or sweeping
language ("critical", "vital", "urgent crisis", "we must act now"), avoid repeating the same
point in different words, and do not lecture the reader. ${languageRule}`;

  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': env.ANTHROPIC_KEY,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1200,
      messages: [{ role: 'user', content: prompt }],
    }),
  });
  if (!r.ok) {
    console.error('anthropic draft failed', r.status, (await r.text()).slice(0, 500));
    return bad('The drafting service is busy. Please use the template for now.', 502);
  }

  const d = await r.json();
  const text = (d.content || [])
    .filter((x) => x.type === 'text')
    .map((x) => x.text)
    .join('')
    .trim();
  if (!text) return bad('The drafting service returned nothing. Please use the template.', 502);
  const closing = isFrench ? 'Cordialement,' : 'Sincerely,';
  return json({ letter: text + `\n\n${closing}\n` });
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

  const ok = await hcaptchaOk(env, String(b.turnstile || ''), request.headers.get('cf-connecting-ip'));
  if (!ok) return bad('The check did not pass. Please try again.');

  const cached = await cacheGet(env, 'pc:' + code);
  if (!cached) return bad('Please look up your postal code again before sending.');
  const riding = JSON.parse(cached);

  const isFrench = request.headers.get('X-Lang') === 'fr';

  // Every letter goes to the visitor's MP plus the fixed government
  // recipients, always — this is not user-selectable.
  const to = [riding.mp.email, ...FIXED_TARGETS.map((t) => t.email)];
  const toNames = [
    `${riding.mp.name} (MP, ${riding.riding})`,
    ...FIXED_TARGETS.map((t) => t.name),
  ];
  const salutations = [
    riding.mp.name,
    ...FIXED_TARGETS.map((t) => (isFrench ? t.salutationFr : t.salutation)),
  ];
  for (const key of recipients) {
    if (typeof key !== 'string' || !key.startsWith('other')) continue;
    const i = parseInt(key.slice(5), 10);
    if (riding.others?.[i]?.email) {
      to.push(riding.others[i].email);
      toNames.push(`${riding.others[i].name} (${riding.others[i].role})`);
      salutations.push(riding.others[i].name);
    }
  }

  // Only ever read if the visitor ticks the newsletter box — this is the
  // consent evidence CASL requires, not used for anything else.
  const consentIp = subscribe ? iph : '';
  const consentUA = subscribe ? String(request.headers.get('user-agent') || '').slice(0, 300) : '';

  const token = newToken();
  const staged = JSON.stringify({
    name, email, street, postal: code, riding: riding.riding,
    language, to, toNames, salutations, letter, subscribe, consentIp, consentUA,
    uiLang: isFrench ? 'fr' : 'en', ts: now(),
  });

  await env.DB.prepare(
    'INSERT INTO pending (k, v, expires_at) VALUES (?, ?, ?)'
  ).bind(await sha256hex(token), await seal(staged, token), now() + TOKEN_TTL).run();

  const link = `${env.PUBLIC_BASE}/confirm?t=${token}`;
  const ce = confirmEmail(env, {
    name, mp: riding.mp.name, riding: riding.riding, link, isFrench,
  });
  const sent = await sendMail(env, {
    to: [email],
    subject: ce.subject,
    text: ce.text,
    html: ce.html,
  });

  if (!sent) {
    await claim(env, await sha256hex(token));
    return bad('We could not send the confirmation email just now. Please try again shortly.', 502);
  }

  ctx.waitUntil(sweep(env));
  return json({ ok: true });
}

const RAINBOW = ['#D6102A', '#C7B800', '#00B3B3', '#12A44B', '#B7169B', '#1B3FC4', '#E86A12', '#EDEFF2'];

/**
 * The thank-you email sent once a letter is confirmed and away. Branded to
 * match the campaign landing page (dark header, wordmark, rainbow stripe),
 * since this is the one email every sender receives and reads in full.
 */
const THANK_YOU_STRINGS = {
  en: {
    subject: 'Your letter is on its way',
    hello: (name) => `Hello ${escHtml(name)},`,
    sentTo: 'Your letter has been sent to:',
    deleted: 'We have now deleted it. Replies will come straight to your own inbox.',
    thanks: 'Thank you for speaking up, on behalf of all Canadians.',
  },
  fr: {
    subject: 'Votre lettre est en chemin',
    hello: (name) => `Bonjour ${escHtml(name)},`,
    sentTo: "Votre lettre a ete envoyee a :",
    deleted: "Nous l'avons maintenant supprimee. Les reponses arriveront directement dans votre propre boite de reception.",
    thanks: "Merci d'avoir pris la parole, au nom de tous les Canadiens.",
  },
};

const CONFIRM_STRINGS = {
  en: {
    subject: 'One click to send your letter',
    hello: (name) => `Hello ${escHtml(name)},`,
    body1: (mp, riding) => `You asked us to send your letter to ${escHtml(mp)}, your MP in ${escHtml(riding)}. Confirm it is really you and we will send it right away.`,
    cta: 'Confirm and send my letter',
    ttl: "The link works for 30 minutes. If you do nothing, your letter is deleted automatically and nothing is sent.",
    encrypted: "Until you click, your letter is stored encrypted and we cannot read it \u2014 the key is in this link and nowhere else.",
    ignore: 'If you did not ask for this, ignore this message. Nobody else receives anything.',
  },
  fr: {
    subject: 'Un clic pour envoyer votre lettre',
    hello: (name) => `Bonjour ${escHtml(name)},`,
    body1: (mp, riding) => `Vous nous avez demande d'envoyer votre lettre a ${escHtml(mp)}, votre depute dans ${escHtml(riding)}. Confirmez que c'est bien vous et nous l'enverrons immediatement.`,
    cta: 'Confirmer et envoyer ma lettre',
    ttl: "Le lien fonctionne pendant 30 minutes. Si vous ne faites rien, votre lettre sera automatiquement supprimee et rien ne sera envoye.",
    encrypted: "Tant que vous n'avez pas clique, votre lettre est stockee chiffree et nous ne pouvons pas la lire \u2014 la cle se trouve uniquement dans ce lien.",
    ignore: "Si vous n'avez pas demande ceci, ignorez ce message. Personne d'autre ne recevra quoi que ce soit.",
  },
};

/**
 * The "click to confirm" email — the one link that actually sends the
 * letter. Bilingual, same brand shell as the thank-you email, with a
 * clear single call-to-action button rather than a bare link.
 */
function confirmEmail(env, { name, mp, riding, link, isFrench }) {
  const stripe = RAINBOW.map((c) => `<td style="background:${c};height:6px;font-size:0;line-height:0;">&nbsp;</td>`).join('');
  const logoUrl = `${env.PUBLIC_BASE}/logo.svg`;
  const order = isFrench ? ['fr', 'en'] : ['en', 'fr'];
  const first = CONFIRM_STRINGS[order[0]];
  const second = CONFIRM_STRINGS[order[1]];

  const block = (t) => `
<p style="margin:0 0 18px;font-family:Arial,Helvetica,sans-serif;font-weight:700;font-size:20px;color:#17151A;">${t.hello(name)}</p>
<p style="margin:0 0 24px;">${t.body1(mp, riding)}</p>
<p style="margin:0 0 24px;"><a href="${link}" style="display:inline-block;padding:14px 28px;background:#D6102A;color:#FFFFFF;text-decoration:none;font-family:Arial,Helvetica,sans-serif;font-weight:700;font-size:15px;">${t.cta}</a></p>
<p style="margin:0 0 12px;color:#5C5A66;font-size:14px;font-family:Arial,Helvetica,sans-serif;">${t.ttl}</p>
<p style="margin:0 0 12px;color:#5C5A66;font-size:14px;font-family:Arial,Helvetica,sans-serif;">${t.encrypted}</p>
<p style="margin:0;color:#5C5A66;font-size:14px;font-family:Arial,Helvetica,sans-serif;">${t.ignore}</p>`;

  const html = `<!DOCTYPE html><html lang="${isFrench ? 'fr' : 'en'}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${first.subject} / ${second.subject}</title></head>
<body style="margin:0;padding:0;background:#F4F2F0;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F4F2F0;padding:32px 16px;">
<tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#17151A;">
<tr><td style="padding:36px 40px 28px;">
<img src="${logoUrl}" width="240" alt="Empower Canadian Ethnic Community TV" style="display:block;width:240px;max-width:60%;height:auto;">
</td></tr>
<tr>${stripe}</tr>
<tr><td style="background:#FFFFFF;padding:36px 40px 8px;font-family:Georgia,'Times New Roman',serif;color:#1B1A20;font-size:16px;line-height:1.6;">
${block(first)}
</td></tr>
<tr><td style="background:#FFFFFF;padding:0 40px;"><hr style="border:none;border-top:1px solid #E2DDD8;margin:20px 0;"></td></tr>
<tr><td style="background:#FFFFFF;padding:0 40px 36px;font-family:Georgia,'Times New Roman',serif;color:#1B1A20;font-size:16px;line-height:1.6;">
${block(second)}
<p style="margin:20px 0 0;color:#5C5A66;font-size:14px;font-family:Arial,Helvetica,sans-serif;">Empower Ethnic Media</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>`;

  const textFor = (t) =>
    `${t.hello(name).replace(/<[^>]+>/g, '')}\n\n${t.body1(mp, riding)}\n\n${link}\n\n`
    + `${t.ttl}\n\n${t.encrypted}\n\n${t.ignore}\n`;

  const text = `${textFor(first)}\n---\n\n${textFor(second)}\nEmpower Ethnic Media\n`;

  return { subject: `${first.subject} / ${second.subject}`, html, text };
}

function thankYouEmail(env, { name, recipients, letterText, isFrench }) {
  const stripe = RAINBOW.map((c) => `<td style="background:${c};height:6px;font-size:0;line-height:0;">&nbsp;</td>`).join('');
  const list = recipients.map((r) => `<li style="margin:0 0 6px;">${escHtml(r)}</li>`).join('');
  const logoUrl = `${env.PUBLIC_BASE}/logo.svg`;
  const order = isFrench ? ['fr', 'en'] : ['en', 'fr'];
  const first = THANK_YOU_STRINGS[order[0]];
  const second = THANK_YOU_STRINGS[order[1]];
  const letterHtml = `<pre style="white-space:pre-wrap;font-family:Georgia,'Times New Roman',serif;font-size:14px;line-height:1.55;color:#3A3742;margin:0;">${escHtml(letterText)}</pre>`;

  const block = (t) => `
<p style="margin:0 0 18px;font-family:Arial,Helvetica,sans-serif;font-weight:700;font-size:20px;color:#17151A;">${t.hello(name)}</p>
<p style="margin:0 0 18px;">${t.sentTo}</p>
<ul style="margin:0 0 18px;padding-left:20px;color:#5C5A66;font-size:14px;font-family:Arial,Helvetica,sans-serif;">${list}</ul>
<p style="margin:0 0 18px;">${t.deleted}</p>
<p style="margin:0;font-weight:600;">${t.thanks}</p>`;

  const html = `<!DOCTYPE html><html lang="${isFrench ? 'fr' : 'en'}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${first.subject} / ${second.subject}</title></head>
<body style="margin:0;padding:0;background:#F4F2F0;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F4F2F0;padding:32px 16px;">
<tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#17151A;">
<tr><td style="padding:36px 40px 28px;">
<img src="${logoUrl}" width="240" alt="Empower Canadian Ethnic Community TV" style="display:block;width:240px;max-width:60%;height:auto;">
</td></tr>
<tr>${stripe}</tr>
<tr><td style="background:#FFFFFF;padding:36px 40px 8px;font-family:Georgia,'Times New Roman',serif;color:#1B1A20;font-size:16px;line-height:1.6;">
${block(first)}
</td></tr>
<tr><td style="background:#FFFFFF;padding:0 40px;"><hr style="border:none;border-top:1px solid #E2DDD8;margin:20px 0;"></td></tr>
<tr><td style="background:#FFFFFF;padding:0 40px 32px;font-family:Georgia,'Times New Roman',serif;color:#1B1A20;font-size:16px;line-height:1.6;">
${block(second)}
<p style="margin:20px 0 0;color:#5C5A66;font-size:14px;font-family:Arial,Helvetica,sans-serif;">Empower Ethnic Media</p>
</td></tr>
<tr><td style="background:#FBF9F7;padding:28px 40px 36px;border-top:1px solid #E2DDD8;">
<p style="margin:0 0 12px;font-family:Arial,Helvetica,sans-serif;font-weight:700;font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:#5C5A66;">A copy of your letter / Une copie de votre lettre</p>
${letterHtml}
</td></tr>
</table>
</td></tr>
</table>
</body></html>`;

  const textFor = (t) =>
    `${t.hello(name).replace(/<[^>]+>/g, '')}\n\n${t.sentTo}\n`
    + recipients.map((r) => `  ${r}`).join('\n')
    + `\n\n${t.deleted}\n\n${t.thanks}\n`;

  const text = `${textFor(first)}\n---\n\n${textFor(second)}\nEmpower Ethnic Media\n\n---\n\nA copy of your letter / Une copie de votre lettre:\n\n${letterText}\n`;

  return { subject: `${first.subject} / ${second.subject}`, html, text };
}

function escHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
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

async function handleConfirm(request, env, url, ctx) {
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

  // The template has no salutation baked in — one line is added per
  // recipient at send time. If the visitor wrote or kept their own
  // "Dear X," opener (blank/edited mode), swap that line instead of
  // stacking a second one on top.
  const salutationLine = /^(Dear|Monsieur\/Madame) [^\n]*,[ \t]*\r?\n+/;
  const isFrenchLetter = /^Monsieur\/Madame /.test(d.letter);
  const bodyFor = (salutation) => {
    if (!salutation) return d.letter.replace(/\s+$/, '') + `\n\n${d.name}\n${d.street}\n${d.postal}\n`;
    const greeting = isFrenchLetter ? 'Monsieur/Madame' : 'Dear';
    const letter = salutationLine.test(d.letter)
      ? d.letter.replace(salutationLine, `${greeting} ${salutation},\n\n`)
      : `${greeting} ${salutation},\n\n${d.letter}`;
    return letter.replace(/\s+$/, '') + `\n\n${d.name}\n${d.street}\n${d.postal}\n`;
  };

  const recipients = env.TEST_MODE
    ? [{ email: env.TEST_MODE, salutation: (d.salutations && d.salutations[0]) || '' }]
    : d.to.map((email, i) => ({ email, salutation: (d.salutations && d.salutations[i]) || '' }));

  let anySent = false;
  for (const rcpt of recipients) {
    const ok = await sendMail(env, {
      to: [rcpt.email],
      bcc: FIXED_BCC,
      subject: (env.TEST_MODE ? '[TEST] ' : '') + SUBJECT,
      text: bodyFor(rcpt.salutation),
      replyTo: d.email,
    });
    if (ok) anySent = true;
  }
  const body = bodyFor((d.salutations && d.salutations[0]) || '');

  if (!anySent) {
    return page('We could not send it just now',
      'Something went wrong on our side and your letter was not sent. Please go back to the '
      + 'campaign page and try again.', 502);
  }

  ctx.waitUntil(logToSheet(env, 'Letters', {
    name: d.name, email: d.email, street: d.street, postal: d.postal, riding: d.riding,
    language: d.language, recipients: d.toNames || d.to || [], letter: body,
  }));

  if (d.subscribe) {
    ctx.waitUntil(logToSheet(env, 'Consent', {
      name: d.name, email: d.email,
      wording: 'Keep me posted on this campaign. We will use your email only for updates on '
        + 'this campaign, and every message has an unsubscribe link.',
      hashedIp: d.consentIp || '', userAgent: d.consentUA || '',
    }));
  }

  if (env.CAMPAIGN_COPY) {
    const toLine = (d.toNames || d.to || []).join('\n  ');
    await sendMail(env, {
      to: [env.CAMPAIGN_COPY],
      subject: (env.TEST_MODE ? '[TEST] ' : '') + `Letter sent — ${d.name}, ${d.riding}`,
      text:
        `Sent to:\n  ${toLine}\n\n`
        + `From: ${d.name} <${d.email}>\n${d.street}, ${d.postal}\n`
        + (d.language ? `Language: ${d.language}\n` : '')
        + `\n---\n\n${body}`,
    });
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

  const ty = thankYouEmail(env, {
    name: d.name, recipients: d.toNames || d.to || [], letterText: body, isFrench: d.uiLang === 'fr',
  });
  await sendMail(env, {
    to: [d.email],
    subject: ty.subject,
    text: ty.text,
    html: ty.html,
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

function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function serveWidget(env) {
  const nonce = hex(crypto.getRandomValues(new Uint8Array(16)));

  const inject = env.HCAPTCHA_SITEKEY
    ? `<script nonce="${nonce}" src="https://js.hcaptcha.com/1/api.js" async defer></script>`
    : '';

  const config = `<script nonce="${nonce}">window.__CONFIG = { testMode: ${JSON.stringify(!!env.TEST_MODE)} };</script>\n`;

  const disableAssist = (env.ANTHROPIC_KEY && !env.DISABLE_ASSIST)
    ? ''
    : `<style>.mode[data-mode="assist"]{display:none}</style>`;

  const html = WIDGET_HTML
    .replace('__HCAPTCHA_SITEKEY__', env.HCAPTCHA_SITEKEY || '')
    .replace('<script>', `${config}<script nonce="${nonce}">`)
    .replace('</body>', inject + disableAssist + '\n</body>');

  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': csp(env, true, nonce),
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
      if (p === '/logo.svg') {
        return new Response(LOGO_SVG, {
          headers: { 'content-type': 'image/svg+xml; charset=utf-8', 'cache-control': 'public, max-age=86400' },
        });
      }
      if (p === '/confirm') return handleConfirm(request, env, url, ctx);
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
