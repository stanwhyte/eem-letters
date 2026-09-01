# letters.empowerethnicmedia.org — Worker setup

No server. No nginx, no certificate to install, no PHP version, no vhost. Nothing in this
stack can affect empowerethnicmedia.org or vestnik.ca, because there is no origin machine
in the path — the Worker runs at Cloudflare's edge and the campaign site continues to be
served by Tilda exactly as it is today.

About 20 minutes.

## What you need

- Node.js on your Mac (`node -v` — anything 18 or newer)
- The Cloudflare account that now holds the empowerethnicmedia.org zone
- Your Turnstile site key and secret key
- Your Resend API key

---

## Step 1. Get the files onto your machine

Put the `worker/` folder somewhere sensible, then:

```bash
cd worker
npm install
npx wrangler login
```

`wrangler login` opens a browser and asks you to authorise. Pick the right account if you
have more than one.

## Step 2. Create the database

```bash
npx wrangler d1 create eem-letters
```

It prints a block containing `database_id = "..."`. Copy that ID into `wrangler.toml`,
replacing `PASTE_DATABASE_ID_FROM_D1_CREATE`.

Then create the tables:

```bash
npm run db:init
```

## Step 3. Fill in wrangler.toml

Open it and set:

- `TURNSTILE_SITEKEY` — the public site key from Turnstile
- `EMAIL_MINISTER`, `EMAIL_PMO`, `EMAIL_HERITAGE` — leave blank for now if you have not
  confirmed the current addresses; blank simply hides that recipient from the widget

Everything else is already correct for this domain.

## Step 4. Set the secrets

These never go in a file. Each command prompts for the value and stores it encrypted:

```bash
npx wrangler secret put RESEND_KEY
npx wrangler secret put TURNSTILE_SECRET
npx wrangler secret put IP_PEPPER
npx wrangler secret put ANTHROPIC_KEY     # optional
```

For `IP_PEPPER`, generate a random value:

```bash
openssl rand -hex 16
```

That salts the hashed IP used for rate limiting, so the stored counter keys cannot be
reversed back to visitor addresses.

If you skip `ANTHROPIC_KEY`, the "Help me write it" button reports itself unavailable and
the other two writing modes work normally.

## Step 5. Update the Turnstile widget hostname

Your Turnstile widget was created for `letters.vestnik.ca`. Change it:

Cloudflare → Turnstile → your widget → Settings → Hostnames → replace with
`letters.empowerethnicmedia.org`. Save.

If you skip this the token check fails and "Send it for me" refuses every letter.

## Step 6. Deploy

```bash
npm run deploy
```

Wrangler creates the custom domain, its DNS record and its certificate automatically.
First deploy takes a minute or two while the certificate issues.

Then:

```bash
curl -s https://letters.empowerethnicmedia.org/api/health
# {"ok":true}

curl -s "https://letters.empowerethnicmedia.org/api/lookup?postal=M5V2T6" | head -c 300
# JSON naming an MP and riding
```

Open `https://letters.empowerethnicmedia.org/` in a browser: red bands, language mosaic,
working lookup, Turnstile checkbox on the last step.

## Step 7. Embed in Tilda

Add a **T123 "HTML code"** block on the campaign page — not a Zero Block, which clips the
iframe as it grows — and paste this:

```html
<div style="max-width:820px;margin:0 auto">
  <iframe
    id="eemLetters"
    src="https://letters.empowerethnicmedia.org/"
    title="Write to your MP"
    style="width:100%;border:0;display:block;min-height:760px"
    scrolling="no"
    referrerpolicy="no-referrer"
    sandbox="allow-scripts allow-forms allow-popups allow-top-navigation-by-user-activation allow-same-origin"
    loading="lazy"></iframe>
</div>
<script>
(function(){
  var frame = document.getElementById('eemLetters');
  window.addEventListener('message', function(e){
    if (e.origin !== 'https://letters.empowerethnicmedia.org') return;
    var d = e.data;
    if (!d || d.eem !== 'height') return;
    var h = parseInt(d.height, 10);
    if (h > 200 && h < 6000) frame.style.height = h + 'px';
  }, false);
})();
</script>
```

Publish, then check the browser console on the live page. A CSP error mentioning
`frame-ancestors` means the page is served from a hostname not listed in
`FRAME_ANCESTORS` in `wrangler.toml`.

---

## Step 8. Test before announcing

On a real phone as well as desktop:

- [ ] A postal code you know returns the right MP.
- [ ] `K0A 1K0` fails with the explanatory message, not a crash.
- [ ] A language tile turns red, moves to the front, and updates the note.
- [ ] "Open in my email app" fills a real message in iOS Mail and Gmail on Android.
- [ ] A very long letter triggers the clipboard fallback instead of a truncated mailto.
- [ ] "Send it for me" produces a confirmation email within a minute.
- [ ] The confirm link sends the letter; a second click says "already sent".
- [ ] Wait 31 minutes, then click an old link: expired page.
- [ ] The staged letter really is opaque. While one is pending:
      `npx wrangler d1 execute eem-letters --remote --command "SELECT v FROM pending"` —
      you should see base64, no readable text.
- [ ] Newsletter box unticked by default; ticking it adds a row to `consent`.
- [ ] Send one to yourself and read the raw headers: **SPF pass, DKIM pass, DMARC pass**.

---

## Running it

**Watch it live** — invaluable during testing:

```bash
npx wrangler tail
```

**Counters**

```bash
npx wrangler d1 execute eem-letters --remote \
  --command "SELECT v FROM stats WHERE k='letters'"
```

**Export consent** — your CASL evidence. Keep it off Cloudflare too:

```bash
npx wrangler d1 execute eem-letters --remote --json \
  --command "SELECT * FROM consent" > consent-$(date +%F).json
```

**Unsubscribe**

```bash
npx wrangler d1 execute eem-letters --remote \
  --command "DELETE FROM consent WHERE email='someone@example.com'"
```

**Change the letter text**

Template: `renderTemplate()` in `src/widget.html`.
AI brief: the `prompt` string in `src/index.js`.
They quote the same figures — update both together. Then `npm run deploy`.

**Change recipients**

Edit the `EMAIL_*` vars in `wrangler.toml`, then `npm run deploy`.

**Roll back a bad deploy**

```bash
npx wrangler deployments list
npx wrangler rollback <deployment-id>
```

That is the thing this architecture buys you that the server never could.

---

## Things worth knowing

**Free tier limits.** 100,000 Worker requests and 100,000 D1 row writes per day. A
campaign push of a few thousand letters sits comfortably inside that. If you exceed it the
Worker returns errors rather than billing you, unless you have a paid plan.

**Recipient addresses go stale.** Represent keeps MPs current; the `EMAIL_*` vars are
yours to maintain. Check them before each push.

**Identical letters get counted once.** Offices deduplicate. The "Help me write it" path
and the free-text field are the reason letters get read, not decoration.

**The relay must not become an open relay.** Turnstile, the rate limit and the email
confirmation guard the same thing: that nobody can send mail to parl.gc.ca in a stranger's
name from your infrastructure. If you disable one for testing, put it back.

**Do not undo the encryption.** Letters are sealed with a key that exists only in the
reader's inbox, which is what makes the privacy text on the page true rather than
aspirational. Adding logging that writes letter bodies anywhere would quietly break it.
