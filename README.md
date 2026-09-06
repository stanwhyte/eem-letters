# Empower Ethnic Media — letter to your MP

A Cloudflare Worker that helps Canadians write to their Member of Parliament in support of
funding for independent ethnic community television. Embedded by iframe into the campaign
site at empowerethnicmedia.org.

Live at https://letters.empowerethnicmedia.org/

## How it handles your letter

Two ways to send, and they differ in what reaches our infrastructure.

**Open in your own email app.** The letter is composed in your browser and handed to your
mail client. Nothing you typed ever reaches our servers.

**Ask us to send it.** The letter is encrypted with AES-256-GCM before it is stored, using
a key derived from the confirmation token that is emailed to you. It is filed under a hash
of that token, so the database does not contain the key. We hold ciphertext we cannot
ourselves read. When you click the link, we decrypt it in memory, send it, and delete the
record. Unconfirmed letters expire after 30 minutes.

This is why the page can say "we do not keep your letter" as a property of the design
rather than a promise about our good behaviour. See `seal()` and `handleConfirm()` in
`src/index.js`.

No cookies. No analytics. No third-party scripts beyond hCaptcha, which is
used to stop the relay being abused to send mail in strangers' names.

The only durable personal data is newsletter consent, for people who tick the box, which
CASL requires us to keep proof of.

## Layout

    src/index.js      the Worker: routing, riding lookup, sealing, sending
    src/widget.html   the embedded interface, self-contained
    schema.sql        D1 tables
    wrangler.toml     config and non-secret variables
    SETUP-WORKER.md   deployment guide

## Local development

    npm install
    npx wrangler dev

Opening `src/widget.html` directly in a browser runs it against a mock backend, which is
useful for design work without deploying.

## Deploying

Pushes to `main` deploy automatically. Manually:

    npm run deploy

Secrets are set with `wrangler secret put` and are never in this repository.
