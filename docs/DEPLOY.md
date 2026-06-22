# Deploying the website (Cloudflare Pages)

The marketing + docs site lives in [`site/`](../site) and deploys to
**Cloudflare Pages** at https://sshache.com. Config is in
[`wrangler.toml`](../wrangler.toml) (`pages_build_output_dir = "site"`).

Pick one of the two paths below.

## Option A — Dashboard (Git integration, recommended)

1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Pages** →
   **Connect to Git** → pick `TanvirMahin24/sshache`.
2. Build settings:
   - Framework preset: **None**
   - Build command: *(leave empty — the site is static)*
   - Build output directory: **`site`**
3. Save and deploy. Every push to `main` auto-builds.
4. Project → **Custom domains** → **Set up a domain** → `sshache.com`
   (already in your account, so it's one click). Add `www` too if you want it.

## Option B — Wrangler / GitHub Actions

CI is wired in [`.github/workflows/pages.yml`](../.github/workflows/pages.yml) —
it deploys on every push to `main` that touches `site/`. It needs two repo
secrets:

- `CLOUDFLARE_API_TOKEN` — a token with the **Cloudflare Pages: Edit** permission
- `CLOUDFLARE_ACCOUNT_ID` — your account id (Workers & Pages → right sidebar)

First-time project creation (once, locally):

```sh
npx wrangler login
npx wrangler pages project create sshache --production-branch main
npx wrangler pages deploy        # reads wrangler.toml
```

After that, pushes to `main` deploy automatically via the workflow, or run
`npx wrangler pages deploy` anytime.

## What's already set up for SEO / serving

- `site/_headers` — security headers + 1-year cache on `/assets/*`.
- `site/robots.txt` + `site/sitemap.xml` — pointed at `https://sshache.com`.
- Per-page `<title>`, meta description, canonical, Open Graph + Twitter cards,
  and JSON-LD (`SoftwareApplication` on the landing page, `TechArticle` on docs).
- `site/assets/og-image.png` (1200×630) is the social share image.

## After the domain is live

- Submit `https://sshache.com/sitemap.xml` in Google Search Console.
- Verify the share preview with the Facebook Sharing Debugger / X Card Validator.
