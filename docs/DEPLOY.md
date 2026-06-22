# Deploying the website (Cloudflare)

The marketing + docs site lives in [`site/`](../site) and is deployed to
**Cloudflare** as a Workers Static-Assets project at https://sshache.com.
It is **prebuilt static HTML/CSS — there is no build step.**

Config: [`wrangler.toml`](../wrangler.toml) →

```toml
name = "sshache"
compatibility_date = "2025-01-01"

[assets]
directory = "./site"
```

`npx wrangler deploy` uploads `site/` as the project's static assets.

## Cloudflare project — Build settings

In the dashboard → your `sshache` project → **Settings → Build**, set:

| Setting | Value |
| --- | --- |
| Root directory | `/`  *(not `/site`)* |
| Build command | *(empty)* |
| Deploy command | `npx wrangler deploy` |

Then **Retry deployment** (or push to `main`). The connected-repo build runs
`wrangler deploy`, which reads `wrangler.toml` and ships `site/`.

> Why these values: `npm run build` builds the **desktop app**, not the site,
> and `/site` as root hides `wrangler.toml`. Root `/` + empty build + the
> `[assets]` block is the whole story.

## Custom domain

Project → **Settings → Domains & Routes → Add → Custom domain → `sshache.com`**.
Cloudflare provisions the cert automatically (the zone is already in your account).

## Local deploy (optional)

```sh
npx wrangler login
npx wrangler deploy        # uploads ./site
```

## Already set up for SEO / serving

- `site/_headers` — security headers + 1-year cache on `/assets/*`.
- `site/robots.txt` + `site/sitemap.xml` — pointed at `https://sshache.com`.
- Per-page `<title>`, meta description, canonical, Open Graph + Twitter cards,
  JSON-LD (`SoftwareApplication` on the landing page, `TechArticle` on docs).
- `site/assets/og-image.png` (1200×630) social share image.

## After the domain is live

- Submit `https://sshache.com/sitemap.xml` in Google Search Console.
- Check the share preview with the Facebook Sharing Debugger / X Card Validator.
