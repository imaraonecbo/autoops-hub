# AutoOps Hub

AutoOps Hub is a web app for account-linked structured-file cleanup and reporting. It includes a public guide site, a FastAPI backend, Supabase authentication/data storage, and PayPal checkout for one-time plan purchases.

## Try it

- **Live workspace:** https://autoops-hub-production.onrender.com/
- **Public website:** https://autoops-hub-public.onrender.com/
- **Kenya CSV example:** https://autoops-hub-public.onrender.com/kenya-csv-stock-cleanup.html
- **Fictional sample CSV:** https://autoops-hub-public.onrender.com/examples/kenya-small-shop-stock.csv
- **Source repository:** https://github.com/imaraonecbo/autoops-hub
- **Production source branch:** `production-paypal-live-20261028`

The current deployment uses Render free plans. Free hosting has limitations and the backend may sleep when idle; a custom domain is not required to use the existing links.

## Current behavior

- CSV cleanup normalizes column headings and trims surrounding whitespace.
- The free allowance supports up to **two jobs** and **100 data rows per CSV job**.
- Other file-processing workflows depend on plan eligibility; check the live app for current limits.
- The app returns a processing summary and output for the user to review.
- PayPal checkout supports one-time plans when production payment settings are enabled.

## Architecture

- `public-site/` — static HTML guides, sitemap, robots.txt, and sample data.
- `backend/main.py` — FastAPI application, auth, processing, payments, and readiness routes.
- `backend/file_processors.py` — format-aware CSV, Excel, JSON, and log workflows.
- Render — Python backend and public static site.
- Supabase — authentication and database.
- PayPal — checkout and capture, depending on production settings.

## Verify safely

- Readiness endpoint: https://autoops-hub-production.onrender.com/api/v1/health
- Start with the fictional sample CSV.
- This is a formatting aid, not a stock, bookkeeping, tax, or financial reconciliation system.
- Do not upload credentials, passwords, payment secrets, private logs, or personal information unless you are authorized to process it.
- The public site is the source of current pricing and plan details.

## Static hosting options

The public site already runs as a free Render static site. The repository also contains `.github/workflows/publish-public-site.yml`, which publishes `public-site/` to GitHub Pages from the default branch when GitHub Pages is enabled and the workflow succeeds. Check Actions/Pages settings before treating the GitHub Pages URL as live.

Cloudflare Pages can host the same `public-site/` folder under a free `pages.dev` URL. It requires the owner to connect their Cloudflare account to this GitHub repository once; a custom domain is not required.

## Organic growth

The public site includes a sitemap and robots.txt. The Kenya-first, copy-ready organic distribution plan is in `public-site/growth-calendar.md`. It prioritizes real examples for Kenyan small businesses before widening to international audiences. Traffic and sales are not guaranteed; use actual signups and verified payments to judge results.
