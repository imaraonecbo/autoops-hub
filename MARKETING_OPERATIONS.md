# AutoOps Hub international marketing operations

## Acquisition tracking

The production backend records idempotent events for:
- `signup_completed` when Supabase Auth creates an account.
- `checkout_started` after a server-created PayPal order is saved.
- `purchase_completed` only after the PayPal capture is verified and applied to the account ledger.

Public landing-page links pass UTM source, medium, campaign, and content into the production workspace. The backend records first-touch and last-touch campaign tags in Supabase without storing raw referrer URLs or copying email addresses into analytics metadata.

The owner-only report endpoint is `GET /api/v1/marketing/report`. It requires a valid signed-in app session and `MARKETING_REPORT_ADMIN_EMAIL` configured on the production Render service. It returns aggregate signups, checkouts, purchases, and captured USD revenue by source / medium / campaign. Historical conversions are not backfilled. The report does not include social impressions or anonymous page-view counts; use connected social analytics for those metrics.

## Social publishing

Metricool must be connected in ChatGPT and each intended social account must be authorized by the account owner inside Metricool. Until that authorization is complete, no social account is treated as connected and no post is claimed as scheduled or published. Start with `public-site/growth-calendar.md`, then schedule platform-specific versions rather than blindly posting identical text everywhere.

## Marketing email safety

This repository does not currently send marketing email. Do not send campaigns to scraped or purchased lists. Before enabling sending, connect an email marketing provider, verify the sender domain, collect explicit opt-in, preserve unsubscribe/suppression records, and test a confirmation and unsubscribe path. Product account creation is not consent to marketing email. Count verified PayPal captures as purchases.

## Release verification

1. Run unit, checkout, and webhook security tests.
2. Check `/api/v1/health` for database reachability and payment readiness.
3. Sign in as the configured owner and request `/api/v1/marketing/report`.
4. Use a tagged landing URL and confirm a `signup_completed` event is recorded.
5. Use PayPal sandbox for checkout verification; never create a live payment merely to test attribution.
6. Confirm Metricool's connection and scheduled post status inside its authenticated interface before announcing social automation as active.
