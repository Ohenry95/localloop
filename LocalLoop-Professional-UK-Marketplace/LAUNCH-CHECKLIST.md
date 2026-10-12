# LocalLoop launch checklist

## Build and hosting
- [ ] GitHub repo contains the full project, excluding secrets.
- [ ] Render web service uses Python runtime and a managed PostgreSQL database.
- [ ] Production secret key is long, random and stored only in hosting environment variables.
- [ ] HTTPS works; `/health` returns OK.
- [ ] Database backups and restore procedure tested.

## Stripe test mode
- [ ] Stripe Connect is enabled and platform account is eligible.
- [ ] Seller onboarding completes; charges/transfers status is correctly refreshed from Stripe.
- [ ] Checkout uses test mode and never takes real money.
- [ ] 15% application fee and seller destination are correct.
- [ ] `checkout.session.completed` webhook marks booking paid only when Stripe says paid.
- [ ] `checkout.session.expired` releases reserved inventory.
- [ ] Duplicate, delayed and out-of-order webhooks tested.
- [ ] Refunds, disputes, cancellations and seller payout behavior documented and tested.

## Product and operations (must finish before public launch)
- [ ] Email verification and password reset.
- [ ] Rate limiting, abuse controls, admin audit logs and monitoring.
- [ ] Inventory locking/atomic reservation tests under concurrent checkout.
- [ ] Voucher redemption by approved seller; refund/revoke rules.
- [ ] Customer support, complaints, cancellations and refunds process.
- [ ] Final UK terms, privacy notice, cookies, seller agreement and tax/accounting review.
- [ ] Accessibility, mobile, browser and security testing.
- [ ] Stripe has confirmed account eligibility and any required adult/guardian arrangement.
- [ ] Explicit approval to switch to live keys after test sign-off.
