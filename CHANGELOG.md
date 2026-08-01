

## v19.0.7 - XHTTP/REALITY exact config links + Trial domain

- Fixed x-ui/3x-ui remote VLESS xHTTP REALITY links so the bot preserves inbound parameters such as `path`, `host`, `mode`, `x_padding_bytes`, `extra`, nested REALITY `publicKey`, `fingerprint`, `serverNames`, `shortIds`, and `spiderX`.
- VLESS generated links now include `encryption=none`, matching modern x-ui/3x-ui share links.
- Added a dedicated domain override for test configs in the admin Trial Config section.
- Test config orders now store and apply `TRIAL_CONFIG_DOMAIN` the same way plan-specific domains are applied.
# IronBot v19.0.6

- Added target panel change inside plan edit screen.
- Admin can select the delivery panel of an existing plan from inline buttons.
- Added command support: `/editplan PLAN_ID|panel|PANEL_ID`.
- The bot validates that the selected panel exists and is enabled before saving.
- If the destination is remote x-ui/3x-ui, the bot reminds the admin to verify the plan inbound on that panel.

# IronBot v19.0.5

- Fixed IronPanel API connection test for same-server HTTPS URLs like `https://127.0.0.1:8001`.
- For loopback hosts only, IronBot can skip TLS hostname verification when `ALLOW_INSECURE_LOCAL_API_SSL=true`, so public-domain certificates no longer break local API calls.
- External panel URLs still use normal SSL verification.

# IronBot v19.0.4

## Panel Management Update

- Added full edit flow for panels from the admin bot panel.
- Added editable x-ui/3x-ui login URL.
- IronBot now tests the entered login URL, username, and password before saving changes.
- Editing IronPanel API address or API token is also tested before saving.
- Local x-ui panel can now be deleted for IronPanel/API-only deployments.
- When deleting a panel that is used by plans, dependent plans are disabled to prevent wrong delivery.
- Panel list now shows Login URL for remote x-ui/3x-ui panels.
- Panel test now uses the saved login URL instead of assuming `/login` from base URL.

## v19.0.3 - Plan edit, group delete, unlimited volume, per-plan domain

- Storefront plan buttons now show only the plan name after the user selects a group.
- Added admin UI to edit existing plans: name, volume, price, duration, inbound, audience, IP limit, and custom domain.
- Added safe group deletion from the admin plan manager. Deleting a group removes the plans inside that group after confirmation.
- Added unlimited-volume plans: set plan volume to `0`, `unlimited`, or `نامحدود`.
- Added per-plan config domain. The selected plan can override the config host used in generated links.
- Added admin commands: `/editplan`, `/setplandomain`, and `/delgroup`.

## v19.0.2 - Optional local x-ui database for IronPanel/API-only installs

- Local x-ui DB is no longer required when the bot is used with IronPanel API or remote panels.
- Fixed repeated Telegram warning: `⚠️ خطای watcher: DB not found` on servers without x-ui installed.
- Local x-ui watcher and usage monitor now skip silently when `/etc/x-ui/x-ui.db` is missing.
- The default local x-ui panel is auto-marked disabled when no local DB exists and no local orders depend on it.
- Installer no longer asks for a local x-ui inbound ID when x-ui DB is missing.
- Systemd service no longer depends on `x-ui.service`.

## v19.0.1 - Fixed SkyShield LicensePanel endpoint

- Fixed the IronBot license server to `http://license.skyshield.space:8002`.
- License checks now use the LicensePanel `/api/check` flow only.
- Disabled changing the license server with `/setlicenseserver` or installer menu.
- Forced license network calls to direct `--noproxy` mode so the configured endpoint remains stable.

# Changelog

## v19.0.0

- Added first-class IronPanel API delivery support.
- The existing panel management section can now add multiple IronPanel targets alongside x-ui / 3x-ui panels.
- Added IronPanel panel wizard: base URL, API token, and public host.
- Added per-plan IronPanel protocol selection.
- Orders created for IronPanel plans are delivered through IronPanel API v2 and save the returned subscription URL.
- Existing x-ui / 3x-ui delivery logic is preserved.
- Added bot-side LicensePanel compatibility through `/api/check` without requiring LicensePanel changes.
- Pro/Admin/Trial licenses can approve the bot when the LicensePanel response is valid and the required feature/type is allowed.
- Added `/setlicensehost` so the bot can use the same LicensePanel activation identity as one IronPanel installation.

## v18.12.2

- Fixed invoice creation compatibility with multi-panel purchases.
- Resolved `_create_invoice_after_optional_name() got an unexpected keyword argument 'panel_id'`.
- Based on v18.12.1 GitHub release with the latest runtime patch.

## v18.12.1
- Fixed buy group keyboard crash: `too many values to unpack (expected 2)`.
- Kept IP-limit features from v18.12.
- Updated GitHub release package for Iron Bot.

## v18.12 / Iron Bot GitHub Edition

- Added per-plan IP limit.
- `0` IP limit means unlimited IPs.
- Added admin panel section for IP-limit suspension duration.
- Temporarily disables configs that exceed the allowed IP count and automatically re-enables them after the configured duration.
- Keeps previous multi-panel, trial config, special customer, plan-group, wallet, multi-admin, QR toggle, and fast delivery features.

## v18.11.4

- Per-panel QR-code delivery toggle.
- Fast delivery retry interval set to 1 second for purchased and trial configs.
- Trial config delivery fixes.

## v18.10

- Trial configuration system with admin-configurable limits, panel, inbound, volume, and duration.
- Default texts for welcome, rules, connection guide, and support.

## v18.9

- Multi x-ui / 3x-ui panel support.
- Per-plan panel selection.

## v18.x

- Branded repository as **Iron Bot**.
- Plan groups and audience filtering for normal and special customers.
- Special customer management and agency request workflow.
- Per-plan pricing and special-customer custom GB pricing.
- Admin bulk free config creation.
- Multi-admin support and approval locking.
- Wallet increase/decrease management by admins.
