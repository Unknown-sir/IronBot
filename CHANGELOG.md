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
