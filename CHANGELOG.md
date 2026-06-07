# Changelog

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

## v18.12.2

- Fixed invoice creation compatibility with multi-panel purchases.
- Resolved `_create_invoice_after_optional_name() got an unexpected keyword argument 'panel_id'`.
- Based on v18.12.1 GitHub release with the latest runtime patch.

