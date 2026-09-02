# Changelog

## v19.1.0 — Ban / Unban users + Admin management

- Added **🚫 مسدود کردن کاربر** button to the Telegram admin panel.
- Admin sends a Chat ID; the bot asks for confirmation, then blocks the user.
- Banned users receive **no response** from the bot in any situation — text, callback buttons, and media are all silently ignored.
- Added **✅ آنبن کردن** button to list banned users and unban them with a single tap.
- Ban data is stored in the `banned_users` SQLite table and survives service restarts.
- The primary admin and currently acting admin cannot be banned.
- Added `👮 مدیریت مدیرها` to the Telegram admin panel.
- Lists every configured bot admin and marks the protected primary admin/current admin.
- Added two-step `🗑 حذف` confirmation for removable admins.
- Prevents removing the first configured admin, the currently acting admin, or the last remaining admin.
- Removing an admin immediately updates `ADMIN_CHAT_IDS` and reloads runtime configuration; no database migration is required.
- The removed account receives a notification and can still use the bot as a normal user.
- Existing `/addadmin` and add-admin flow remain compatible.
- Updated remote-panel User-Agent to `IronBot/19.1.0`.

## v19.0.16 — Single config with multi-user capacity

- Changed multi-user plan semantics: a 2/3/N-user plan now creates exactly **one** service/config/subscription link.
- `user_count` is now the maximum users/distinct IPs allowed to share that single config (1..100), not the number of configs to provision.
- x-ui / 3x-ui clients receive native `limitIp = user_count` on the same client.
- IronPanel orders keep one API user; `connection_limit` is patched to the selected capacity and IronBot's API-token IP monitor uses the same limit as a second guard.
- IronPanel suspend/resume for IP-limit enforcement now uses `/api/v2/users/{id}` with API Token and never falls back to x-ui `/login`.
- v19.0.15 bundle/child-order provisioning is bypassed. Retry/approval cannot create additional configs for a multi-user plan.
- Plan wizard, edit, list, detail and invoice text now explicitly say "one config" and show its user/IP capacity.
- Existing v19.0.15 bundle tables are retained only for database compatibility; already-created duplicate remote services are not deleted automatically.

# IronBot v19.0.15

- Added `user_count` to sales plans (1..100). A plan can now sell two or more independent configs/users for one total invoice price.
- Multi-user plan volume, duration, panel, protocol set and IP limit are applied independently to each generated service.
- Approval provisions the first service through the normal atomic approval flow, then creates only missing bundle children; retrying approval is idempotent and does not charge or duplicate completed services.
- Existing plans/orders migrate safely to one user. Orders created by older builds can recover a later multi-user plan count when no bundle snapshot exists.
- Plan create/edit/list/detail and invoice text show the number of users and clarify that the entered price is the total bundle price.
- v19.0.14 on-demand panel authentication remains active; the remote x-ui User-Agent is now `IronBot/19.0.15`.

# IronBot v19.0.14

- Removed background one-minute x-ui login attempts from the IP-limit monitor by default.
- IronPanel session/IP checks now use `/api/v2/sessions` with the configured API token and never POST to the panel `/login` form.
- Remote x-ui/3x-ui login is now on-demand only for operations that actually require an authenticated session (for example create/update/test/manual checks).
- Empty remote username/password is rejected locally before any HTTP login request is sent.
- Successful remote x-ui session cookies are cached for 15 minutes by default (`REMOTE_PANEL_SESSION_TTL=900`) to avoid repeated logins during nearby operations.
- Updated the remote login User-Agent to `IronBot/19.0.14`.

# IronBot v19.0.13

- Added an admin section for delayed automatic approval of agency/special-customer requests.
- Admin can enable/disable the feature and set the waiting time in minutes.
- Only rows in `agency_requests` that are still `pending` after the delay are eligible; purchase orders are not auto-approved.
- Manual approval, manual rejection, and timer approval now use conditional atomic status changes to prevent race-condition overwrites.

# IronBot v19.0.12

- دو جمله اضافی از متن راهنمای تحویل لینک ساب IronPanel حذف شد.
- در تحویل کانفیگ تست و پلن‌های فروش IronPanel یک دکمه شیشه‌ای «باز کردن لینک ساب» اضافه شد.
- دکمه با URL مستقیم، همان لینک ساب تحویلی را در تلگرام باز می‌کند.
- fallback متنی IronPanel نیز همچنان فقط لینک ساب را تحویل می‌دهد.

# IronBot v19.0.11

- وقتی کانفیگ تست یا پلن فروش از پنل نوع IronPanel API ساخته شود، ربات فقط لینک ساب IronPanel را تحویل می‌دهد.
- برای IronPanel API دیگر لینک مستقیم کانفیگ یا QR جداگانه ارسال نمی‌شود.
- متن راهنمای زیر لینک ساب اضافه شد تا کاربر بداند باید وارد لینک ساب شود، کانفیگ موجود را کپی کند یا لینک را در بخش Subscription برنامه وارد کند.
# IronBot v19.0.10 - Mandatory Channel Join

- Added admin section: `📢 ادد اجباری`.
- Admin can set a Telegram channel and enable/disable mandatory membership.
- The bot validates that it is administrator in the configured channel before saving/enabling it.
- Users who are not members receive two inline buttons: join channel and `عضو شدم`.
- Pressing `عضو شدم` checks Telegram membership via `getChatMember` and only then allows bot usage.

# IronBot v19.0.9

- IronPanel API delivery no longer asks for inbound in plan, trial and bulk-create flows.
- Added admin bulk config builder with target panel selection, username base + numeric range, random password length/type, duration and unlimited traffic support.
- Bulk IronPanel API orders pass the generated password to IronPanel for OpenVPN/Cisco/L2TP-style credentials.
- Custom GB purchase is hidden and blocked when the effective per-GB price is empty or 0; users can only buy defined plans.
- Keeps v19.0.8 Cisco/OpenConnect/ocserv aliases and clean Xray labels.
