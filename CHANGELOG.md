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
