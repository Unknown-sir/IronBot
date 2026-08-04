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
