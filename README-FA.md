# Iron Bot

نسخه فعلی: **v19.0.0**

**Iron Bot** ربات فروش و مدیریت کانفیگ برای پنل‌های VPN است. این نسخه پشتیبانی قبلی از **x-ui / 3x-ui** را حفظ می‌کند و اتصال مستقیم به **IronPanel API** را هم اضافه می‌کند؛ یعنی می‌توانید چند IronPanel را هم‌زمان داخل همین ربات اضافه کنید.

مالک گیت‌هاب: [Unknown-sir](https://github.com/Unknown-sir)  
نام ریپازیتوری: `IronBot`

> مسیرهای داخلی نصب برای سازگاری با نسخه‌های قبلی watcher2 حفظ شده‌اند تا آپدیت روی سرورهای قبلی بدون از دست رفتن اطلاعات انجام شود.

---

## امکانات اصلی

- منوی مشتری و پنل مدیریت تلگرام
- پشتیبانی از چند مدیر ربات
- جلوگیری از تأیید دوباره فاکتور یا افزایش شارژ توسط مدیر دیگر
- کیف پول، پرداخت از کیف پول و افزایش/کسر موجودی توسط مدیر
- مشتری عادی و مشتری ویژه
- درخواست نمایندگی/ویژه شدن توسط کاربر و تأیید یا رد توسط مدیر
- گروه‌بندی پلن‌ها، قیمت مستقل، مدت مستقل، پنل تحویل مستقل و محدودیت IP مستقل برای هر پلن
- مقدار `0` برای مدت یعنی بی‌نهایت؛ مقدار `0` برای محدودیت IP یعنی نامحدود
- توقف موقت کانفیگ در صورت عبور از تعداد IP مجاز و فعال‌سازی خودکار بعد از زمان تعیین‌شده توسط مدیر
- اتصال هم‌زمان به چند پنل **IronPanel**، **x-ui** و **3x-ui**
- امکان افزودن چند IronPanel از همان بخش مدیریت پنل‌ها
- انتخاب پروتکل‌های IronPanel برای هر پلن، مثل `xray`، `openvpn`، `wireguard`، `hysteria2`، `ocserv`، `l2tp`، `pptp` و `telegram_proxy`
- فعال/غیرفعال کردن ارسال QR برای هر پنل به صورت جداگانه
- سیستم کانفیگ تست با محدودیت قابل تنظیم
- ساخت عمده رایگان کانفیگ برای مدیر
- نام‌گذاری امن کانفیگ‌ها و جلوگیری از خطای نام تکراری
- ارسال لینک سابسکریپشن وقتی پنل مقصد لینک ساب تحویل بدهد یا برای آن لینک تنظیم شده باشد
- retry تحویل کانفیگ با فاصله ۱ ثانیه
- متن‌های پیش‌فرض برای خوش‌آمد، قوانین، راهنمای اتصال و پشتیبانی
- هماهنگی لایسنس ربات با لایسنس‌های Pro در LicensePanel

---

## پیش‌نیازها

- سرور لینوکسی با systemd
- Python 3
- ابزارهای `curl`، `sqlite3`، `qrencode` و `openssl`
- حداقل یک پنل مقصد: IronPanel API، x-ui یا 3x-ui
- توکن ربات تلگرام از BotFather
- Chat ID مدیر

اسکریپت نصب در صورت امکان پکیج‌های لازم را روی Debian/Ubuntu و توزیع‌های RedHat-based نصب می‌کند.

---

## نصب سریع از GitHub

```bash
sudo apt update
sudo apt install -y git

git clone https://github.com/Unknown-sir/IronBot.git
cd IronBot
sudo bash install.sh
```

بعد داخل تلگرام به ربات پیام بدهید:

```text
/admin
```

---

## آپدیت از فایل zip

```bash
cd /tmp
unzip IronBot.zip
cd IronBot
sudo cp watcher2_core.py /opt/watcher2/watcher2_core.py
sudo cp install.sh /opt/watcher2/install.sh
sudo chmod +x /opt/watcher2/watcher2_core.py /opt/watcher2/install.sh
sudo python3 -m py_compile /opt/watcher2/watcher2_core.py
sudo systemctl restart xui-watcher2
sudo journalctl -u xui-watcher2 -n 120 --no-pager
```

---

## مسیرهای مهم نصب

```text
/opt/watcher2/watcher2_core.py
/etc/watcher2/config.env
/var/lib/watcher2/watcher2.sqlite
/var/lib/watcher2/qrcodes
/var/log/watcher2
```

نام سرویس systemd:

```text
xui-watcher2
```

---

## تنظیمات

فایل تنظیمات اصلی:

```bash
/etc/watcher2/config.env
```

بیشتر تنظیمات از داخل پنل مدیریت ربات قابل تغییر هستند. توکن ربات و تنظیمات حساس را می‌توانید از منوی نصب یا مستقیم داخل `config.env` تنظیم کنید.

کلیدهای جدید نسخه `v19.0.0`:

```text
LICENSE_PANEL_HOST=''
LICENSE_ACCEPT_LICENSE_TYPES='pro,admin,trial'
LICENSE_REQUIRE_FEATURE='sales_bot'
IRONPANEL_DEFAULT_PROTOCOLS='xray,openvpn,wireguard,hysteria2,ocserv,l2tp,pptp,telegram_proxy'
```

---

## اتصال چند پنل

از پنل مدیریت تلگرام وارد شوید:

```text
/admin → مدیریت پنل‌ها
```

هنگام افزودن پنل، ربات نوع پنل را می‌پرسد:

1. **IronPanel API**
2. **x-ui / 3x-ui**

### پنل IronPanel API

برای هر IronPanel این موارد را وارد می‌کنید:

- نام پنل
- آدرس اصلی IronPanel، مثل `https://panel.example.com`
- API Token ساخته‌شده برای مسیرهای `/api/v2`
- هاست عمومی برای نمایش و هماهنگی لایسنس

می‌توانید چند IronPanel اضافه کنید. هنگام ساخت پلن فروش، همان IronPanel مقصد را انتخاب می‌کنید و پروتکل‌های مجاز همان پلن را وارد می‌کنید. ربات کاربر را از طریق API v2 داخل IronPanel می‌سازد و لینک سابسکریپشن برگشتی را ذخیره می‌کند.

### پنل x-ui / 3x-ui

برای هر پنل x-ui یا 3x-ui این موارد را وارد می‌کنید:

- نام پنل
- آدرس پنل همراه پورت، مثل `http://1.2.3.4:2053`
- Web Base Path اگر پنل مسیر مخفی دارد، مثل `/secret`
- نام کاربری پنل
- رمز عبور پنل
- هاست عمومی برای ساخت لینک کانفیگ
- لینک سابسکریپشن در صورت نیاز
- وضعیت ارسال QR همان پنل

---

## هماهنگی با لایسنس Pro در LicensePanel

در این نسخه فقط سمت ربات تغییر کرده و لازم نیست LicensePanel را تغییر بدهید.

ربات از این نسخه لایسنس را فقط از آدرس ثابت SkyShield LicensePanel چک می‌کند:

```text
http://license.skyshield.space:8002/api/check
```

آدرس سرور لایسنس از کاربر پرسیده نمی‌شود و دستور `/setlicenseserver` دیگر امکان تغییر آدرس را ندارد. لایسنس Pro وقتی پذیرفته می‌شود که پاسخ LicensePanel معتبر باشد و یکی از این شرایط برقرار باشد:

- نوع لایسنس داخل لیست مجاز باشد، مثل `pro`، `admin` یا `trial`؛ یا
- features لایسنس شامل قابلیت موردنیاز باشد که پیش‌فرض آن `sales_bot` است.

برای اینکه یک لایسنس Pro هم یک IronPanel و هم یک Iron Bot را تأیید کند، هاست لایسنس ربات را برابر public_host همان IronPanel بگذارید:

```text
/setlicensehost panel.example.com
/setlicense YOUR_LICENSE_KEY
```

یا مستقیم داخل فایل زیر تنظیم کنید:

```text
/etc/watcher2/config.env
LICENSE_PANEL_HOST='panel.example.com'
```

---

## محدودیت IP پلن‌ها

هنگام تعریف هر پلن، ربات از مدیر مقدار حداکثر IP مجاز را می‌پرسد.

- مقدار `0` یعنی نامحدود.
- اگر عددی بیشتر از صفر وارد شود، کانفیگ‌های ساخته‌شده از آن پلن مانیتور می‌شوند.
- اگر تعداد IPهای دیده‌شده از حد مجاز بیشتر شود، کانفیگ به‌صورت موقت غیرفعال می‌شود.
- مدت توقف موقت از بخش محدودیت IP در پنل مدیریت قابل تنظیم است.

---

## کانفیگ تست

از پنل مدیریت بخش کانفیگ تست را باز کنید. موارد قابل تنظیم:

- هر کاربر چند بار بتواند کانفیگ تست بگیرد
- ریست محدودیت تست برای همه کاربران
- ریست محدودیت تست برای یک کاربر خاص با Chat ID
- پنل تحویل تست
- inbound تست برای پنل‌های x-ui / 3x-ui
- حجم تست
- مدت تست؛ مقدار `0` یعنی بی‌نهایت

---

## نکات امنیتی

- فایل واقعی `config.env` را روی GitHub قرار ندهید.
- دیتابیس، کلید خصوصی، کلید لایسنس، توکن ربات و API Tokenها را commit نکنید.
- اگر ارسال QR از طریق پروکسی کند بود، QR همان پنل را از پنل مدیریت غیرفعال کنید.


### نکته نصب بدون x-ui

IronBot می‌تواند روی سروری نصب شود که x-ui روی آن نصب نیست. در این حالت دیتابیس محلی `/etc/x-ui/x-ui.db` اختیاری است، watcher دیگر پیام تکراری `DB not found` برای ادمین‌ها ارسال نمی‌کند، و می‌توانید از منوی ادمین تلگرام IronPanel یا پنل‌های API را اضافه کنید.


## v19.0.6 Plan target panel edit

Admins can now change the delivery panel of an existing sales plan from the plan edit menu.


### v19.0.7
Fixes exact VLESS xHTTP REALITY link generation and adds test config domain override.

### v19.0.8

- IronPanel plans now accept Cisco/OpenConnect as `ocserv`, `cisco`, `openconnect`, or `anyconnect`.
- Xray links generated directly by the bot no longer keep an old visible `ironpanel-` prefix in the config remark.


## تغییرات v19.0.9

- در حالت IronPanel API دیگر Inbound درخواست نمی‌شود.
- ساخت عمده: پنل مقصد، نام پایه، بازه شماره، طول رمز و نوع رمز انتخاب می‌شود.
- اگر قیمت هر گیگ 0 یا خالی باشد، خرید حجم دلخواه برای کاربر غیرفعال است و فقط پلن‌ها نمایش داده می‌شوند.


## v19.0.10 - Mandatory Channel Join / ادد اجباری

Admin panel now includes `📢 ادد اجباری`. When enabled, users must be members of the configured Telegram channel before using the bot. The bot checks that it is an administrator in the channel before saving/enabling the channel.


## تغییر v19.0.11

اگر مقصد ساخت کانفیگ در IronBot از نوع **IronPanel API** باشد، خروجی فروش و کانفیگ تست فقط به شکل لینک ساب تحویل داده می‌شود. زیر لینک ساب، راهنمای کاربر نمایش داده می‌شود که وارد لینک شود و کانفیگ‌های موجود را کپی کند یا خود لینک را در بخش Subscription برنامه وارد کند.

## تغییر v19.0.12

در تحویل کانفیگ تست و پلن‌های فروش از نوع **IronPanel API**، متن راهنما کوتاه‌تر شده و فقط روش بازکردن صفحه ساب و کپی‌کردن کانفیگ را نمایش می‌دهد. همچنین دکمه شیشه‌ای **«🔗 باز کردن لینک ساب»** زیر پیام قرار می‌گیرد و همان لینک ساب را مستقیم باز می‌کند.

