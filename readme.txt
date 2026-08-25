=== LocaSentinel – Geo-Security & Fraud Prevention for IP2Location ===
Contributors: mardhiahnetwork
Tags: locasentinel, ip2location, geoip, security, 2fa, firewall, comment spam, impossible travel, captcha, redis
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Geo-blocking firewall, impossible travel 2FA verification, comment spam filtering, path rate limiting, and proxy detection powered by IP2Location.io.

== Description ==

LocaSentinel provides geolocation-based access control, impossible travel detection with email OTP verification, proxy blocking, anti-spam path rate limiting, and comment spam filtering for WordPress using the IP2Location.io API.

Built for the **IP2Location Programming Contest 2026** by **Mardhiah Air Network**, LocaSentinel follows PSR-4 architecture with zero external PHP dependencies, Redis and transient caching, and native WordPress admin UI patterns.

### Core Modules

* **Geo Firewall Rules**:
  * Blocklist or allowlist by country with regional preset groups (North America, South America, European Union, ASEAN, Middle East & GCC, Asia-Pacific, Common Spam Origins).
  * Granular blocking by region/state, city name, postal/ZIP code, and ASN / organization.
  * Proxy, VPN, and hosting data center detection (`is_proxy == true`).
  * Extended crawler allowlist (Search Engines, Social Media Previewers, SEO Tools, AI Crawlers, Feeds, and custom regex) with reverse DNS anti-spoofing verification.
  * IP and CIDR exception lists (IPv4 and IPv6).

* **Endpoint & Discussion Protection**:
  * **Comment Spam & Geo Shield**:
    * Intercepts and rejects new comment submissions from forbidden countries or anonymous proxies before database insertion.
    * Dynamically hides comment forms, discussion lists, and comment counters from visitors originating in restricted territories.
    * Filters historical spam comments dynamically based on commenter IP address and current geo rules.
  * **XML-RPC Protection**: Blocks unauthorized XML-RPC requests and pingbacks commonly targeted by DDoS and brute-force campaigns.
  * **Login Protection**: Restricts access to `wp-login.php` by geographical region.
  * **REST API & Frontend**: Optional filtering for REST endpoints and frontend visitor traffic.

* **Anti-Spam Whole-Website Rate Limiting & CAPTCHA Challenge**:
  * Monitors request frequency per URL path. When an IP exceeds configured rate limits, the IP is locked into a challenge state in the database for 24 hours. Waiting or refreshing does not bypass the challenge.
  * Supports Cloudflare Turnstile, hCaptcha, Google reCAPTCHA v2 (Checkbox), and Google reCAPTCHA v3 (Invisible).
  * Solved challenges grant 24 hours of whole-website clearance for legitimate visitors while strictly preserving 403 blocks for restricted geographical origins.
  * Optional defense setting to challenge allowed/whitelisted country traffic if repetitive spam thresholds are exceeded.

* **Impossible Travel Velocity Detection & 2FA**:
  * Computes physical velocity between successive user logins using Haversine great-circle distance formulas and timestamps.
  * Challenges logins that exceed physical travel thresholds (configurable speed and minimum distance) with a 6-digit email OTP.
  * **Dynamic Mobile Carrier Tolerance**: Prevents false-positive lockouts for domestic mobile users whose dynamic cellular IPs hop between regional gateways.
  * **SMTP Safety Check**: Detects SMTP configurations and mutes OTP when SMTP is absent to prevent admin lockouts.
  * **Webhook Alerts with `{{variable}}` Templating**: Dispatches security notifications to Discord, Slack, Telegram, or custom endpoints with full template variable substitution.

* **Cache & CDN Compatibility**:
  * Redis in-memory auto-driver for high-performance lookup caching and log debouncing.
  * Sends `DONOTCACHEPAGE` and `X-LiteSpeed-Vary` headers to prevent blocked responses from being cached.
  * Compatible with LiteSpeed Cache, WP Rocket, W3 Total Cache, WP Super Cache, WP Fastest Cache, and SG Optimizer.
  * Automatically resolves real visitor IPs behind Cloudflare (`CF-Connecting-IP`), Sucuri (`X-Sucuri-ClientIP`), Fastly, Akamai, AWS CloudFront, and Nginx reverse proxies.

* **Security Audit Logging & Analytics**:
  * Custom indexed database table storing timestamp, IP, country, city, ASN, HTTP method, URL path, target endpoint, action verdict, username, user-agent, device type, browser, OS, and aggregated hit count.
  * Real-time AJAX POST filtering without page reloads.
  * Anti-spam log debouncing and noise filtering (ignoring favicons, robots.txt, sitemaps, static assets).
  * Search, filter, and CSV export capabilities with automatic retention cleanup cron.

== Installation ==

1. Upload the `ip2location-sentinel` directory to `/wp-content/plugins/`.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Navigate to **LocaSentinel > API & Settings** and enter your [IP2Location.io](https://www.ip2location.io) API key.
4. Click **Test Connection** to verify your API credentials.
5. Configure your access rules under **LocaSentinel > Geo Firewall** and **Endpoint Protection**.

== Frequently Asked Questions ==

= Does this plugin work with caching plugins? =
Yes. LocaSentinel automatically attaches `DONOTCACHEPAGE` constants and cache vary headers to prevent static cache engines from caching blocked pages or serving blocked pages to legitimate visitors.

= What happens if SMTP is not configured on my server? =
The plugin checks for active SMTP mailer plugins before challenging administrators with email OTP. If SMTP is not detected, OTP challenges are safely bypassed to avoid accidental admin lockouts.

= What is the difference between Blocklist and Allowlist mode? =
* **Blocklist**: Blocks traffic originating from selected countries while allowing all others.
* **Allowlist**: Allows traffic strictly from selected countries while blocking everyone else.

= How are API calls cached? =
Geolocation lookup responses from IP2Location.io are cached in memory (Redis when available) and WordPress transients (default 24 hours). This reduces API query consumption while maintaining fast page load speeds.

= Can I use the free IP2Location.io API tier? =
Yes. The plugin is built and optimized to work with the free IP2Location.io tier (50,000 free queries per month).

== Screenshots ==

1. Dashboard with KPI metrics, real-time traffic chart, and live IP inspection tool.
2. Geo Firewall rules with regional presets, proxy blocking, and ASN filtering.
3. Endpoint protection settings for login, XML-RPC, and comment spam prevention.
4. Impossible travel velocity settings, domestic carrier tolerance, and webhook integrations.
5. Security audit log viewer with MobileDetect device badges, search, filtering, and CSV export.
6. Cache & CDN diagnostic tools and HTTP header inspector.
7. API configuration with live connection test and key validation.
8. Public 403 Forbidden Geo-Blocked response shield template.
9. Public 429 Anti-Spam whole-website CAPTCHA verification challenge template.

== Credits ==

* Geolocation data and threat intelligence provided by IP2Location.io (IP2Location Programming Contest 2026).
* 271 local SVG country flags from Flag Icons by Lipis (Panayiotis Lipiridis), released under the MIT License.

== Changelog ==

= 1.0.0 =
* Initial release for the IP2Location Programming Contest 2026 under the LocaSentinel brand.
* PSR-4 compliant architecture with zero external PHP dependencies.
* Integrated IP2Location.io API client with transient and Redis in-memory caching.
* Country, region, city, zip, ASN, proxy, and IP filtering with regional presets.
* Extended crawler allowlist with reverse DNS verification.
* Anti-spam path rate limiting with Cloudflare Turnstile, hCaptcha, and Google reCAPTCHA.
* Impossible travel velocity detection with Haversine formula and email OTP verification.
* Built-in MobileDetect parser for device, browser, and OS logging.
* Cellular carrier detection and domestic mobile tolerance.
* Multi-platform security webhook notifications (Discord, Slack, Telegram, Custom) with placeholder templates.
* Reverse proxy IP resolution (Cloudflare, Sucuri, AWS, Nginx).
* Cache engine vary integration (LiteSpeed, WP Rocket, W3TC, Super Cache, Redis).
* Dedicated audit log table with debounced hit counting, CSV export, and retention cron.
