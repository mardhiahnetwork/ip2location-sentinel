<?php
/**
 * Zero-Dependency MobileDetect & Extended Crawler / User-Agent Parser Engine
 *
 * Provides detection for Mobile, Tablet, Desktop, Operating Systems, Browsers,
 * Search Engines, Social Previewers, SEO Crawlers, AI Bots, and Custom Regex Patterns.
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class UserAgent {

	/**
	 * Tablet regex patterns (based on Mobile-Detect)
	 */
	private const TABLET_REGEX = '/iPad|PlayBook|Silk|Kindle|TouchPad|Xoom|Kobo|Tablet|SM-T[0-9]+|GT-P[0-9]+|MediaPad|Nexus\s+(?:7|9|10)|MI\s+PAD|Tab\s+[0-9A-Z]+|(?:Android(?!.*Mobile))/i';

	/**
	 * Mobile phone regex patterns (based on Mobile-Detect)
	 */
	private const MOBILE_REGEX = '/Mobile|iPhone|iPod|Android|BlackBerry|BB10|IEMobile|WPDesktop|Opera\s+Mobi|Opera\s+Mini|Fennec|Windows\s+Phone|Lumia|HTC|LG[-0-9a-zA-Z]+|MOT-[0-9a-zA-Z]+|Samsung|SAMSUNG|Galaxy|HUAWEI|HONOR|Xiaomi|Redmi|POCO|OnePlus|OPPO|vivo|realme|Pixel|SonyEricsson|Symbian|ZTE|Meizu/i';

	/**
	 * General Bot, spider, and crawler regex patterns
	 */
	private const BOT_REGEX = '/bot|crawler|spider|crawling|slurp|facebookexternalhit|curl|wget|python|urllib|guzzle|aiohttp|httpclient|postman|insomnia|go-http-client|apache-httpclient|headlesschrome|semrush|ahrefs|mj12|dotbot|yandex|baidu|duckduck|bingbot|googlebot|gptbot|claudebot|perplexity/i';

	/**
	 * Search Engine Crawler regex patterns
	 */
	private const SEARCH_ENGINE_REGEX = '/Googlebot|Google-Inspection|Mediapartners-Google|Feedfetcher-Google|bingbot|BingPreview|Slurp|Baiduspider|YandexBot|DuckDuckBot|Applebot|Yeti|Sogou|SeznamBot|Qwantify|Exabot/i';

	/**
	 * Social Media Link Previewer regex patterns
	 */
	private const SOCIAL_BOT_REGEX = '/facebookexternalhit|Facebot|Twitterbot|LinkedInBot|Pinterest|WhatsApp|TelegramBot|Discordbot|Slackbot|SkypeUriPreview|Viber|Mastodon/i';

	/**
	 * SEO & Site Uptime Monitoring regex patterns
	 */
	private const SEO_MONITORING_REGEX = '/AhrefsBot|SemrushBot|DotBot|MJ12bot|Rogerbot|MozBar|Moz\.com|Screaming\s*Frog|UptimeRobot|Pingdom|Site24x7|StatusCake|Better\s*Uptime|HetrixTools/i';

	/**
	 * AI & LLM Scraper regex patterns
	 */
	private const AI_LLM_REGEX = '/GPTBot|ChatGPT-User|ClaudeBot|Claude-Web|anthropic-ai|PerplexityBot|Google-Extended|Bytespider|CCBot|Diffbot|Cohere-ai|Omgilibot/i';

	/**
	 * Feed & RSS Reader regex patterns
	 */
	private const FEED_BOT_REGEX = '/Feedly|NewsBlur|Inoreader|Feedbin|Netvibes/i';

	/**
	 * Parse raw User-Agent string into structured components.
	 *
	 * @param string $ua Optional user-agent string. If omitted, uses $_SERVER['HTTP_USER_AGENT'].
	 * @return array
	 */
	public static function parse( string $ua = '' ): array {
		if ( empty( $ua ) ) {
			$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		}

		// Bound UA length to prevent ReDoS / CPU spikes
		$ua = substr( trim( $ua ), 0, 1024 );

		if ( empty( $ua ) ) {
			return array(
				'device'     => 'Unknown',
				'browser'    => 'Unknown Browser',
				'os'         => 'Unknown OS',
				'is_mobile'  => false,
				'is_tablet'  => false,
				'is_bot'     => false,
				'bot_name'   => '',
				'user_agent' => 'None / Empty User-Agent',
			);
		}

		$is_bot    = self::is_bot( $ua );
		$bot_name  = $is_bot ? self::get_bot_name( $ua ) : '';
		$is_tablet = ! $is_bot && self::is_tablet( $ua );
		$is_mobile = ! $is_bot && ! $is_tablet && self::is_mobile( $ua );
		$device    = self::get_device_type( $ua, $is_bot, $is_tablet, $is_mobile );
		$browser   = $is_bot ? ( $bot_name ?: 'Bot / Crawler' ) : self::get_browser( $ua );
		$os        = self::get_os( $ua );

		return array(
			'device'     => $device,
			'browser'    => $browser,
			'os'         => $os,
			'is_mobile'  => $is_mobile,
			'is_tablet'  => $is_tablet,
			'is_bot'     => $is_bot,
			'bot_name'   => $bot_name,
			'user_agent' => substr( $ua, 0, 1000 ),
		);
	}

	/**
	 * Check if current user is on a mobile device.
	 *
	 * @param string $ua
	 * @return bool
	 */
	public static function is_mobile( string $ua = '' ): bool {
		if ( empty( $ua ) ) {
			$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		}
		if ( empty( $ua ) || self::is_bot( $ua ) || self::is_tablet( $ua ) ) {
			return false;
		}
		return (bool) preg_match( self::MOBILE_REGEX, $ua );
	}

	/**
	 * Check if current user is on a tablet device.
	 *
	 * @param string $ua
	 * @return bool
	 */
	public static function is_tablet( string $ua = '' ): bool {
		if ( empty( $ua ) ) {
			$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		}
		if ( empty( $ua ) || self::is_bot( $ua ) ) {
			return false;
		}
		return (bool) preg_match( self::TABLET_REGEX, $ua );
	}

	/**
	 * Check if current user is a search engine crawler or bot.
	 *
	 * @param string $ua
	 * @return bool
	 */
	public static function is_bot( string $ua = '' ): bool {
		if ( empty( $ua ) ) {
			$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		}
		if ( empty( $ua ) ) {
			return false;
		}
		return (bool) preg_match( self::BOT_REGEX, $ua );
	}

	/**
	 * Check if user agent matches major Search Engine crawlers.
	 *
	 * @param string $ua
	 * @return bool
	 */
	public static function is_search_engine( string $ua = '' ): bool {
		if ( empty( $ua ) ) {
			$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		}
		return ! empty( $ua ) && (bool) preg_match( self::SEARCH_ENGINE_REGEX, $ua );
	}

	/**
	 * Check if user agent matches Social Media previewers.
	 *
	 * @param string $ua
	 * @return bool
	 */
	public static function is_social_bot( string $ua = '' ): bool {
		if ( empty( $ua ) ) {
			$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		}
		return ! empty( $ua ) && (bool) preg_match( self::SOCIAL_BOT_REGEX, $ua );
	}

	/**
	 * Check if user agent matches SEO or Uptime Monitoring bots.
	 *
	 * @param string $ua
	 * @return bool
	 */
	public static function is_seo_bot( string $ua = '' ): bool {
		if ( empty( $ua ) ) {
			$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		}
		return ! empty( $ua ) && (bool) preg_match( self::SEO_MONITORING_REGEX, $ua );
	}

	/**
	 * Check if user agent matches AI or LLM crawlers.
	 *
	 * @param string $ua
	 * @return bool
	 */
	public static function is_ai_bot( string $ua = '' ): bool {
		if ( empty( $ua ) ) {
			$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		}
		return ! empty( $ua ) && (bool) preg_match( self::AI_LLM_REGEX, $ua );
	}

	/**
	 * Check if user agent matches Feed or RSS readers.
	 *
	 * @param string $ua
	 * @return bool
	 */
	public static function is_feed_bot( string $ua = '' ): bool {
		if ( empty( $ua ) ) {
			$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		}
		return ! empty( $ua ) && (bool) preg_match( self::FEED_BOT_REGEX, $ua );
	}

	/**
	 * Match User-Agent against custom patterns or substrings.
	 *
	 * @param string       $ua
	 * @param array|string $custom_list
	 * @return bool
	 */
	public static function matches_custom_crawler( string $ua, $custom_list ): bool {
		if ( empty( $ua ) || empty( $custom_list ) ) {
			return false;
		}

		if ( is_string( $custom_list ) ) {
			$items = preg_split( '/[\r\n,]+/', $custom_list );
		} else {
			$items = (array) $custom_list;
		}

		foreach ( $items as $pattern ) {
			$pattern = trim( $pattern );
			if ( empty( $pattern ) ) {
				continue;
			}

			// If pattern is a delimited regex (e.g. /pattern/i or #pattern#i or /pattern/)
			if ( preg_match( '/^([\/#~])(.+)\1([imsuxADSUXJ]*)$/', $pattern, $m ) ) {
				$modifiers = strpos( $m[3], 'i' ) === false ? $m[3] . 'i' : $m[3];
				if ( @preg_match( $m[1] . $m[2] . $m[1] . $modifiers, $ua ) ) {
					return true;
				}
			} elseif ( stripos( $ua, $pattern ) !== false ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Verify genuine Search Engine crawler IP via Reverse DNS (Anti-Spoofing).
	 *
	 * @param string $ip
	 * @param string $ua
	 * @return bool
	 */
	public static function verify_search_bot_rdns( string $ip, string $ua = '' ): bool {
		if ( empty( $ip ) || $ip === '127.0.0.1' || $ip === '::1' ) {
			return true;
		}

		$hostname = @gethostbyaddr( $ip );
		if ( empty( $hostname ) || $hostname === $ip ) {
			return false;
		}

		// Double-check forward DNS
		$forward_ips = @gethostbynamel( $hostname );
		if ( empty( $forward_ips ) || ! in_array( $ip, $forward_ips, true ) ) {
			return false;
		}

		// Check valid search engine domain suffixes
		$valid_domains = array(
			'google.com',
			'googlebot.com',
			'search.msn.com',
			'bing.com',
			'yandex.ru',
			'yandex.net',
			'yandex.com',
			'applebot.apple.com',
			'baidu.com',
			'baidu.jp',
			'crawl.yahoo.net',
			'duckduckgo.com',
		);

		foreach ( $valid_domains as $domain ) {
			if ( substr( $hostname, -strlen( '.' . $domain ) ) === '.' . $domain || $hostname === $domain ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get device type label (Desktop, Mobile, Tablet, Bot).
	 *
	 * @param string    $ua
	 * @param bool|null $is_bot
	 * @param bool|null $is_tablet
	 * @param bool|null $is_mobile
	 * @return string
	 */
	public static function get_device_type( string $ua, ?bool $is_bot = null, ?bool $is_tablet = null, ?bool $is_mobile = null ): string {
		if ( null === $is_bot ) {
			$is_bot = self::is_bot( $ua );
		}
		if ( $is_bot ) {
			return 'Bot / Crawler';
		}

		if ( null === $is_tablet ) {
			$is_tablet = self::is_tablet( $ua );
		}
		if ( $is_tablet ) {
			return 'Tablet';
		}

		if ( null === $is_mobile ) {
			$is_mobile = self::is_mobile( $ua );
		}
		if ( $is_mobile ) {
			return 'Mobile';
		}

		return 'Desktop';
	}

	/**
	 * Extract specific bot / crawler name.
	 *
	 * @param string $ua
	 * @return string
	 */
	public static function get_bot_name( string $ua ): string {
		$bot_map = array(
			'Googlebot-Image'      => 'Googlebot Image',
			'Googlebot-News'       => 'Googlebot News',
			'Googlebot'            => 'Googlebot',
			'Google-Inspection'    => 'Google InspectionTool',
			'Mediapartners-Google' => 'Google AdSense Bot',
			'Feedfetcher-Google'   => 'Google Feedfetcher',
			'bingbot'              => 'Bingbot',
			'BingPreview'          => 'Bing Preview',
			'Slurp'                => 'Yahoo! Slurp',
			'Baiduspider'          => 'Baiduspider',
			'YandexBot'            => 'YandexBot',
			'DuckDuckBot'          => 'DuckDuckBot',
			'facebookexternalhit'  => 'Facebook External Hit',
			'Twitterbot'           => 'Twitterbot',
			'Pinterestbot'         => 'Pinterestbot',
			'LinkedInBot'          => 'LinkedInBot',
			'Applebot'             => 'Applebot',
			'GPTBot'               => 'OpenAI GPTBot',
			'ChatGPT-User'         => 'ChatGPT User',
			'ClaudeBot'            => 'Anthropic ClaudeBot',
			'Claude-Web'           => 'Anthropic Claude-Web',
			'anthropic-ai'         => 'Anthropic AI',
			'PerplexityBot'        => 'PerplexityBot',
			'Google-Extended'      => 'Google-Extended AI',
			'Bytespider'           => 'ByteDance Bytespider',
			'CCBot'                => 'Common Crawl Bot',
			'Diffbot'              => 'Diffbot',
			'SemrushBot'           => 'SemrushBot',
			'AhrefsBot'            => 'AhrefsBot',
			'MJ12bot'              => 'MJ12bot',
			'DotBot'               => 'DotBot',
			'UptimeRobot'          => 'UptimeRobot',
			'Pingdom'              => 'Pingdom',
			'Feedly'               => 'Feedly Reader',
			'cURL'                 => 'cURL Client',
			'Wget'                 => 'Wget',
			'Python-urllib'        => 'Python urllib',
			'Python'               => 'Python Script',
			'GuzzleHttp'           => 'Guzzle HTTP',
			'Go-http-client'       => 'Go HTTP Client',
			'PostmanRuntime'       => 'Postman',
			'Insomnia'             => 'Insomnia REST',
			'okhttp'               => 'OkHttp',
		);

		foreach ( $bot_map as $needle => $name ) {
			if ( stripos( $ua, $needle ) !== false ) {
				return $name;
			}
		}

		return 'Bot / Crawler';
	}

	/**
	 * Detect browser name and major version.
	 *
	 * @param string $ua
	 * @return string
	 */
	public static function get_browser( string $ua ): string {
		// Microsoft Edge (Chromium & Legacy)
		if ( preg_match( '/Edg(?:e|A|iOS)?\/([0-9]+(?:\.[0-9]+)?)/i', $ua, $m ) ) {
			return 'Microsoft Edge ' . $m[1];
		}

		// Opera
		if ( preg_match( '/(?:OPR|Opera)\/([0-9]+(?:\.[0-9]+)?)/i', $ua, $m ) ) {
			return 'Opera ' . $m[1];
		}

		// Samsung Internet
		if ( preg_match( '/SamsungBrowser\/([0-9]+(?:\.[0-9]+)?)/i', $ua, $m ) ) {
			return 'Samsung Browser ' . $m[1];
		}

		// UC Browser
		if ( preg_match( '/UCBrowser\/([0-9]+(?:\.[0-9]+)?)/i', $ua, $m ) ) {
			return 'UC Browser ' . $m[1];
		}

		// Chrome
		if ( preg_match( '/Chrome\/([0-9]+(?:\.[0-9]+)?)/i', $ua, $m ) && stripos( $ua, 'CriOS' ) === false ) {
			return 'Google Chrome ' . $m[1];
		}

		// Chrome on iOS
		if ( preg_match( '/CriOS\/([0-9]+(?:\.[0-9]+)?)/i', $ua, $m ) ) {
			return 'Chrome iOS ' . $m[1];
		}

		// Firefox
		if ( preg_match( '/(?:Firefox|FxiOS)\/([0-9]+(?:\.[0-9]+)?)/i', $ua, $m ) ) {
			return 'Mozilla Firefox ' . $m[1];
		}

		// Safari
		if ( preg_match( '/Version\/([0-9]+(?:\.[0-9]+)?).*Safari/i', $ua, $m ) ) {
			return 'Apple Safari ' . $m[1];
		}

		return 'Unknown Browser';
	}

	/**
	 * Detect Operating System.
	 *
	 * @param string $ua
	 * @return string
	 */
	public static function get_os( string $ua ): string {
		if ( stripos( $ua, 'Windows NT 10.0' ) !== false ) {
			return 'Windows 10 / 11';
		}
		if ( stripos( $ua, 'Windows NT 6.3' ) !== false ) {
			return 'Windows 8.1';
		}
		if ( stripos( $ua, 'Windows NT 6.1' ) !== false ) {
			return 'Windows 7';
		}
		if ( stripos( $ua, 'Windows' ) !== false ) {
			return 'Windows';
		}

		if ( preg_match( '/Android\s+([0-9]+(?:\.[0-9]+)?)/i', $ua, $m ) ) {
			return 'Android ' . $m[1];
		}
		if ( stripos( $ua, 'Android' ) !== false ) {
			return 'Android';
		}

		if ( preg_match( '/OS\s+([0-9_]+)\s+like\s+Mac\s+OS\s+X/i', $ua, $m ) ) {
			return 'iOS ' . str_replace( '_', '.', $m[1] );
		}
		if ( stripos( $ua, 'iPhone' ) !== false || stripos( $ua, 'iPad' ) !== false ) {
			return 'iOS';
		}

		if ( preg_match( '/Mac\s+OS\s+X\s+([0-9_]+)/i', $ua, $m ) ) {
			return 'macOS ' . str_replace( '_', '.', $m[1] );
		}
		if ( stripos( $ua, 'Macintosh' ) !== false || stripos( $ua, 'Mac OS' ) !== false ) {
			return 'macOS';
		}

		if ( stripos( $ua, 'Linux' ) !== false ) {
			return 'Linux';
		}
		if ( stripos( $ua, 'CrOS' ) !== false ) {
			return 'Chrome OS';
		}

		return 'Unknown OS';
	}
}
