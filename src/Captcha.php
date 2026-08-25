<?php
/**
 * Anti-Spam Whole-Website Rate Limiting & CAPTCHA Verification Engine
 *
 * Protects the entire WordPress website against excessive automated traffic,
 * spam floods, and scraping loops with interactive CAPTCHA verification
 * (Cloudflare Turnstile, hCaptcha, Google reCAPTCHA).
 *
 * Persistent 24-Hour Enforcement:
 * When an IP triggers rate limiting, it is placed in a locked state in the
 * database for 24 hours. Waiting or refreshing does NOT bypass the challenge;
 * the visitor MUST successfully solve the challenge to gain 24-hour clearance.
 *
 * Geo-Restriction Policy:
 * Even when a visitor solves the challenge, if their origin IP resides in a
 * restricted/blocked geographical region or proxy, LocaSentinel strictly
 * maintains the block to preserve total access control.
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Captcha {

	/**
	 * Cookie name prefix for verified site clearance.
	 */
	public const CLEARANCE_COOKIE = 'ip2loc_site_clearance';

	/**
	 * Default lockout and solved clearance duration in seconds (24 hours).
	 */
	public const CLEARANCE_24_HOURS = 86400;

	/**
	 * Get the captcha database table name.
	 *
	 * @return string
	 */
	public static function get_table_name(): string {
		global $wpdb;
		return $wpdb->prefix . 'ip2location_captcha_locks';
	}

	/**
	 * Check if Anti-Spam CAPTCHA feature is enabled.
	 *
	 * @return bool
	 */
	public static function is_enabled(): bool {
		$settings = get_option( 'ip2loc_settings', array() );
		return ! empty( $settings['enable_captcha'] );
	}

	/**
	 * Check if CAPTCHA is fully configured with valid keys.
	 *
	 * @return bool
	 */
	public static function is_configured(): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}

		$settings = get_option( 'ip2loc_settings', array() );
		return ! empty( $settings['captcha_site_key'] ) && ! empty( $settings['captcha_secret_key'] );
	}

	/**
	 * Get configured rate limiting threshold settings.
	 *
	 * @return array
	 */
	public static function get_rate_limit_thresholds(): array {
		$settings = get_option( 'ip2loc_settings', array() );

		return array(
			'max_hits'          => isset( $settings['captcha_rate_limit_hits'] ) ? max( 3, (int) $settings['captcha_rate_limit_hits'] ) : 10,
			'window_seconds'    => isset( $settings['captcha_rate_limit_window'] ) ? max( 5, (int) $settings['captcha_rate_limit_window'] ) : 60,
			'clearance_seconds' => self::CLEARANCE_24_HOURS,
		);
	}

	/**
	 * Check if an IP is currently in a persistent LOCKED state in DB / Redis.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function is_ip_locked( string $ip ): bool {
		$cache_key = 'captcha_lock_' . md5( $ip );
		$cached    = RedisDriver::get( $cache_key );

		if ( 'locked' === $cached ) {
			return true;
		}

		global $wpdb;
		$table = self::get_table_name();

		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id FROM {$table} WHERE ip = %s AND status = 'locked' AND expires_at > %s LIMIT 1",
				$ip,
				current_time( 'mysql' )
			)
		);

		if ( ! empty( $row ) ) {
			RedisDriver::set( $cache_key, 'locked', 3600 );
			return true;
		}

		return false;
	}

	/**
	 * Check if visitor has valid solved clearance for the website in DB / Redis / Cookie.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function has_clearance( string $ip ): bool {
		// 1. If currently locked, clearance is invalid
		if ( self::is_ip_locked( $ip ) ) {
			return false;
		}

		$cache_key = 'captcha_solved_' . md5( $ip );
		$cached    = RedisDriver::get( $cache_key );

		if ( ! empty( $cached ) ) {
			return true;
		}

		// 2. Check signed HMAC cookie
		if ( isset( $_COOKIE[ self::CLEARANCE_COOKIE ] ) ) {
			$cookie_val = sanitize_text_field( wp_unslash( $_COOKIE[ self::CLEARANCE_COOKIE ] ) );
			$expected   = self::generate_site_token( $ip );
			if ( hash_equals( $expected, $cookie_val ) ) {
				return true;
			}
		}

		// 3. Check database record for 24-hour solved status
		global $wpdb;
		$table = self::get_table_name();

		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id FROM {$table} WHERE ip = %s AND status = 'solved' AND expires_at > %s LIMIT 1",
				$ip,
				current_time( 'mysql' )
			)
		);

		if ( ! empty( $row ) ) {
			RedisDriver::set( $cache_key, '1', self::CLEARANCE_24_HOURS );
			return true;
		}

		return false;
	}

	/**
	 * Check if visitor has valid solved clearance for a specific URL path.
	 *
	 * @param string $ip
	 * @param string $path
	 * @return bool
	 */
	public static function has_path_clearance( string $ip, string $path ): bool {
		return self::has_clearance( $ip );
	}

	/**
	 * Put an IP into a persistent LOCKED state in database and Redis for 24 hours.
	 *
	 * @param string $ip
	 * @param int    $duration_seconds Default: 86400 (24 hours).
	 */
	public static function lock_ip( string $ip, int $duration_seconds = 86400 ): void {
		global $wpdb;
		$table      = self::get_table_name();
		$now        = current_time( 'mysql' );
		$expires_at = gmdate( 'Y-m-d H:i:s', time() + $duration_seconds );

		// Clear any solved state
		RedisDriver::delete( 'captcha_solved_' . md5( $ip ) );
		RedisDriver::set( 'captcha_lock_' . md5( $ip ), 'locked', $duration_seconds );

		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$table} (ip, status, locked_at, expires_at, created_at)
				 VALUES (%s, 'locked', %s, %s, %s)
				 ON DUPLICATE KEY UPDATE status = 'locked', locked_at = %s, expires_at = %s",
				$ip,
				$now,
				$expires_at,
				$now,
				$now,
				$expires_at
			)
		);
	}

	/**
	 * Unlock an IP and grant 24-hour persistent clearance upon successfully solving CAPTCHA.
	 *
	 * @param string $ip
	 * @param int    $duration_seconds Default: 86400 (24 hours).
	 */
	public static function unlock_and_solve_ip( string $ip, int $duration_seconds = 86400 ): void {
		global $wpdb;
		$table      = self::get_table_name();
		$now        = current_time( 'mysql' );
		$expires_at = gmdate( 'Y-m-d H:i:s', time() + $duration_seconds );

		// 1. Update Database
		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$table} (ip, status, locked_at, solved_at, expires_at, created_at)
				 VALUES (%s, 'solved', %s, %s, %s, %s)
				 ON DUPLICATE KEY UPDATE status = 'solved', solved_at = %s, expires_at = %s",
				$ip,
				$now,
				$now,
				$expires_at,
				$now,
				$now,
				$expires_at
			)
		);

		// 2. Clear Lock and set Redis solved cache
		RedisDriver::delete( 'captcha_lock_' . md5( $ip ) );
		RedisDriver::set( 'captcha_solved_' . md5( $ip ), '1', $duration_seconds );

		// 3. Issue cryptographic HMAC cookie for whole website
		if ( ! headers_sent() ) {
			$token       = self::generate_site_token( $ip );
			$cookie_path = defined( 'COOKIEPATH' ) ? COOKIEPATH : '/';
			$is_ssl      = is_ssl();
			setcookie(
				self::CLEARANCE_COOKIE,
				$token,
				time() + $duration_seconds,
				$cookie_path,
				COOKIE_DOMAIN ?: '',
				$is_ssl,
				true
			);
		}
	}

	/**
	 * Issue whole-website clearance (alias to unlock_and_solve_ip).
	 *
	 * @param string $ip
	 * @param int    $duration_seconds
	 */
	public static function issue_clearance( string $ip, int $duration_seconds = 86400 ): void {
		self::unlock_and_solve_ip( $ip, $duration_seconds );
	}

	/**
	 * Reset the rate limit counter for a specific IP + path.
	 *
	 * @param string $ip
	 * @param string $path
	 */
	public static function reset_path_rate_limit( string $ip, string $path ): void {
		$clean_path = self::normalize_path( $path );
		$rl_key     = 'rl_path_' . md5( $ip . '|' . $clean_path );
		RedisDriver::delete( $rl_key );
	}

	/**
	 * Reset all rate limit counters for a specific IP.
	 *
	 * @param string $ip
	 */
	public static function reset_rate_limit( string $ip ): void {
		$rl_key = 'rl_ip_' . md5( $ip );
		RedisDriver::delete( $rl_key );
	}

	/**
	 * Track incoming request and determine if CAPTCHA challenge is required.
	 *
	 * @param string $ip
	 * @param string $path
	 * @return bool True if challenge MUST be presented.
	 */
	public static function is_challenge_required( string $ip, string $path ): bool {
		// 1. If IP is already locked in DB, ALWAYS require CAPTCHA
		if ( self::is_ip_locked( $ip ) ) {
			return true;
		}

		// 2. If IP has solved clearance in DB/Cookie/Redis, ALLOW without challenge
		if ( self::has_clearance( $ip ) ) {
			return false;
		}

		// 3. Track request frequency on path
		$thresholds = self::get_rate_limit_thresholds();
		$clean_path = self::normalize_path( $path );
		$rl_key     = 'rl_path_' . md5( $ip . '|' . $clean_path );

		$current_hits = RedisDriver::incr( $rl_key, $thresholds['window_seconds'] );

		if ( $current_hits > $thresholds['max_hits'] ) {
			// Lock this IP in database for 24 hours!
			self::lock_ip( $ip, self::CLEARANCE_24_HOURS );
			return true;
		}

		return false;
	}

	/**
	 * Display the interactive Anti-Spam Security Challenge Page (HTTP 429).
	 *
	 * @param string $ip
	 * @param string $path
	 */
	public static function render_challenge_page( string $ip, string $path = '/' ): void {
		CacheCompat::disable_caching();
		status_header( 429 );

		$client_ip   = $ip;
		$target_path = $path;
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : $path;

		$template = plugin_dir_path( dirname( __FILE__ ) ) . 'admin/views/captcha-challenge-template.php';

		if ( file_exists( $template ) ) {
			include $template;
		} else {
			wp_die(
				esc_html__( 'Security verification required. Please complete the challenge to proceed.', 'ip2location-sentinel' ),
				esc_html__( '429 Security Challenge', 'ip2location-sentinel' ),
				array( 'response' => 429 )
			);
		}

		exit;
	}

	/**
	 * Render the client-side CAPTCHA widget HTML & JS tags.
	 *
	 * @return string
	 */
	public static function render_widget(): string {
		if ( ! self::is_configured() ) {
			return '';
		}

		$settings = get_option( 'ip2loc_settings', array() );
		$provider = $settings['captcha_provider'] ?? 'turnstile';
		$site_key = esc_attr( trim( $settings['captcha_site_key'] ?? '' ) );

		$output = '';

		switch ( $provider ) {
			case 'turnstile':
				$output .= '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>';
				$output .= '<div class="cf-turnstile" data-sitekey="' . $site_key . '" data-theme="dark" style="margin: 15px auto; display: flex; justify-content: center;"></div>';
				break;

			case 'hcaptcha':
				$output .= '<script src="https://js.hcaptcha.com/1/api.js" async defer></script>';
				$output .= '<div class="h-captcha" data-sitekey="' . $site_key . '" data-theme="dark" style="margin: 15px auto; display: flex; justify-content: center;"></div>';
				break;

			case 'recaptcha_v2':
				$output .= '<script src="https://www.google.com/recaptcha/api.js" async defer></script>';
				$output .= '<div class="g-recaptcha" data-sitekey="' . $site_key . '" data-theme="dark" style="margin: 15px auto; display: flex; justify-content: center;"></div>';
				break;

			case 'recaptcha_v3':
				$output .= '<script src="https://www.google.com/recaptcha/api.js?render=' . $site_key . '"></script>';
				$output .= '<input type="hidden" name="g-recaptcha-response" id="ip2loc_recaptcha_v3_token" value="" />';
				$output .= '<script>grecaptcha.ready(function(){grecaptcha.execute("' . $site_key . '",{action:"submit"}).then(function(token){document.getElementById("ip2loc_recaptcha_v3_token").value=token;});});</script>';
				break;
		}

		return $output;
	}

	/**
	 * Verify CAPTCHA response token via remote verification API.
	 *
	 * @param string|null $token
	 * @return bool
	 */
	public static function verify_submission( ?string $token = null ): bool {
		if ( ! self::is_configured() ) {
			return false;
		}

		$settings   = get_option( 'ip2loc_settings', array() );
		$provider   = $settings['captcha_provider'] ?? 'turnstile';
		$secret_key = trim( $settings['captcha_secret_key'] ?? '' );
		$ip         = IpResolver::get_client_ip();

		if ( empty( $token ) ) {
			if ( isset( $_POST['cf-turnstile-response'] ) ) {
				$token = sanitize_text_field( wp_unslash( $_POST['cf-turnstile-response'] ) );
			} elseif ( isset( $_POST['h-captcha-response'] ) ) {
				$token = sanitize_text_field( wp_unslash( $_POST['h-captcha-response'] ) );
			} elseif ( isset( $_POST['g-recaptcha-response'] ) ) {
				$token = sanitize_text_field( wp_unslash( $_POST['g-recaptcha-response'] ) );
			}
		}

		if ( empty( $token ) || empty( $secret_key ) ) {
			return false;
		}

		$verify_urls = array(
			'turnstile'    => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
			'hcaptcha'     => 'https://hcaptcha.com/siteverify',
			'recaptcha_v2' => 'https://www.google.com/recaptcha/api/siteverify',
			'recaptcha_v3' => 'https://www.google.com/recaptcha/api/siteverify',
		);

		$verify_url = $verify_urls[ $provider ] ?? $verify_urls['turnstile'];

		$response = wp_remote_post(
			$verify_url,
			array(
				'timeout'   => 6,
				'sslverify' => true,
				'body'      => array(
					'secret'   => $secret_key,
					'response' => $token,
					'remoteip' => $ip,
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		return is_array( $data ) && ! empty( $data['success'] );
	}

	/**
	 * Normalize path for rate limiting.
	 *
	 * @param string $path
	 * @return string
	 */
	public static function normalize_path( string $path ): string {
		$clean = strtok( trim( $path ), '?' );
		return $clean ? rtrim( $clean, '/' ) ?: '/' : '/';
	}

	/**
	 * Generate cryptographic token for an IP across the entire site.
	 *
	 * @param string $ip
	 * @return string
	 */
	private static function generate_site_token( string $ip ): string {
		$salt = wp_salt( 'auth' );
		return hash_hmac( 'sha256', $ip . '|whole_site_shield|' . current_time( 'Y-m-d' ), $salt );
	}
}
