<?php
/**
 * Cache Plugin Compatibility Engine
 *
 * Provides compatibility with LiteSpeed Cache, WP Rocket, W3 Total Cache,
 * WP Super Cache, WP Fastest Cache, SG Optimizer, Cache Enabler, Varnish, and CDNs.
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CacheCompat {

	/**
	 * Initialize cache compatibility hooks.
	 */
	public static function init(): void {
		add_action( 'init', array( __CLASS__, 'apply_cache_vary_rules' ), 1 );
	}

	/**
	 * Mark the current request as uncacheable.
	 */
	public static function disable_caching(): void {
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true );
		}
		if ( ! defined( 'DONOTCACHEDB' ) ) {
			define( 'DONOTCACHEDB', true );
		}
		if ( ! defined( 'DONOTMINIFY' ) ) {
			define( 'DONOTMINIFY', true );
		}
		if ( ! defined( 'DONOTCDN' ) ) {
			define( 'DONOTCDN', true );
		}
		if ( ! defined( 'WPFC_SERVE_ONLY_FOR_ADMIN' ) ) {
			define( 'WPFC_SERVE_ONLY_FOR_ADMIN', true );
		}

		if ( ! headers_sent() ) {
			header( 'Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0', true );
			header( 'Pragma: no-cache', true );
			header( 'Expires: Thu, 01 Jan 1970 00:00:00 GMT', true );
			header( 'X-LiteSpeed-Cache-Control: no-cache', true );
		}

		if ( function_exists( 'do_action' ) ) {
			do_action( 'litespeed_control_set_nocache', 'ip2location_sentinel_block' );
		}

		add_filter( 'sgo_bypass_fastcgi_cache', '__return_true' );

		global $cache_enabled;
		if ( isset( $cache_enabled ) ) {
			$cache_enabled = false;
		}
	}

	/**
	 * Apply Geo Vary headers/cookies.
	 */
	public static function apply_cache_vary_rules(): void {
		if ( is_admin() || wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		$settings = get_option( 'ip2loc_settings', array() );
		if ( empty( $settings['enable_cache_vary'] ) ) {
			return;
		}

		if ( ! headers_sent() ) {
			header( 'Vary: Accept-Encoding, X-Forwarded-For, CF-Connecting-IP', false );
		}
	}

	/**
	 * Helper to check if a plugin is active in WordPress.
	 *
	 * @param string $plugin_basename
	 * @return bool
	 */
	public static function is_plugin_active( string $plugin_basename ): bool {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			include_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		return function_exists( 'is_plugin_active' ) && is_plugin_active( $plugin_basename );
	}

	/**
	 * Detect active cache plugins and server-level caching layers.
	 *
	 * @return array
	 */
	public static function get_active_cache_engines(): array {
		$redis_status = RedisDriver::get_status();

		return array(
			'redis' => array(
				'name'      => 'Redis In-Memory Object Cache',
				'active'    => $redis_status['available'],
				'type'      => 'In-Memory / Auto-Driver',
				'notes'     => $redis_status['label'],
			),
			'litespeed' => array(
				'name'      => 'LiteSpeed Cache',
				'active'    => self::is_plugin_active( 'litespeed-cache/litespeed-cache.php' ) || defined( 'LSCWP_V' ) || class_exists( 'LiteSpeed\Core' ),
				'type'      => 'Plugin / Server',
				'notes'     => __( 'X-LiteSpeed-Vary & no-cache headers natively supported.', 'ip2location-sentinel' ),
			),
			'wp_rocket' => array(
				'name'      => 'WP Rocket',
				'active'    => self::is_plugin_active( 'wp-rocket/wp-rocket.php' ) || defined( 'WP_ROCKET_VERSION' ),
				'type'      => 'Plugin',
				'notes'     => __( 'DONOTCACHEPAGE & dynamic cookies supported.', 'ip2location-sentinel' ),
			),
			'w3_total_cache' => array(
				'name'      => 'W3 Total Cache',
				'active'    => self::is_plugin_active( 'w3-total-cache/w3-total-cache.php' ) || defined( 'W3TC' ) || class_exists( 'W3_Config' ),
				'type'      => 'Plugin',
				'notes'     => __( 'DONOTCACHEPAGE & dynamic fragments supported.', 'ip2location-sentinel' ),
			),
			'wp_super_cache' => array(
				'name'      => 'WP Super Cache',
				'active'    => self::is_plugin_active( 'wp-super-cache/wp-cache.php' ) || defined( 'WPCACHEHOME' ) || function_exists( 'wp_cache_clean_cache' ),
				'type'      => 'Plugin',
				'notes'     => __( 'DONOTCACHEPAGE hook supported.', 'ip2location-sentinel' ),
			),
			'wp_fastest_cache' => array(
				'name'      => 'WP Fastest Cache',
				'active'    => self::is_plugin_active( 'wp-fastest-cache/wpFastestCache.php' ) || class_exists( 'WpFastestCache' ) || defined( 'WPFC_WP_PLUGIN_DIR' ),
				'type'      => 'Plugin',
				'notes'     => __( 'WPFC_SERVE_ONLY_FOR_ADMIN & runtime bypass supported.', 'ip2location-sentinel' ),
			),
			'sg_optimizer' => array(
				'name'      => 'SiteGround SG Optimizer',
				'active'    => self::is_plugin_active( 'sg-cachepress/sg-cachepress.php' ) || function_exists( 'sg_cachepress_purge_cache' ) || class_exists( 'SiteGround_Optimizer\Options\Options' ),
				'type'      => 'Plugin / Hosting',
				'notes'     => __( 'FastCGI cache bypass filter supported.', 'ip2location-sentinel' ),
			),
			'cache_enabler' => array(
				'name'      => 'Cache Enabler',
				'active'    => self::is_plugin_active( 'cache-enabler/cache-enabler.php' ) || defined( 'CACHE_ENABLER_VERSION' ),
				'type'      => 'Plugin',
				'notes'     => __( 'DONOTCACHEPAGE constant supported.', 'ip2location-sentinel' ),
			),
			'cloudflare' => array(
				'name'      => 'Cloudflare CDN / Edge Cache',
				'active'    => ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) || ! empty( $_SERVER['HTTP_CF_RAY'] ),
				'type'      => 'Edge CDN',
				'notes'     => __( 'CF-Connecting-IP & Cache-Control no-store headers supported.', 'ip2location-sentinel' ),
			),
			'sucuri' => array(
				'name'      => 'Sucuri CloudProxy',
				'active'    => ! empty( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ),
				'type'      => 'Cloud WAF / CDN',
				'notes'     => __( 'X-Sucuri-ClientIP header supported.', 'ip2location-sentinel' ),
			),
		);
	}
}
