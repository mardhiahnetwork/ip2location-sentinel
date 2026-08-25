<?php
/**
 * Plugin Activation Handler
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Activator {

	/**
	 * Run activation tasks.
	 */
	public static function activate(): void {
		self::create_tables();
		self::set_default_settings();
		self::schedule_cron_jobs();
	}

	/**
	 * Create or upgrade custom database tables.
	 */
	public static function create_tables(): void {
		global $wpdb;

		$table_name      = $wpdb->prefix . 'ip2location_logs';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			timestamp datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
			ip varchar(45) NOT NULL DEFAULT '',
			country_code varchar(2) NOT NULL DEFAULT '',
			country_name varchar(100) NOT NULL DEFAULT '',
			region_name varchar(100) NOT NULL DEFAULT '',
			city_name varchar(100) NOT NULL DEFAULT '',
			zip_code varchar(20) NOT NULL DEFAULT '',
			asn varchar(50) NOT NULL DEFAULT '',
			as_name varchar(255) NOT NULL DEFAULT '',
			is_proxy tinyint(1) NOT NULL DEFAULT 0,
			http_method varchar(10) NOT NULL DEFAULT 'GET',
			request_url text NOT NULL,
			target_endpoint varchar(255) NOT NULL DEFAULT '',
			action_taken varchar(50) NOT NULL DEFAULT '',
			rule_triggered varchar(255) NOT NULL DEFAULT '',
			user_login varchar(60) NOT NULL DEFAULT '',
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			user_agent text NOT NULL,
			device_type varchar(50) NOT NULL DEFAULT '',
			browser varchar(100) NOT NULL DEFAULT '',
			os varchar(100) NOT NULL DEFAULT '',
			http_status int(5) NOT NULL DEFAULT 200,
			hit_count int(11) unsigned NOT NULL DEFAULT 1,
			PRIMARY KEY  (id),
			KEY ip (ip),
			KEY country_code (country_code),
			KEY action_taken (action_taken),
			KEY http_method (http_method),
			KEY timestamp (timestamp)
		) {$charset_collate};";

		$captcha_table = $wpdb->prefix . 'ip2location_captcha_locks';
		$sql_captcha   = "CREATE TABLE {$captcha_table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			ip varchar(45) NOT NULL DEFAULT '',
			status varchar(20) NOT NULL DEFAULT 'locked',
			locked_at datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
			solved_at datetime DEFAULT NULL,
			expires_at datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
			created_at datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
			PRIMARY KEY  (id),
			UNIQUE KEY ip (ip),
			KEY status_expires (status, expires_at)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
		dbDelta( $sql_captcha );
	}

	/**
	 * Set sensible default options.
	 */
	public static function set_default_settings(): void {
		$existing = get_option( 'ip2loc_settings' );

		if ( false === $existing ) {
			$defaults = array(
				'api_key'                   => '',
				'cdn_mode'                  => 'auto',
				'country_mode'              => 'blacklist',
				'countries'                 => array(),
				'blocked_regions'           => '',
				'blocked_cities'            => '',
				'blocked_zips'              => '',
				'blocked_asns'              => '',
				'block_proxies'             => 1,
				'allow_search_bots'         => 1,
				'whitelist_ips'             => "127.0.0.1\n::1",
				'blacklist_ips'             => '',
				'protect_login'             => 1,
				'protect_xmlrpc'            => 1,
				'protect_comments'          => 1,
				'protect_rest_api'          => 0,
				'protect_frontend'          => 0,
				'enable_impossible_travel'  => 1,
				'impossible_speed_threshold'=> 800,
				'impossible_min_distance'   => 300,
				'impossible_domestic_mode'  => 'mobile_tolerance',
				'impossible_action'         => 'otp',
				'force_otp_without_smtp'    => 0,
				'enable_webhooks'           => 0,
				'webhook_url'               => '',
				'webhook_type'              => 'auto',
				'enable_audit_logging'      => 1,
				'log_retention_days'        => 30,
				'log_allowed_frontend'      => 0,
				'enable_cache_vary'         => 1,
				'api_fail_mode'             => 'open',
				'api_timeout'               => 4,
				'cache_ttl'                 => 86400,
				'block_action'              => 'template',
				'block_redirect_url'        => '',
				'block_page_title'          => __( 'Access Restricted (403)', 'locasentinel' ),
				'block_page_message'        => __( 'Access from your IP address or geographical region is restricted by the site security policy.', 'locasentinel' ),
				'comments_blocked_msg'      => __( 'Comments from your geographical region or network are not accepted on this website.', 'locasentinel' ),
				'delete_data_on_uninstall'  => 0,
			);

			update_option( 'ip2loc_settings', $defaults );
		}
	}

	/**
	 * Register recurring cron jobs.
	 */
	public static function schedule_cron_jobs(): void {
		if ( ! wp_next_scheduled( 'ip2loc_daily_maintenance_cron' ) ) {
			wp_schedule_event( time(), 'daily', 'ip2loc_daily_maintenance_cron' );
		}
	}
}
