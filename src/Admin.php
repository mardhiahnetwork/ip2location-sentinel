<?php
/**
 * Admin Panel & Controller for IP2Location Sentinel
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Admin {

	/**
	 * Initialize admin hooks
	 */
	public static function init(): void {
		add_action( 'admin_menu', array( __CLASS__, 'register_admin_menus' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_admin_assets' ) );
		add_action( 'admin_notices', array( __CLASS__, 'render_admin_notices' ) );

		// AJAX Endpoints
		add_action( 'wp_ajax_ip2loc_test_api_key', array( __CLASS__, 'ajax_test_api_key' ) );
		add_action( 'wp_ajax_ip2loc_test_smtp', array( __CLASS__, 'ajax_test_smtp' ) );
		add_action( 'wp_ajax_ip2loc_test_webhook', array( __CLASS__, 'ajax_test_webhook' ) );
		add_action( 'wp_ajax_ip2loc_lookup_ip', array( __CLASS__, 'ajax_lookup_ip' ) );
		add_action( 'wp_ajax_ip2loc_clear_logs', array( __CLASS__, 'ajax_clear_logs' ) );
		add_action( 'wp_ajax_ip2loc_dismiss_notice', array( __CLASS__, 'ajax_dismiss_notice' ) );
		add_action( 'wp_ajax_ip2loc_auto_save_settings', array( __CLASS__, 'ajax_auto_save_settings' ) );
		add_action( 'wp_ajax_ip2loc_filter_audit_logs', array( __CLASS__, 'ajax_filter_audit_logs' ) );

		// CSV Export Action
		add_action( 'admin_post_ip2loc_export_csv', array( Logger::class, 'export_csv' ) );

		// Settings Save Handler
		add_action( 'admin_post_ip2loc_save_settings', array( __CLASS__, 'handle_save_settings' ) );

		// CAPTCHA Verification Submission
		add_action( 'admin_post_ip2loc_verify_captcha', array( __CLASS__, 'handle_verify_captcha' ) );
		add_action( 'admin_post_nopriv_ip2loc_verify_captcha', array( __CLASS__, 'handle_verify_captcha' ) );
	}

	/**
	 * Register Top-Level and Sub-Level Admin Menus.
	 */
	public static function register_admin_menus(): void {
		add_menu_page(
			__( 'LocaSentinel', 'locasentinel' ),
			__( 'LocaSentinel', 'locasentinel' ),
			'manage_options',
			'ip2location-sentinel',
			array( __CLASS__, 'render_dashboard_page' ),
			'dashicons-shield-alt',
			80
		);

		add_submenu_page(
			'ip2location-sentinel',
			__( 'Dashboard & Analytics - LocaSentinel', 'locasentinel' ),
			__( 'Dashboard', 'locasentinel' ),
			'manage_options',
			'ip2location-sentinel',
			array( __CLASS__, 'render_dashboard_page' )
		);

		add_submenu_page(
			'ip2location-sentinel',
			__( 'Geo Firewall Rules - LocaSentinel', 'locasentinel' ),
			__( 'Geo Firewall', 'locasentinel' ),
			'manage_options',
			'ip2loc-rules',
			array( __CLASS__, 'render_rules_page' )
		);

		add_submenu_page(
			'ip2location-sentinel',
			__( 'Endpoint Protection - LocaSentinel', 'locasentinel' ),
			__( 'Endpoint Protection', 'locasentinel' ),
			'manage_options',
			'ip2loc-endpoints',
			array( __CLASS__, 'render_endpoints_page' )
		);

		add_submenu_page(
			'ip2location-sentinel',
			__( 'Impossible Travel & 2FA - LocaSentinel', 'locasentinel' ),
			__( 'Impossible Travel & 2FA', 'locasentinel' ),
			'manage_options',
			'ip2loc-impossible-travel',
			array( __CLASS__, 'render_impossible_travel_page' )
		);

		add_submenu_page(
			'ip2location-sentinel',
			__( 'Security Audit Logs - LocaSentinel', 'locasentinel' ),
			__( 'Audit Logs', 'locasentinel' ),
			'manage_options',
			'ip2loc-audit-logs',
			array( __CLASS__, 'render_audit_logs_page' )
		);

		add_submenu_page(
			'ip2location-sentinel',
			__( 'Cache & CDN Compatibility - LocaSentinel', 'locasentinel' ),
			__( 'Cache & CDN', 'locasentinel' ),
			'manage_options',
			'ip2loc-cache-cdn',
			array( __CLASS__, 'render_cache_cdn_page' )
		);

		add_submenu_page(
			'ip2location-sentinel',
			__( 'API Configuration & Settings - LocaSentinel', 'locasentinel' ),
			__( 'API & Settings', 'locasentinel' ),
			'manage_options',
			'ip2loc-settings',
			array( __CLASS__, 'render_settings_page' )
		);
	}

	/**
	 * Enqueue Admin Assets.
	 *
	 * @param string $hook_suffix
	 */
	public static function enqueue_admin_assets( string $hook_suffix ): void {
		if ( strpos( $hook_suffix, 'ip2loc' ) === false && strpos( $hook_suffix, 'ip2location-sentinel' ) === false ) {
			return;
		}

		$plugin_url = plugin_dir_url( dirname( __FILE__ ) );

		wp_enqueue_style( 'select2', 'https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css', array(), '4.1.0' );
		wp_enqueue_script( 'select2', 'https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js', array( 'jquery' ), '4.1.0', true );

		wp_enqueue_script( 'chartjs', 'https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js', array(), '4.4.1', true );

		$plugin_dir = plugin_dir_path( dirname( __FILE__ ) );
		$css_ver    = file_exists( $plugin_dir . 'admin/css/ip2loc-admin.css' ) ? (string) filemtime( $plugin_dir . 'admin/css/ip2loc-admin.css' ) : IP2LOC_VERSION;
		$js_ver     = file_exists( $plugin_dir . 'admin/js/ip2loc-admin.js' ) ? (string) filemtime( $plugin_dir . 'admin/js/ip2loc-admin.js' ) : IP2LOC_VERSION;

		wp_enqueue_style( 'ip2loc-admin-css', $plugin_url . 'admin/css/ip2loc-admin.css', array(), $css_ver );
		wp_enqueue_script( 'ip2loc-admin-js', $plugin_url . 'admin/js/ip2loc-admin.js', array( 'jquery', 'select2' ), $js_ver, true );

		wp_localize_script(
			'ip2loc-admin-js',
			'ip2locAdminData',
			array(
				'ajax_url'     => admin_url( 'admin-ajax.php' ),
				'flags_url'    => $plugin_url . 'assets/flags/',
				'nonce'        => wp_create_nonce( 'ip2loc_admin_nonce' ),
				'testing_text' => __( 'Testing connection...', 'locasentinel' ),
				'sending_text' => __( 'Sending...', 'locasentinel' ),
				'confirm_clear'=> __( 'Are you sure you want to delete all audit logs? This action cannot be undone.', 'locasentinel' ),
			)
		);
	}

	/**
	 * Display Global Admin Alerts on Non-Plugin Pages.
	 */
	public static function render_admin_notices(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$current_page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '';
		$screen       = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$is_plugin    = ( $screen && ( strpos( $screen->id, 'ip2loc' ) !== false || strpos( $screen->id, 'ip2location-sentinel' ) !== false ) ) ||
						( strpos( $current_page, 'ip2loc' ) !== false || strpos( $current_page, 'ip2location-sentinel' ) !== false );

		// On plugin screens, notices are rendered directly in the page header without DOM shifting
		if ( $is_plugin ) {
			return;
		}

		$settings = get_option( 'ip2loc_settings', array() );
		$api_key  = isset( $settings['api_key'] ) ? trim( $settings['api_key'] ) : '';

		if ( empty( $api_key ) ) {
			$dismissed = get_user_meta( get_current_user_id(), 'ip2loc_dismissed_api_notice', true );
			if ( ! $dismissed ) {
				$settings_url = admin_url( 'admin.php?page=ip2loc-settings' );
				?>
				<div class="notice notice-warning is-dismissible ip2loc-admin-notice" data-notice="api_key">
					<p>
						<strong><?php esc_html_e( 'LocaSentinel:', 'locasentinel' ); ?></strong>
						<?php esc_html_e( 'Please add your IP2Location.io API key to enable geolocation lookups.', 'locasentinel' ); ?>
						<a href="<?php echo esc_url( $settings_url ); ?>" class="button button-secondary button-small" style="margin-left: 8px;">
							<?php esc_html_e( 'Enter API Key', 'locasentinel' ); ?>
						</a>
					</p>
				</div>
				<?php
			}
		}
	}

	/**
	 * Render In-Page Notice for Plugin Screens (Zero-Flicker).
	 */
	public static function render_plugin_header_notices(): void {
		$settings = get_option( 'ip2loc_settings', array() );
		$api_key  = isset( $settings['api_key'] ) ? trim( $settings['api_key'] ) : '';

		// Success notice upon saving settings
		if ( isset( $_GET['settings-updated'] ) && $_GET['settings-updated'] === 'true' ) {
			?>
			<div class="notice notice-success inline is-dismissible" style="margin: 12px 0 16px 0;">
				<p><?php esc_html_e( 'Settings saved successfully.', 'locasentinel' ); ?></p>
			</div>
			<?php
		}

		// API Key verification error notice
		if ( isset( $_GET['api_error'] ) ) {
			$api_err_msg = sanitize_text_field( wp_unslash( $_GET['api_error'] ) );
			?>
			<div class="notice notice-error inline is-dismissible" style="margin: 12px 0 16px 0;">
				<p>
					<strong><?php esc_html_e( 'API Key Verification Failed:', 'locasentinel' ); ?></strong>
					<?php echo esc_html( $api_err_msg ); ?>
					<br />
					<span class="description"><?php esc_html_e( 'The invalid API key was not saved. Please verify your key on ip2location.io.', 'locasentinel' ); ?></span>
				</p>
			</div>
			<?php
		}

		if ( empty( $api_key ) ) {
			$current_page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '';
			$screen       = function_exists( 'get_current_screen' ) ? get_current_screen() : null;

			// Don't show "Enter API Key" prompt on the actual API settings page
			if ( $current_page === 'ip2loc-settings' || ( $screen && strpos( $screen->id, 'ip2loc-settings' ) !== false ) ) {
				return;
			}
			$settings_url = admin_url( 'admin.php?page=ip2loc-settings' );
			?>
			<div class="notice notice-warning inline ip2loc-admin-notice" style="margin: 12px 0 16px 0;">
				<p>
					<strong><?php esc_html_e( 'LocaSentinel:', 'locasentinel' ); ?></strong>
					<?php esc_html_e( 'Please add your IP2Location.io API key to enable geolocation lookups.', 'locasentinel' ); ?>
					<a href="<?php echo esc_url( $settings_url ); ?>" class="button button-secondary button-small" style="margin-left: 8px;">
						<?php esc_html_e( 'Enter API Key', 'locasentinel' ); ?>
					</a>
				</p>
			</div>
			<?php
		}

		$last_error = get_option( 'ip2loc_last_api_error' );
		if ( ! empty( $last_error ) && is_array( $last_error ) ) {
			?>
			<div class="notice notice-error inline" style="margin: 12px 0 16px 0;">
				<p>
					<strong><?php esc_html_e( 'IP2Location.io API Error:', 'ip2location-sentinel' ); ?></strong>
					<?php
					printf(
						/* translators: 1: error code, 2: error message, 3: timestamp */
						esc_html__( '[Code %1$d] %2$s (Reported at: %3$s)', 'ip2location-sentinel' ),
						(int) $last_error['code'],
						esc_html( $last_error['message'] ),
						esc_html( $last_error['timestamp'] )
					);
					?>
				</p>
			</div>
			<?php
		}
	}

	/**
	 * Render Dashboard Page
	 */
	public static function render_dashboard_page(): void {
		$stats     = Logger::get_stats( 7 );
		$settings  = get_option( 'ip2loc_settings', array() );
		$client_ip = IpResolver::get_client_ip();
		$geo_test  = ApiClient::lookup( $client_ip );

		include plugin_dir_path( dirname( __FILE__ ) ) . 'admin/views/dashboard.php';
	}

	/**
	 * Render Rules Page
	 */
	public static function render_rules_page(): void {
		$settings  = get_option( 'ip2loc_settings', array() );
		$countries = Countries::get_all_countries_with_flags();
		$presets   = Countries::get_preset_groups();

		include plugin_dir_path( dirname( __FILE__ ) ) . 'admin/views/settings-rules.php';
	}

	/**
	 * Render Endpoints Page
	 */
	public static function render_endpoints_page(): void {
		$settings = get_option( 'ip2loc_settings', array() );

		include plugin_dir_path( dirname( __FILE__ ) ) . 'admin/views/settings-protection.php';
	}

	/**
	 * Render Impossible Travel Page
	 */
	public static function render_impossible_travel_page(): void {
		$settings   = get_option( 'ip2loc_settings', array() );
		$smtp_check = SmtpChecker::check_smtp_status();

		include plugin_dir_path( dirname( __FILE__ ) ) . 'admin/views/settings-impossible-travel.php';
	}

	/**
	 * Render Audit Logs Page
	 */
	public static function render_audit_logs_page(): void {
		$search   = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';
		$action   = isset( $_GET['action_filter'] ) ? sanitize_text_field( wp_unslash( $_GET['action_filter'] ) ) : '';
		$endpoint = isset( $_GET['endpoint_filter'] ) ? sanitize_text_field( wp_unslash( $_GET['endpoint_filter'] ) ) : '';
		$per_page = isset( $_GET['per_page'] ) ? max( 1, (int) $_GET['per_page'] ) : 10;
		$page     = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;

		$log_data = Logger::get_logs(
			array(
				'search'   => $search,
				'action'   => $action,
				'endpoint' => $endpoint,
				'page'     => $page,
				'per_page' => $per_page,
			)
		);

		include plugin_dir_path( dirname( __FILE__ ) ) . 'admin/views/audit-logs.php';
	}

	/**
	 * Render Cache & CDN Page
	 */
	public static function render_cache_cdn_page(): void {
		$settings     = get_option( 'ip2loc_settings', array() );
		$cache_engines= CacheCompat::get_active_cache_engines();
		$headers_diag = IpResolver::get_server_headers_diagnostic();
		$detected_ip  = IpResolver::mask_ip_for_privacy( IpResolver::get_client_ip() );

		include plugin_dir_path( dirname( __FILE__ ) ) . 'admin/views/settings-cache-cdn.php';
	}

	/**
	 * Render API Settings Page
	 */
	public static function render_settings_page(): void {
		$settings = get_option( 'ip2loc_settings', array() );

		include plugin_dir_path( dirname( __FILE__ ) ) . 'admin/views/settings-api.php';
	}

	/**
	 * Save plugin settings form (merged cleanly per-tab).
	 */
	public static function handle_save_settings(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized access.', 'ip2location-sentinel' ), 403 );
		}

		check_admin_referer( 'ip2loc_save_settings_action', 'ip2loc_nonce' );

		$current = get_option( 'ip2loc_settings', array() );
		if ( ! is_array( $current ) ) {
			$current = array();
		}

		$tab   = isset( $_POST['ip2loc_tab'] ) ? sanitize_text_field( wp_unslash( $_POST['ip2loc_tab'] ) ) : '';
		$input = isset( $_POST['ip2loc'] ) && is_array( $_POST['ip2loc'] ) ? $_POST['ip2loc'] : array();

		// 1. Rules Tab
		if ( $tab === 'rules' || isset( $input['country_mode'] ) || isset( $input['countries'] ) || isset( $input['blocked_regions'] ) || isset( $input['whitelist_ips'] ) ) {
			$current['country_mode']      = isset( $input['country_mode'] ) && in_array( $input['country_mode'], array( 'blacklist', 'whitelist' ), true ) ? $input['country_mode'] : 'blacklist';
			$current['countries']         = isset( $input['countries'] ) && is_array( $input['countries'] ) ? array_values( array_unique( array_map( 'sanitize_text_field', $input['countries'] ) ) ) : array();
			$current['blocked_regions']   = isset( $input['blocked_regions'] ) ? sanitize_textarea_field( $input['blocked_regions'] ) : '';
			$current['blocked_cities']             = isset( $input['blocked_cities'] ) ? sanitize_textarea_field( $input['blocked_cities'] ) : '';
			$current['blocked_zips']               = isset( $input['blocked_zips'] ) ? sanitize_textarea_field( $input['blocked_zips'] ) : '';
			$current['blocked_asns']               = isset( $input['blocked_asns'] ) ? sanitize_textarea_field( $input['blocked_asns'] ) : '';
			$current['block_proxies']              = ! empty( $input['block_proxies'] ) ? 1 : 0;
			$current['allow_search_bots']          = ! empty( $input['allow_search_bots'] ) ? 1 : 0;
			$current['allow_social_bots']          = ! empty( $input['allow_social_bots'] ) ? 1 : 0;
			$current['allow_seo_bots']             = ! empty( $input['allow_seo_bots'] ) ? 1 : 0;
			$current['allow_ai_bots']              = ! empty( $input['allow_ai_bots'] ) ? 1 : 0;
			$current['allow_feed_bots']            = ! empty( $input['allow_feed_bots'] ) ? 1 : 0;
			$current['bot_rdns_verify']            = ! empty( $input['bot_rdns_verify'] ) ? 1 : 0;
			$current['allowed_crawlers_custom']    = isset( $input['allowed_crawlers_custom'] ) ? sanitize_textarea_field( $input['allowed_crawlers_custom'] ) : '';
			$current['whitelist_ips']              = isset( $input['whitelist_ips'] ) ? sanitize_textarea_field( $input['whitelist_ips'] ) : '';
			$current['blacklist_ips']              = isset( $input['blacklist_ips'] ) ? sanitize_textarea_field( $input['blacklist_ips'] ) : '';
		}

		// 2. Protection / Endpoints Tab
		if ( $tab === 'endpoints' || isset( $input['block_action'] ) || isset( $input['protect_comments'] ) || isset( $input['protect_login'] ) ) {
			$current['protect_login']                          = ! empty( $input['protect_login'] ) ? 1 : 0;
			$current['protect_xmlrpc']                         = ! empty( $input['protect_xmlrpc'] ) ? 1 : 0;
			$current['protect_comments']                       = ! empty( $input['protect_comments'] ) ? 1 : 0;
			$current['hide_comments_for_restricted_visitors'] = ! empty( $input['hide_comments_for_restricted_visitors'] ) ? 1 : 0;
			$current['hide_blocked_author_comments']           = ! empty( $input['hide_blocked_author_comments'] ) ? 1 : 0;
			$current['protect_rest_api']                       = ! empty( $input['protect_rest_api'] ) ? 1 : 0;
			$current['protect_frontend']                       = ! empty( $input['protect_frontend'] ) ? 1 : 0;
			$current['block_action']                           = isset( $input['block_action'] ) && in_array( $input['block_action'], array( 'template', 'redirect' ), true ) ? $input['block_action'] : 'template';
			$current['block_redirect_url']                     = isset( $input['block_redirect_url'] ) ? esc_url_raw( trim( $input['block_redirect_url'] ) ) : '';
			$current['block_page_title']                       = isset( $input['block_page_title'] ) ? sanitize_text_field( $input['block_page_title'] ) : '';
			$current['block_page_message']                     = isset( $input['block_page_message'] ) ? sanitize_textarea_field( $input['block_page_message'] ) : '';
			$current['comments_blocked_msg']                   = isset( $input['comments_blocked_msg'] ) ? sanitize_textarea_field( $input['comments_blocked_msg'] ) : '';
			$current['enable_captcha']                         = ! empty( $input['enable_captcha'] ) ? 1 : 0;
			$current['captcha_challenge_allowed_countries']    = ! empty( $input['captcha_challenge_allowed_countries'] ) ? 1 : 0;
			$current['captcha_rate_limit_hits']                = isset( $input['captcha_rate_limit_hits'] ) ? max( 3, (int) $input['captcha_rate_limit_hits'] ) : 10;
			$current['captcha_rate_limit_window']              = isset( $input['captcha_rate_limit_window'] ) ? max( 5, (int) $input['captcha_rate_limit_window'] ) : 60;
			$current['captcha_clearance_duration']             = isset( $input['captcha_clearance_duration'] ) ? max( 5, (int) $input['captcha_clearance_duration'] ) : 60;
			$current['captcha_provider']                       = isset( $input['captcha_provider'] ) && in_array( $input['captcha_provider'], array( 'turnstile', 'hcaptcha', 'recaptcha_v2', 'recaptcha_v3' ), true ) ? $input['captcha_provider'] : 'turnstile';
			$current['captcha_site_key']                       = isset( $input['captcha_site_key'] ) ? sanitize_text_field( trim( $input['captcha_site_key'] ) ) : '';
			$current['captcha_secret_key']                     = isset( $input['captcha_secret_key'] ) ? sanitize_text_field( trim( $input['captcha_secret_key'] ) ) : '';
		}

		// 3. Impossible Travel Tab
		if ( $tab === 'impossible_travel' || isset( $input['impossible_speed_threshold'] ) || isset( $input['impossible_action'] ) ) {
			$current['enable_impossible_travel']   = ! empty( $input['enable_impossible_travel'] ) ? 1 : 0;
			$current['impossible_speed_threshold'] = isset( $input['impossible_speed_threshold'] ) ? max( 100, (float) $input['impossible_speed_threshold'] ) : 800;
			$current['impossible_min_distance']    = isset( $input['impossible_min_distance'] ) ? max( 50, (float) $input['impossible_min_distance'] ) : 300;
			$current['impossible_domestic_mode']   = isset( $input['impossible_domestic_mode'] ) && in_array( $input['impossible_domestic_mode'], array( 'mobile_tolerance', 'ignore_domestic', 'strict' ), true ) ? $input['impossible_domestic_mode'] : 'mobile_tolerance';
			$current['impossible_action']          = isset( $input['impossible_action'] ) && in_array( $input['impossible_action'], array( 'otp', 'webhook_only' ), true ) ? $input['impossible_action'] : 'otp';
			$current['force_otp_without_smtp']     = ! empty( $input['force_otp_without_smtp'] ) ? 1 : 0;
			$current['enable_webhooks']            = ! empty( $input['enable_webhooks'] ) ? 1 : 0;
			$current['webhook_url']                = isset( $input['webhook_url'] ) ? sanitize_text_field( wp_unslash( $input['webhook_url'] ) ) : '';
			$current['webhook_type']               = isset( $input['webhook_type'] ) && in_array( $input['webhook_type'], array( 'auto', 'discord', 'slack', 'telegram', 'custom' ), true ) ? $input['webhook_type'] : 'auto';
			$current['webhook_custom_payload']     = isset( $input['webhook_custom_payload'] ) ? wp_unslash( $input['webhook_custom_payload'] ) : '';
		}

		// 4. Cache & CDN Tab
		if ( $tab === 'cache_cdn' || isset( $input['cdn_mode'] ) ) {
			$current['cdn_mode']          = isset( $input['cdn_mode'] ) && in_array( $input['cdn_mode'], array( 'auto', 'cloudflare', 'sucuri', 'x_forwarded_for', 'remote_addr' ), true ) ? $input['cdn_mode'] : 'auto';
			$current['enable_cache_vary'] = ! empty( $input['enable_cache_vary'] ) ? 1 : 0;
		}

		// 5. API & Settings Tab
		if ( $tab === 'api_settings' || isset( $input['api_key'] ) || isset( $input['cache_ttl'] ) || isset( $input['log_retention_days'] ) ) {
			if ( isset( $input['api_key'] ) ) {
				$new_key = sanitize_text_field( trim( $input['api_key'] ) );
				$old_key = $current['api_key'] ?? '';

				if ( empty( $new_key ) ) {
					// Clearing the API key is allowed
					$current['api_key'] = '';
					delete_option( 'ip2loc_last_api_error' );
				} elseif ( $new_key !== $old_key ) {
					// Changed / new key: MUST test connection and pass live verification!
					$test_result = ApiClient::test_api_key( $new_key );
					if ( empty( $test_result['success'] ) ) {
						$redirect_url = add_query_arg(
							array(
								'api_error' => rawurlencode( $test_result['message'] ?? __( 'Invalid API key or connection failed.', 'ip2location-sentinel' ) ),
							),
							admin_url( 'admin.php?page=ip2loc-settings' )
						);
						wp_safe_redirect( $redirect_url );
						exit;
					}

					$current['api_key'] = $new_key;
					delete_option( 'ip2loc_last_api_error' );
				}
			}

			$current['api_timeout']              = isset( $input['api_timeout'] ) ? max( 2, (int) $input['api_timeout'] ) : ( $current['api_timeout'] ?? 4 );
			$current['cache_ttl']                = isset( $input['cache_ttl'] ) ? max( 300, (int) $input['cache_ttl'] ) : ( $current['cache_ttl'] ?? 86400 );
			$current['api_fail_mode']            = isset( $input['api_fail_mode'] ) && in_array( $input['api_fail_mode'], array( 'open', 'safe' ), true ) ? $input['api_fail_mode'] : ( $current['api_fail_mode'] ?? 'open' );
			$current['log_retention_days']       = isset( $input['log_retention_days'] ) ? max( 1, (int) $input['log_retention_days'] ) : ( $current['log_retention_days'] ?? 30 );
			$current['delete_data_on_uninstall'] = ! empty( $input['delete_data_on_uninstall'] ) ? 1 : 0;
		}

		update_option( 'ip2loc_settings', $current );

		$referer = wp_get_referer();
		$redirect_url = add_query_arg( array( 'settings-updated' => 'true' ), $referer ?: admin_url( 'admin.php?page=ip2location-sentinel' ) );

		wp_safe_redirect( $redirect_url );
		exit;
	}

	/**
	 * AJAX: Test API Key
	 */
	public static function ajax_test_api_key(): void {
		check_ajax_referer( 'ip2loc_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'ip2location-sentinel' ) ) );
		}

		$api_key = isset( $_POST['api_key'] ) ? sanitize_text_field( wp_unslash( $_POST['api_key'] ) ) : '';
		$result  = ApiClient::test_api_key( $api_key );

		if ( $result['success'] ) {
			wp_send_json_success( $result );
		} else {
			wp_send_json_error( $result );
		}
	}

	/**
	 * AJAX: Test SMTP Email
	 */
	public static function ajax_test_smtp(): void {
		check_ajax_referer( 'ip2loc_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'ip2location-sentinel' ) ) );
		}

		$email  = isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : wp_get_current_user()->user_email;
		$result = SmtpChecker::send_test_email( $email );

		if ( $result['success'] ) {
			wp_send_json_success( $result );
		} else {
			wp_send_json_error( $result );
		}
	}

	/**
	 * AJAX: Test Webhook
	 */
	public static function ajax_test_webhook(): void {
		check_ajax_referer( 'ip2loc_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'locasentinel' ) ) );
		}

		$url            = isset( $_POST['url'] ) ? sanitize_text_field( wp_unslash( $_POST['url'] ) ) : '';
		$type           = isset( $_POST['type'] ) ? sanitize_text_field( wp_unslash( $_POST['type'] ) ) : 'auto';
		$custom_payload = isset( $_POST['custom_payload'] ) ? wp_unslash( $_POST['custom_payload'] ) : '';

		$result = Webhook::test_webhook( $url, $type, $custom_payload );

		if ( $result['success'] ) {
			wp_send_json_success( $result );
		} else {
			wp_send_json_error( $result );
		}
	}

	/**
	 * AJAX: Live IP Diagnostic Lookup
	 */
	public static function ajax_lookup_ip(): void {
		check_ajax_referer( 'ip2loc_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'ip2location-sentinel' ) ) );
		}

		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( empty( $ip ) ) {
			$ip = IpResolver::get_client_ip();
		}

		$lookup = ApiClient::lookup( $ip, true );

		if ( is_wp_error( $lookup ) ) {
			wp_send_json_error( array( 'message' => $lookup->get_error_message() ) );
		}

		$eval = RuleEngine::evaluate( $ip, $lookup );

		wp_send_json_success(
			array(
				'geo'        => $lookup,
				'evaluation' => $eval,
			)
		);
	}

	/**
	 * AJAX: Clear Audit Logs
	 */
	public static function ajax_clear_logs(): void {
		check_ajax_referer( 'ip2loc_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'ip2location-sentinel' ) ) );
		}

		Logger::clear_all_logs();
		wp_send_json_success( array( 'message' => __( 'Audit logs successfully cleared.', 'ip2location-sentinel' ) ) );
	}

	/**
	 * AJAX: Dismiss Notice
	 */
	public static function ajax_dismiss_notice(): void {
		check_ajax_referer( 'ip2loc_admin_nonce', 'nonce' );

		update_user_meta( get_current_user_id(), 'ip2loc_dismissed_api_notice', 1 );
		wp_send_json_success();
	}

	/**
	 * AJAX: Auto-Save Settings on Tab Change
	 */
	public static function ajax_auto_save_settings(): void {
		check_ajax_referer( 'ip2loc_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'locasentinel' ) ) );
		}

		$current = get_option( 'ip2loc_settings', array() );
		if ( ! is_array( $current ) ) {
			$current = array();
		}

		$tab   = isset( $_POST['ip2loc_tab'] ) ? sanitize_text_field( wp_unslash( $_POST['ip2loc_tab'] ) ) : '';
		$input = isset( $_POST['ip2loc'] ) && is_array( $_POST['ip2loc'] ) ? $_POST['ip2loc'] : array();

		// 1. Rules Tab
		if ( $tab === 'rules' || isset( $input['country_mode'] ) || isset( $input['countries'] ) || isset( $input['blocked_regions'] ) || isset( $input['whitelist_ips'] ) ) {
			$current['country_mode']      = isset( $input['country_mode'] ) && in_array( $input['country_mode'], array( 'blacklist', 'whitelist' ), true ) ? $input['country_mode'] : ( $current['country_mode'] ?? 'blacklist' );
			$current['countries']         = isset( $input['countries'] ) && is_array( $input['countries'] ) ? array_map( 'sanitize_text_field', $input['countries'] ) : array();
			$current['blocked_regions']   = isset( $input['blocked_regions'] ) ? sanitize_textarea_field( $input['blocked_regions'] ) : ( $current['blocked_regions'] ?? '' );
			$current['blocked_cities']    = isset( $input['blocked_cities'] ) ? sanitize_textarea_field( $input['blocked_cities'] ) : ( $current['blocked_cities'] ?? '' );
			$current['blocked_zips']               = isset( $input['blocked_zips'] ) ? sanitize_textarea_field( $input['blocked_zips'] ) : ( $current['blocked_zips'] ?? '' );
			$current['blocked_asns']               = isset( $input['blocked_asns'] ) ? sanitize_textarea_field( $input['blocked_asns'] ) : ( $current['blocked_asns'] ?? '' );
			$current['block_proxies']              = ! empty( $input['block_proxies'] ) ? 1 : 0;
			$current['allow_search_bots']          = ! empty( $input['allow_search_bots'] ) ? 1 : 0;
			$current['allow_social_bots']          = ! empty( $input['allow_social_bots'] ) ? 1 : 0;
			$current['allow_seo_bots']             = ! empty( $input['allow_seo_bots'] ) ? 1 : 0;
			$current['allow_ai_bots']              = ! empty( $input['allow_ai_bots'] ) ? 1 : 0;
			$current['allow_feed_bots']            = ! empty( $input['allow_feed_bots'] ) ? 1 : 0;
			$current['bot_rdns_verify']            = ! empty( $input['bot_rdns_verify'] ) ? 1 : 0;
			$current['allowed_crawlers_custom']    = isset( $input['allowed_crawlers_custom'] ) ? sanitize_textarea_field( $input['allowed_crawlers_custom'] ) : ( $current['allowed_crawlers_custom'] ?? '' );
			$current['whitelist_ips']              = isset( $input['whitelist_ips'] ) ? sanitize_textarea_field( $input['whitelist_ips'] ) : ( $current['whitelist_ips'] ?? '' );
			$current['blacklist_ips']              = isset( $input['blacklist_ips'] ) ? sanitize_textarea_field( $input['blacklist_ips'] ) : ( $current['blacklist_ips'] ?? '' );
		}

		// 2. Protection / Endpoints Tab
		if ( $tab === 'endpoints' || isset( $input['block_action'] ) || isset( $input['protect_comments'] ) || isset( $input['protect_login'] ) ) {
			$current['protect_login']                          = ! empty( $input['protect_login'] ) ? 1 : 0;
			$current['protect_xmlrpc']                         = ! empty( $input['protect_xmlrpc'] ) ? 1 : 0;
			$current['protect_comments']                       = ! empty( $input['protect_comments'] ) ? 1 : 0;
			$current['hide_comments_for_restricted_visitors'] = ! empty( $input['hide_comments_for_restricted_visitors'] ) ? 1 : 0;
			$current['hide_blocked_author_comments']           = ! empty( $input['hide_blocked_author_comments'] ) ? 1 : 0;
			$current['protect_rest_api']                       = ! empty( $input['protect_rest_api'] ) ? 1 : 0;
			$current['protect_frontend']                       = ! empty( $input['protect_frontend'] ) ? 1 : 0;
			$current['block_action']                           = isset( $input['block_action'] ) && in_array( $input['block_action'], array( 'template', 'redirect' ), true ) ? $input['block_action'] : ( $current['block_action'] ?? 'template' );
			$current['block_redirect_url']                     = isset( $input['block_redirect_url'] ) ? esc_url_raw( trim( $input['block_redirect_url'] ) ) : ( $current['block_redirect_url'] ?? '' );
			$current['block_page_title']                       = isset( $input['block_page_title'] ) ? sanitize_text_field( $input['block_page_title'] ) : ( $current['block_page_title'] ?? '' );
			$current['block_page_message']                     = isset( $input['block_page_message'] ) ? sanitize_textarea_field( $input['block_page_message'] ) : ( $current['block_page_message'] ?? '' );
			$current['comments_blocked_msg']                   = isset( $input['comments_blocked_msg'] ) ? sanitize_textarea_field( $input['comments_blocked_msg'] ) : ( $current['comments_blocked_msg'] ?? '' );
			$current['enable_captcha']                         = ! empty( $input['enable_captcha'] ) ? 1 : 0;
			$current['captcha_challenge_allowed_countries']    = isset( $input['captcha_challenge_allowed_countries'] ) ? ( ! empty( $input['captcha_challenge_allowed_countries'] ) ? 1 : 0 ) : ( $current['captcha_challenge_allowed_countries'] ?? 1 );
			$current['captcha_rate_limit_hits']                = isset( $input['captcha_rate_limit_hits'] ) ? max( 3, (int) $input['captcha_rate_limit_hits'] ) : ( $current['captcha_rate_limit_hits'] ?? 10 );
			$current['captcha_rate_limit_window']              = isset( $input['captcha_rate_limit_window'] ) ? max( 5, (int) $input['captcha_rate_limit_window'] ) : ( $current['captcha_rate_limit_window'] ?? 60 );
			$current['captcha_clearance_duration']             = isset( $input['captcha_clearance_duration'] ) ? max( 5, (int) $input['captcha_clearance_duration'] ) : ( $current['captcha_clearance_duration'] ?? 60 );
			$current['captcha_provider']                       = isset( $input['captcha_provider'] ) && in_array( $input['captcha_provider'], array( 'turnstile', 'hcaptcha', 'recaptcha_v2', 'recaptcha_v3' ), true ) ? $input['captcha_provider'] : ( $current['captcha_provider'] ?? 'turnstile' );
			$current['captcha_site_key']                       = isset( $input['captcha_site_key'] ) ? sanitize_text_field( trim( $input['captcha_site_key'] ) ) : ( $current['captcha_site_key'] ?? '' );
			$current['captcha_secret_key']                     = isset( $input['captcha_secret_key'] ) ? sanitize_text_field( trim( $input['captcha_secret_key'] ) ) : ( $current['captcha_secret_key'] ?? '' );
		}

		// 3. Impossible Travel Tab
		if ( $tab === 'impossible_travel' || isset( $input['impossible_speed_threshold'] ) || isset( $input['impossible_action'] ) ) {
			$current['enable_impossible_travel']   = ! empty( $input['enable_impossible_travel'] ) ? 1 : 0;
			$current['impossible_speed_threshold'] = isset( $input['impossible_speed_threshold'] ) ? max( 100, (float) $input['impossible_speed_threshold'] ) : 800;
			$current['impossible_min_distance']    = isset( $input['impossible_min_distance'] ) ? max( 50, (float) $input['impossible_min_distance'] ) : 300;
			$current['impossible_domestic_mode']   = isset( $input['impossible_domestic_mode'] ) && in_array( $input['impossible_domestic_mode'], array( 'mobile_tolerance', 'ignore_domestic', 'strict' ), true ) ? $input['impossible_domestic_mode'] : 'mobile_tolerance';
			$current['impossible_action']          = isset( $input['impossible_action'] ) && in_array( $input['impossible_action'], array( 'otp', 'webhook_only' ), true ) ? $input['impossible_action'] : 'otp';
			$current['force_otp_without_smtp']     = ! empty( $input['force_otp_without_smtp'] ) ? 1 : 0;
			$current['enable_webhooks']            = ! empty( $input['enable_webhooks'] ) ? 1 : 0;
			$current['webhook_url']                = isset( $input['webhook_url'] ) ? sanitize_text_field( wp_unslash( $input['webhook_url'] ) ) : '';
			$current['webhook_type']               = isset( $input['webhook_type'] ) && in_array( $input['webhook_type'], array( 'auto', 'discord', 'slack', 'telegram', 'custom' ), true ) ? $input['webhook_type'] : 'auto';
			$current['webhook_custom_payload']     = isset( $input['webhook_custom_payload'] ) ? wp_unslash( $input['webhook_custom_payload'] ) : '';
		}

		// 4. Cache & CDN Tab
		if ( $tab === 'cache_cdn' || isset( $input['cdn_mode'] ) ) {
			$current['cdn_mode']          = isset( $input['cdn_mode'] ) && in_array( $input['cdn_mode'], array( 'auto', 'cloudflare', 'sucuri', 'x_forwarded_for', 'remote_addr' ), true ) ? $input['cdn_mode'] : 'auto';
			$current['enable_cache_vary'] = ! empty( $input['enable_cache_vary'] ) ? 1 : 0;
		}

		// 5. API & Settings Tab
		if ( $tab === 'api_settings' || isset( $input['api_key'] ) || isset( $input['cache_ttl'] ) || isset( $input['log_retention_days'] ) ) {
			if ( isset( $input['api_key'] ) ) {
				$new_key = sanitize_text_field( trim( $input['api_key'] ) );
				if ( ! empty( $new_key ) && $new_key !== ( $current['api_key'] ?? '' ) ) {
					$test_res = ApiClient::test_api_key( $new_key );
					if ( ! $test_res['success'] ) {
						wp_send_json_error( array( 'message' => $test_res['message'] ?? __( 'Invalid API Key.', 'locasentinel' ) ) );
					}
					$current['api_key'] = $new_key;
					delete_option( 'ip2loc_last_api_error' );
				}
			}

			if ( isset( $input['api_timeout'] ) ) {
				$current['api_timeout'] = max( 2, (int) $input['api_timeout'] );
			}
			if ( isset( $input['cache_ttl'] ) ) {
				$current['cache_ttl'] = max( 60, (int) $input['cache_ttl'] );
			}
			if ( isset( $input['api_fail_mode'] ) ) {
				$current['api_fail_mode'] = in_array( $input['api_fail_mode'], array( 'open', 'safe' ), true ) ? $input['api_fail_mode'] : 'open';
			}
			if ( isset( $input['log_retention_days'] ) ) {
				$current['log_retention_days'] = max( 1, (int) $input['log_retention_days'] );
			}
			if ( isset( $input['delete_data_on_uninstall'] ) ) {
				$current['delete_data_on_uninstall'] = ! empty( $input['delete_data_on_uninstall'] ) ? 1 : 0;
			}
		}

		update_option( 'ip2loc_settings', $current );
		wp_send_json_success( array( 'message' => __( 'Settings saved automatically.', 'locasentinel' ) ) );
	}

	/**
	 * AJAX Handler for Seamless Real-Time POST Filtering & Pagination of Audit Logs.
	 */
	public static function ajax_filter_audit_logs(): void {
		check_ajax_referer( 'ip2loc_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'locasentinel' ) ), 403 );
		}

		$search   = isset( $_POST['s'] ) ? sanitize_text_field( wp_unslash( $_POST['s'] ) ) : '';
		$action   = isset( $_POST['action_filter'] ) ? sanitize_text_field( wp_unslash( $_POST['action_filter'] ) ) : '';
		$endpoint = isset( $_POST['endpoint_filter'] ) ? sanitize_text_field( wp_unslash( $_POST['endpoint_filter'] ) ) : '';
		$per_page = isset( $_POST['per_page'] ) ? max( 1, (int) $_POST['per_page'] ) : 10;
		$page     = isset( $_POST['paged'] ) ? max( 1, (int) $_POST['paged'] ) : 1;

		$log_data = Logger::get_logs(
			array(
				'search'   => $search,
				'action'   => $action,
				'endpoint' => $endpoint,
				'page'     => $page,
				'per_page' => $per_page,
			)
		);

		ob_start();
		self::render_audit_log_rows( $log_data['items'] );
		$html_tbody = ob_get_clean();

		ob_start();
		if ( $log_data['total_pages'] > 1 ) {
			?>
			<div class="tablenav bottom" style="margin-top: 12px;">
				<div class="tablenav-pages">
					<span class="displaying-num"><?php echo sprintf( esc_html__( '%s items', 'locasentinel' ), number_format_i18n( $log_data['total_count'] ) ); ?></span>
					<div class="pagination-links">
						<?php if ( $log_data['page'] > 1 ) : ?>
							<a class="first-page button ip2loc-ajax-page" data-paged="1" href="#"><span class="screen-reader-text"><?php esc_html_e( 'First page', 'locasentinel' ); ?></span><span aria-hidden="true">&laquo;</span></a>
							<a class="prev-page button ip2loc-ajax-page" data-paged="<?php echo ( $log_data['page'] - 1 ); ?>" href="#"><span class="screen-reader-text"><?php esc_html_e( 'Previous page', 'locasentinel' ); ?></span><span aria-hidden="true">&lsaquo;</span></a>
						<?php endif; ?>
						<span class="paging-input">
							<span class="tablenav-paging-text">
								<?php echo esc_html( $log_data['page'] ); ?> <?php esc_html_e( 'of', 'locasentinel' ); ?> <span class="total-pages"><?php echo esc_html( $log_data['total_pages'] ); ?></span>
							</span>
						</span>
						<?php if ( $log_data['page'] < $log_data['total_pages'] ) : ?>
							<a class="next-page button ip2loc-ajax-page" data-paged="<?php echo ( $log_data['page'] + 1 ); ?>" href="#"><span class="screen-reader-text"><?php esc_html_e( 'Next page', 'locasentinel' ); ?></span><span aria-hidden="true">&rsaquo;</span></a>
							<a class="last-page button ip2loc-ajax-page" data-paged="<?php echo ( $log_data['total_pages'] ); ?>" href="#"><span class="screen-reader-text"><?php esc_html_e( 'Last page', 'locasentinel' ); ?></span><span aria-hidden="true">&raquo;</span></a>
						<?php endif; ?>
					</div>
				</div>
			</div>
			<?php
		}
		$html_pagination = ob_get_clean();

		wp_send_json_success(
			array(
				'html_tbody'      => $html_tbody,
				'html_pagination' => $html_pagination,
				'total_count'     => $log_data['total_count'],
				'total_pages'     => $log_data['total_pages'],
				'page'            => $log_data['page'],
				'per_page'        => $log_data['per_page'],
			)
		);
	}

	/**
	 * Helper method to render audit log table rows.
	 *
	 * @param array $items
	 */
	public static function render_audit_log_rows( array $items ): void {
		if ( ! empty( $items ) ) :
			foreach ( $items as $row ) :
				$endpoint_display = $row['target_endpoint'] ?? ( $row['endpoint'] ?? '—' );
				$request_url      = ! empty( $row['request_url'] ) ? $row['request_url'] : $endpoint_display;
				$http_method      = ! empty( $row['http_method'] ) ? strtoupper( $row['http_method'] ) : 'GET';
				$rule_display     = $row['rule_triggered'] ?? ( $row['rule_matched'] ?? '—' );
				$user_agent_str   = ! empty( $row['user_agent'] ) ? $row['user_agent'] : '';
				$device_type      = ! empty( $row['device_type'] ) ? $row['device_type'] : 'Desktop';
				$browser_name     = ! empty( $row['browser'] ) ? $row['browser'] : 'Unknown Browser';
				$os_name          = ! empty( $row['os'] ) ? $row['os'] : 'Unknown OS';
				?>
				<tr>
					<td>
						<small><?php echo esc_html( date_i18n( 'M j, Y H:i:s', strtotime( $row['timestamp'] ) ) ); ?></small>
					</td>
					<td>
						<code><?php echo esc_html( $row['ip'] ); ?></code>
					</td>
					<td>
						<?php if ( ! empty( $row['country_code'] ) ) : ?>
							<?php echo Countries::get_flag_html( $row['country_code'] ); ?>
							<?php echo esc_html( ( $row['city_name'] ? $row['city_name'] . ', ' : '' ) . $row['country_code'] ); ?>
						<?php else : ?>
							<span class="description"><?php esc_html_e( 'Unknown', 'locasentinel' ); ?></span>
						<?php endif; ?>
					</td>
					<td>
						<div class="ip2loc-endpoint-cell">
							<span class="ip2loc-method-badge method-<?php echo strtolower( esc_attr( $http_method ) ); ?>">
								<?php echo esc_html( $http_method ); ?>
							</span>
							<code class="ip2loc-endpoint-url" title="<?php echo esc_attr( $request_url ); ?>">
								<?php echo esc_html( $request_url ); ?>
							</code>
						</div>
					</td>
					<td>
						<?php
						$badge_class = 'pill-info';
						if ( strpos( $row['action_taken'], 'BLOCKED' ) !== false ) {
							$badge_class = 'pill-danger';
						} elseif ( strpos( $row['action_taken'], 'FLAGGED' ) !== false ) {
							$badge_class = 'pill-warning';
						} elseif ( $row['action_taken'] === 'ALLOWED' ) {
							$badge_class = 'pill-success';
						}
						$hit_count = ! empty( $row['hit_count'] ) ? (int) $row['hit_count'] : 1;
						?>
						<span class="ip2loc-pill <?php echo esc_attr( $badge_class ); ?>">
							<?php echo esc_html( $row['action_taken'] ); ?>
						</span>
						<?php if ( $hit_count > 1 ) : ?>
							<br />
							<span class="ip2loc-pill pill-warning" style="font-size: 10px; margin-top: 3px; display: inline-block;" title="<?php echo esc_attr( sprintf( __( '%d identical requests aggregated', 'locasentinel' ), $hit_count ) ); ?>">
								<?php echo sprintf( esc_html__( '%d× hits', 'locasentinel' ), $hit_count ); ?>
							</span>
						<?php endif; ?>
					</td>
					<td>
						<small><?php echo esc_html( $rule_display ); ?></small>
					</td>
					<td>
						<small><?php echo esc_html( $row['as_name'] ?: '—' ); ?></small>
					</td>
					<td>
						<?php echo esc_html( $row['user_login'] ?: '—' ); ?>
					</td>
					<td>
						<div style="line-height: 1.35;">
							<span class="ip2loc-pill pill-info" style="font-size: 10px; padding: 2px 6px; margin-bottom: 3px; display: inline-block;">
								<?php echo esc_html( $device_type ); ?>
							</span>
							<br />
							<small><strong><?php echo esc_html( $browser_name ); ?></strong></small>
							<br />
							<small class="description"><?php echo esc_html( $os_name ); ?></small>
							<?php if ( ! empty( $user_agent_str ) && $user_agent_str !== 'None / Empty User-Agent' ) : ?>
								<details style="margin-top: 4px;">
									<summary style="cursor: pointer; font-size: 11px; color: #2271b1;"><?php esc_html_e( 'View Full UA', 'locasentinel' ); ?></summary>
									<code style="display: block; font-size: 10px; line-height: 1.3; word-break: break-all; max-width: 280px; white-space: normal; margin-top: 4px; padding: 4px 6px; background: #f0f0f1; border-radius: 3px;"><?php echo esc_html( $user_agent_str ); ?></code>
								</details>
							<?php endif; ?>
						</div>
					</td>
				</tr>
			<?php endforeach; ?>
		<?php else : ?>
			<tr>
				<td colspan="9" style="text-align: center; padding: 30px;">
					<div class="ip2loc-empty-state">
						<p><?php esc_html_e( 'No log entries found.', 'locasentinel' ); ?></p>
					</div>
				</td>
			</tr>
		<?php endif;
	}

	/**
	 * Handle visitor CAPTCHA verification submission.
	 */
	public static function handle_verify_captcha(): void {
		$redirect_to = isset( $_POST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_POST['redirect_to'] ) ) : home_url( '/' );

		// Validate nonce safely without triggering wp_die()
		$nonce = isset( $_POST['nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['nonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'ip2loc_captcha_verify_nonce' ) ) {
			wp_safe_redirect( add_query_arg( 'captcha_err', '1', $redirect_to ) );
			exit;
		}

		$verified = Captcha::verify_submission();

		if ( $verified ) {
			$ip = IpResolver::get_client_ip();

			// Strict Geo-Restriction Policy:
			// Even if the CAPTCHA is solved, if the visitor's IP is located in a restricted/blocked geo territory, maintain the block!
			$geo_eval = RuleEngine::evaluate( $ip );
			if ( ! empty( $geo_eval['blocked'] ) ) {
				Logger::log_event(
					$ip,
					'CAPTCHA Verification',
					'BLOCKED',
					sprintf( '%s (Geo-blocked origin restricted despite CAPTCHA solution)', $geo_eval['reason'] ?? 'Geo Restriction' ),
					'',
					0,
					$geo_eval['geo'] ?? array(),
					403
				);

				Firewall::handle_blocked_request( $geo_eval );
				exit;
			}

			$thresholds = Captcha::get_rate_limit_thresholds();
			Captcha::issue_clearance( $ip, $thresholds['clearance_seconds'] ?? 86400 );

			$clean_redirect = remove_query_arg( 'captcha_err', $redirect_to );
			wp_safe_redirect( $clean_redirect );
			exit;
		}

		// On verification failure, redirect cleanly back to the target URL with inline error
		wp_safe_redirect( add_query_arg( 'captcha_err', '1', $redirect_to ) );
		exit;
	}
}
