<?php
/**
 * IP2Location Core Firewall & Sensitive Endpoint Interceptor
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

use WP_Error;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Firewall {

	/**
	 * Initialize firewall interceptors.
	 */
	public static function init(): void {
		add_action( 'xmlrpc_call', array( __CLASS__, 'protect_xmlrpc' ), 1 );
		add_action( 'login_init', array( __CLASS__, 'protect_login_page' ), 1 );
		add_filter( 'preprocess_comment', array( __CLASS__, 'protect_comments' ), 1 );
		add_filter( 'comments_open', array( __CLASS__, 'filter_comments_open' ), 10, 2 );
		add_filter( 'comments_array', array( __CLASS__, 'filter_comments_display' ), 10, 2 );
		add_filter( 'the_comments', array( __CLASS__, 'filter_comments_display' ), 10, 2 );
		add_filter( 'get_comments_number', array( __CLASS__, 'filter_comments_number' ), 10, 2 );
		add_filter( 'comments_template', array( __CLASS__, 'filter_comments_template' ), 10, 1 );
		add_filter( 'rest_authentication_errors', array( __CLASS__, 'protect_rest_api' ), 99 );
		add_action( 'template_redirect', array( __CLASS__, 'protect_frontend' ), 1 );
		add_action( 'init', array( __CLASS__, 'check_path_rate_limit' ), 1 );
	}

	/**
	 * Protect XML-RPC endpoint against DDoS, brute force, and amplification.
	 */
	public static function protect_xmlrpc(): void {
		$settings = get_option( 'ip2loc_settings', array() );

		$enabled = ! isset( $settings['protect_xmlrpc'] ) || ! empty( $settings['protect_xmlrpc'] );
		if ( ! $enabled ) {
			return;
		}

		$ip     = IpResolver::get_client_ip();
		$result = RuleEngine::evaluate( $ip );

		if ( $result['blocked'] ) {
			CacheCompat::disable_caching();

			Logger::log_event(
				$ip,
				'XML-RPC (xmlrpc.php)',
				'BLOCKED',
				$result['reason'],
				'',
				0,
				$result['geo'],
				403
			);

			Webhook::send_event(
				'XMLRPC_BLOCKED',
				array(
					'ip'           => $ip,
					'reason'       => $result['reason'],
					'country'      => $result['geo']['country_code'] ?? '',
					'action_taken' => 'Blocked XML-RPC Request',
				)
			);

			status_header( 403 );
			header( 'Content-Type: text/plain; charset=utf-8' );
			echo 'Access denied by IP2Location Sentinel.';
			exit;
		}
	}

	/**
	 * Protect wp-login.php endpoint against unauthorized geo logins.
	 */
	public static function protect_login_page(): void {
		if ( isset( $_REQUEST['action'] ) && $_REQUEST['action'] === 'ip2loc_otp' ) {
			return;
		}

		$settings = get_option( 'ip2loc_settings', array() );
		if ( empty( $settings['protect_login'] ) ) {
			return;
		}

		$ip     = IpResolver::get_client_ip();
		$result = RuleEngine::evaluate( $ip );

		if ( $result['blocked'] ) {
			CacheCompat::disable_caching();

			Logger::log_event(
				$ip,
				'Login (wp-login.php)',
				'BLOCKED',
				$result['reason'],
				isset( $_POST['log'] ) ? sanitize_text_field( wp_unslash( $_POST['log'] ) ) : '',
				0,
				$result['geo'],
				403
			);

			self::handle_blocked_request( $result );
		}
	}

	/**
	 * Protect Comments and Discussion endpoints against Geo/Proxy spam.
	 * Active by default as requested.
	 *
	 * @param array $commentdata
	 * @return array
	 */
	public static function protect_comments( array $commentdata ): array {
		$settings = get_option( 'ip2loc_settings', array() );

		$enabled = ! isset( $settings['protect_comments'] ) || ! empty( $settings['protect_comments'] );
		if ( ! $enabled ) {
			return $commentdata;
		}

		$ip = IpResolver::get_client_ip();

		$result = RuleEngine::evaluate( $ip );

		if ( $result['blocked'] ) {
			CacheCompat::disable_caching();

			$post_id   = isset( $commentdata['comment_post_ID'] ) ? (int) $commentdata['comment_post_ID'] : 0;
			$author    = isset( $commentdata['comment_author'] ) ? sanitize_text_field( $commentdata['comment_author'] ) : '';
			$post_title = $post_id ? get_the_title( $post_id ) : 'Unknown Post';

			Logger::log_event(
				$ip,
				sprintf( 'Comment (Post #%d: %s)', $post_id, substr( $post_title, 0, 30 ) ),
				'COMMENT_SPAM_BLOCKED',
				$result['reason'],
				$author,
				0,
				$result['geo'],
				403
			);

			Webhook::send_event(
				'COMMENT_SPAM_BLOCKED',
				array(
					'ip'           => $ip,
					'author'       => $author,
					'post_id'      => $post_id,
					'post_title'   => $post_title,
					'reason'       => $result['reason'],
					'action_taken' => 'Comment Submission Rejected (403 Forbidden)',
				)
			);

			$custom_msg = ! empty( $settings['comments_blocked_msg'] )
				? $settings['comments_blocked_msg']
				: __( 'Comments from your geographical region or network are not accepted on this website.', 'ip2location-sentinel' );

			wp_die(
				esc_html( $custom_msg ),
				esc_html__( 'Comment Blocked by Geo Security', 'ip2location-sentinel' ),
				array( 'response' => 403, 'back_link' => true )
			);
		}

		return $commentdata;
	}

	/**
	 * Dynamically close comments for visitors from restricted locations.
	 *
	 * @param bool $open
	 * @param int  $post_id
	 * @return bool
	 */
	public static function filter_comments_open( $open, $post_id ) {
		if ( ! $open || is_admin() ) {
			return $open;
		}

		$settings = get_option( 'ip2loc_settings', array() );
		if ( empty( $settings['hide_comments_for_restricted_visitors'] ) ) {
			return $open;
		}

		$ip     = IpResolver::get_client_ip();
		$result = RuleEngine::evaluate( $ip );

		if ( $result['blocked'] ) {
			return false;
		}

		return $open;
	}

	/**
	 * Filter comments list to hide discussions from restricted visitors or filter out historical spam.
	 *
	 * @param array $comments
	 * @param int   $post_id
	 * @return array
	 */
	public static function filter_comments_display( $comments, $post_id ) {
		if ( is_admin() || empty( $comments ) || ! is_array( $comments ) ) {
			return $comments;
		}

		$settings = get_option( 'ip2loc_settings', array() );

		// 1. Hide all comments for visitors from restricted locations
		if ( ! empty( $settings['hide_comments_for_restricted_visitors'] ) ) {
			$ip     = IpResolver::get_client_ip();
			$result = RuleEngine::evaluate( $ip );
			if ( $result['blocked'] ) {
				return array();
			}
		}

		// 2. Hide historical comments posted from restricted locations
		if ( ! empty( $settings['hide_blocked_author_comments'] ) ) {
			$filtered = array();
			foreach ( $comments as $comment ) {
				$author_ip = is_object( $comment ) ? ( $comment->comment_author_IP ?? '' ) : ( $comment['comment_author_IP'] ?? '' );
				if ( ! empty( $author_ip ) ) {
					$eval = RuleEngine::evaluate( $author_ip );
					if ( $eval['blocked'] ) {
						continue; // Filter out comment from restricted origin
					}
				}
				$filtered[] = $comment;
			}
			return $filtered;
		}

		return $comments;
	}

	/**
	 * Override displayed comment count when comments are hidden for restricted visitors.
	 *
	 * @param int $count
	 * @param int $post_id
	 * @return int
	 */
	public static function filter_comments_number( $count, $post_id ) {
		if ( is_admin() ) {
			return $count;
		}

		$settings = get_option( 'ip2loc_settings', array() );
		if ( empty( $settings['hide_comments_for_restricted_visitors'] ) ) {
			return $count;
		}

		$ip     = IpResolver::get_client_ip();
		$result = RuleEngine::evaluate( $ip );

		if ( $result['blocked'] ) {
			return 0;
		}

		return $count;
	}

	/**
	 * Short-circuit comments template to clean empty file when comments are hidden for restricted visitors.
	 *
	 * @param string $template
	 * @return string
	 */
	public static function filter_comments_template( $template ) {
		if ( is_admin() ) {
			return $template;
		}

		$settings = get_option( 'ip2loc_settings', array() );
		if ( empty( $settings['hide_comments_for_restricted_visitors'] ) ) {
			return $template;
		}

		$ip     = IpResolver::get_client_ip();
		$result = RuleEngine::evaluate( $ip );

		if ( $result['blocked'] ) {
			$empty_file = plugin_dir_path( dirname( __FILE__ ) ) . 'admin/views/empty-comments.php';
			if ( file_exists( $empty_file ) ) {
				return $empty_file;
			}
		}

		return $template;
	}

	/**
	 * Protect WordPress REST API endpoints against unauthorized geo access.
	 * Authenticated administrators and editors with valid session/nonces are automatically exempted.
	 *
	 * @param mixed $errors
	 * @return mixed
	 */
	public static function protect_rest_api( $errors ) {
		// If an authentication error has already occurred, preserve it
		if ( ! empty( $errors ) && is_wp_error( $errors ) ) {
			return $errors;
		}

		// Authenticated administrators and editors always bypass public REST restrictions
		if ( is_user_logged_in() && ( current_user_can( 'manage_options' ) || current_user_can( 'edit_posts' ) ) ) {
			return $errors;
		}

		$settings = get_option( 'ip2loc_settings', array() );
		if ( empty( $settings['protect_rest_api'] ) ) {
			return $errors;
		}

		$ip     = IpResolver::get_client_ip();
		$result = RuleEngine::evaluate( $ip );

		if ( $result['blocked'] ) {
			CacheCompat::disable_caching();

			$rest_route = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/wp-json/';

			Logger::log_event(
				$ip,
				'REST API (' . substr( $rest_route, 0, 45 ) . ')',
				'BLOCKED',
				$result['reason'],
				'',
				0,
				$result['geo'],
				403
			);

			return new WP_Error(
				'ip2loc_rest_geo_blocked',
				__( 'Access to the REST API is restricted for your geographical region.', 'locasentinel' ),
				array( 'status' => 403 )
			);
		}

		return $errors;
	}

	/**
	 * Protect Frontend / Whole Site if enabled.
	 * Authenticated administrators are exempt from frontend lockout.
	 */
	public static function protect_frontend(): void {
		if ( is_admin() || wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		// Never lock out authenticated site administrators browsing the frontend
		if ( is_user_logged_in() && current_user_can( 'manage_options' ) ) {
			return;
		}

		$settings = get_option( 'ip2loc_settings', array() );
		if ( empty( $settings['protect_frontend'] ) ) {
			return;
		}

		$ip     = IpResolver::get_client_ip();
		$result = RuleEngine::evaluate( $ip );

		if ( $result['blocked'] ) {
			CacheCompat::disable_caching();

			$current_url = home_url( add_query_arg( array(), $GLOBALS['wp']->request ?? '' ) );

			Logger::log_event(
				$ip,
				'Frontend (' . substr( $current_url, 0, 50 ) . ')',
				'BLOCKED',
				$result['reason'],
				'',
				0,
				$result['geo'],
				403
			);

			self::handle_blocked_request( $result );
		}
	}

	/**
	 * Render the blocked response or execute redirect.
	 *
	 * @param array $eval_result
	 */
	public static function handle_blocked_request( array $eval_result ): void {
		$settings = get_option( 'ip2loc_settings', array() );

		if ( ! empty( $settings['block_action'] ) && $settings['block_action'] === 'redirect' && ! empty( $settings['block_redirect_url'] ) ) {
			$target_url = esc_url_raw( $settings['block_redirect_url'] );
			wp_safe_redirect( $target_url, 302 );
			exit;
		}

		CacheCompat::disable_caching();
		status_header( 403 );

		$block_template = plugin_dir_path( dirname( __FILE__ ) ) . 'admin/views/block-template.php';

		$incident_id  = 'INC-' . strtoupper( substr( md5( uniqid( (string) wp_rand(), true ) ), 0, 10 ) );
		$client_ip    = $eval_result['geo']['ip'] ?? IpResolver::get_client_ip();
		$country_code = $eval_result['geo']['country_code'] ?? '';
		$country_name = $eval_result['geo']['country_name'] ?? '';
		$rule_reason  = $eval_result['reason'] ?? __( 'Location or network access rule.', 'locasentinel' );
		$custom_title = ! empty( $settings['block_page_title'] ) ? $settings['block_page_title'] : __( 'Access Restricted (403)', 'locasentinel' );
		$custom_body  = ! empty( $settings['block_page_message'] ) ? $settings['block_page_message'] : __( 'Access from your IP address or geographical region is restricted by the site security policy.', 'locasentinel' );

		if ( file_exists( $block_template ) ) {
			include $block_template;
		} else {
			wp_die(
				esc_html( $custom_body ),
				esc_html( $custom_title ),
				array( 'response' => 403 )
			);
		}

		exit;
	}

	/**
	 * Monitor request frequency per path and challenge excessive spam hits with CAPTCHA.
	 */
	public static function check_path_rate_limit(): void {
		if ( ! Captcha::is_configured() ) {
			return;
		}

		// Skip WP-Admin, Cron, and Authenticated Admins
		if ( is_admin() || wp_doing_cron() || ( is_user_logged_in() && current_user_can( 'manage_options' ) ) ) {
			return;
		}

		$ip = IpResolver::get_client_ip();

		// Whitelisted IPs and Private LANs never get rate-limited
		if ( IpResolver::is_private_ip( $ip ) ) {
			return;
		}

		$settings      = get_option( 'ip2loc_settings', array() );
		$whitelist_ips = RuleEngine::parse_list( $settings['whitelist_ips'] ?? "127.0.0.1\n::1" );
		if ( RuleEngine::matches_ip_list( $ip, $whitelist_ips ) ) {
			return;
		}

		// Verified genuine search engine bots never get rate-limited
		$raw_ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		if ( ! empty( $settings['allow_search_bots'] ) && ! empty( $raw_ua ) && UserAgent::is_search_engine( $raw_ua ) ) {
			if ( UserAgent::verify_search_bot_rdns( $ip, $raw_ua ) ) {
				return;
			}
		}

		$raw_path = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
		$path     = Captcha::normalize_path( $raw_path );

		// Skip AJAX / Cron / Verification endpoints
		if ( strpos( $path, 'admin-post.php' ) !== false || strpos( $path, 'admin-ajax.php' ) !== false ) {
			return;
		}

		// If admin disabled rate limiting for allowed/non-restricted countries, skip when geo is allowed
		if ( isset( $settings['captcha_challenge_allowed_countries'] ) && empty( $settings['captcha_challenge_allowed_countries'] ) ) {
			$geo_eval = RuleEngine::evaluate( $ip );
			if ( ! $geo_eval['blocked'] ) {
				return;
			}
		}

		// Check if IP is in a persistent 24h lockout or exceeded rate limits
		if ( Captcha::is_challenge_required( $ip, $path ) ) {
			Captcha::render_challenge_page( $ip, $path );
		}
	}
}
