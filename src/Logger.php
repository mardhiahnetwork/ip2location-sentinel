<?php
/**
 * Audit Logger & Database Analytics Handler
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Logger {

	/**
	 * Log table name without prefix
	 */
	public const TABLE_NAME = 'ip2location_logs';

	/**
	 * Get full table name with WordPress database prefix.
	 *
	 * @return string
	 */
	public static function get_table_name(): string {
		global $wpdb;
		return $wpdb->prefix . self::TABLE_NAME;
	}

	/**
	 * Record a security or access event to the audit log.
	 *
	 * @param string $ip
	 * @param string $endpoint
	 * @param string $action
	 * @param string $rule_triggered
	 * @param string $user_login
	 * @param int    $user_id
	 * @param array  $geo_data
	 * @param int    $http_status
	 * @return int|false
	 */
	public static function log_event( string $ip, string $endpoint, string $action, string $rule_triggered = '', string $user_login = '', int $user_id = 0, array $geo_data = array(), int $http_status = 200 ) {
		global $wpdb;

		$table = self::get_table_name();

		$settings = get_option( 'ip2loc_settings', array() );
		if ( isset( $settings['enable_audit_logging'] ) && ! $settings['enable_audit_logging'] ) {
			return false;
		}

		if ( $action === 'ALLOWED' && $endpoint === 'Frontend' && empty( $settings['log_allowed_frontend'] ) ) {
			return false;
		}

		$ua_info = UserAgent::parse();

		$method      = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		if ( empty( $request_uri ) ) {
			if ( wp_doing_ajax() ) {
				$request_uri = '/wp-admin/admin-ajax.php';
			} elseif ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
				$request_uri = '/xmlrpc.php';
			} elseif ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
				$request_uri = '/wp-json/';
			}
		}

		// Skip CAPTCHA challenges, favicons, robots.txt, sitemaps, and common static assets
		if ( self::is_ignorable_request( $request_uri, $endpoint, $action ) ) {
			return false;
		}

		// Anti-Spam Log Debouncer & Hit Accumulator (aggregates repeated identical hits to same URL within 5 mins)
		$fingerprint = md5( $ip . '|' . $method . '|' . $request_uri . '|' . $endpoint . '|' . $action . '|' . $rule_triggered );
		$cache_key   = 'recent_log_' . $fingerprint;

		$recent_id = RedisDriver::get( $cache_key );
		if ( ! empty( $recent_id ) && is_numeric( $recent_id ) ) {
			// Increment hit_count and update timestamp on existing log row
			$updated = $wpdb->query(
				$wpdb->prepare(
					"UPDATE {$table} SET hit_count = hit_count + 1, timestamp = %s WHERE id = %d",
					current_time( 'mysql' ),
					(int) $recent_id
				)
			);
			if ( false !== $updated ) {
				return (int) $recent_id;
			}
		}

		$data = array(
			'timestamp'       => current_time( 'mysql' ),
			'ip'              => substr( sanitize_text_field( $ip ), 0, 45 ),
			'country_code'    => isset( $geo_data['country_code'] ) ? substr( sanitize_text_field( $geo_data['country_code'] ), 0, 2 ) : '',
			'country_name'    => isset( $geo_data['country_name'] ) ? substr( sanitize_text_field( $geo_data['country_name'] ), 0, 100 ) : '',
			'region_name'     => isset( $geo_data['region_name'] ) ? substr( sanitize_text_field( $geo_data['region_name'] ), 0, 100 ) : '',
			'city_name'       => isset( $geo_data['city_name'] ) ? substr( sanitize_text_field( $geo_data['city_name'] ), 0, 100 ) : '',
			'zip_code'        => isset( $geo_data['zip_code'] ) ? substr( sanitize_text_field( $geo_data['zip_code'] ), 0, 20 ) : '',
			'asn'             => isset( $geo_data['asn'] ) ? substr( sanitize_text_field( $geo_data['asn'] ), 0, 50 ) : '',
			'as_name'         => isset( $geo_data['as'] ) ? substr( sanitize_text_field( $geo_data['as'] ), 0, 255 ) : '',
			'is_proxy'        => ! empty( $geo_data['is_proxy'] ) ? 1 : 0,
			'http_method'     => substr( $method, 0, 10 ),
			'request_url'     => $request_uri,
			'target_endpoint' => substr( sanitize_text_field( $endpoint ), 0, 255 ),
			'action_taken'    => substr( sanitize_text_field( $action ), 0, 50 ),
			'rule_triggered'  => substr( sanitize_text_field( $rule_triggered ), 0, 255 ),
			'user_login'      => substr( sanitize_text_field( $user_login ), 0, 60 ),
			'user_id'         => (int) $user_id,
			'user_agent'      => $ua_info['user_agent'],
			'device_type'     => $ua_info['device'],
			'browser'         => $ua_info['browser'],
			'os'              => $ua_info['os'],
			'http_status'     => (int) $http_status,
			'hit_count'       => 1,
		);

		$inserted = $wpdb->insert( $table, $data );
		if ( $inserted ) {
			$new_id = (int) $wpdb->insert_id;
			RedisDriver::set( $cache_key, $new_id, 300 );
			return $new_id;
		}

		return false;
	}

	/**
	 * Retrieve audit logs with filtering and pagination.
	 *
	 * @param array $args
	 * @return array
	 */
	public static function get_logs( array $args = array() ): array {
		global $wpdb;

		$table = self::get_table_name();

		$defaults = array(
			'search'   => '',
			'action'   => '',
			'endpoint' => '',
			'page'     => 1,
			'per_page' => 10,
			'orderby'  => 'id',
			'order'    => 'DESC',
		);

		$args = wp_parse_args( $args, $defaults );

		$where_clauses = array( '1=1' );
		$values        = array();

		if ( ! empty( $args['search'] ) ) {
			$search = '%' . $wpdb->esc_like( trim( $args['search'] ) ) . '%';
			$where_clauses[] = '(ip LIKE %s OR country_code LIKE %s OR country_name LIKE %s OR city_name LIKE %s OR as_name LIKE %s OR user_login LIKE %s OR rule_triggered LIKE %s OR request_url LIKE %s OR http_method LIKE %s)';
			$values = array_merge( $values, array( $search, $search, $search, $search, $search, $search, $search, $search, $search ) );
		}

		if ( ! empty( $args['action'] ) ) {
			$where_clauses[] = 'action_taken = %s';
			$values[] = sanitize_text_field( $args['action'] );
		}

		if ( ! empty( $args['endpoint'] ) ) {
			$where_clauses[] = 'target_endpoint LIKE %s';
			$values[] = '%' . $wpdb->esc_like( sanitize_text_field( $args['endpoint'] ) ) . '%';
		}

		$where_sql = implode( ' AND ', $where_clauses );

		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}";
		$total     = ! empty( $values ) ? (int) $wpdb->get_var( $wpdb->prepare( $count_sql, $values ) ) : (int) $wpdb->get_var( $count_sql );

		$allowed_orders = array( 'ASC', 'DESC' );
		$order          = in_array( strtoupper( $args['order'] ), $allowed_orders, true ) ? strtoupper( $args['order'] ) : 'DESC';

		$allowed_orderbys = array( 'id', 'timestamp', 'ip', 'country_code', 'action_taken', 'target_endpoint' );
		$orderby          = in_array( $args['orderby'], $allowed_orderbys, true ) ? $args['orderby'] : 'id';

		$per_page = max( 1, (int) $args['per_page'] );
		$page     = max( 1, (int) $args['page'] );
		$offset   = ( $page - 1 ) * $per_page;

		$query_sql = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d";
		$query_values = array_merge( $values, array( $per_page, $offset ) );

		$items = $wpdb->get_results( $wpdb->prepare( $query_sql, $query_values ), ARRAY_A );

		return array(
			'items'       => is_array( $items ) ? $items : array(),
			'total_count' => $total,
			'total_pages' => ceil( $total / $per_page ),
			'page'        => $page,
			'per_page'    => $per_page,
		);
	}

	/**
	 * Get summary statistics for dashboard.
	 *
	 * @param int $days
	 * @return array
	 */
	public static function get_stats( int $days = 7 ): array {
		global $wpdb;

		$table = self::get_table_name();

		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
			return array(
				'total_events'       => 0,
				'total_blocked'      => 0,
				'total_spam_blocked' => 0,
				'total_travel_caught'=> 0,
				'top_countries'      => array(),
				'daily_trends'       => array(),
			);
		}

		$date_since = date( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );

		$total_events = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE timestamp >= %s", $date_since ) );
		$total_blocked = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE action_taken IN ('BLOCKED', 'COMMENT_SPAM_BLOCKED') AND timestamp >= %s", $date_since ) );
		$total_spam_blocked = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE action_taken = 'COMMENT_SPAM_BLOCKED' AND timestamp >= %s", $date_since ) );
		$total_travel_caught = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE action_taken LIKE '%%IMPOSSIBLE_TRAVEL%%' AND timestamp >= %s", $date_since ) );

		$top_countries = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT country_code, country_name, COUNT(*) as count FROM {$table} WHERE action_taken IN ('BLOCKED', 'COMMENT_SPAM_BLOCKED') AND country_code != '' AND timestamp >= %s GROUP BY country_code, country_name ORDER BY count DESC LIMIT 5",
				$date_since
			),
			ARRAY_A
		);

		$daily_trends = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT DATE(timestamp) as date_val, COUNT(*) as total, SUM(CASE WHEN action_taken IN ('BLOCKED', 'COMMENT_SPAM_BLOCKED') THEN 1 ELSE 0 END) as blocked FROM {$table} WHERE timestamp >= %s GROUP BY DATE(timestamp) ORDER BY date_val ASC",
				$date_since
			),
			ARRAY_A
		);

		return array(
			'total_events'        => $total_events,
			'total_blocked'       => $total_blocked,
			'total_spam_blocked'  => $total_spam_blocked,
			'total_travel_caught' => $total_travel_caught,
			'top_countries'       => is_array( $top_countries ) ? $top_countries : array(),
			'daily_trends'        => is_array( $daily_trends ) ? $daily_trends : array(),
		);
	}

	/**
	 * Prune old logs based on retention days.
	 *
	 * @param int $days
	 * @return int Number of rows deleted
	 */
	public static function prune_logs( int $days = 30 ): int {
		global $wpdb;

		$table = self::get_table_name();
		$days  = max( 1, $days );
		$cutoff_date = date( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );

		return (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE timestamp < %s", $cutoff_date ) );
	}

	/**
	 * Truncate entire audit logs table.
	 *
	 * @return bool
	 */
	public static function clear_all_logs(): bool {
		global $wpdb;
		$table = self::get_table_name();
		return (bool) $wpdb->query( "TRUNCATE TABLE {$table}" );
	}

	/**
	 * Export audit logs to CSV and stream to browser.
	 */
	public static function export_csv(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized access.', 'ip2location-sentinel' ), 403 );
		}

		check_admin_referer( 'ip2loc_export_csv_nonce', 'nonce' );

		global $wpdb;
		$table = self::get_table_name();

		if ( ob_get_level() ) {
			ob_end_clean();
		}

		$filename = 'ip2location-sentinel-audit-log-' . gmdate( 'Y-m-d-His' ) . '.csv';

		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=' . $filename );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		$output = fopen( 'php://output', 'w' );

		fputs( $output, "\xEF\xBB\xBF" );

		fputcsv(
			$output,
			array(
				'ID',
				'Timestamp (UTC/Local)',
				'IP Address',
				'Country Code',
				'Country Name',
				'Region',
				'City',
				'Zip Code',
				'ASN',
				'ISP / Organization',
				'Proxy/VPN',
				'Target Endpoint',
				'Action Taken',
				'Rule Triggered',
				'Username',
				'Device Type',
				'Browser',
				'OS',
				'User Agent',
			)
		);

		$results = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY id DESC LIMIT 5000", ARRAY_A );

		if ( ! empty( $results ) ) {
			foreach ( $results as $row ) {
				fputcsv(
					$output,
					array(
						$row['id'],
						$row['timestamp'],
						$row['ip'],
						$row['country_code'],
						$row['country_name'],
						$row['region_name'],
						$row['city_name'],
						$row['zip_code'],
						$row['asn'],
						$row['as_name'],
						$row['is_proxy'] ? 'YES' : 'NO',
						$row['target_endpoint'],
						$row['action_taken'],
						$row['rule_triggered'],
						$row['user_login'],
						$row['device_type'],
						$row['browser'],
						$row['os'],
						$row['user_agent'],
					)
				);
			}
		}

		fclose( $output );
		exit;
	}

	/**
	 * Determine if request is a common static asset, CAPTCHA challenge, or ignorable background probe.
	 *
	 * @param string $request_uri
	 * @param string $endpoint
	 * @param string $action
	 * @return bool
	 */
	public static function is_ignorable_request( string $request_uri, string $endpoint, string $action ): bool {
		// Never ignore REST API, Login, Comments, or XML-RPC endpoints
		if ( stripos( $endpoint, 'REST API' ) !== false || stripos( $request_uri, 'wp-json' ) !== false || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return false;
		}

		if ( stripos( $endpoint, 'Login' ) !== false || stripos( $endpoint, 'Comments' ) !== false || stripos( $endpoint, 'XML-RPC' ) !== false ) {
			return false;
		}

		// 1. Skip all CAPTCHA challenges & rate limit events
		if ( stripos( $action, 'CAPTCHA' ) !== false || stripos( $endpoint, 'Rate Limit' ) !== false ) {
			return true;
		}

		$clean_path = strtolower( strtok( trim( $request_uri ), '?' ) ?: '' );

		if ( empty( $clean_path ) ) {
			return false;
		}

		// 2. Skip favicon, app icons, and web manifests
		if ( preg_match( '/\b(favicon\.(ico|png|svg)|apple-touch-icon.*\.png|android-chrome.*\.png|site\.webmanifest|manifest\.json|browserconfig\.xml)$/i', $clean_path ) ) {
			return true;
		}

		// 3. Skip robots.txt, sitemaps, and service workers
		if ( preg_match( '/\b(robots\.txt|sitemap.*\.xml|sw\.js|service-worker\.js)$/i', $clean_path ) ) {
			return true;
		}

		// 4. Skip common static file extensions
		if ( preg_match( '/\.(ico|png|jpe?g|gif|webp|svg|css|js|map|woff2?|ttf|eot|otf|pdf|txt)$/i', $clean_path ) ) {
			return true;
		}

		return false;
	}
}
