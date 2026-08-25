<?php
/**
 * IP2Location.io API Client with Caching & Error Handling
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

use WP_Error;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ApiClient {

	/**
	 * Base API URL
	 */
	public const API_BASE_URL = 'https://api.ip2location.io/';

	/**
	 * Standard Error Messages Map
	 */
	public const ERROR_MAP = array(
		10000 => 'Invalid API key or insufficient query.',
		10001 => 'Invalid IP address.',
		10002 => 'Internal server error.',
		10003 => 'Invalid language code.',
		10004 => 'Translation is not available with your plan.',
	);

	/**
	 * Lookup an IP address via IP2Location.io API (with caching).
	 *
	 * @param string $ip
	 * @param bool   $force_refresh
	 * @return array|WP_Error Normalized geolocation data array or WP_Error.
	 */
	public static function lookup( string $ip = '', bool $force_refresh = false ) {
		if ( empty( $ip ) ) {
			$ip = IpResolver::get_client_ip();
		}

		$ip = trim( $ip );

		if ( empty( $ip ) || ! IpResolver::is_valid_ip( $ip ) ) {
			return new WP_Error(
				'10001',
				__( 'Invalid IP address.', 'ip2location-sentinel' ),
				array( 'error_code' => 10001 )
			);
		}

		// Check for private/local IP
		if ( IpResolver::is_private_ip( $ip ) ) {
			return self::get_private_ip_response( $ip );
		}

		$cache_key = 'geo_' . md5( $ip );

		if ( ! $force_refresh ) {
			$cached = RedisDriver::get( $cache_key );
			if ( false !== $cached && is_array( $cached ) ) {
				$cached['cached'] = true;
				return $cached;
			}
		}

		$settings = get_option( 'ip2loc_settings', array() );
		$api_key  = isset( $settings['api_key'] ) ? trim( $settings['api_key'] ) : '';

		if ( empty( $api_key ) ) {
			return new WP_Error(
				'10000',
				__( 'IP2Location API key is not configured.', 'ip2location-sentinel' ),
				array( 'error_code' => 10000 )
			);
		}

		$url = add_query_arg(
			array(
				'key'    => rawurlencode( $api_key ),
				'ip'     => rawurlencode( $ip ),
				'format' => 'json',
			),
			self::API_BASE_URL
		);

		$timeout = isset( $settings['api_timeout'] ) ? max( 2, (int) $settings['api_timeout'] ) : 4;

		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => $timeout,
				'user-agent'  => 'IP2LocationSentinel/1.0.0 (WordPress; ' . home_url() . ')',
				'sslverify'   => true,
				'httpversion' => '1.1',
			)
		);

		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'http_request_failed',
				sprintf(
					/* translators: %s: error message */
					__( 'IP2Location API request error: %s', 'ip2location-sentinel' ),
					$response->get_error_message()
				)
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) ) {
			return new WP_Error(
				'json_parse_error',
				__( 'Invalid JSON response from IP2Location API.', 'ip2location-sentinel' )
			);
		}

		// Handle API error structure
		if ( isset( $data['error'] ) && is_array( $data['error'] ) ) {
			$error_code = isset( $data['error']['error_code'] ) ? (int) $data['error']['error_code'] : 10002;
			$error_msg  = $data['error']['error_message'] ?? self::get_error_message( $error_code );

			update_option(
				'ip2loc_last_api_error',
				array(
					'code'      => $error_code,
					'message'   => $error_msg,
					'timestamp' => current_time( 'mysql' ),
				)
			);

			return new WP_Error(
				(string) $error_code,
				$error_msg,
				array( 'error_code' => $error_code )
			);
		}

		delete_option( 'ip2loc_last_api_error' );

		$normalized = self::normalize_response( $data, $ip );

		$cache_ttl = isset( $settings['cache_ttl'] ) ? max( 3600, (int) $settings['cache_ttl'] ) : 86400;
		RedisDriver::set( $cache_key, $normalized, $cache_ttl );

		return $normalized;
	}

	/**
	 * Normalize IP2Location.io payload for predictable consumption.
	 *
	 * @param array  $data
	 * @param string $ip
	 * @return array
	 */
	public static function normalize_response( array $data, string $ip ): array {
		return array(
			'ip'           => isset( $data['ip'] ) ? sanitize_text_field( $data['ip'] ) : $ip,
			'country_code' => isset( $data['country_code'] ) ? strtoupper( sanitize_text_field( $data['country_code'] ) ) : '',
			'country_name' => isset( $data['country_name'] ) ? sanitize_text_field( $data['country_name'] ) : '',
			'region_name'  => isset( $data['region_name'] ) ? sanitize_text_field( $data['region_name'] ) : '',
			'city_name'    => isset( $data['city_name'] ) ? sanitize_text_field( $data['city_name'] ) : '',
			'latitude'     => isset( $data['latitude'] ) ? (float) $data['latitude'] : 0.0,
			'longitude'    => isset( $data['longitude'] ) ? (float) $data['longitude'] : 0.0,
			'zip_code'     => isset( $data['zip_code'] ) ? sanitize_text_field( $data['zip_code'] ) : '',
			'time_zone'    => isset( $data['time_zone'] ) ? sanitize_text_field( $data['time_zone'] ) : '',
			'asn'          => isset( $data['asn'] ) ? sanitize_text_field( $data['asn'] ) : '',
			'as'           => isset( $data['as'] ) ? sanitize_text_field( $data['as'] ) : '',
			'is_proxy'     => ! empty( $data['is_proxy'] ),
			'is_private'   => false,
			'cached'       => false,
			'fetched_at'   => current_time( 'mysql' ),
		);
	}

	/**
	 * Mock response for Local / RFC 1918 Private IPs.
	 *
	 * @param string $ip
	 * @return array
	 */
	public static function get_private_ip_response( string $ip ): array {
		return array(
			'ip'           => $ip,
			'country_code' => 'LOCAL',
			'country_name' => __( 'Local / Private Network', 'ip2location-sentinel' ),
			'region_name'  => __( 'Localhost', 'ip2location-sentinel' ),
			'city_name'    => __( 'Localhost', 'ip2location-sentinel' ),
			'latitude'     => 0.0,
			'longitude'    => 0.0,
			'zip_code'     => '00000',
			'time_zone'    => '+00:00',
			'asn'          => '0',
			'as'           => __( 'Private Network Loopback', 'ip2location-sentinel' ),
			'is_proxy'     => false,
			'is_private'   => true,
			'cached'       => false,
			'fetched_at'   => current_time( 'mysql' ),
		);
	}

	/**
	 * Get descriptive error message from error code.
	 *
	 * @param int $code
	 * @return string
	 */
	public static function get_error_message( int $code ): string {
		return self::ERROR_MAP[ $code ] ?? __( 'Unknown IP2Location API Error.', 'ip2location-sentinel' );
	}

	/**
	 * Test API Key validity.
	 *
	 * @param string $api_key
	 * @return array Array with 'success' => bool, 'message' => string, 'data' => array
	 */
	public static function test_api_key( string $api_key ): array {
		$api_key = trim( $api_key );
		if ( empty( $api_key ) ) {
			return array(
				'success' => false,
				'message' => __( 'API key cannot be empty.', 'ip2location-sentinel' ),
			);
		}

		$test_ip = '8.8.8.8';
		$url     = add_query_arg(
			array(
				'key'    => rawurlencode( $api_key ),
				'ip'     => $test_ip,
				'format' => 'json',
			),
			self::API_BASE_URL
		);

		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => 6,
				'user-agent'  => 'IP2LocationSentinel/1.0.0 (KeyTest; ' . home_url() . ')',
				'sslverify'   => true,
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'success' => false,
				'message' => sprintf(
					/* translators: %s: error message */
					__( 'Network error connecting to IP2Location.io: %s', 'ip2location-sentinel' ),
					$response->get_error_message()
				),
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) ) {
			return array(
				'success' => false,
				'message' => __( 'Invalid response received from IP2Location.io.', 'ip2location-sentinel' ),
			);
		}

		if ( isset( $data['error'] ) && is_array( $data['error'] ) ) {
			$err_code = isset( $data['error']['error_code'] ) ? (int) $data['error']['error_code'] : 10002;
			$err_msg  = $data['error']['error_message'] ?? self::get_error_message( $err_code );

			return array(
				'success'    => false,
				'error_code' => $err_code,
				'message'    => sprintf(
					/* translators: 1: error code, 2: error message */
					__( 'API Error [%1$d]: %2$s', 'ip2location-sentinel' ),
					$err_code,
					$err_msg
				),
			);
		}

		return array(
			'success' => true,
			'message' => __( 'API Key successfully verified! IP2Location.io connection is active.', 'ip2location-sentinel' ),
			'data'    => $data,
		);
	}
}
