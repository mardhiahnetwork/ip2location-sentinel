<?php
/**
 * Secure IP Resolver for CDN / Reverse Proxy / Direct Connections.
 *
 * Security model:
 *
 * 1. NEVER trust a forwarding header merely because it contains a valid IP.
 * 2. The immediate peer (REMOTE_ADDR) must belong to a trusted proxy range.
 * 3. Only then is the provider-specific client-IP header accepted.
 * 4. X-Forwarded-For is only accepted when its immediate sender is trusted.
 * 5. Direct connections always fall back to REMOTE_ADDR.
 *
 * @package IP2Location\Sentinel
 */

namespace IP2Location\Sentinel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class IpResolver {

	/**
	 * Built-in Cloudflare networks.
	 *
	 * Keep this list synchronized with Cloudflare's published ranges.
	 *
	 * @return array
	 */
	private static function get_cloudflare_ranges(): array {

		return array(
			// IPv4.
			'103.21.244.0/22',
			'103.22.200.0/22',
			'103.31.4.0/22',
			'104.16.0.0/13',
			'104.24.0.0/14',
			'108.162.192.0/18',
			'131.0.72.0/22',
			'141.101.64.0/18',
			'162.158.0.0/15',
			'172.64.0.0/13',
			'173.245.48.0/20',
			'188.114.96.0/20',
			'190.93.240.0/20',
			'197.234.240.0/22',
			'198.41.128.0/17',

			// IPv6.
			'2400:cb00::/32',
			'2606:4700::/32',
			'2803:f800::/32',
			'2405:b500::/32',
			'2405:8100::/32',
			'2a06:98c0::/29',
			'2c0f:f248::/32',
		);
	}

	/**
	 * Built-in Sucuri WAF networks.
	 *
	 * These are Sucuri WAF/origin-facing ranges, not arbitrary
	 * "Sucuri-looking" addresses.
	 *
	 * @return array
	 */
	private static function get_sucuri_ranges(): array {

		return array(
			'192.88.134.0/23',
			'185.93.228.0/22',
			'66.248.200.0/22',
			'208.109.0.0/22',
			'2a02:fe80::/29',
		);
	}

	/**
	 * Provider-specific trusted ranges.
	 *
	 * IMPORTANT:
	 *
	 * Akamai and Fastly should be configured with the actual ranges
	 * used by the customer's service.
	 *
	 * CloudFront ranges should preferably be maintained automatically
	 * from AWS ip-ranges.json or enforced at the infrastructure layer.
	 *
	 * @param string $provider Provider name.
	 * @return array
	 */
	private static function get_trusted_ranges( string $provider ): array {

		$ranges = array();

		switch ( $provider ) {

			case 'cloudflare':
				$ranges = self::get_cloudflare_ranges();
				break;

			case 'sucuri':
				$ranges = self::get_sucuri_ranges();
				break;

			case 'akamai':
				$ranges = array();

				/**
				 * Site-specific Akamai ranges should be added here
				 * using the filter below.
				 */
				break;

			case 'fastly':
				$ranges = array();

				/**
				 * Fastly service-specific trusted ranges should be
				 * added here using the filter below.
				 */
				break;

			case 'cloudfront':
				$ranges = array();

				/**
				 * CloudFront ranges should be supplied dynamically
				 * from AWS or via administrator configuration.
				 */
				break;
		}

		/**
		 * Allow site administrators to add provider-specific CIDRs.
		 *
		 * Example:
		 *
		 * add_filter(
		 *     'ip2loc_trusted_proxy_ranges',
		 *     function ( $ranges, $provider ) {
		 *         if ( 'akamai' === $provider ) {
		 *             $ranges[] = '203.0.113.0/24';
		 *         }
		 *
		 *         return $ranges;
		 *     },
		 *     10,
		 *     2
		 * );
		 */
		$ranges = apply_filters(
			'ip2loc_trusted_proxy_ranges',
			$ranges,
			$provider
		);

		return self::normalize_ranges( $ranges );
	}

	/**
	 * Get client IP.
	 *
	 * @param string $mode Detection mode.
	 * @param bool   $resolve_local_public Resolve public IP for local development.
	 * @return string
	 */
	public static function get_client_ip(
		string $mode = 'auto',
		bool $resolve_local_public = false
	): string {

		if ( empty( $mode ) ) {
			$settings = get_option( 'ip2loc_settings', array() );
			$mode     = isset( $settings['cdn_mode'] )
				? sanitize_key( $settings['cdn_mode'] )
				: 'auto';
		}

		$remote_ip = self::get_remote_addr();

		/*
		 * Security rule:
		 *
		 * If REMOTE_ADDR is invalid, we cannot authenticate the
		 * connecting peer and therefore cannot trust ANY proxy header.
		 */
		if ( empty( $remote_ip ) ) {
			return '';
		}

		switch ( $mode ) {

			case 'cloudflare':
				$ip = self::resolve_trusted_provider(
					$remote_ip,
					'cloudflare',
					'HTTP_CF_CONNECTING_IP'
				);

				break;

			case 'sucuri':
				$ip = self::resolve_trusted_provider(
					$remote_ip,
					'sucuri',
					'HTTP_X_SUCURI_CLIENTIP'
				);

				break;

			case 'akamai':
				$ip = self::resolve_trusted_provider(
					$remote_ip,
					'akamai',
					'HTTP_TRUE_CLIENT_IP'
				);

				break;

			case 'fastly':
				$ip = self::resolve_trusted_provider(
					$remote_ip,
					'fastly',
					'HTTP_FASTLY_CLIENT_IP'
				);

				break;

			case 'cloudfront':
				$ip = self::resolve_cloudfront(
					$remote_ip
				);

				break;

			case 'remote_addr':
				$ip = $remote_ip;
				break;

			case 'x_forwarded_for':

				/*
				 * NEVER accept XFF unless the immediate peer is
				 * explicitly trusted by configuration.
				 */
				$ip = self::resolve_generic_forwarded(
					$remote_ip
				);

				break;

			case 'auto':
			default:

				$ip = self::auto_resolve(
					$remote_ip
				);

				break;
		}

		/*
		 * Last-resort fallback.
		 *
		 * This is deliberately REMOTE_ADDR, never an arbitrary
		 * HTTP header.
		 */
		if ( empty( $ip ) ) {
			$ip = $remote_ip;
		}

		/*
		 * Local development convenience.
		 *
		 * SECURITY:
		 * This MUST NOT be enabled on a production server.
		 */
		if (
			$resolve_local_public &&
			self::is_private_ip( $ip )
		) {
			$public_ip = self::get_public_ip_fallback();

			if ( ! empty( $public_ip ) ) {
				$ip = $public_ip;
			}
		}

		$ip = self::normalize_ip( $ip );

		return apply_filters(
			'ip2loc_client_ip',
			$ip
		);
	}

	/**
	 * Automatic provider detection.
	 *
	 * IMPORTANT:
	 * Provider detection is based ONLY on REMOTE_ADDR.
	 *
	 * @param string $remote_ip Immediate peer.
	 * @return string
	 */
	private static function auto_resolve(
		string $remote_ip
	): string {

		$providers = array(
			'cloudflare' => 'HTTP_CF_CONNECTING_IP',
			'sucuri'     => 'HTTP_X_SUCURI_CLIENTIP',
			'akamai'     => 'HTTP_TRUE_CLIENT_IP',
			'fastly'     => 'HTTP_FASTLY_CLIENT_IP',
		);

		foreach ( $providers as $provider => $header ) {

			if ( ! self::is_trusted_proxy(
				$remote_ip,
				$provider
			) ) {
				continue;
			}

			$ip = self::get_header_ip( $header );

			if ( ! empty( $ip ) ) {
				return $ip;
			}
		}

		/*
		 * CloudFront is special because its viewer header contains:
		 *
		 *     IP:PORT
		 *
		 * and must be explicitly configured / refreshed.
		 */
		$cloudfront = self::resolve_cloudfront(
			$remote_ip
		);

		if ( ! empty( $cloudfront ) ) {
			return $cloudfront;
		}

		/*
		 * Generic XFF is intentionally NOT automatically trusted.
		 */
		return $remote_ip;
	}

	/**
	 * Resolve a provider-specific trusted header.
	 *
	 * @param string $remote_ip Remote peer.
	 * @param string $provider Provider.
	 * @param string $header   SERVER header key.
	 * @return string
	 */
	private static function resolve_trusted_provider(
		string $remote_ip,
		string $provider,
		string $header
	): string {

		if (
			! self::is_trusted_proxy(
				$remote_ip,
				$provider
			)
		) {
			return $remote_ip;
		}

		$ip = self::get_header_ip( $header );

		return ! empty( $ip )
			? $ip
			: $remote_ip;
	}

	/**
	 * Resolve CloudFront viewer address.
	 *
	 * CloudFront-Viewer-Address has the form:
	 *
	 *     198.51.100.10:46532
	 *
	 * @param string $remote_ip Immediate peer.
	 * @return string
	 */
	private static function resolve_cloudfront(
		string $remote_ip
	): string {

		if (
			! self::is_trusted_proxy(
				$remote_ip,
				'cloudfront'
			)
		) {
			return '';
		}

		if (
			empty(
				$_SERVER['HTTP_CLOUDFRONT_VIEWER_ADDRESS']
			)
		) {
			return '';
		}

		$value = sanitize_text_field(
			wp_unslash(
				$_SERVER['HTTP_CLOUDFRONT_VIEWER_ADDRESS']
			)
		);

		/*
		 * IPv6 contains ':' so do not blindly explode(':').
		 */
		if ( filter_var(
			$value,
			FILTER_VALIDATE_IP
		) ) {
			return $value;
		}

		/*
		 * IPv4:PORT.
		 */
		if (
			preg_match(
				'/^([0-9.]+):([0-9]{1,5})$/',
				$value,
				$matches
			)
		) {

			if (
				filter_var(
					$matches[1],
					FILTER_VALIDATE_IP,
					FILTER_FLAG_IPV4
				)
			) {
				return $matches[1];
			}
		}

		/*
		 * IPv6:PORT.
		 *
		 * CloudFront may represent IPv6 using:
		 *
		 *     [2001:db8::1]:443
		 */
		if (
			preg_match(
				'/^\[([0-9a-fA-F:]+)\]:([0-9]{1,5})$/',
				$value,
				$matches
			)
		) {

			if (
				filter_var(
					$matches[1],
					FILTER_VALIDATE_IP,
					FILTER_FLAG_IPV6
				)
			) {
				return $matches[1];
			}
		}

		return '';
	}

	/**
	 * Resolve generic X-Forwarded-For only from trusted proxies.
	 *
	 * Right-to-left processing is used.
	 *
	 * artistic-to-left processing is used.
	 * The right-most trusted hop is the immediate proxy.
	 * We walk left until we reach the first untrusted address.
	 *
	 * @param string $remote_ip Immediate peer.
	 * @return string
	 */
	private static function resolve_generic_forwarded(
		string $remote_ip
	): string {

		$trusted_ranges = apply_filters(
			'ip2loc_generic_trusted_proxy_ranges',
			array()
		);

		$trusted_ranges = self::normalize_ranges(
			$trusted_ranges
		);

		if (
			empty( $trusted_ranges ) ||
			! self::ip_in_ranges(
				$remote_ip,
				$trusted_ranges
			)
		) {
			return $remote_ip;
		}

		if (
			empty( $_SERVER['HTTP_X_FORWARDED_FOR'] )
		) {
			return $remote_ip;
		}

		$header = sanitize_text_field(
			wp_unslash(
				$_SERVER['HTTP_X_FORWARDED_FOR']
			)
		);

		// Bound header length to prevent ReDoS / memory exhaustion
		$header = substr( $header, 0, 1024 );

		$ips = array_map(
			'trim',
			explode( ',', $header )
		);

		$ips = array_values(
			array_filter(
				$ips,
				array( __CLASS__, 'is_valid_ip' )
			)
		);

		// Limit to last 20 hops
		if ( count( $ips ) > 20 ) {
			$ips = array_slice( $ips, -20 );
		}

		if ( empty( $ips ) ) {
			return $remote_ip;
		}

		/*
		 * Walk from nearest proxy backwards.
		 *
		 * First untrusted IP encountered is the client.
		 */
		for ( $i = count( $ips ) - 1; $i >= 0; $i-- ) {

			$candidate = $ips[ $i ];

			if (
				! self::ip_in_ranges(
					$candidate,
					$trusted_ranges
				)
			) {
				return $candidate;
			}
		}

		return $remote_ip;
	}

	/**
	 * Check whether immediate peer is trusted.
	 *
	 * @param string $remote_ip Provider connection IP.
	 * @param string $provider Provider.
	 * @return bool
	 */
	private static function is_trusted_proxy(
		string $remote_ip,
		string $provider
	): bool {

		$ranges = self::get_trusted_ranges(
			$provider
		);

		return self::ip_in_ranges(
			$remote_ip,
			$ranges
		);
	}

	/**
	 * Read and validate a SERVER header.
	 *
	 * @param string $header SERVER key.
	 * @return string
	 */
	private static function get_header_ip(
		string $header
	): string {

		if (
			empty( $_SERVER[ $header ] )
		) {
			return '';
		}

		$value = sanitize_text_field(
			wp_unslash(
				$_SERVER[ $header ]
			)
		);

		// Strip IPv4:PORT
		if ( preg_match( '/^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):[0-9]{1,5}$/', $value, $m ) ) {
			$value = $m[1];
		}
		// Strip [IPv6]:PORT
		if ( preg_match( '/^\[([0-9a-fA-F:]+)\]:[0-9]{1,5}$/', $value, $m ) ) {
			$value = $m[1];
		}

		return self::is_valid_ip( $value )
			? self::normalize_ip( $value )
			: '';
	}

	/**
	 * Get the immediate socket peer.
	 *
	 * @return string
	 */
	private static function get_remote_addr(): string {

		if ( empty( $_SERVER['REMOTE_ADDR'] ) ) {
			return '';
		}

		$ip = sanitize_text_field(
			wp_unslash(
				$_SERVER['REMOTE_ADDR']
			)
		);

		return self::is_valid_ip( $ip )
			? self::normalize_ip( $ip )
			: '';
	}

	/**
	 * Normalize an IP.
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	public static function normalize_ip(
		string $ip
	): string {

		$ip = trim( $ip );

		if ( ! self::is_valid_ip( $ip ) ) {
			return '';
		}

		/*
		 * inet_pton/inet_ntop normalizes IPv6 representation.
		 */
		$packed = inet_pton( $ip );

		if ( false === $packed ) {
			return '';
		}

		return inet_ntop( $packed );
	}

	/**
	 * Validate IP.
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_valid_ip(
		string $ip
	): bool {

		return false !== filter_var(
			trim( $ip ),
			FILTER_VALIDATE_IP
		);
	}

	/**
	 * Check private/reserved address.
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_private_ip(
		string $ip
	): bool {

		if ( ! self::is_valid_ip( $ip ) ) {
			return false;
		}

		return false === filter_var(
			$ip,
			FILTER_VALIDATE_IP,
			FILTER_FLAG_NO_PRIV_RANGE |
			FILTER_FLAG_NO_RES_RANGE
		);
	}

	/**
	 * Check whether IP belongs to one of the CIDRs.
	 *
	 * @param string $ip     IP.
	 * @param array  $ranges CIDRs.
	 * @return bool
	 */
	private static function ip_in_ranges(
		string $ip,
		array $ranges
	): bool {

		foreach ( $ranges as $range ) {

			if (
				self::ip_in_range(
					$ip,
					$range
				)
			) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Normalize CIDR list.
	 *
	 * @param array $ranges CIDR ranges.
	 * @return array
	 */
	private static function normalize_ranges(
		array $ranges
	): array {

		$result = array();

		foreach ( $ranges as $range ) {

			if ( ! is_string( $range ) ) {
				continue;
			}

			$range = trim( $range );

			if ( empty( $range ) ) {
				continue;
			}

			if ( strpos( $range, '/' ) === false ) {
				if ( self::is_valid_ip( $range ) ) {
					$bits  = false !== filter_var( $range, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ? 128 : 32;
					$range = $range . '/' . $bits;
				} else {
					continue;
				}
			}

			list( $network, $bits ) =
				array_pad(
					explode(
						'/',
						$range,
						2
					),
					2,
					null
				);

			if (
				! self::is_valid_ip( $network ) ||
				! is_numeric( $bits )
			) {
				continue;
			}

			$bits = (int) $bits;

			$is_ipv4 = false !== filter_var(
				$network,
				FILTER_VALIDATE_IP,
				FILTER_FLAG_IPV4
			);

			if (
				$is_ipv4 &&
				( $bits < 0 || $bits > 32 )
			) {
				continue;
			}

			$is_ipv6 = false !== filter_var(
				$network,
				FILTER_VALIDATE_IP,
				FILTER_FLAG_IPV6
			);

			if (
				$is_ipv6 &&
				( $bits < 0 || $bits > 128 )
			) {
				continue;
			}

			if ( ! $is_ipv4 && ! $is_ipv6 ) {
				continue;
			}

			$result[] = $network . '/' . $bits;
		}

		return array_values(
			array_unique( $result )
		);
	}

	/**
	 * Check IP against CIDR.
	 *
	 * @param string $ip    IP.
	 * @param string $range CIDR.
	 * @return bool
	 */
	public static function ip_in_range(
		string $ip,
		string $range
	): bool {

		$ip    = trim( $ip );
		$range = trim( $range );

		if ( ! self::is_valid_ip( $ip ) ) {
			return false;
		}

		if ( strpos( $range, '/' ) === false ) {
			if ( ! self::is_valid_ip( $range ) ) {
				return false;
			}

			return self::normalize_ip( $ip ) === self::normalize_ip( $range );
		}

		list( $subnet, $bits ) =
			array_pad(
				explode(
					'/',
					$range,
					2
				),
				2,
				null
			);

		$bits = is_numeric( $bits )
			? (int) $bits
			: -1;

		if ( ! self::is_valid_ip( $subnet ) ) {
			return false;
		}

		$ip_bin     = inet_pton( $ip );
		$subnet_bin = inet_pton( $subnet );

		if (
			false === $ip_bin ||
			false === $subnet_bin ||
			strlen( $ip_bin ) !== strlen( $subnet_bin )
		) {
			return false;
		}

		$max_bits = 8 * strlen( $ip_bin );

		if (
			$bits < 0 ||
			$bits > $max_bits
		) {
			return false;
		}

		$full_bytes = intdiv(
			$bits,
			8
		);

		$remaining_bits = $bits % 8;

		if ( $full_bytes > 0 ) {

			if (
				substr(
					$ip_bin,
					0,
					$full_bytes
				) !== substr(
					$subnet_bin,
					0,
					$full_bytes
				)
			) {
				return false;
			}
		}

		if ( 0 === $remaining_bits ) {
			return true;
		}

		$mask = 0xFF << ( 8 - $remaining_bits );

		return (
			( ord( $ip_bin[ $full_bytes ] ) & $mask ) ===
			( ord( $subnet_bin[ $full_bytes ] ) & $mask )
		);
	}

	/**
	 * Public-IP fallback for local development only.
	 *
	 * @return string
	 */
	public static function get_public_ip_fallback(): string {

		$cached = get_transient(
			'ip2loc_public_client_ip'
		);

		if (
			false !== $cached &&
			is_string( $cached ) &&
			self::is_valid_ip( $cached )
		) {
			return $cached;
		}

		$response = wp_remote_get(
			'https://api.ipify.org?format=json',
			array(
				'timeout'   => 3,
				'sslverify' => true,
			)
		);

		if ( ! is_wp_error( $response ) ) {

			$body = wp_remote_retrieve_body(
				$response
			);

			$json = json_decode(
				$body,
				true
			);

			if (
				! empty( $json['ip'] ) &&
				self::is_valid_ip( $json['ip'] )
			) {

				$ip = self::normalize_ip(
					$json['ip']
				);

				set_transient(
					'ip2loc_public_client_ip',
					$ip,
					HOUR_IN_SECONDS
				);

				return $ip;
			}
		}

		return '';
	}

	/**
	 * Diagnostic headers.
	 *
	 * @return array
	 */
	public static function get_server_headers_diagnostic(): array {

		$keys = array(
			'REMOTE_ADDR',
			'HTTP_CF_CONNECTING_IP',
			'HTTP_X_SUCURI_CLIENTIP',
			'HTTP_TRUE_CLIENT_IP',
			'HTTP_FASTLY_CLIENT_IP',
			'HTTP_CLOUDFRONT_VIEWER_ADDRESS',
			'HTTP_X_REAL_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_CLIENT_IP',
		);

		$headers = array();

		foreach ( $keys as $key ) {

			if ( ! isset( $_SERVER[ $key ] ) ) {
				continue;
			}

			$value = sanitize_text_field(
				wp_unslash(
					$_SERVER[ $key ]
				)
			);

			if ( '' !== $value ) {
				$headers[ $key ] = $value;
			}
		}

		return $headers;
	}

	/**
	 * Mask IP for privacy UI.
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	public static function mask_ip_for_privacy(
		string $ip
	): string {

		if (
			empty( $ip ) ||
			self::is_private_ip( $ip )
		) {
			return '127.0.0.1 (Direct Connection)';
		}

		return $ip;
	}
}
