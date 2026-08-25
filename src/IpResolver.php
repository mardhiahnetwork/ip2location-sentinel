<?php
/**
 * IP Resolver for CDN, Reverse Proxies, and Direct Connections
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class IpResolver {

	/**
	 * Get client IP address according to configured detection mode.
	 *
	 * @param string $mode Detection mode ('auto', 'cloudflare', 'sucuri', 'x_forwarded_for', 'remote_addr').
	 * @param bool   $resolve_local_public Whether to resolve real public IP if client is on localhost/private network.
	 * @return string Validated IP address or empty string.
	 */
	public static function get_client_ip( string $mode = 'auto', bool $resolve_local_public = true ): string {
		if ( empty( $mode ) ) {
			$settings = get_option( 'ip2loc_settings', array() );
			$mode     = $settings['cdn_mode'] ?? 'auto';
		}

		$ip = '';

		switch ( $mode ) {
			case 'cloudflare':
				if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && self::is_valid_ip( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
					$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
				}
				break;

			case 'sucuri':
				if ( ! empty( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) && self::is_valid_ip( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) ) {
					$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) );
				}
				break;

			case 'x_forwarded_for':
				if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
					$ip = self::parse_x_forwarded_for( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
				}
				break;

			case 'remote_addr':
				if ( ! empty( $_SERVER['REMOTE_ADDR'] ) && self::is_valid_ip( $_SERVER['REMOTE_ADDR'] ) ) {
					$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
				}
				break;

			case 'auto':
			default:
				// 1. Cloudflare
				if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && self::is_valid_ip( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
					$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
					break;
				}

				// 2. Sucuri
				if ( ! empty( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) && self::is_valid_ip( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) ) {
					$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) );
					break;
				}

				// 3. Incapsula / Imperva
				if ( ! empty( $_SERVER['HTTP_INCAP_CLIENT_IP'] ) && self::is_valid_ip( $_SERVER['HTTP_INCAP_CLIENT_IP'] ) ) {
					$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_INCAP_CLIENT_IP'] ) );
					break;
				}

				// 4. Akamai / Fastly / AWS True Client IP
				if ( ! empty( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) && self::is_valid_ip( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) ) {
					$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) );
					break;
				}
				if ( ! empty( $_SERVER['HTTP_FASTLY_CLIENT_IP'] ) && self::is_valid_ip( $_SERVER['HTTP_FASTLY_CLIENT_IP'] ) ) {
					$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_FASTLY_CLIENT_IP'] ) );
					break;
				}

				// 5. X-Real-IP
				if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) && self::is_valid_ip( $_SERVER['HTTP_X_REAL_IP'] ) ) {
					$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
					break;
				}

				// 6. X-Forwarded-For
				if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
					$parsed = self::parse_x_forwarded_for( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
					if ( ! empty( $parsed ) ) {
						$ip = $parsed;
						break;
					}
				}

				// 7. Client-IP
				if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) && self::is_valid_ip( $_SERVER['HTTP_CLIENT_IP'] ) ) {
					$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CLIENT_IP'] ) );
					break;
				}

				// 8. Fallback to REMOTE_ADDR
				if ( ! empty( $_SERVER['REMOTE_ADDR'] ) && self::is_valid_ip( $_SERVER['REMOTE_ADDR'] ) ) {
					$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
					break;
				}
				break;
		}

		if ( empty( $ip ) && ! empty( $_SERVER['REMOTE_ADDR'] ) && self::is_valid_ip( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}

		// If connected locally (127.0.0.1 or private network), resolve actual public outbound IP when online
		if ( $resolve_local_public && ( empty( $ip ) || self::is_private_ip( $ip ) ) ) {
			$public_ip = self::get_public_ip_fallback();
			if ( ! empty( $public_ip ) ) {
				$ip = $public_ip;
			}
		}

		return apply_filters( 'ip2loc_client_ip', $ip );
	}

	/**
	 * Discover public IP address when running on local development (Laragon, localhost, XAMPP).
	 * Cached in transient for 1 hour to prevent unnecessary external requests.
	 *
	 * @return string
	 */
	public static function get_public_ip_fallback(): string {
		$cached = get_transient( 'ip2loc_public_client_ip' );
		if ( false !== $cached && is_string( $cached ) && self::is_valid_ip( $cached ) ) {
			return $cached;
		}

		$response = wp_remote_get(
			'https://api.ipify.org?format=json',
			array(
				'timeout'   => 3,
				'sslverify' => false,
			)
		);

		if ( ! is_wp_error( $response ) ) {
			$body = wp_remote_retrieve_body( $response );
			$json = json_decode( $body, true );
			if ( ! empty( $json['ip'] ) && self::is_valid_ip( $json['ip'] ) ) {
				set_transient( 'ip2loc_public_client_ip', sanitize_text_field( $json['ip'] ), 3600 );
				return sanitize_text_field( $json['ip'] );
			}
		}

		// Secondary fallback via icanhazip
		$response2 = wp_remote_get(
			'https://icanhazip.com',
			array(
				'timeout'   => 3,
				'sslverify' => false,
			)
		);

		if ( ! is_wp_error( $response2 ) ) {
			$clean_ip = trim( wp_remote_retrieve_body( $response2 ) );
			if ( self::is_valid_ip( $clean_ip ) ) {
				set_transient( 'ip2loc_public_client_ip', sanitize_text_field( $clean_ip ), 3600 );
				return sanitize_text_field( $clean_ip );
			}
		}

		return '';
	}

	/**
	 * Parse X-Forwarded-For header to find the first valid public IP address.
	 *
	 * @param string $header
	 * @return string
	 */
	public static function parse_x_forwarded_for( string $header ): string {
		$ips = explode( ',', $header );
		$fallback = '';

		foreach ( $ips as $candidate ) {
			$candidate = trim( $candidate );
			if ( self::is_valid_ip( $candidate ) ) {
				if ( ! self::is_private_ip( $candidate ) ) {
					return $candidate;
				}
				if ( empty( $fallback ) ) {
					$fallback = $candidate;
				}
			}
		}

		return $fallback;
	}

	/**
	 * Check if an IP address is syntactically valid (IPv4 or IPv6).
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function is_valid_ip( string $ip ): bool {
		return (bool) filter_var( $ip, FILTER_VALIDATE_IP );
	}

	/**
	 * Check if an IP address is private or reserved loopback.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function is_private_ip( string $ip ): bool {
		if ( ! self::is_valid_ip( $ip ) ) {
			return false;
		}

		$is_public = filter_var(
			$ip,
			FILTER_VALIDATE_IP,
			FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
		);

		return $is_public === false;
	}

	/**
	 * Check if an IP matches a CIDR range or wildcard rule.
	 *
	 * @param string $ip Client IP.
	 * @param string $range Target rule or CIDR.
	 * @return bool
	 */
	public static function ip_in_range( string $ip, string $range ): bool {
		$ip    = trim( $ip );
		$range = trim( $range );

		if ( empty( $ip ) || empty( $range ) ) {
			return false;
		}

		if ( $ip === $range ) {
			return true;
		}

		// Wildcard match (e.g. 192.168.1.*)
		if ( strpos( $range, '*' ) !== false ) {
			$pattern = '/^' . str_replace( array( '.', '*' ), array( '\.', '[0-9]+' ), $range ) . '$/';
			return (bool) preg_match( $pattern, $ip );
		}

		// CIDR IPv4 / IPv6
		if ( strpos( $range, '/' ) !== false ) {
			list( $subnet, $bits ) = explode( '/', $range, 2 );
			$bits = (int) $bits;

			// IPv4 CIDR
			if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) && filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				if ( $bits < 0 || $bits > 32 ) {
					return false;
				}
				$ip_long     = ip2long( $ip );
				$subnet_long = ip2long( $subnet );
				$mask        = -1 << ( 32 - $bits );
				$subnet_long &= $mask;
				return ( ( $ip_long & $mask ) === $subnet_long );
			}

			// IPv6 CIDR
			if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) && filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
				if ( $bits < 0 || $bits > 128 ) {
					return false;
				}
				$ip_bin     = inet_pton( $ip );
				$subnet_bin = inet_pton( $subnet );
				if ( $ip_bin === false || $subnet_bin === false ) {
					return false;
				}
				$mask = str_repeat( "\xff", (int) ( $bits / 8 ) );
				if ( ( $bits % 8 ) > 0 ) {
					$mask .= chr( 256 - ( 1 << ( 8 - ( $bits % 8 ) ) ) );
				}
				$mask = str_pad( $mask, 16, "\x00" );
				return ( ( $ip_bin & $mask ) === ( $subnet_bin & $mask ) );
			}
		}

		return false;
	}

	/**
	 * Get diagnostic server headers for IP resolution inspection.
	 *
	 * @return array
	 */
	public static function get_server_headers_diagnostic(): array {
		$headers = array(
			'REMOTE_ADDR'          => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '',
			'HTTP_CF_CONNECTING_IP'=> isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : '',
			'HTTP_X_SUCURI_CLIENTIP'=> isset( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) ) : '',
			'HTTP_INCAP_CLIENT_IP' => isset( $_SERVER['HTTP_INCAP_CLIENT_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_INCAP_CLIENT_IP'] ) ) : '',
			'HTTP_TRUE_CLIENT_IP'  => isset( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) ) : '',
			'HTTP_FASTLY_CLIENT_IP'=> isset( $_SERVER['HTTP_FASTLY_CLIENT_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_FASTLY_CLIENT_IP'] ) ) : '',
			'HTTP_X_REAL_IP'       => isset( $_SERVER['HTTP_X_REAL_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) ) : '',
			'HTTP_X_FORWARDED_FOR' => isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) : '',
			'HTTP_CLIENT_IP'       => isset( $_SERVER['HTTP_CLIENT_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CLIENT_IP'] ) ) : '',
		);

		return array_filter( $headers );
	}

	/**
	 * Anonymize or mask an IP address for privacy in admin views / screenshots.
	 *
	 * @param string $ip
	 * @return string
	 */
	public static function mask_ip_for_privacy( string $ip ): string {
		if ( empty( $ip ) || self::is_private_ip( $ip ) ) {
			return '127.0.0.1 (Direct Connection)';
		}

		return $ip;
	}
}
