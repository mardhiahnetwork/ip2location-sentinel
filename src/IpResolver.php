<?php
/**
 * IP Resolver for CDN, Reverse Proxies, and Direct Connections with Strict Origin Verification
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
	 * Official Cloudflare Inbound IP Ranges (IPv4 + IPv6)
	 *
	 * @see https://www.cloudflare.com/ips/
	 */
	public const CLOUDFLARE_RANGES = array(
		// IPv4
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'172.64.0.0/13',
		'131.0.72.0/22',
		// IPv6
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32',
	);

	/**
	 * Official Sucuri WAF Inbound IP Ranges (IPv4 + IPv6)
	 *
	 * @see https://sucuri.net/
	 */
	public const SUCURI_RANGES = array(
		'192.88.134.0/23',
		'185.93.228.0/22',
		'66.248.200.0/22',
		'208.109.0.0/22',
		'2a02:fe80::/29',
	);

	/**
	 * Private / Local Loopback & Internal Reverse Proxy Subnets
	 */
	public const LOCAL_PROXY_RANGES = array(
		'127.0.0.1',
		'::1',
		'10.0.0.0/8',
		'172.16.0.0/12',
		'192.168.0.0/16',
		'fc00::/7',
		'fe80::/10',
	);

	/**
	 * Check if an IP address belongs to Cloudflare's verified network.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function is_cloudflare_proxy( string $ip ): bool {
		if ( empty( $ip ) || ! self::is_valid_ip( $ip ) ) {
			return false;
		}

		foreach ( self::CLOUDFLARE_RANGES as $range ) {
			if ( self::ip_in_range( $ip, $range ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if an IP address belongs to Sucuri WAF's verified network.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function is_sucuri_proxy( string $ip ): bool {
		if ( empty( $ip ) || ! self::is_valid_ip( $ip ) ) {
			return false;
		}

		foreach ( self::SUCURI_RANGES as $range ) {
			if ( self::ip_in_range( $ip, $range ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if an IP address is a local loopback or private subnet reverse proxy.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function is_local_proxy( string $ip ): bool {
		if ( empty( $ip ) || ! self::is_valid_ip( $ip ) ) {
			return false;
		}

		foreach ( self::LOCAL_PROXY_RANGES as $range ) {
			if ( self::ip_in_range( $ip, $range ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if an IP address is listed in user-configured custom trusted proxies.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function is_custom_trusted_proxy( string $ip ): bool {
		if ( empty( $ip ) || ! self::is_valid_ip( $ip ) ) {
			return false;
		}

		$settings = get_option( 'ip2loc_settings', array() );
		$custom   = isset( $settings['trusted_proxies'] ) ? trim( $settings['trusted_proxies'] ) : '';

		if ( empty( $custom ) ) {
			return false;
		}

		$lines = preg_split( '/[\r\n,]+/', $custom );
		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( ! empty( $line ) && self::ip_in_range( $ip, $line ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Verify whether REMOTE_ADDR originates from an authorized reverse proxy.
	 *
	 * @param string $remote_addr
	 * @return bool
	 */
	public static function is_trusted_proxy( string $remote_addr ): bool {
		return self::is_cloudflare_proxy( $remote_addr )
			|| self::is_sucuri_proxy( $remote_addr )
			|| self::is_local_proxy( $remote_addr )
			|| self::is_custom_trusted_proxy( $remote_addr );
	}

	/**
	 * Get client IP address according to configured detection mode with strict origin verification.
	 *
	 * @param string $mode Detection mode ('auto', 'cloudflare', 'sucuri', 'x_forwarded_for', 'remote_addr').
	 * @param bool   $resolve_local_public Whether to resolve real public IP if client is on localhost/private network.
	 * @return string Validated IP address or empty string.
	 */
	public static function get_client_ip( string $mode = 'auto', bool $resolve_local_public = true ): string {
		$settings = get_option( 'ip2loc_settings', array() );

		if ( empty( $mode ) ) {
			$mode = $settings['cdn_mode'] ?? 'auto';
		}

		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) ) : '';

		if ( empty( $remote_addr ) || ! self::is_valid_ip( $remote_addr ) ) {
			$remote_addr = '127.0.0.1';
		}

		$strict_verification = ! isset( $settings['strict_proxy_verification'] ) || ! empty( $settings['strict_proxy_verification'] );

		$is_cf_proxy     = self::is_cloudflare_proxy( $remote_addr );
		$is_sucuri_proxy = self::is_sucuri_proxy( $remote_addr );
		$is_local_proxy  = self::is_local_proxy( $remote_addr );
		$is_custom_proxy = self::is_custom_trusted_proxy( $remote_addr );
		$is_trusted      = $is_cf_proxy || $is_sucuri_proxy || $is_local_proxy || $is_custom_proxy;

		$ip = '';

		// If strict verification is enabled and REMOTE_ADDR is an untrusted direct connection:
		// Reject any spoofed/injected CDN or proxy headers (e.g. CF-Connecting-IP, X-Forwarded-For)
		if ( $strict_verification && ! $is_trusted && $mode !== 'remote_addr' ) {
			$ip = $remote_addr;
		} else {
			switch ( $mode ) {
				case 'cloudflare':
					if ( ( ! $strict_verification || $is_cf_proxy || $is_local_proxy || $is_custom_proxy )
						&& ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] )
						&& self::is_valid_ip( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
						$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
					} else {
						$ip = $remote_addr;
					}
					break;

				case 'sucuri':
					if ( ( ! $strict_verification || $is_sucuri_proxy || $is_local_proxy || $is_custom_proxy )
						&& ! empty( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] )
						&& self::is_valid_ip( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) ) {
						$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) );
					} else {
						$ip = $remote_addr;
					}
					break;

				case 'x_forwarded_for':
					if ( ( ! $strict_verification || $is_trusted ) && ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
						$ip = self::parse_x_forwarded_for( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
					}
					if ( empty( $ip ) ) {
						$ip = $remote_addr;
					}
					break;

				case 'remote_addr':
					$ip = $remote_addr;
					break;

				case 'auto':
				default:
					// 1. Cloudflare: accept CF-Connecting-IP only if REMOTE_ADDR is verified Cloudflare or local proxy
					if ( ( ! $strict_verification || $is_cf_proxy || $is_local_proxy || $is_custom_proxy )
						&& ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] )
						&& self::is_valid_ip( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
						$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
						break;
					}

					// 2. Sucuri: accept X-Sucuri-ClientIP only if REMOTE_ADDR is verified Sucuri or local proxy
					if ( ( ! $strict_verification || $is_sucuri_proxy || $is_local_proxy || $is_custom_proxy )
						&& ! empty( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] )
						&& self::is_valid_ip( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) ) {
						$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) );
						break;
					}

					// 3. Incapsula / Fastly / Akamai / X-Real-IP / X-Forwarded-For: only trust if incoming connection is a local/custom reverse proxy
					if ( ! $strict_verification || $is_local_proxy || $is_custom_proxy ) {
						if ( ! empty( $_SERVER['HTTP_INCAP_CLIENT_IP'] ) && self::is_valid_ip( $_SERVER['HTTP_INCAP_CLIENT_IP'] ) ) {
							$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_INCAP_CLIENT_IP'] ) );
							break;
						}
						if ( ! empty( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) && self::is_valid_ip( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) ) {
							$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) );
							break;
						}
						if ( ! empty( $_SERVER['HTTP_FASTLY_CLIENT_IP'] ) && self::is_valid_ip( $_SERVER['HTTP_FASTLY_CLIENT_IP'] ) ) {
							$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_FASTLY_CLIENT_IP'] ) );
							break;
						}
						if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) && self::is_valid_ip( $_SERVER['HTTP_X_REAL_IP'] ) ) {
							$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
							break;
						}
						if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
							$parsed = self::parse_x_forwarded_for( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
							if ( ! empty( $parsed ) ) {
								$ip = $parsed;
								break;
							}
						}
					}

					// 4. Default: Direct connection from untrusted IP -> Strictly use REMOTE_ADDR
					$ip = $remote_addr;
					break;
			}
		}

		if ( empty( $ip ) && ! empty( $remote_addr ) ) {
			$ip = $remote_addr;
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
	 * Get diagnostic server headers and proxy verification status.
	 *
	 * @return array
	 */
	public static function get_server_headers_diagnostic(): array {
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		$status = __( 'Direct Connection (No Proxy Header)', 'ip2location-sentinel' );
		if ( ! empty( $remote_addr ) ) {
			if ( self::is_cloudflare_proxy( $remote_addr ) ) {
				$status = __( 'Verified Cloudflare CDN Edge IP (Headers Trusted)', 'ip2location-sentinel' );
			} elseif ( self::is_sucuri_proxy( $remote_addr ) ) {
				$status = __( 'Verified Sucuri WAF Node (Headers Trusted)', 'ip2location-sentinel' );
			} elseif ( self::is_local_proxy( $remote_addr ) ) {
				$status = __( 'Verified Local Loopback / Internal Reverse Proxy (Headers Trusted)', 'ip2location-sentinel' );
			} elseif ( self::is_custom_trusted_proxy( $remote_addr ) ) {
				$status = __( 'Verified Custom Trusted Proxy Range (Headers Trusted)', 'ip2location-sentinel' );
			} else {
				$status = __( 'Direct Origin Connection (Untrusted Inbound Headers Ignored for Security)', 'ip2location-sentinel' );
			}
		}

		$headers = array(
			'REMOTE_ADDR'               => $remote_addr,
			'PROXY_ORIGIN_VERIFICATION' => $status,
			'HTTP_CF_CONNECTING_IP'     => isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : '',
			'HTTP_X_SUCURI_CLIENTIP'    => isset( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) ) : '',
			'HTTP_INCAP_CLIENT_IP'      => isset( $_SERVER['HTTP_INCAP_CLIENT_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_INCAP_CLIENT_IP'] ) ) : '',
			'HTTP_TRUE_CLIENT_IP'       => isset( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) ) : '',
			'HTTP_FASTLY_CLIENT_IP'     => isset( $_SERVER['HTTP_FASTLY_CLIENT_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_FASTLY_CLIENT_IP'] ) ) : '',
			'HTTP_X_REAL_IP'            => isset( $_SERVER['HTTP_X_REAL_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) ) : '',
			'HTTP_X_FORWARDED_FOR'      => isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) : '',
			'HTTP_CLIENT_IP'            => isset( $_SERVER['HTTP_CLIENT_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CLIENT_IP'] ) ) : '',
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
