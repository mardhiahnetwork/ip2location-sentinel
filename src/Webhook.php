<?php
/**
 * Security Webhook Dispatcher with SSRF Hardening & {{variable}} Template Support
 *
 * Dispatches real-time security alerts to external platforms (Discord, Slack,
 * Telegram, Custom REST Webhooks) while enforcing strict SSRF (Server-Side
 * Request Forgery) protection against private subnets, localhost, and cloud
 * metadata services.
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Webhook {

	/**
	 * Forbidden hostnames that must never be targeted by outbound webhooks.
	 */
	private const FORBIDDEN_HOSTNAMES = array(
		'localhost',
		'localhost.localdomain',
		'ip6-localhost',
		'ip6-loopback',
		'metadata.google.internal',
		'instance-data',
	);

	/**
	 * Build comprehensive dictionary of template placeholder variables.
	 *
	 * @param string $event_type Security event code.
	 * @param array  $details    Event context metadata.
	 * @return array<string, string>
	 */
	public static function get_template_variables( string $event_type, array $details = array() ): array {
		$site_name   = get_bloginfo( 'name' );
		$site_url    = home_url();
		$admin_email = get_option( 'admin_email', '' );
		$timestamp   = current_time( 'mysql' );
		$iso_time    = current_time( 'c' );

		$ip  = $details['ip'] ?? IpResolver::get_client_ip();
		$geo = $details['geo'] ?? array();

		$country_code = $details['country_code'] ?? ( $geo['country_code'] ?? '' );
		$country_name = $details['country_name'] ?? ( $geo['country_name'] ?? ( $country_code ? Countries::get_country_name( $country_code ) : '' ) );
		$region_name  = $details['region_name'] ?? ( $geo['region_name'] ?? '' );
		$city_name    = $details['city_name'] ?? ( $geo['city_name'] ?? '' );
		$zip_code     = $details['zip_code'] ?? ( $geo['zip_code'] ?? '' );
		$asn          = $details['asn'] ?? ( $geo['asn'] ?? '' );
		$as_name      = $details['as_name'] ?? ( $details['as'] ?? ( $geo['as'] ?? '' ) );
		$is_proxy     = ! empty( $details['is_proxy'] ) || ! empty( $geo['is_proxy'] ) ? 'true' : 'false';

		$user_login = $details['user_login'] ?? ( $details['author'] ?? '' );
		$user_email = $details['user_email'] ?? '';
		if ( empty( $user_email ) && ! empty( $user_login ) ) {
			$u = get_user_by( 'login', $user_login );
			if ( $u ) {
				$user_email = $u->user_email;
			}
		}

		$rule_triggered  = $details['rule_triggered'] ?? ( $details['reason'] ?? '' );
		$action_taken    = $details['action_taken'] ?? ( $details['action'] ?? '' );
		$target_endpoint = $details['target_endpoint'] ?? ( $details['endpoint'] ?? ( $_SERVER['REQUEST_URI'] ?? '' ) );
		$request_url     = $details['request_url'] ?? ( $_SERVER['REQUEST_URI'] ?? '' );
		$http_method     = $details['http_method'] ?? ( $_SERVER['REQUEST_METHOD'] ?? 'GET' );

		$speed_kmh     = isset( $details['speed_kmh'] ) ? (string) round( (float) $details['speed_kmh'], 1 ) : '';
		$distance_km   = isset( $details['distance_km'] ) ? (string) round( (float) $details['distance_km'], 1 ) : '';
		$time_diff_hrs = isset( $details['time_diff_hours'] ) ? (string) round( (float) $details['time_diff_hours'], 2 ) : '';
		$loc_current   = $details['location_current'] ?? ( $city_name ? "$city_name, $country_code" : ( $country_name ?: $country_code ) );
		$loc_prev      = $details['location_previous'] ?? '';

		return array(
			'event_type'        => $event_type,
			'event'             => $event_type,
			'ip'                => $ip,
			'country_code'      => $country_code,
			'country_name'      => $country_name,
			'country'           => $country_name,
			'region_name'       => $region_name,
			'region'            => $region_name,
			'city_name'         => $city_name,
			'city'              => $city_name,
			'zip_code'          => $zip_code,
			'zip'               => $zip_code,
			'asn'               => $asn,
			'as_name'           => $as_name,
			'asn_name'          => $as_name,
			'is_proxy'          => $is_proxy,
			'user_login'        => $user_login,
			'username'          => $user_login,
			'user_email'        => $user_email,
			'action_taken'      => $action_taken,
			'action'            => $action_taken,
			'rule_triggered'    => $rule_triggered,
			'reason'            => $rule_triggered,
			'target_endpoint'   => $target_endpoint,
			'endpoint'          => $target_endpoint,
			'request_url'       => $request_url,
			'url'               => $request_url,
			'http_method'       => $http_method,
			'method'            => $http_method,
			'speed_kmh'         => $speed_kmh,
			'distance_km'       => $distance_km,
			'time_diff_hours'   => $time_diff_hrs,
			'location_current'  => $loc_current,
			'location_previous' => $loc_prev,
			'site_name'         => $site_name,
			'site_url'          => $site_url,
			'admin_email'       => $admin_email,
			'timestamp'         => $timestamp,
			'iso_timestamp'     => $iso_time,
		);
	}

	/**
	 * Render template with {{variable}} placeholders (alias for replace_variables).
	 *
	 * @param string $template
	 * @param array  $vars
	 * @param bool   $url_encode
	 * @return string
	 */
	public static function render_template( string $template, array $vars, bool $url_encode = false ): string {
		return self::replace_variables( $template, $vars, $url_encode );
	}

	/**
	 * Replace all {{variable}} placeholders within a template string.
	 *
	 * @param string $template
	 * @param array  $vars
	 * @param bool   $url_encode
	 * @return string
	 */
	public static function replace_variables( string $template, array $vars, bool $url_encode = false ): string {
		if ( empty( $template ) ) {
			return '';
		}

		foreach ( $vars as $key => $val ) {
			$search      = '{{' . $key . '}}';
			$replacement = $url_encode ? rawurlencode( (string) $val ) : (string) $val;
			$template    = str_ireplace( $search, $replacement, $template );
		}

		return $template;
	}

	/**
	 * Validate whether an IP address is a publicly routable, safe outbound target.
	 * Blocks RFC1918, Loopback, Link-Local, Cloud Metadata (169.254.169.254),
	 * CGNAT, IPv6 ULA, 6to4, IPv4-mapped, and Multicast/Reserved addresses.
	 *
	 * @param string $ip
	 * @return bool True if safe/public, False if private/reserved/loopback.
	 */
	public static function is_public_safe_ip( string $ip ): bool {
		$norm_ip = IpResolver::normalize_ip( $ip );
		if ( empty( $norm_ip ) ) {
			return false;
		}

		// Baseline filter_var check with strict flags
		if ( ! filter_var( $norm_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return false;
		}

		// IPv4 Validation
		if ( filter_var( $norm_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$long = ip2long( $norm_ip );
			if ( false === $long ) {
				return false;
			}

			// 0.0.0.0/8 (Current network)
			if ( ( $long & 0xFF000000 ) === 0x00000000 ) {
				return false;
			}

			// 127.0.0.0/8 (Loopback)
			if ( ( $long & 0xFF000000 ) === 0x7F000000 ) {
				return false;
			}

			// 10.0.0.0/8 (RFC 1918 Class A)
			if ( ( $long & 0xFF000000 ) === 0x0A000000 ) {
				return false;
			}

			// 100.64.0.0/10 (Carrier-Grade NAT RFC 6598)
			if ( ( $long & 0xFFC00000 ) === 0x64400000 ) {
				return false;
			}

			// 172.16.0.0/12 (RFC 1918 Class B)
			if ( ( $long & 0xFFF00000 ) === 0xAC100000 ) {
				return false;
			}

			// 169.254.0.0/16 (Link-Local & Cloud Instance Metadata Service 169.254.169.254)
			if ( ( $long & 0xFFFF0000 ) === 0xA9FE0000 ) {
				return false;
			}

			// 192.0.0.0/24 (IETF Protocol Assignments)
			if ( ( $long & 0xFFFFFF00 ) === 0xC0000000 ) {
				return false;
			}

			// 192.0.2.0/24 (TEST-NET-1)
			if ( ( $long & 0xFFFFFF00 ) === 0xC0000200 ) {
				return false;
			}

			// 192.168.0.0/16 (RFC 1918 Class C)
			if ( ( $long & 0xFFFF0000 ) === 0xC0A80000 ) {
				return false;
			}

			// 198.18.0.0/15 (Network Benchmark Tests)
			if ( ( $long & 0xFFFE0000 ) === 0xC6120000 ) {
				return false;
			}

			// 198.51.100.0/24 (TEST-NET-2)
			if ( ( $long & 0xFFFFFF00 ) === 0xC6336400 ) {
				return false;
			}

			// 203.0.113.0/24 (TEST-NET-3)
			if ( ( $long & 0xFFFFFF00 ) === 0xCB007100 ) {
				return false;
			}

			// 224.0.0.0/4 (Multicast) and 240.0.0.0/4 (Reserved)
			if ( ( $long & 0xE0000000 ) === 0xE0000000 || ( $long & 0xF0000000 ) === 0xF0000000 ) {
				return false;
			}

			// 255.255.255.255 (Broadcast)
			if ( $long === -1 || ( $long & 0xFFFFFFFF ) === 0xFFFFFFFF ) {
				return false;
			}

			return true;
		}

		// IPv6 Validation
		if ( filter_var( $norm_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			// Handle IPv4-mapped IPv6 e.g. ::ffff:127.0.0.1
			if ( stripos( $norm_ip, '::ffff:' ) === 0 ) {
				$ipv4_part = substr( $norm_ip, 7 );
				if ( filter_var( $ipv4_part, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
					return self::is_public_safe_ip( $ipv4_part );
				}
			}

			$binary = inet_pton( $norm_ip );
			if ( false === $binary || strlen( $binary ) !== 16 ) {
				return false;
			}

			// Loopback ::1 (15 zeroes followed by 0x01)
			if ( $binary === ( str_repeat( "\0", 15 ) . "\x01" ) ) {
				return false;
			}

			// Unspecified :: (16 zeroes)
			if ( $binary === str_repeat( "\0", 16 ) ) {
				return false;
			}

			$first_byte  = ord( $binary[0] );
			$second_byte = ord( $binary[1] );

			// Link-local: fe80::/10 (first byte 0xFE, second byte has top 2 bits 0x80)
			if ( $first_byte === 0xFE && ( $second_byte & 0xC0 ) === 0x80 ) {
				return false;
			}

			// Unique Local Address (ULA): fc00::/7 (first byte 0xFC or 0xFD)
			if ( ( $first_byte & 0xFE ) === 0xFC ) {
				return false;
			}

			// Multicast: ff00::/8 (first byte 0xFF)
			if ( $first_byte === 0xFF ) {
				return false;
			}

			// 6to4: 2002::/16 (first 2 bytes 0x20 0x02) - extract embedded IPv4 in bytes 2-5
			if ( $binary[0] === "\x20" && $binary[1] === "\x02" ) {
				$embedded_ipv4 = inet_ntop( substr( $binary, 2, 4 ) );
				if ( ! self::is_public_safe_ip( $embedded_ipv4 ) ) {
					return false;
				}
			}

			return true;
		}

		return false;
	}

	/**
	 * Verify that a webhook destination URL is safe against SSRF attacks.
	 * Resolves ALL DNS A and AAAA records and ensures every resolved IP is public.
	 *
	 * @param string $url
	 * @return bool
	 */
	public static function is_safe_webhook_url( string $url ): bool {
		if ( empty( $url ) ) {
			return false;
		}

		$parsed = parse_url( $url );
		if ( false === $parsed || empty( $parsed['scheme'] ) || empty( $parsed['host'] ) ) {
			return false;
		}

		// 1. Strict scheme check: Only http and https
		$scheme = strtolower( $parsed['scheme'] );
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			return false;
		}

		// 2. Reject embedded user/pass authentication credentials
		if ( ! empty( $parsed['user'] ) || ! empty( $parsed['pass'] ) ) {
			return false;
		}

		$host = trim( $parsed['host'] );

		// Strip IPv6 enclosing brackets if present
		if ( strpos( $host, '[' ) === 0 && substr( $host, -1 ) === ']' ) {
			$host = substr( $host, 1, -1 );
		}

		// 3. Reject forbidden hostnames & suffix patterns
		$lower_host = strtolower( $host );
		if ( in_array( $lower_host, self::FORBIDDEN_HOSTNAMES, true ) ||
			 substr( $lower_host, -10 ) === '.localhost' ||
			 substr( $lower_host, -6 ) === '.local' ||
			 substr( $lower_host, -9 ) === '.internal' ) {
			return false;
		}

		// 4. Resolve and normalize IP addresses
		$ips_to_check = array();

		// Handle raw decimal or hex integer notation e.g. 2130706433 or 0x7f000001
		if ( is_numeric( $host ) || preg_match( '/^0x[0-9a-f]+$/i', $host ) ) {
			$long_val = is_numeric( $host ) ? (float) $host : hexdec( $host );
			if ( $long_val >= 0 && $long_val <= 4294967295 ) {
				$converted_ip = long2ip( (int) $long_val );
				if ( ! empty( $converted_ip ) ) {
					$ips_to_check[] = $converted_ip;
				}
			}
		} elseif ( preg_match( '/^(0x[0-9a-f]+|\d+)\.(0x[0-9a-f]+|\d+)\.(0x[0-9a-f]+|\d+)\.(0x[0-9a-f]+|\d+)$/i', $host, $m ) ) {
			// Handle dotted hex/octal e.g. 0x7f.0.0.1 or 0177.0.0.1
			$p1 = ( stripos( $m[1], '0x' ) === 0 ) ? hexdec( $m[1] ) : ( ( strpos( $m[1], '0' ) === 0 && strlen( $m[1] ) > 1 ) ? octdec( $m[1] ) : (int) $m[1] );
			$p2 = ( stripos( $m[2], '0x' ) === 0 ) ? hexdec( $m[2] ) : ( ( strpos( $m[2], '0' ) === 0 && strlen( $m[2] ) > 1 ) ? octdec( $m[2] ) : (int) $m[2] );
			$p3 = ( stripos( $m[3], '0x' ) === 0 ) ? hexdec( $m[3] ) : ( ( strpos( $m[3], '0' ) === 0 && strlen( $m[3] ) > 1 ) ? octdec( $m[3] ) : (int) $m[3] );
			$p4 = ( stripos( $m[4], '0x' ) === 0 ) ? hexdec( $m[4] ) : ( ( strpos( $m[4], '0' ) === 0 && strlen( $m[4] ) > 1 ) ? octdec( $m[4] ) : (int) $m[4] );
			$canon_ip = "$p1.$p2.$p3.$p4";
			if ( filter_var( $canon_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				$ips_to_check[] = $canon_ip;
			}
		} elseif ( filter_var( $host, FILTER_VALIDATE_IP ) ) {
			$ips_to_check[] = $host;
		} else {
			// Resolve IPv4 (DNS A records)
			$resolved_v4 = @gethostbynamel( $host );
			if ( is_array( $resolved_v4 ) ) {
				$ips_to_check = array_merge( $ips_to_check, $resolved_v4 );
			}

			// Resolve IPv6 (DNS AAAA records)
			if ( function_exists( 'dns_get_record' ) ) {
				$records_v6 = @dns_get_record( $host, DNS_AAAA );
				if ( is_array( $records_v6 ) ) {
					foreach ( $records_v6 as $rec ) {
						if ( ! empty( $rec['ipv6'] ) ) {
							$ips_to_check[] = $rec['ipv6'];
						}
					}
				}
			}

			// If DNS resolution returned zero IP addresses, reject
			if ( empty( $ips_to_check ) ) {
				return false;
			}
		}

		// 5. Inspect EVERY resolved IP against SSRF blacklists (ALL must be public/safe)
		foreach ( $ips_to_check as $ip ) {
			if ( ! self::is_public_safe_ip( $ip ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Send a security event notification via configured Webhook with {{variable}} interpolation.
	 *
	 * @param string $event_type
	 * @param array  $details
	 * @return bool
	 */
	public static function send_event( string $event_type, array $details = array() ): bool {
		$settings = get_option( 'ip2loc_settings', array() );

		if ( empty( $settings['enable_webhooks'] ) || empty( $settings['webhook_url'] ) ) {
			return false;
		}

		$raw_url = trim( $settings['webhook_url'] );
		$vars    = self::get_template_variables( $event_type, $details );

		// Interpolate {{variables}} in Webhook URL (with URL-encoding for query string safety)
		$webhook_url = self::replace_variables( $raw_url, $vars, true );
		$webhook_url = esc_url_raw( $webhook_url );

		if ( ! self::is_safe_webhook_url( $webhook_url ) ) {
			return false;
		}

		$webhook_type = $settings['webhook_type'] ?? 'auto';

		if ( $webhook_type === 'auto' ) {
			if ( strpos( $webhook_url, 'discord.com/api/webhooks' ) !== false || strpos( $webhook_url, 'discordapp.com/api/webhooks' ) !== false ) {
				$webhook_type = 'discord';
			} elseif ( strpos( $webhook_url, 'hooks.slack.com' ) !== false ) {
				$webhook_type = 'slack';
			} elseif ( strpos( $webhook_url, 'api.telegram.org' ) !== false ) {
				$webhook_type = 'telegram';
			} else {
				$webhook_type = 'custom';
			}
		}

		$site_name = $vars['site_name'];
		$site_url  = $vars['site_url'];

		$headers = array( 'Content-Type' => 'application/json; charset=utf-8' );
		$body    = '';

		switch ( $webhook_type ) {
			case 'discord':
				$color  = ( strpos( $event_type, 'IMPOSSIBLE_TRAVEL' ) !== false ) ? 15158332 : 16753920;
				$fields = array(
					array( 'name' => 'Event Type', 'value' => '`' . esc_html( $event_type ) . '`', 'inline' => true ),
					array( 'name' => 'IP Address', 'value' => '`' . esc_html( $vars['ip'] ?: 'N/A' ) . '`', 'inline' => true ),
				);

				if ( ! empty( $vars['user_login'] ) ) {
					$fields[] = array( 'name' => 'User Account', 'value' => '**' . esc_html( $vars['user_login'] ) . '**', 'inline' => true );
				}

				if ( ! empty( $vars['location_current'] ) ) {
					$fields[] = array( 'name' => 'Location', 'value' => esc_html( $vars['location_current'] ), 'inline' => true );
				}

				if ( ! empty( $vars['location_previous'] ) ) {
					$fields[] = array( 'name' => 'Previous Hop', 'value' => esc_html( $vars['location_previous'] ), 'inline' => true );
				}

				if ( ! empty( $vars['speed_kmh'] ) ) {
					$fields[] = array( 'name' => 'Calculated Speed', 'value' => '**' . esc_html( $vars['speed_kmh'] ) . ' km/h**', 'inline' => true );
				}

				if ( ! empty( $vars['rule_triggered'] ) ) {
					$fields[] = array( 'name' => 'Rule Triggered', 'value' => esc_html( $vars['rule_triggered'] ), 'inline' => true );
				}

				if ( ! empty( $vars['action_taken'] ) ) {
					$fields[] = array( 'name' => 'Action Taken', 'value' => esc_html( $vars['action_taken'] ), 'inline' => true );
				}

				$payload = array(
					'username'   => 'LocaSentinel',
					'avatar_url' => 'https://www.ip2location.io/assets/img/logo.png',
					'embeds'     => array(
						array(
							'title'       => '🛡️ Security Alert: ' . esc_html( $event_type ),
							'description' => sprintf( 'Security event detected on [%s](%s).', esc_html( $site_name ), esc_url( $site_url ) ),
							'color'       => $color,
							'fields'      => $fields,
							'footer'      => array( 'text' => 'LocaSentinel • ' . $vars['timestamp'] ),
						),
					),
				);
				$body = wp_json_encode( $payload );
				break;

			case 'slack':
				$text = sprintf( "*[LocaSentinel Alert]*\n*Site:* %s (%s)\n*Event:* `%s`\n*IP:* `%s`\n", $site_name, $site_url, $event_type, $vars['ip'] );
				if ( ! empty( $vars['user_login'] ) ) {
					$text .= '*User:* ' . $vars['user_login'] . "\n";
				}
				if ( ! empty( $vars['location_current'] ) ) {
					$text .= '*Location:* ' . $vars['location_current'] . "\n";
				}
				if ( ! empty( $vars['speed_kmh'] ) ) {
					$text .= '*Calculated Speed:* ' . $vars['speed_kmh'] . " km/h\n";
				}
				if ( ! empty( $vars['rule_triggered'] ) ) {
					$text .= '*Rule:* ' . $vars['rule_triggered'] . "\n";
				}
				$payload = array( 'text' => $text );
				$body    = wp_json_encode( $payload );
				break;

			case 'telegram':
				$text = sprintf( "*[LocaSentinel Alert]*\n*Site:* %s\n*Event:* `%s`\n*IP:* `%s`\n", $site_name, $event_type, $vars['ip'] );
				if ( ! empty( $vars['user_login'] ) ) {
					$text .= '*User:* ' . $vars['user_login'] . "\n";
				}
				if ( ! empty( $vars['location_current'] ) ) {
					$text .= '*Location:* ' . $vars['location_current'] . "\n";
				}
				if ( ! empty( $vars['speed_kmh'] ) ) {
					$text .= '*Speed:* ' . $vars['speed_kmh'] . " km/h\n";
				}
				if ( ! empty( $vars['rule_triggered'] ) ) {
					$text .= '*Rule:* ' . $vars['rule_triggered'] . "\n";
				}
				$payload = array(
					'text'       => $text,
					'parse_mode' => 'Markdown',
				);
				$body = wp_json_encode( $payload );
				break;

			case 'custom':
			default:
				$custom_template = trim( $settings['webhook_custom_payload'] ?? '' );
				if ( ! empty( $custom_template ) ) {
					// Interpolate variables into custom user template
					$interpolated = self::replace_variables( $custom_template, $vars, false );
					$json_decoded = json_decode( $interpolated, true );
					if ( json_last_error() === JSON_ERROR_NONE && is_array( $json_decoded ) ) {
						$body = wp_json_encode( $json_decoded );
					} else {
						$body = $interpolated;
					}
				} else {
					$payload = array(
						'event'     => $event_type,
						'site_name' => $site_name,
						'site_url'  => $site_url,
						'timestamp' => $vars['iso_timestamp'],
						'data'      => $vars,
						'details'   => $details,
					);
					$body = wp_json_encode( $payload );
				}
				break;
		}

		$response = wp_safe_remote_post(
			$webhook_url,
			array(
				'timeout'            => 5,
				'redirection'        => 0, // Prevent redirect-based SSRF pivots
				'reject_unsafe_urls' => true, // Enforce WordPress unsafe URL rejection
				'headers'            => $headers,
				'body'               => $body,
				'sslverify'          => true,
			)
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$status = wp_remote_retrieve_response_code( $response );
		return ( $status >= 200 && $status < 300 );
	}

	/**
	 * Send test webhook with rich diagnostic output.
	 *
	 * @param string $url
	 * @param string $type
	 * @param string $custom_payload
	 * @return array
	 */
	public static function test_webhook( string $url, string $type = 'auto', string $custom_payload = '' ): array {
		$raw_url = trim( $url );
		if ( empty( $raw_url ) ) {
			return array(
				'success' => false,
				'message' => __( 'Please enter a valid Webhook URL.', 'locasentinel' ),
			);
		}

		if ( ! self::is_safe_webhook_url( $raw_url ) ) {
			return array(
				'success' => false,
				'message' => __( 'Invalid or unsafe Webhook URL: Requests to localhost, private IP subnets, and cloud metadata services are blocked for security.', 'locasentinel' ),
			);
		}

		$sample_details = array(
			'user_login'        => wp_get_current_user()->user_login ?: 'admin_demo',
			'user_email'        => wp_get_current_user()->user_email ?: 'admin@example.com',
			'ip'                => IpResolver::get_client_ip(),
			'country_code'      => 'MY',
			'country_name'      => 'Malaysia',
			'region_name'       => 'Federal Territory of Kuala Lumpur',
			'city_name'         => 'Kuala Lumpur',
			'zip_code'          => '50450',
			'asn'               => '4788',
			'as_name'           => 'TM Technology Services Sdn. Bhd.',
			'is_proxy'          => false,
			'location_current'  => 'Kuala Lumpur, Malaysia (MY)',
			'location_previous' => 'London, United Kingdom (GB)',
			'speed_kmh'         => 1450.8,
			'distance_km'       => 10560.2,
			'time_diff_hours'   => 7.28,
			'action_taken'      => '2FA OTP Challenge & Webhook Notification',
			'rule_triggered'    => 'Impossible Travel Velocity > 800 km/h',
			'target_endpoint'   => '/wp-login.php',
			'http_method'       => 'POST',
		);

		$temp_settings = get_option( 'ip2loc_settings', array() );
		$temp_settings['enable_webhooks']        = 1;
		$temp_settings['webhook_url']            = $raw_url;
		$temp_settings['webhook_type']           = $type;
		$temp_settings['webhook_custom_payload'] = $custom_payload;
		update_option( 'ip2loc_settings', $temp_settings );

		$result = self::send_event( 'IMPOSSIBLE_TRAVEL_TEST', $sample_details );

		if ( $result ) {
			return array(
				'success' => true,
				'message' => __( 'Webhook test payload successfully dispatched! Check your destination channel.', 'locasentinel' ),
			);
		}

		return array(
			'success' => false,
			'message' => __( 'Failed to dispatch webhook. Please check the URL, network connection, or webhook endpoint status.', 'locasentinel' ),
		);
	}
}
