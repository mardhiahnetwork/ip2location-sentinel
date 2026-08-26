<?php
/**
 * IP2Location Rule Engine & Geo Access Evaluator
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class RuleEngine {

	/**
	 * Evaluate incoming IP and Geolocation data against active firewall rules.
	 *
	 * Precedence Hierarchy:
	 * 1. IP Whitelist (Immediate Allow)
	 * 2. IP Blacklist (Immediate Block)
	 * 3. Geolocation & ASN Lookup (Fail-Safe / Fail-Open)
	 * 4. Localhost / Private Network Bypass
	 * 5. Explicit ASN / ISP Blacklist (Always Block)
	 * 6. Verified Search Engine Crawler Exemption (rDNS & Forward DNS Verified)
	 * 7. Proxy / VPN / Data Center Detection
	 * 8. Country Rules (Whitelist / Blacklist)
	 * 9. Region, City, Zip Code Blocklists
	 * 10. Secondary Non-Search Crawler Allowlist (Social, SEO, AI, Feed)
	 * 11. Default Allow
	 *
	 * @param string     $ip
	 * @param array|null $geo_data
	 * @return array Evaluation result
	 */
	public static function evaluate( string $ip = '', ?array $geo_data = null ): array {
		if ( empty( $ip ) ) {
			$ip = IpResolver::get_client_ip();
		}

		$settings = get_option( 'ip2loc_settings', array() );

		// 1. Check IP Whitelist (Highest precedence)
		$whitelist_ips = self::parse_list( $settings['whitelist_ips'] ?? '' );
		foreach ( $whitelist_ips as $allowed_range ) {
			if ( IpResolver::ip_in_range( $ip, $allowed_range ) ) {
				return array(
					'blocked' => false,
					'reason'  => sprintf( 'Whitelisted IP: %s', $allowed_range ),
					'rule'    => 'ip_whitelist',
					'geo'     => $geo_data ?? array(),
				);
			}
		}

		// 2. Check IP Blacklist (Always block, cannot be bypassed)
		$blacklist_ips = self::parse_list( $settings['blacklist_ips'] ?? '' );
		foreach ( $blacklist_ips as $blocked_range ) {
			if ( IpResolver::ip_in_range( $ip, $blocked_range ) ) {
				return array(
					'blocked' => true,
					'reason'  => sprintf( 'Blacklisted IP/Range: %s', $blocked_range ),
					'rule'    => 'ip_blacklist',
					'geo'     => $geo_data ?? array(),
				);
			}
		}

		// 3. Fetch Geolocation if not already provided
		if ( ! is_array( $geo_data ) || empty( $geo_data['country_code'] ) ) {
			$lookup = ApiClient::lookup( $ip );
			if ( is_wp_error( $lookup ) ) {
				$fail_mode = $settings['api_fail_mode'] ?? 'open';
				if ( $fail_mode === 'safe' ) {
					return array(
						'blocked' => true,
						'reason'  => 'API Error (Fail-Safe Lockdown Mode Active)',
						'rule'    => 'api_fail_safe',
						'geo'     => array( 'ip' => $ip ),
					);
				}
				return array(
					'blocked' => false,
					'reason'  => 'API Error (Fail-Open Mode Active)',
					'rule'    => 'api_fail_open',
					'geo'     => array( 'ip' => $ip ),
				);
			}
			$geo_data = $lookup;
		}

		// 4. Always allow local/loopback IPs
		if ( ! empty( $geo_data['is_private'] ) ) {
			return array(
				'blocked' => false,
				'reason'  => 'Localhost / Private Network',
				'rule'    => 'local_bypass',
				'geo'     => $geo_data,
			);
		}

		// 5. Explicit ASN / AS Organization Blacklist (Takes precedence over crawler allowlist)
		$blocked_asns = self::parse_list( $settings['blocked_asns'] ?? '' );
		if ( ! empty( $blocked_asns ) ) {
			$raw_asn    = (string) ( $geo_data['asn'] ?? '' );
			$raw_as     = (string) ( $geo_data['as'] ?? $geo_data['as_name'] ?? '' );
			$client_asn = preg_replace( '/[^0-9]/', '', $raw_asn );
			$client_org = strtolower( $raw_as );

			foreach ( $blocked_asns as $asn_rule ) {
				$asn_rule_trimmed = trim( $asn_rule );

				// Numeric ASN rule (e.g. "15169" or "AS15169")
				if ( preg_match( '/^(?:AS)?([0-9]+)$/i', $asn_rule_trimmed, $matches ) ) {
					$clean_rule_asn = $matches[1];
					if ( ! empty( $clean_rule_asn ) && $clean_rule_asn === $client_asn ) {
						return array(
							'blocked' => true,
							'reason'  => sprintf( 'ASN Blocked: AS%s (%s)', $raw_asn, $raw_as ),
							'rule'    => 'asn_block',
							'geo'     => $geo_data,
						);
					}
				} else {
					// Textual ISP / Organization name match
					if ( ! empty( $client_org ) && stripos( $client_org, $asn_rule_trimmed ) !== false ) {
						return array(
							'blocked' => true,
							'reason'  => sprintf( 'ISP/Organization Blocked: %s', $raw_as ),
							'rule'    => 'asn_org_block',
							'geo'     => $geo_data,
						);
					}
				}
			}
		}

		// 6. Verified Search Engine Crawler Exemption (rDNS & Forward DNS Cryptographically/DNS Anchored)
		$raw_ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		if ( ! empty( $settings['allow_search_bots'] ) && ! empty( $raw_ua ) && UserAgent::is_search_engine( $raw_ua ) ) {
			if ( UserAgent::verify_search_bot_rdns( $ip, $raw_ua ) ) {
				$ua_info  = UserAgent::parse( $raw_ua );
				$bot_name = ! empty( $ua_info['bot_name'] ) ? $ua_info['bot_name'] : 'Search Engine';
				return array(
					'blocked' => false,
					'reason'  => sprintf( 'Allowed Verified Search Engine Crawler: %s', $bot_name ),
					'rule'    => 'bot_search_engine_allow',
					'geo'     => $geo_data,
				);
			}
			// Unverified or spoofed Googlebot/Bingbot User-Agent proceeds to security checks below
		}

		// 7. Proxy / VPN / Tor Detection
		if ( ! empty( $settings['block_proxies'] ) && ! empty( $geo_data['is_proxy'] ) ) {
			return array(
				'blocked' => true,
				'reason'  => 'Proxy / VPN / Data Center Connection Detected',
				'rule'    => 'proxy_block',
				'geo'     => $geo_data,
			);
		}

		// 8. Country Rules (Whitelist vs Blacklist)
		$country_mode = $settings['country_mode'] ?? 'blacklist';
		$country_list = isset( $settings['countries'] ) && is_array( $settings['countries'] ) ? array_map( 'strtoupper', $settings['countries'] ) : array();

		$client_country = strtoupper( $geo_data['country_code'] ?? '' );

		if ( ! empty( $country_list ) ) {
			if ( $country_mode === 'blacklist' ) {
				if ( in_array( $client_country, $country_list, true ) ) {
					$c_name = Countries::get_country_name( $client_country );
					return array(
						'blocked' => true,
						'reason'  => sprintf( 'Country Blacklisted: %s (%s)', $c_name, $client_country ),
						'rule'    => 'country_blacklist',
						'geo'     => $geo_data,
					);
				}
			} elseif ( $country_mode === 'whitelist' ) {
				if ( ! in_array( $client_country, $country_list, true ) ) {
					$c_name = Countries::get_country_name( $client_country );
					return array(
						'blocked' => true,
						'reason'  => sprintf( 'Country Not in Whitelist: %s (%s)', $c_name, $client_country ),
						'rule'    => 'country_whitelist',
						'geo'     => $geo_data,
					);
				}
			}
		}

		// 9. Region / State Blocklist
		$blocked_regions = self::parse_list( $settings['blocked_regions'] ?? '' );
		if ( ! empty( $blocked_regions ) && ! empty( $geo_data['region_name'] ) ) {
			foreach ( $blocked_regions as $region ) {
				if ( strcasecmp( $geo_data['region_name'], $region ) === 0 ) {
					return array(
						'blocked' => true,
						'reason'  => sprintf( 'Region Blocked: %s', $geo_data['region_name'] ),
						'rule'    => 'region_block',
						'geo'     => $geo_data,
					);
				}
			}
		}

		// 10. City Blocklist
		$blocked_cities = self::parse_list( $settings['blocked_cities'] ?? '' );
		if ( ! empty( $blocked_cities ) && ! empty( $geo_data['city_name'] ) ) {
			foreach ( $blocked_cities as $city ) {
				if ( strcasecmp( $geo_data['city_name'], $city ) === 0 ) {
					return array(
						'blocked' => true,
						'reason'  => sprintf( 'City Blocked: %s', $geo_data['city_name'] ),
						'rule'    => 'city_block',
						'geo'     => $geo_data,
					);
				}
			}
		}

		// 11. Zip / Postal Code Blocklist
		$blocked_zips = self::parse_list( $settings['blocked_zips'] ?? '' );
		if ( ! empty( $blocked_zips ) && ! empty( $geo_data['zip_code'] ) ) {
			foreach ( $blocked_zips as $zip ) {
				if ( strcasecmp( $geo_data['zip_code'], $zip ) === 0 ) {
					return array(
						'blocked' => true,
						'reason'  => sprintf( 'Zip Code Blocked: %s', $geo_data['zip_code'] ),
						'rule'    => 'zip_block',
						'geo'     => $geo_data,
					);
				}
			}
		}

		// 12. Secondary Bot Allowlist (Social, SEO, AI, Feed - only applicable after security checks pass)
		$secondary_crawler = self::evaluate_secondary_crawlers( $raw_ua, $settings, $geo_data );
		if ( null !== $secondary_crawler ) {
			return $secondary_crawler;
		}

		return array(
			'blocked' => false,
			'reason'  => 'Allowed by Geo Firewall Policy',
			'rule'    => 'allow',
			'geo'     => $geo_data,
		);
	}

	/**
	 * Helper to parse comma/newline delimited text into a sanitized array.
	 *
	 * @param string|array $input
	 * @return array
	 */
	public static function parse_list( $input ): array {
		if ( is_array( $input ) ) {
			return array_filter( array_map( 'trim', $input ) );
		}

		if ( empty( $input ) || ! is_string( $input ) ) {
			return array();
		}

		$lines = preg_split( '/[\r\n,]+/', $input );
		$clean = array();

		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( ! empty( $line ) ) {
				$clean[] = $line;
			}
		}

		return array_unique( $clean );
	}

	/**
	 * Check if an IP matches any entry in a list of IPs / CIDR ranges.
	 *
	 * @param string $ip
	 * @param array  $ip_list
	 * @return bool
	 */
	public static function matches_ip_list( string $ip, array $ip_list ): bool {
		foreach ( $ip_list as $range ) {
			if ( IpResolver::ip_in_range( $ip, $range ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Evaluate secondary non-search engine bots (Social, SEO, AI, Feed)
	 * Only applied after proxy, country, region, city, zip, and ASN checks have passed.
	 *
	 * @param string $raw_ua
	 * @param array  $settings
	 * @param array  $geo_data
	 * @return array|null
	 */
	private static function evaluate_secondary_crawlers( string $raw_ua, array $settings, array $geo_data ): ?array {
		if ( empty( $raw_ua ) ) {
			return null;
		}

		$ua_info  = UserAgent::parse( $raw_ua );
		$bot_name = ! empty( $ua_info['bot_name'] ) ? $ua_info['bot_name'] : 'Bot / Crawler';

		// Social Media Previewers (Facebook, Twitter/X, LinkedIn, WhatsApp, Telegram, Discord, Slack)
		if ( ! empty( $settings['allow_social_bots'] ) && UserAgent::is_social_bot( $raw_ua ) ) {
			return array(
				'blocked' => false,
				'reason'  => sprintf( 'Allowed Social Media Previewer: %s', $bot_name ),
				'rule'    => 'bot_social_allow',
				'geo'     => $geo_data,
			);
		}

		// SEO & Uptime Monitoring Bots (Ahrefs, Semrush, Moz, UptimeRobot, Pingdom)
		if ( ! empty( $settings['allow_seo_bots'] ) && UserAgent::is_seo_bot( $raw_ua ) ) {
			return array(
				'blocked' => false,
				'reason'  => sprintf( 'Allowed SEO / Uptime Bot: %s', $bot_name ),
				'rule'    => 'bot_seo_allow',
				'geo'     => $geo_data,
			);
		}

		// AI & LLM Crawlers (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, Bytespider)
		if ( ! empty( $settings['allow_ai_bots'] ) && UserAgent::is_ai_bot( $raw_ua ) ) {
			return array(
				'blocked' => false,
				'reason'  => sprintf( 'Allowed AI / LLM Bot: %s', $bot_name ),
				'rule'    => 'bot_ai_allow',
				'geo'     => $geo_data,
			);
		}

		// Feed & RSS Readers (Feedly, Inoreader, NewsBlur)
		if ( ! empty( $settings['allow_feed_bots'] ) && UserAgent::is_feed_bot( $raw_ua ) ) {
			return array(
				'blocked' => false,
				'reason'  => sprintf( 'Allowed Feed Reader: %s', $bot_name ),
				'rule'    => 'bot_feed_allow',
				'geo'     => $geo_data,
			);
		}

		// Custom User-Agent Substrings & Regex Patterns
		if ( ! empty( $settings['allowed_crawlers_custom'] ) ) {
			if ( UserAgent::matches_custom_crawler( $raw_ua, $settings['allowed_crawlers_custom'] ) ) {
				return array(
					'blocked' => false,
					'reason'  => sprintf( 'Allowed Custom Crawler Match: %s', substr( $raw_ua, 0, 45 ) ),
					'rule'    => 'bot_custom_allow',
					'geo'     => $geo_data,
				);
			}
		}

		return null;
	}
}
