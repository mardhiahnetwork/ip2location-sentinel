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
	 * @param string     $ip
	 * @param array|null $geo_data
	 * @return array Evaluation result
	 */
	public static function evaluate( string $ip = '', ?array $geo_data = null ): array {
		if ( empty( $ip ) ) {
			$ip = IpResolver::get_client_ip();
		}

		$settings = get_option( 'ip2loc_settings', array() );

		// 1. Check IP Whitelist
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

		// 2. Check IP Blacklist
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

		// Fetch Geolocation if not already provided
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

		// Always allow local/loopback IPs
		if ( ! empty( $geo_data['is_private'] ) ) {
			return array(
				'blocked' => false,
				'reason'  => 'Localhost / Private Network',
				'rule'    => 'local_bypass',
				'geo'     => $geo_data,
			);
		}

		// 3. Extended & Customizable Crawler Allowlist
		$crawler_allow = self::evaluate_crawlers( $ip, $settings, $geo_data );
		if ( null !== $crawler_allow ) {
			return $crawler_allow;
		}

		// 4. Proxy / VPN / Tor Detection
		if ( ! empty( $settings['block_proxies'] ) && ! empty( $geo_data['is_proxy'] ) ) {
			return array(
				'blocked' => true,
				'reason'  => 'Proxy / VPN / Data Center Connection Detected',
				'rule'    => 'proxy_block',
				'geo'     => $geo_data,
			);
		}

		// 5. Country Rules (Whitelist vs Blacklist)
		$country_mode = $settings['country_mode'] ?? 'blacklist';
		$country_list = isset( $settings['countries'] ) && is_array( $settings['countries'] ) ? array_map( 'strtoupper', $settings['countries'] ) : array();

		$client_country = strtoupper( $geo_data['country_code'] );

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

		// 6. Region / State Blocklist
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

		// 7. City Blocklist
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

		// 8. Zip / Postal Code Blocklist
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

		// 9. ASN / AS Organization Blocklist
		$blocked_asns = self::parse_list( $settings['blocked_asns'] ?? '' );
		if ( ! empty( $blocked_asns ) ) {
			$raw_asn     = (string) ( $geo_data['asn'] ?? '' );
			$raw_as      = (string) ( $geo_data['as'] ?? $geo_data['as_name'] ?? '' );
			$client_asn  = preg_replace( '/[^0-9]/', '', $raw_asn );
			$client_org  = strtolower( $raw_as );

			foreach ( $blocked_asns as $asn_rule ) {
				$clean_rule_asn = preg_replace( '/[^0-9]/', '', $asn_rule );

				if ( ! empty( $clean_rule_asn ) && $clean_rule_asn === $client_asn ) {
					return array(
						'blocked' => true,
						'reason'  => sprintf( 'ASN Blocked: AS%s (%s)', $raw_asn, $raw_as ),
						'rule'    => 'asn_block',
						'geo'     => $geo_data,
					);
				}

				if ( ! empty( $client_org ) && stripos( $client_org, strtolower( $asn_rule ) ) !== false ) {
					return array(
						'blocked' => true,
						'reason'  => sprintf( 'ISP/Organization Blocked: %s', $raw_as ),
						'rule'    => 'asn_org_block',
						'geo'     => $geo_data,
					);
				}
			}
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
	 * Evaluate incoming request against active crawler and bot allowlist rules.
	 *
	 * @param string $ip
	 * @param array  $settings
	 * @param array  $geo_data
	 * @return array|null
	 */
	public static function evaluate_crawlers( string $ip, array $settings, array $geo_data ): ?array {
		$raw_ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		if ( empty( $raw_ua ) ) {
			return null;
		}

		$ua_info  = UserAgent::parse( $raw_ua );
		$bot_name = ! empty( $ua_info['bot_name'] ) ? $ua_info['bot_name'] : 'Bot / Crawler';

		// A. Major Search Engine Crawlers (Google, Bing, Yahoo, Baidu, Yandex, DuckDuckGo, Applebot)
		if ( ! empty( $settings['allow_search_bots'] ) && UserAgent::is_search_engine( $raw_ua ) ) {
			// Optional Reverse DNS Anti-Spoofing Verification
			if ( ! empty( $settings['bot_rdns_verify'] ) && ! UserAgent::verify_search_bot_rdns( $ip, $raw_ua ) ) {
				// Spoofed user-agent detected! Do not bypass firewall
			} else {
				return array(
					'blocked' => false,
					'reason'  => sprintf( 'Allowed Search Engine Crawler: %s', $bot_name ),
					'rule'    => 'bot_search_engine_allow',
					'geo'     => $geo_data,
				);
			}
		}

		// B. Social Media Previewers (Facebook, Twitter/X, LinkedIn, WhatsApp, Telegram, Discord, Slack)
		if ( ! empty( $settings['allow_social_bots'] ) && UserAgent::is_social_bot( $raw_ua ) ) {
			return array(
				'blocked' => false,
				'reason'  => sprintf( 'Allowed Social Media Previewer: %s', $bot_name ),
				'rule'    => 'bot_social_allow',
				'geo'     => $geo_data,
			);
		}

		// C. SEO & Uptime Monitoring Bots (Ahrefs, Semrush, Moz, UptimeRobot, Pingdom)
		if ( ! empty( $settings['allow_seo_bots'] ) && UserAgent::is_seo_bot( $raw_ua ) ) {
			return array(
				'blocked' => false,
				'reason'  => sprintf( 'Allowed SEO / Uptime Bot: %s', $bot_name ),
				'rule'    => 'bot_seo_allow',
				'geo'     => $geo_data,
			);
		}

		// D. AI & LLM Crawlers (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, Bytespider)
		if ( ! empty( $settings['allow_ai_bots'] ) && UserAgent::is_ai_bot( $raw_ua ) ) {
			return array(
				'blocked' => false,
				'reason'  => sprintf( 'Allowed AI / LLM Bot: %s', $bot_name ),
				'rule'    => 'bot_ai_allow',
				'geo'     => $geo_data,
			);
		}

		// E. Feed & RSS Readers (Feedly, Inoreader, NewsBlur)
		if ( ! empty( $settings['allow_feed_bots'] ) && UserAgent::is_feed_bot( $raw_ua ) ) {
			return array(
				'blocked' => false,
				'reason'  => sprintf( 'Allowed Feed Reader: %s', $bot_name ),
				'rule'    => 'bot_feed_allow',
				'geo'     => $geo_data,
			);
		}

		// F. Custom User-Agent Substrings & Regex Patterns
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
