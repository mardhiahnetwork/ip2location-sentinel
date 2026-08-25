<?php
/**
 * IP2Location Countries Helper
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Countries {

	/**
	 * Static in-memory cache for country flag emojis
	 *
	 * @var array<string, string>
	 */
	private static array $flag_cache = array();

	/**
	 * Static in-memory cache for country lists with flags
	 *
	 * @var array<string, string>
	 */
	private static array $countries_with_flags_cache = array();

	/**
	 * Get complete list of countries (alias).
	 *
	 * @return array<string, string>
	 */
	public static function get_all(): array {
		return self::get_all_countries();
	}

	/**
	 * Get absolute path to local SVG flag file.
	 *
	 * @param string $code
	 * @return string
	 */
	public static function get_flag_path( string $code ): string {
		$code = strtolower( trim( $code ) );
		return plugin_dir_path( dirname( __FILE__ ) ) . 'assets/flags/' . $code . '.svg';
	}

	/**
	 * Get complete list of countries (ISO 3166-1 alpha-2 => Country Name).
	 *
	 * @return array<string, string>
	 */
	public static function get_all_countries(): array {
		return array(
			'AF' => __( 'Afghanistan', 'ip2location-sentinel' ),
			'AX' => __( 'Åland Islands', 'ip2location-sentinel' ),
			'AL' => __( 'Albania', 'ip2location-sentinel' ),
			'DZ' => __( 'Algeria', 'ip2location-sentinel' ),
			'AS' => __( 'American Samoa', 'ip2location-sentinel' ),
			'AD' => __( 'Andorra', 'ip2location-sentinel' ),
			'AO' => __( 'Angola', 'ip2location-sentinel' ),
			'AI' => __( 'Anguilla', 'ip2location-sentinel' ),
			'AQ' => __( 'Antarctica', 'ip2location-sentinel' ),
			'AG' => __( 'Antigua and Barbuda', 'ip2location-sentinel' ),
			'AR' => __( 'Argentina', 'ip2location-sentinel' ),
			'AM' => __( 'Armenia', 'ip2location-sentinel' ),
			'AW' => __( 'Aruba', 'ip2location-sentinel' ),
			'AU' => __( 'Australia', 'ip2location-sentinel' ),
			'AT' => __( 'Austria', 'ip2location-sentinel' ),
			'AZ' => __( 'Azerbaijan', 'ip2location-sentinel' ),
			'BS' => __( 'Bahamas', 'ip2location-sentinel' ),
			'BH' => __( 'Bahrain', 'ip2location-sentinel' ),
			'BD' => __( 'Bangladesh', 'ip2location-sentinel' ),
			'BB' => __( 'Barbados', 'ip2location-sentinel' ),
			'BY' => __( 'Belarus', 'ip2location-sentinel' ),
			'BE' => __( 'Belgium', 'ip2location-sentinel' ),
			'BZ' => __( 'Belize', 'ip2location-sentinel' ),
			'BJ' => __( 'Benin', 'ip2location-sentinel' ),
			'BM' => __( 'Bermuda', 'ip2location-sentinel' ),
			'BT' => __( 'Bhutan', 'ip2location-sentinel' ),
			'BO' => __( 'Bolivia', 'ip2location-sentinel' ),
			'BQ' => __( 'Bonaire, Sint Eustatius and Saba', 'ip2location-sentinel' ),
			'BA' => __( 'Bosnia and Herzegovina', 'ip2location-sentinel' ),
			'BW' => __( 'Botswana', 'ip2location-sentinel' ),
			'BV' => __( 'Bouvet Island', 'ip2location-sentinel' ),
			'BR' => __( 'Brazil', 'ip2location-sentinel' ),
			'IO' => __( 'British Indian Ocean Territory', 'ip2location-sentinel' ),
			'BN' => __( 'Brunei Darussalam', 'ip2location-sentinel' ),
			'BG' => __( 'Bulgaria', 'ip2location-sentinel' ),
			'BF' => __( 'Burkina Faso', 'ip2location-sentinel' ),
			'BI' => __( 'Burundi', 'ip2location-sentinel' ),
			'CV' => __( 'Cabo Verde', 'ip2location-sentinel' ),
			'KH' => __( 'Cambodia', 'ip2location-sentinel' ),
			'CM' => __( 'Cameroon', 'ip2location-sentinel' ),
			'CA' => __( 'Canada', 'ip2location-sentinel' ),
			'KY' => __( 'Cayman Islands', 'ip2location-sentinel' ),
			'CF' => __( 'Central African Republic', 'ip2location-sentinel' ),
			'TD' => __( 'Chad', 'ip2location-sentinel' ),
			'CL' => __( 'Chile', 'ip2location-sentinel' ),
			'CN' => __( 'China', 'ip2location-sentinel' ),
			'CX' => __( 'Christmas Island', 'ip2location-sentinel' ),
			'CC' => __( 'Cocos (Keeling) Islands', 'ip2location-sentinel' ),
			'CO' => __( 'Colombia', 'ip2location-sentinel' ),
			'KM' => __( 'Comoros', 'ip2location-sentinel' ),
			'CG' => __( 'Congo', 'ip2location-sentinel' ),
			'CD' => __( 'Congo (Democratic Republic)', 'ip2location-sentinel' ),
			'CK' => __( 'Cook Islands', 'ip2location-sentinel' ),
			'CR' => __( 'Costa Rica', 'ip2location-sentinel' ),
			'CI' => __( "Côte d'Ivoire", 'ip2location-sentinel' ),
			'HR' => __( 'Croatia', 'ip2location-sentinel' ),
			'CU' => __( 'Cuba', 'ip2location-sentinel' ),
			'CW' => __( 'Curaçao', 'ip2location-sentinel' ),
			'CY' => __( 'Cyprus', 'ip2location-sentinel' ),
			'CZ' => __( 'Czech Republic', 'ip2location-sentinel' ),
			'DK' => __( 'Denmark', 'ip2location-sentinel' ),
			'DJ' => __( 'Djibouti', 'ip2location-sentinel' ),
			'DM' => __( 'Dominica', 'ip2location-sentinel' ),
			'DO' => __( 'Dominican Republic', 'ip2location-sentinel' ),
			'EC' => __( 'Ecuador', 'ip2location-sentinel' ),
			'EG' => __( 'Egypt', 'ip2location-sentinel' ),
			'SV' => __( 'El Salvador', 'ip2location-sentinel' ),
			'GQ' => __( 'Equatorial Guinea', 'ip2location-sentinel' ),
			'ER' => __( 'Eritrea', 'ip2location-sentinel' ),
			'EE' => __( 'Estonia', 'ip2location-sentinel' ),
			'SZ' => __( 'Eswatini', 'ip2location-sentinel' ),
			'ET' => __( 'Ethiopia', 'ip2location-sentinel' ),
			'FK' => __( 'Falkland Islands', 'ip2location-sentinel' ),
			'FO' => __( 'Faroe Islands', 'ip2location-sentinel' ),
			'FJ' => __( 'Fiji', 'ip2location-sentinel' ),
			'FI' => __( 'Finland', 'ip2location-sentinel' ),
			'FR' => __( 'France', 'ip2location-sentinel' ),
			'GF' => __( 'French Guiana', 'ip2location-sentinel' ),
			'PF' => __( 'French Polynesia', 'ip2location-sentinel' ),
			'TF' => __( 'French Southern Territories', 'ip2location-sentinel' ),
			'GA' => __( 'Gabon', 'ip2location-sentinel' ),
			'GM' => __( 'Gambia', 'ip2location-sentinel' ),
			'GE' => __( 'Georgia', 'ip2location-sentinel' ),
			'DE' => __( 'Germany', 'ip2location-sentinel' ),
			'GH' => __( 'Ghana', 'ip2location-sentinel' ),
			'GI' => __( 'Gibraltar', 'ip2location-sentinel' ),
			'GR' => __( 'Greece', 'ip2location-sentinel' ),
			'GL' => __( 'Greenland', 'ip2location-sentinel' ),
			'GD' => __( 'Grenada', 'ip2location-sentinel' ),
			'GP' => __( 'Guadeloupe', 'ip2location-sentinel' ),
			'GU' => __( 'Guam', 'ip2location-sentinel' ),
			'GT' => __( 'Guatemala', 'ip2location-sentinel' ),
			'GG' => __( 'Guernsey', 'ip2location-sentinel' ),
			'GN' => __( 'Guinea', 'ip2location-sentinel' ),
			'GW' => __( 'Guinea-Bissau', 'ip2location-sentinel' ),
			'GY' => __( 'Guyana', 'ip2location-sentinel' ),
			'HT' => __( 'Haiti', 'ip2location-sentinel' ),
			'HM' => __( 'Heard Island and McDonald Islands', 'ip2location-sentinel' ),
			'VA' => __( 'Holy See', 'ip2location-sentinel' ),
			'HN' => __( 'Honduras', 'ip2location-sentinel' ),
			'HK' => __( 'Hong Kong', 'ip2location-sentinel' ),
			'HU' => __( 'Hungary', 'ip2location-sentinel' ),
			'IS' => __( 'Iceland', 'ip2location-sentinel' ),
			'IN' => __( 'India', 'ip2location-sentinel' ),
			'ID' => __( 'Indonesia', 'ip2location-sentinel' ),
			'IR' => __( 'Iran', 'ip2location-sentinel' ),
			'IQ' => __( 'Iraq', 'ip2location-sentinel' ),
			'IE' => __( 'Ireland', 'ip2location-sentinel' ),
			'IM' => __( 'Isle of Man', 'ip2location-sentinel' ),
			'IL' => __( 'Israel', 'ip2location-sentinel' ),
			'IT' => __( 'Italy', 'ip2location-sentinel' ),
			'JM' => __( 'Jamaica', 'ip2location-sentinel' ),
			'JP' => __( 'Japan', 'ip2location-sentinel' ),
			'JE' => __( 'Jersey', 'ip2location-sentinel' ),
			'JO' => __( 'Jordan', 'ip2location-sentinel' ),
			'KZ' => __( 'Kazakhstan', 'ip2location-sentinel' ),
			'KE' => __( 'Kenya', 'ip2location-sentinel' ),
			'KI' => __( 'Kiribati', 'ip2location-sentinel' ),
			'KP' => __( 'North Korea', 'ip2location-sentinel' ),
			'KR' => __( 'South Korea', 'ip2location-sentinel' ),
			'KW' => __( 'Kuwait', 'ip2location-sentinel' ),
			'KG' => __( 'Kyrgyzstan', 'ip2location-sentinel' ),
			'LA' => __( 'Laos', 'ip2location-sentinel' ),
			'LV' => __( 'Latvia', 'ip2location-sentinel' ),
			'LB' => __( 'Lebanon', 'ip2location-sentinel' ),
			'LS' => __( 'Lesotho', 'ip2location-sentinel' ),
			'LR' => __( 'Liberia', 'ip2location-sentinel' ),
			'LY' => __( 'Libya', 'ip2location-sentinel' ),
			'LI' => __( 'Liechtenstein', 'ip2location-sentinel' ),
			'LT' => __( 'Lithuania', 'ip2location-sentinel' ),
			'LU' => __( 'Luxembourg', 'ip2location-sentinel' ),
			'MO' => __( 'Macao', 'ip2location-sentinel' ),
			'MG' => __( 'Madagascar', 'ip2location-sentinel' ),
			'MW' => __( 'Malawi', 'ip2location-sentinel' ),
			'MY' => __( 'Malaysia', 'ip2location-sentinel' ),
			'MV' => __( 'Maldives', 'ip2location-sentinel' ),
			'ML' => __( 'Mali', 'ip2location-sentinel' ),
			'MT' => __( 'Malta', 'ip2location-sentinel' ),
			'MH' => __( 'Marshall Islands', 'ip2location-sentinel' ),
			'MQ' => __( 'Martinique', 'ip2location-sentinel' ),
			'MR' => __( 'Mauritania', 'ip2location-sentinel' ),
			'MU' => __( 'Mauritius', 'ip2location-sentinel' ),
			'YT' => __( 'Mayotte', 'ip2location-sentinel' ),
			'MX' => __( 'Mexico', 'ip2location-sentinel' ),
			'FM' => __( 'Micronesia', 'ip2location-sentinel' ),
			'MD' => __( 'Moldova', 'ip2location-sentinel' ),
			'MC' => __( 'Monaco', 'ip2location-sentinel' ),
			'MN' => __( 'Mongolia', 'ip2location-sentinel' ),
			'ME' => __( 'Montenegro', 'ip2location-sentinel' ),
			'MS' => __( 'Montserrat', 'ip2location-sentinel' ),
			'MA' => __( 'Morocco', 'ip2location-sentinel' ),
			'MZ' => __( 'Mozambique', 'ip2location-sentinel' ),
			'MM' => __( 'Myanmar', 'ip2location-sentinel' ),
			'NA' => __( 'Namibia', 'ip2location-sentinel' ),
			'NR' => __( 'Nauru', 'ip2location-sentinel' ),
			'NP' => __( 'Nepal', 'ip2location-sentinel' ),
			'NL' => __( 'Netherlands', 'ip2location-sentinel' ),
			'NC' => __( 'New Caledonia', 'ip2location-sentinel' ),
			'NZ' => __( 'New Zealand', 'ip2location-sentinel' ),
			'NI' => __( 'Nicaragua', 'ip2location-sentinel' ),
			'NE' => __( 'Niger', 'ip2location-sentinel' ),
			'NG' => __( 'Nigeria', 'ip2location-sentinel' ),
			'NU' => __( 'Niue', 'ip2location-sentinel' ),
			'NF' => __( 'Norfolk Island', 'ip2location-sentinel' ),
			'MK' => __( 'North Macedonia', 'ip2location-sentinel' ),
			'MP' => __( 'Northern Mariana Islands', 'ip2location-sentinel' ),
			'NO' => __( 'Norway', 'ip2location-sentinel' ),
			'OM' => __( 'Oman', 'ip2location-sentinel' ),
			'PK' => __( 'Pakistan', 'ip2location-sentinel' ),
			'PW' => __( 'Palau', 'ip2location-sentinel' ),
			'PS' => __( 'Palestine', 'ip2location-sentinel' ),
			'PA' => __( 'Panama', 'ip2location-sentinel' ),
			'PG' => __( 'Papua New Guinea', 'ip2location-sentinel' ),
			'PY' => __( 'Paraguay', 'ip2location-sentinel' ),
			'PE' => __( 'Peru', 'ip2location-sentinel' ),
			'PH' => __( 'Philippines', 'ip2location-sentinel' ),
			'PN' => __( 'Pitcairn', 'ip2location-sentinel' ),
			'PL' => __( 'Poland', 'ip2location-sentinel' ),
			'PT' => __( 'Portugal', 'ip2location-sentinel' ),
			'PR' => __( 'Puerto Rico', 'ip2location-sentinel' ),
			'QA' => __( 'Qatar', 'ip2location-sentinel' ),
			'RE' => __( 'Réunion', 'ip2location-sentinel' ),
			'RO' => __( 'Romania', 'ip2location-sentinel' ),
			'RU' => __( 'Russia', 'ip2location-sentinel' ),
			'RW' => __( 'Rwanda', 'ip2location-sentinel' ),
			'BL' => __( 'Saint Barthélemy', 'ip2location-sentinel' ),
			'SH' => __( 'Saint Helena, Ascension and Tristan da Cunha', 'ip2location-sentinel' ),
			'KN' => __( 'Saint Kitts and Nevis', 'ip2location-sentinel' ),
			'LC' => __( 'Saint Lucia', 'ip2location-sentinel' ),
			'MF' => __( 'Saint Martin (French part)', 'ip2location-sentinel' ),
			'PM' => __( 'Saint Pierre and Miquelon', 'ip2location-sentinel' ),
			'VC' => __( 'Saint Vincent and the Grenadines', 'ip2location-sentinel' ),
			'WS' => __( 'Samoa', 'ip2location-sentinel' ),
			'SM' => __( 'San Marino', 'ip2location-sentinel' ),
			'ST' => __( 'Sao Tome and Principe', 'ip2location-sentinel' ),
			'SA' => __( 'Saudi Arabia', 'ip2location-sentinel' ),
			'SN' => __( 'Senegal', 'ip2location-sentinel' ),
			'RS' => __( 'Serbia', 'ip2location-sentinel' ),
			'SC' => __( 'Seychelles', 'ip2location-sentinel' ),
			'SL' => __( 'Sierra Leone', 'ip2location-sentinel' ),
			'SG' => __( 'Singapore', 'ip2location-sentinel' ),
			'SX' => __( 'Sint Maarten (Dutch part)', 'ip2location-sentinel' ),
			'SK' => __( 'Slovakia', 'ip2location-sentinel' ),
			'SI' => __( 'Slovenia', 'ip2location-sentinel' ),
			'SB' => __( 'Solomon Islands', 'ip2location-sentinel' ),
			'SO' => __( 'Somalia', 'ip2location-sentinel' ),
			'ZA' => __( 'South Africa', 'ip2location-sentinel' ),
			'GS' => __( 'South Georgia and the South Sandwich Islands', 'ip2location-sentinel' ),
			'SS' => __( 'South Sudan', 'ip2location-sentinel' ),
			'ES' => __( 'Spain', 'ip2location-sentinel' ),
			'LK' => __( 'Sri Lanka', 'ip2location-sentinel' ),
			'SD' => __( 'Sudan', 'ip2location-sentinel' ),
			'SR' => __( 'Suriname', 'ip2location-sentinel' ),
			'SJ' => __( 'Svalbard and Jan Mayen', 'ip2location-sentinel' ),
			'SE' => __( 'Sweden', 'ip2location-sentinel' ),
			'CH' => __( 'Switzerland', 'ip2location-sentinel' ),
			'SY' => __( 'Syria', 'ip2location-sentinel' ),
			'TW' => __( 'Taiwan', 'ip2location-sentinel' ),
			'TJ' => __( 'Tajikistan', 'ip2location-sentinel' ),
			'TZ' => __( 'Tanzania', 'ip2location-sentinel' ),
			'TH' => __( 'Thailand', 'ip2location-sentinel' ),
			'TL' => __( 'Timor-Leste', 'ip2location-sentinel' ),
			'TG' => __( 'Togo', 'ip2location-sentinel' ),
			'TK' => __( 'Tokelau', 'ip2location-sentinel' ),
			'TO' => __( 'Tonga', 'ip2location-sentinel' ),
			'TT' => __( 'Trinidad and Tobago', 'ip2location-sentinel' ),
			'TN' => __( 'Tunisia', 'ip2location-sentinel' ),
			'TR' => __( 'Turkey', 'ip2location-sentinel' ),
			'TM' => __( 'Turkmenistan', 'ip2location-sentinel' ),
			'TC' => __( 'Turks and Caicos Islands', 'ip2location-sentinel' ),
			'TV' => __( 'Tuvalu', 'ip2location-sentinel' ),
			'UG' => __( 'Uganda', 'ip2location-sentinel' ),
			'UA' => __( 'Ukraine', 'ip2location-sentinel' ),
			'AE' => __( 'United Arab Emirates', 'ip2location-sentinel' ),
			'GB' => __( 'United Kingdom', 'ip2location-sentinel' ),
			'US' => __( 'United States', 'ip2location-sentinel' ),
			'UM' => __( 'United States Minor Outlying Islands', 'ip2location-sentinel' ),
			'UY' => __( 'Uruguay', 'ip2location-sentinel' ),
			'UZ' => __( 'Uzbekistan', 'ip2location-sentinel' ),
			'VU' => __( 'Vanuatu', 'ip2location-sentinel' ),
			'VE' => __( 'Venezuela', 'ip2location-sentinel' ),
			'VN' => __( 'Vietnam', 'ip2location-sentinel' ),
			'VG' => __( 'Virgin Islands (British)', 'ip2location-sentinel' ),
			'VI' => __( 'Virgin Islands (U.S.)', 'ip2location-sentinel' ),
			'WF' => __( 'Wallis and Futuna', 'ip2location-sentinel' ),
			'EH' => __( 'Western Sahara', 'ip2location-sentinel' ),
			'YE' => __( 'Yemen', 'ip2location-sentinel' ),
			'ZM' => __( 'Zambia', 'ip2location-sentinel' ),
			'ZW' => __( 'Zimbabwe', 'ip2location-sentinel' ),
		);
	}

	/**
	 * Get country name by 2-letter ISO code.
	 *
	 * @param string $code
	 * @return string
	 */
	public static function get_country_name( string $code ): string {
		$code      = strtoupper( trim( $code ) );
		$countries = self::get_all_countries();
		return $countries[ $code ] ?? $code;
	}

	/**
	 * Get Local SVG Country Flag URL.
	 *
	 * @param string $code 2-letter ISO country code.
	 * @return string
	 */
	public static function get_flag_url( string $code ): string {
		$code = strtolower( trim( $code ) );
		if ( strlen( $code ) !== 2 ) {
			return '';
		}

		if ( isset( self::$flag_cache[ $code ] ) ) {
			return self::$flag_cache[ $code ];
		}

		$plugin_url = plugin_dir_url( dirname( __FILE__ ) );
		$file_path  = plugin_dir_path( dirname( __FILE__ ) ) . 'assets/flags/' . $code . '.svg';

		if ( file_exists( $file_path ) ) {
			$url = $plugin_url . 'assets/flags/' . $code . '.svg';
		} else {
			$url = '';
		}

		self::$flag_cache[ $code ] = $url;
		return $url;
	}

	/**
	 * Get Local Country Flag HTML element.
	 *
	 * @param string $code 2-letter ISO country code.
	 * @param string $alt Optional alt label.
	 * @return string
	 */
	public static function get_flag_html( string $code, string $alt = '' ): string {
		$url = self::get_flag_url( $code );
		if ( ! $url ) {
			return '';
		}

		$code_upper = strtoupper( trim( $code ) );
		$alt_text   = $alt ?: $code_upper;

		return sprintf(
			'<img src="%s" alt="%s" class="ip2loc-flag-img" width="18" height="13" loading="lazy" />',
			esc_url( $url ),
			esc_attr( $alt_text )
		);
	}

	/**
	 * Get Country Flag (alias returning local flag HTML for compatibility).
	 *
	 * @param string $code
	 * @return string
	 */
	public static function get_flag_emoji( string $code ): string {
		return self::get_flag_html( $code );
	}

	/**
	 * Get complete list of countries.
	 * Cached in static memory for ultra-fast rendering.
	 *
	 * @return array<string, string>
	 */
	public static function get_all_countries_with_flags(): array {
		if ( ! empty( self::$countries_with_flags_cache ) ) {
			return self::$countries_with_flags_cache;
		}

		$countries = self::get_all_countries();
		$result    = array();

		foreach ( $countries as $code => $name ) {
			$result[ $code ] = $name . ' (' . $code . ')';
		}

		self::$countries_with_flags_cache = $result;
		return self::$countries_with_flags_cache;
	}

	/**
	 * Predefined Regional Presets
	 *
	 * @return array
	 */
	public static function get_preset_groups(): array {
		return array(
			'NA' => array(
				'name'      => __( 'North America (US, CA, MX)', 'ip2location-sentinel' ),
				'countries' => array( 'US', 'CA', 'MX' ),
			),
			'SA' => array(
				'name'      => __( 'South America', 'ip2location-sentinel' ),
				'countries' => array( 'BR', 'AR', 'CL', 'CO', 'PE', 'VE', 'EC', 'UY', 'PY', 'BO', 'GY', 'SR' ),
			),
			'EU' => array(
				'name'      => __( 'European Union (27 countries)', 'ip2location-sentinel' ),
				'countries' => array( 'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE' ),
			),
			'ASEAN' => array(
				'name'      => __( 'ASEAN (Southeast Asia)', 'ip2location-sentinel' ),
				'countries' => array( 'BN', 'KH', 'ID', 'LA', 'MY', 'MM', 'PH', 'SG', 'TH', 'VN' ),
			),
			'GCC' => array(
				'name'      => __( 'Middle East & GCC', 'ip2location-sentinel' ),
				'countries' => array( 'AE', 'SA', 'QA', 'KW', 'BH', 'OM', 'IL', 'JO', 'LB' ),
			),
			'APAC' => array(
				'name'      => __( 'Asia-Pacific', 'ip2location-sentinel' ),
				'countries' => array( 'JP', 'KR', 'AU', 'NZ', 'TW', 'HK', 'SG', 'IN' ),
			),
			'HIGH_RISK_SPAM' => array(
				'name'      => __( 'Common Spam Origins', 'ip2location-sentinel' ),
				'countries' => array( 'RU', 'CN', 'KP', 'IR', 'BY', 'VN', 'NG', 'PK', 'BD', 'UA' ),
			),
		);
	}
}
