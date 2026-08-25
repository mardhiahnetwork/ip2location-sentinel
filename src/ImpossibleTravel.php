<?php
/**
 * Impossible Travel Detector & Smart 2FA Login OTP Controller
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

use WP_User;
use WP_Error;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ImpossibleTravel {

	/**
	 * Earth radius in kilometers
	 */
	public const EARTH_RADIUS_KM = 6371.0;

	/**
	 * Trusted device cookie name prefix
	 */
	public const TRUSTED_COOKIE_NAME = 'ip2loc_trusted_device';

	/**
	 * Initialize hooks
	 */
	public static function init(): void {
		add_filter( 'authenticate', array( __CLASS__, 'check_impossible_travel' ), 40, 3 );
		add_action( 'login_form_ip2loc_otp', array( __CLASS__, 'render_otp_screen' ) );
		add_action( 'wp_login', array( __CLASS__, 'record_login_location' ), 10, 2 );
	}

	/**
	 * Calculate Great-Circle Distance between two coordinates using Haversine formula (in kilometers).
	 *
	 * @param float $lat1
	 * @param float $lon1
	 * @param float $lat2
	 * @param float $lon2
	 * @return float
	 */
	public static function calculate_distance_km( float $lat1, float $lon1, float $lat2, float $lon2 ): float {
		$lat1 = deg2rad( $lat1 );
		$lon1 = deg2rad( $lon1 );
		$lat2 = deg2rad( $lat2 );
		$lon2 = deg2rad( $lon2 );

		$dlat = $lat2 - $lat1;
		$dlon = $lon2 - $lon1;

		$a = sin( $dlat / 2 ) * sin( $dlat / 2 ) +
			cos( $lat1 ) * cos( $lat2 ) *
			sin( $dlon / 2 ) * sin( $dlon / 2 );

		$c = 2 * atan2( sqrt( $a ), sqrt( 1 - $a ) );

		return self::EARTH_RADIUS_KM * $c;
	}

	/**
	 * Detect if an IP / connection belongs to a mobile cellular carrier or mobile device.
	 *
	 * @param array  $geo_data
	 * @param string $ua
	 * @return bool
	 */
	public static function is_mobile_or_carrier( array $geo_data, string $ua = '' ): bool {
		if ( empty( $ua ) && isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
			$ua = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );
		}

		$ua_info = UserAgent::parse( $ua );
		if ( in_array( $ua_info['device'], array( 'Mobile', 'Tablet' ), true ) || ! empty( $ua_info['is_mobile'] ) ) {
			return true;
		}

		$as_name = strtolower( $geo_data['as'] ?? ( $geo_data['as_name'] ?? '' ) );
		$carrier_keywords = array(
			'cellular', 'mobile', 'wireless', 'telecom', 'telekom', 'maxis', 'celcom',
			'digi', 'u mobile', 'umobile', 'ytl', 'yes 4g', 'vodafone', 't-mobile',
			'verizon', 'at&t', 'sprint', 'o2', 'ee limited', 'airtel', 'jio', 'singtel',
			'starhub', 'm1', 'telkomsel', 'indosat', 'xl axiata', 'smartfren', 'globe',
			'smart communications', 'optus', 'telstra', 'three', 'claro', 'movistar',
			'tim brasil', 'vivo', 'reliance', 'bsnl', 'zain', 'stc', 'du telecom',
			'tm technology', 'time dotcom', 'unifi', 'hotlink', 'xox', 'redone', 'tunetalk', 'altel',
		);

		foreach ( $carrier_keywords as $keyword ) {
			if ( strpos( $as_name, $keyword ) !== false ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if current browser has a valid trusted device cookie for this user.
	 *
	 * @param int    $user_id
	 * @param string $country_code
	 * @return bool
	 */
	public static function has_valid_trusted_device( int $user_id, string $country_code = '' ): bool {
		if ( empty( $user_id ) || empty( $_COOKIE[ self::TRUSTED_COOKIE_NAME ] ) ) {
			return false;
		}

		$cookie_val = sanitize_text_field( wp_unslash( $_COOKIE[ self::TRUSTED_COOKIE_NAME ] ) );
		$parts      = explode( '|', $cookie_val );

		if ( count( $parts ) !== 3 ) {
			return false;
		}

		list( $cookie_uid, $expires, $hmac ) = $parts;

		if ( (int) $cookie_uid !== (int) $user_id || time() > (int) $expires ) {
			return false;
		}

		$key      = wp_salt( 'secure_auth' );
		$expected = hash_hmac( 'sha256', $user_id . '|' . $expires, $key );

		return hash_equals( $expected, $hmac );
	}

	/**
	 * Issue a 30-day secure trusted device cookie to the browser.
	 *
	 * @param int $user_id
	 */
	public static function issue_trusted_device_cookie( int $user_id ): void {
		if ( empty( $user_id ) || headers_sent() ) {
			return;
		}

		$expires  = time() + ( 30 * DAY_IN_SECONDS );
		$key      = wp_salt( 'secure_auth' );
		$hmac     = hash_hmac( 'sha256', $user_id . '|' . $expires, $key );
		$val      = $user_id . '|' . $expires . '|' . $hmac;
		$secure   = is_ssl();
		$httponly = true;

		setcookie( self::TRUSTED_COOKIE_NAME, $val, $expires, COOKIEPATH ?: '/', COOKIE_DOMAIN ?: '', $secure, $httponly );
	}

	/**
	 * Inspect user login for Impossible Travel conditions.
	 *
	 * @param mixed  $user
	 * @param string $username
	 * @param string $password
	 * @return mixed
	 */
	public static function check_impossible_travel( $user, string $username, string $password ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return $user;
		}

		$settings = get_option( 'ip2loc_settings', array() );
		if ( empty( $settings['enable_impossible_travel'] ) ) {
			return $user;
		}

		$curr_ip  = IpResolver::get_client_ip();
		$curr_geo = ApiClient::lookup( $curr_ip );

		if ( is_wp_error( $curr_geo ) ) {
			return $user;
		}

		$curr_ua      = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$curr_ua_hash = md5( $curr_ua );
		$curr_cc      = $curr_geo['country_code'] ?? '';

		$prev_time    = (int) get_user_meta( $user->ID, '_ip2loc_last_login_time', true );
		$prev_lat     = (float) get_user_meta( $user->ID, '_ip2loc_last_login_lat', true );
		$prev_lon     = (float) get_user_meta( $user->ID, '_ip2loc_last_login_lon', true );
		$prev_ip      = get_user_meta( $user->ID, '_ip2loc_last_login_ip', true );
		$prev_city    = get_user_meta( $user->ID, '_ip2loc_last_login_city', true );
		$prev_cc      = get_user_meta( $user->ID, '_ip2loc_last_login_country', true );
		$prev_as      = get_user_meta( $user->ID, '_ip2loc_last_login_as', true );
		$prev_ua_hash = get_user_meta( $user->ID, '_ip2loc_last_ua_hash', true );

		// 1. If trusted device cookie is valid and login is from recognized country -> Instant Bypass
		if ( self::has_valid_trusted_device( $user->ID, $curr_cc ) ) {
			return $user;
		}

		// 2. Same IP address -> Immediate Match
		if ( ! empty( $prev_ip ) && $prev_ip === $curr_ip ) {
			return $user;
		}

		// 3. First login ever or local connection -> Record and allow
		if ( empty( $prev_time ) || ( empty( $prev_lat ) && empty( $prev_lon ) ) || ! empty( $curr_geo['is_private'] ) ) {
			return $user;
		}

		$same_country  = ( ! empty( $prev_cc ) && ! empty( $curr_cc ) && strtoupper( $prev_cc ) === strtoupper( $curr_cc ) );
		$domestic_mode = $settings['impossible_domestic_mode'] ?? 'mobile_tolerance';

		// 4. Same-Country mode: Bypass within same country (e.g. Malaysia)
		if ( $same_country && $domestic_mode === 'ignore_domestic' ) {
			return $user;
		}

		// 5. Smart Mobile & Carrier Tolerance: Bypass domestic dynamic IP hops on telco carriers / mobile devices
		if ( $same_country && $domestic_mode === 'mobile_tolerance' ) {
			$curr_is_mobile = self::is_mobile_or_carrier( $curr_geo, $curr_ua );
			$prev_is_mobile = self::is_mobile_or_carrier( array( 'as' => $prev_as ), '' );

			if ( $curr_is_mobile || $prev_is_mobile || ( ! empty( $prev_ua_hash ) && $prev_ua_hash === $curr_ua_hash ) ) {
				return $user;
			}
		}

		$curr_time        = time();
		$curr_lat         = (float) $curr_geo['latitude'];
		$curr_lon         = (float) $curr_geo['longitude'];
		$time_diff_hours  = ( $curr_time - $prev_time ) / 3600;
		if ( $time_diff_hours <= 0 ) {
			$time_diff_hours = 0.01;
		}

		$distance_km     = self::calculate_distance_km( $prev_lat, $prev_lon, $curr_lat, $curr_lon );
		$speed_kmh       = $distance_km / $time_diff_hours;
		$threshold_speed = isset( $settings['impossible_speed_threshold'] ) ? (float) $settings['impossible_speed_threshold'] : 800.0;
		$min_distance    = isset( $settings['impossible_min_distance'] ) ? (float) $settings['impossible_min_distance'] : 300.0;

		// Genuine Impossible Travel detected (excessive physical speed across borders/regions)
		if ( $distance_km > $min_distance && $speed_kmh > $threshold_speed ) {
			$prev_loc_str = ( $prev_city ? $prev_city . ', ' : '' ) . $prev_cc;
			$curr_loc_str = ( $curr_geo['city_name'] ? $curr_geo['city_name'] . ', ' : '' ) . $curr_geo['country_code'];

			$details = array(
				'user_id'           => $user->ID,
				'user_login'        => $user->user_login,
				'ip'                => $curr_ip,
				'location_current'  => $curr_loc_str,
				'location_previous' => $prev_loc_str,
				'distance_km'       => round( $distance_km, 1 ),
				'speed_kmh'         => round( $speed_kmh, 1 ),
				'action_taken'      => 'Flagged Impossible Travel',
			);

			Logger::log_event(
				$curr_ip,
				'Login (wp-login.php)',
				'IMPOSSIBLE_TRAVEL_FLAGGED',
				sprintf( 'Impossible velocity: %s km/h over %s km in %s hrs', round( $speed_kmh, 1 ), round( $distance_km, 1 ), round( $time_diff_hours, 2 ) ),
				$user->user_login,
				$user->ID,
				$curr_geo,
				200
			);

			Webhook::send_event( 'IMPOSSIBLE_TRAVEL', $details );

			$action_mode = $settings['impossible_action'] ?? 'otp';

			if ( $action_mode === 'otp' ) {
				$smtp_check = SmtpChecker::check_smtp_status();

				if ( ! $smtp_check['is_safe_for_otp'] && empty( $settings['force_otp_without_smtp'] ) ) {
					return $user;
				}

				self::initiate_otp_flow( $user, $curr_geo, $details );
				exit;
			}
		}

		return $user;
	}

	/**
	 * Initiate OTP flow for user upon impossible travel detection.
	 *
	 * @param WP_User $user
	 * @param array   $geo
	 * @param array   $details
	 */
	public static function initiate_otp_flow( WP_User $user, array $geo, array $details ): void {
		$otp_code   = sprintf( '%06d', wp_rand( 100000, 999999 ) );
		$otp_token  = wp_generate_password( 32, false );
		$otp_secret = wp_hash_password( $otp_code );

		set_transient(
			'ip2loc_otp_' . $otp_token,
			array(
				'user_id'    => $user->ID,
				'secret'     => $otp_secret,
				'ip'         => $details['ip'],
				'geo'        => $geo,
				'attempts'   => 0,
				'created_at' => time(),
			),
			600
		);

		$site_name = get_bloginfo( 'name' );
		$to        = $user->user_email;
		$subject   = sprintf(
			/* translators: 1: site name, 2: OTP code */
			__( '[%1$s] Verification Code: %2$s (Unusual Login Location)', 'ip2location-sentinel' ),
			$site_name,
			$otp_code
		);

		$message = sprintf(
			/* translators: 1: username, 2: OTP code, 3: current location, 4: previous location, 5: IP address, 6: site name */
			__(
				"Hello %1\$s,\r\n\r\nWe detected a login attempt from an unusual geographical location.\r\n\r\nYour One-Time Verification Code (OTP) is:\r\n\r\n=== %2\$s ===\r\n\r\nThis code expires in 10 minutes.\r\n\r\nDetails:\r\n- Current Location: %3\$s (IP: %5\$s)\r\n- Previous Location: %4\$s\r\n\r\nIf this was you, enter the code on the verification screen to remember this device.\r\n\r\nRegards,\r\n%6\$s Security Team",
				'ip2location-sentinel'
			),
			$user->user_login,
			$otp_code,
			$details['location_current'],
			$details['location_previous'],
			$details['ip'],
			$site_name
		);

		$headers = array( 'Content-Type: text/plain; charset=UTF-8' );
		wp_mail( $to, $subject, $message, $headers );

		$redirect_url = add_query_arg(
			array(
				'action' => 'ip2loc_otp',
				'token'  => rawurlencode( $otp_token ),
			),
			wp_login_url()
		);

		wp_safe_redirect( $redirect_url );
		exit;
	}

	/**
	 * Render and handle the OTP verification screen on wp-login.php.
	 */
	public static function render_otp_screen(): void {
		$token = isset( $_REQUEST['token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['token'] ) ) : '';
		$error = '';

		if ( empty( $token ) ) {
			wp_die( esc_html__( 'Security token missing or invalid.', 'ip2location-sentinel' ), 403 );
		}

		$data = get_transient( 'ip2loc_otp_' . $token );
		if ( false === $data || ! is_array( $data ) ) {
			login_header( __( 'Session Expired', 'ip2location-sentinel' ) );
			echo '<p class="message">' . esc_html__( 'Your verification session has expired. Please log in again.', 'ip2location-sentinel' ) . '</p>';
			echo '<p><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Return to Login', 'ip2location-sentinel' ) . '</a></p>';
			login_footer();
			exit;
		}

		if ( isset( $_POST['ip2loc_otp_verify'] ) && check_admin_referer( 'ip2loc_otp_verify_action', 'ip2loc_otp_nonce' ) ) {
			$input_otp = isset( $_POST['otp_code'] ) ? sanitize_text_field( wp_unslash( $_POST['otp_code'] ) ) : '';

			if ( wp_check_password( $input_otp, $data['secret'] ) ) {
				delete_transient( 'ip2loc_otp_' . $token );

				$user = get_user_by( 'id', $data['user_id'] );
				if ( $user ) {
					wp_set_auth_cookie( $user->ID, true );
					self::issue_trusted_device_cookie( $user->ID );
					self::record_login_location( $user->user_login, $user );

					Logger::log_event(
						$data['ip'],
						'Login (wp-login.php)',
						'ALLOWED',
						'2FA OTP Challenge Verified (Device Trusted for 30 Days)',
						$user->user_login,
						$user->ID,
						$data['geo'],
						200
					);

					wp_safe_redirect( admin_url() );
					exit;
				}
			} else {
				$data['attempts'] = (int) $data['attempts'] + 1;
				if ( $data['attempts'] >= 5 ) {
					delete_transient( 'ip2loc_otp_' . $token );
					wp_die( esc_html__( 'Too many failed verification attempts. Please log in again.', 'ip2location-sentinel' ), 403 );
				}
				set_transient( 'ip2loc_otp_' . $token, $data, 600 );
				$error = sprintf(
					/* translators: %d: attempts remaining */
					__( 'Invalid verification code. You have %d attempts remaining.', 'ip2location-sentinel' ),
					5 - $data['attempts']
				);
			}
		}

		login_header( __( 'Security Verification Required', 'ip2location-sentinel' ), '', $error ? new WP_Error( 'otp_error', $error ) : null );
		?>
		<form name="ip2loc_otp_form" id="ip2loc_otp_form" action="<?php echo esc_url( add_query_arg( array( 'action' => 'ip2loc_otp', 'token' => rawurlencode( $token ) ), wp_login_url() ) ); ?>" method="post">
			<?php wp_nonce_field( 'ip2loc_otp_verify_action', 'ip2loc_otp_nonce' ); ?>
			<p style="margin-bottom: 16px; font-size: 13px; line-height: 1.5; color: #444;">
				<strong><?php esc_html_e( 'Unusual Login Location Detected', 'ip2location-sentinel' ); ?></strong><br>
				<?php esc_html_e( 'An email with a 6-digit verification code has been dispatched to your registered address. Enter it below to verify and trust this device for 30 days.', 'ip2location-sentinel' ); ?>
			</p>
			<p>
				<label for="otp_code"><?php esc_html_e( '6-Digit Verification Code', 'ip2location-sentinel' ); ?><br />
				<input type="text" name="otp_code" id="otp_code" class="input" value="" size="20" maxlength="6" autocomplete="one-time-code" placeholder="123456" style="letter-spacing: 4px; font-size: 20px; text-align: center;" required autofocus />
				</label>
			</p>
			<p class="ip2loc-trust-device-wrap" style="margin: 10px 0 16px;">
				<label for="ip2loc_trust_device" style="font-size: 13px; color: #3c434a; display: inline-flex; align-items: center; gap: 6px; cursor: pointer;">
					<input type="checkbox" name="ip2loc_trust_device" id="ip2loc_trust_device" value="1" checked />
					<span><?php esc_html_e( 'Trust me for 30 days', 'ip2location-sentinel' ); ?></span>
				</label>
			</p>
			<p class="submit">
				<input type="submit" name="ip2loc_otp_verify" id="ip2loc_otp_verify" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify & Sign In', 'ip2location-sentinel' ); ?>" style="width:100%;" />
			</p>
		</form>
		<p id="backtoblog" style="text-align:center;">
			<a href="<?php echo esc_url( wp_login_url() ); ?>">&larr; <?php esc_html_e( 'Back to standard login', 'ip2location-sentinel' ); ?></a>
		</p>
		<?php
		login_footer();
		exit;
	}

	/**
	 * Record user's login location upon successful authentication and log event.
	 *
	 * @param string  $user_login
	 * @param mixed   $user
	 */
	public static function record_login_location( string $user_login, $user ): void {
		if ( ! ( $user instanceof WP_User ) ) {
			return;
		}

		$ip  = IpResolver::get_client_ip();
		$geo = ApiClient::lookup( $ip );

		if ( ! is_wp_error( $geo ) ) {
			$ua_str = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

			update_user_meta( $user->ID, '_ip2loc_last_login_ip', $ip );
			update_user_meta( $user->ID, '_ip2loc_last_login_time', time() );
			update_user_meta( $user->ID, '_ip2loc_last_login_lat', $geo['latitude'] );
			update_user_meta( $user->ID, '_ip2loc_last_login_lon', $geo['longitude'] );
			update_user_meta( $user->ID, '_ip2loc_last_login_country', $geo['country_code'] );
			update_user_meta( $user->ID, '_ip2loc_last_login_city', $geo['city_name'] );
			update_user_meta( $user->ID, '_ip2loc_last_login_as', $geo['as'] );
			update_user_meta( $user->ID, '_ip2loc_last_ua_hash', md5( $ua_str ) );

			// Automatically issue/renew 30-day trusted device cookie
			self::issue_trusted_device_cookie( $user->ID );

			// Always log the allowed login event in Security Audit Logs
			$rule_msg = sprintf(
				__( 'Legitimate Login from %s (%s)', 'ip2location-sentinel' ),
				! empty( $geo['country_name'] ) ? $geo['country_name'] : 'Known Origin',
				! empty( $geo['city_name'] ) ? $geo['city_name'] : 'Local'
			);

			Logger::log_event(
				$ip,
				'Login (wp-login.php)',
				'ALLOWED',
				$rule_msg,
				$user->user_login,
				$user->ID,
				$geo,
				200
			);
		}
	}
}
