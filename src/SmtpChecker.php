<?php
/**
 * SMTP Configuration & Health Checker
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SmtpChecker {

	/**
	 * Known WordPress SMTP plugins
	 */
	public const SMTP_PLUGINS = array(
		'wp-mail-smtp/wp_mail_smtp.php'       => 'WP Mail SMTP',
		'fluent-smtp/fluent-smtp.php'         => 'FluentSMTP',
		'post-smtp/postman-smtp.php'           => 'Post SMTP',
		'easy-wp-smtp/easy-wp-smtp.php'       => 'Easy WP SMTP',
		'wp-offload-ses/wp-offload-ses.php'   => 'WP Offload SES',
		'smtp-mailer/main.php'                => 'SMTP Mailer',
		'sendgrid-email-delivery-vendor/sendgrid-email-delivery-vendor.php' => 'SendGrid',
		'mailgun/mailgun.php'                 => 'Mailgun',
		'sparkpost/sparkpost.php'             => 'SparkPost',
	);

	/**
	 * Inspect the system's SMTP & email delivery readiness.
	 *
	 * @return array
	 */
	public static function check_smtp_status(): array {
		$active_plugin      = self::get_active_smtp_plugin();
		$has_phpmailer_hook = has_action( 'phpmailer_init' );
		$has_sendmail       = (bool) ini_get( 'sendmail_path' ) || (bool) ini_get( 'SMTP' );

		$status  = 'unverified';
		$label   = __( 'Unverified / Native PHP Mail', 'ip2location-sentinel' );
		$is_safe = false;

		if ( ! empty( $active_plugin ) ) {
			$status  = 'active_plugin';
			$label   = sprintf(
				/* translators: %s: plugin name */
				__( 'Active Plugin: %s', 'ip2location-sentinel' ),
				$active_plugin
			);
			$is_safe = true;
		} elseif ( $has_phpmailer_hook ) {
			$status  = 'custom_phpmailer';
			$label   = __( 'Custom PHPMailer Configuration (via theme/code)', 'ip2location-sentinel' );
			$is_safe = true;
		} elseif ( $has_sendmail ) {
			$status  = 'native_mail';
			$label   = __( 'Native PHP sendmail (Deliverability may be low)', 'ip2location-sentinel' );
			$is_safe = false;
		}

		return array(
			'status'             => $status,
			'label'              => $label,
			'active_plugin'      => $active_plugin,
			'has_phpmailer_hook' => $has_phpmailer_hook,
			'is_safe_for_otp'    => $is_safe,
			'recommendation'     => $is_safe
				? __( 'SMTP service is configured. Email OTP is safe to enable.', 'ip2location-sentinel' )
				: __( 'No dedicated SMTP plugin detected. Native PHP mail often fails or lands in spam. We recommend configuring an SMTP plugin (e.g. FluentSMTP / WP Mail SMTP) or enabling the Webhook Alert alternative to prevent admin lockouts.', 'ip2location-sentinel' ),
		);
	}

	/**
	 * Detect if any known SMTP plugin is active.
	 *
	 * @return string Plugin name or empty string.
	 */
	public static function get_active_smtp_plugin(): string {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		foreach ( self::SMTP_PLUGINS as $plugin_file => $plugin_name ) {
			if ( is_plugin_active( $plugin_file ) ) {
				return $plugin_name;
			}
		}

		if ( class_exists( 'WPMailSMTP\Core' ) ) {
			return 'WP Mail SMTP';
		}
		if ( class_exists( 'FluentSmtp\App\FluentSmtp' ) ) {
			return 'FluentSMTP';
		}
		if ( class_exists( 'Postman' ) ) {
			return 'Post SMTP';
		}

		return '';
	}

	/**
	 * Send a diagnostic test email to verify real delivery.
	 *
	 * @param string $recipient
	 * @return array
	 */
	public static function send_test_email( string $recipient ): array {
		$recipient = sanitize_email( $recipient );
		if ( ! is_email( $recipient ) ) {
			return array(
				'success' => false,
				'message' => __( 'Invalid email address specified.', 'ip2location-sentinel' ),
			);
		}

		$subject = sprintf(
			/* translators: %s: site name */
			__( '[%s] IP2Location Sentinel SMTP Test', 'ip2location-sentinel' ),
			get_bloginfo( 'name' )
		);

		$message  = __( "Hello,\r\n\r\nThis is a test email sent from IP2Location Sentinel to verify your WordPress SMTP delivery configuration for Impossible Travel 2FA/OTP login alerts.\r\n\r\nIf you received this email, your SMTP configuration is working perfectly!", 'ip2location-sentinel' );
		$headers  = array( 'Content-Type: text/plain; charset=UTF-8' );

		$mail_error = '';
		$error_catcher = function( $wp_error ) use ( &$mail_error ) {
			if ( is_wp_error( $wp_error ) ) {
				$mail_error = $wp_error->get_error_message();
			}
		};

		add_action( 'wp_mail_failed', $error_catcher );
		$sent = wp_mail( $recipient, $subject, $message, $headers );
		remove_action( 'wp_mail_failed', $error_catcher );

		if ( $sent ) {
			return array(
				'success' => true,
				'message' => sprintf(
					/* translators: %s: email address */
					__( 'Test email successfully dispatched to %s. Please check your inbox.', 'ip2location-sentinel' ),
					$recipient
				),
			);
		}

		return array(
			'success' => false,
			'message' => ! empty( $mail_error )
				? sprintf(
					/* translators: %s: error message */
					__( 'wp_mail failed: %s', 'ip2location-sentinel' ),
					$mail_error
				)
				: __( 'wp_mail() returned false. Please check your SMTP settings or mail server logs.', 'ip2location-sentinel' ),
		);
	}
}
