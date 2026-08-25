use IP2Location\Sentinel\IpResolver;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$custom_title = isset( $custom_title ) && ! empty( $custom_title ) ? $custom_title : ( isset( $block_title ) && ! empty( $block_title ) ? $block_title : __( 'Access Restricted (403)', 'ip2location-sentinel' ) );
$custom_body  = isset( $custom_body ) && ! empty( $custom_body ) ? $custom_body : ( isset( $block_message ) && ! empty( $block_message ) ? $block_message : __( 'Access from your IP address or geographical region is restricted by site security policy.', 'ip2location-sentinel' ) );
$client_ip    = isset( $client_ip ) && ! empty( $client_ip ) ? $client_ip : IpResolver::mask_ip_for_privacy( IpResolver::get_client_ip() );
$incident_id  = isset( $incident_id ) && ! empty( $incident_id ) ? $incident_id : 'INC-' . strtoupper( substr( md5( $client_ip . time() ), 0, 10 ) );
?>
<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1.0" />
	<meta name="robots" content="noindex, nofollow, noarchive" />
	<title><?php echo esc_html( $custom_title ); ?></title>
	<style type="text/css">
		html {
			background: #f0f0f1;
		}
		body {
			background: #fff;
			border: 1px solid #c3c4c7;
			color: #3c434a;
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
			margin: 50px auto;
			padding: 24px 32px 32px;
			max-width: 680px;
			border-radius: 4px;
			box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
			line-height: 1.5;
		}
		h1 {
			border-bottom: 1px solid #dcdcde;
			color: #1d2327;
			font-size: 22px;
			font-weight: 600;
			margin: 0 0 16px 0;
			padding: 0 0 12px 0;
		}
		p {
			font-size: 14px;
			line-height: 1.6;
			margin: 14px 0;
		}
		.wp-error-meta {
			background: #f6f7f7;
			border: 1px solid #dcdcde;
			border-radius: 3px;
			padding: 12px 16px;
			margin: 20px 0;
			font-size: 13px;
		}
		.wp-error-row {
			display: flex;
			justify-content: space-between;
			padding: 5px 0;
			border-bottom: 1px solid #f0f0f1;
		}
		.wp-error-row:last-child {
			border-bottom: none;
		}
		.wp-error-label {
			color: #646970;
			font-weight: 600;
		}
		.wp-error-value {
			color: #2c3338;
			font-family: Consolas, Monaco, monospace;
			font-size: 12px;
		}
		.wp-error-actions {
			margin-top: 24px;
			display: flex;
			align-items: center;
			justify-content: space-between;
		}
		a.button {
			background: #2271b1;
			border: 1px solid #2271b1;
			color: #fff;
			display: inline-block;
			text-decoration: none;
			font-size: 13px;
			line-height: 2.15384615;
			min-height: 30px;
			margin: 0;
			padding: 0 14px;
			cursor: pointer;
			border-radius: 3px;
			white-space: nowrap;
			box-sizing: border-box;
			font-weight: 500;
		}
		a.button:hover,
		a.button:focus {
			background: #135e96;
			border-color: #135e96;
			color: #fff;
		}
		.wp-error-footer {
			font-size: 11px;
			color: #8c8f94;
			margin: 0;
		}
		.wp-error-footer a {
			color: #646970;
			text-decoration: none;
		}
		.wp-error-footer a:hover {
			text-decoration: underline;
		}
		@media screen and (max-width: 782px) {
			body {
				margin: 20px 12px;
				padding: 20px 18px;
			}
			.wp-error-actions {
				flex-direction: column-reverse;
				align-items: flex-start;
				gap: 16px;
			}
		}
	</style>
</head>
<body id="error-page">
	<h1><?php echo esc_html( $custom_title ); ?></h1>

	<p><?php echo esc_html( $custom_body ); ?></p>

	<div class="wp-error-meta">
		<div class="wp-error-row">
			<span class="wp-error-label"><?php esc_html_e( 'Incident ID', 'ip2location-sentinel' ); ?></span>
			<span class="wp-error-value"><?php echo esc_html( $incident_id ); ?></span>
		</div>
		<div class="wp-error-row">
			<span class="wp-error-label"><?php esc_html_e( 'Client IP', 'ip2location-sentinel' ); ?></span>
			<span class="wp-error-value"><?php echo esc_html( $client_ip ); ?></span>
		</div>
	</div>

	<div class="wp-error-actions">
		<a href="<?php echo esc_url( home_url( '/' ) ); ?>" class="button"><?php esc_html_e( 'Return to Homepage', 'ip2location-sentinel' ); ?></a>
		<p class="wp-error-footer">
			<?php esc_html_e( 'Protected by LocaSentinel', 'ip2location-sentinel' ); ?> &bull; <a href="https://www.ip2location.io" target="_blank" rel="noopener noreferrer">IP2Location.io</a>
		</p>
	</div>
</body>
</html>
