<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1.0" />
	<meta name="robots" content="noindex, nofollow, noarchive" />
	<title><?php esc_html_e( 'Security Verification Required', 'locasentinel' ); ?></title>
	<style type="text/css">
		html {
			background: #0f172a;
			color: #f8fafc;
		}
		body {
			background: #1e293b;
			border: 1px solid #334155;
			color: #cbd5e1;
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
			margin: 80px auto;
			padding: 28px 36px 32px;
			max-width: 520px;
			border-radius: 8px;
			box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px rgba(0, 0, 0, 0.3);
			line-height: 1.5;
		}
		.challenge-header {
			text-align: center;
			padding-bottom: 14px;
			border-bottom: 1px solid #334155;
			margin-bottom: 18px;
		}
		.challenge-shield {
			display: inline-flex;
			align-items: center;
			justify-content: center;
			width: 48px;
			height: 48px;
			background: rgba(14, 165, 233, 0.15);
			border: 1px solid rgba(14, 165, 233, 0.35);
			border-radius: 50%;
			color: #38bdf8;
			margin-bottom: 12px;
		}
		h1 {
			color: #f8fafc;
			font-size: 19px;
			font-weight: 600;
			margin: 0;
		}
		.challenge-box {
			background: #0f172a;
			border: 1px solid #334155;
			border-radius: 6px;
			padding: 20px;
			margin: 20px 0 16px 0;
			text-align: center;
		}
		button.button-verify {
			background: #0284c7;
			border: 1px solid #0369a1;
			color: #fff;
			font-size: 14px;
			font-weight: 600;
			padding: 10px 24px;
			border-radius: 4px;
			cursor: pointer;
			width: 100%;
			margin-top: 14px;
			transition: background 0.15s ease;
		}
		button.button-verify:hover {
			background: #0369a1;
		}
		.challenge-footer {
			margin-top: 18px;
			text-align: center;
			font-size: 11px;
			color: #64748b;
		}
		.challenge-footer a {
			color: #94a3b8;
			text-decoration: none;
		}
		.challenge-footer a:hover {
			text-decoration: underline;
		}
		@media screen and (max-width: 640px) {
			body {
				margin: 20px 12px;
				padding: 20px 16px;
			}
		}
	</style>
</head>
<body>
	<div class="challenge-header">
		<div class="challenge-shield">
			<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
				<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
			</svg>
		</div>
		<h1><?php esc_html_e( 'Checking your browser before accessing', 'locasentinel' ); ?> <?php echo esc_html( get_bloginfo( 'name' ) ); ?></h1>
	</div>

	<div class="challenge-box">
		<?php if ( isset( $_GET['captcha_err'] ) ) : ?>
			<div style="background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.35); color: #fca5a5; padding: 10px 14px; border-radius: 6px; font-size: 13px; margin-bottom: 16px; text-align: center;">
				<?php esc_html_e( 'Verification failed or expired. Please solve the challenge and click Verify.', 'locasentinel' ); ?>
			</div>
		<?php endif; ?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="ip2loc_verify_captcha" />
			<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $request_uri ); ?>" />
			<?php wp_nonce_field( 'ip2loc_captcha_verify_nonce', 'nonce' ); ?>

			<?php echo \IP2Location\Sentinel\Captcha::render_widget( $active_provider ?? null, $client_ip ?? '' ); ?>

			<button type="submit" class="button-verify">
				<?php esc_html_e( 'Verify', 'locasentinel' ); ?>
			</button>
		</form>
	</div>

	<div class="challenge-footer">
		<?php esc_html_e( 'Protected by LocaSentinel Anti-Spam Shield', 'locasentinel' ); ?> &bull; <a href="https://www.ip2location.io" target="_blank" rel="noopener noreferrer">IP2Location.io</a>
	</div>
</body>
</html>
