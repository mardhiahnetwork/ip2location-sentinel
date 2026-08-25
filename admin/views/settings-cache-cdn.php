<?php
/**
 * Admin View: Cache & CDN Compatibility (Native WordPress Tabbed Layout)
 *
 * @package LocaSentinel
 */

use IP2Location\Sentinel\Admin;
use IP2Location\Sentinel\IpResolver;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$cdn_mode                  = $settings['cdn_mode'] ?? 'auto';
$enable_cache_vary         = ! empty( $settings['enable_cache_vary'] );
$strict_proxy_verification = ! isset( $settings['strict_proxy_verification'] ) || ! empty( $settings['strict_proxy_verification'] );
$trusted_proxies           = $settings['trusted_proxies'] ?? '';
$remote_addr               = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

$proxy_status_badge = '<span class="ip2loc-pill pill-info">' . esc_html__( 'Direct Origin Connection', 'ip2location-sentinel' ) . '</span>';
if ( IpResolver::is_cloudflare_proxy( $remote_addr ) ) {
	$proxy_status_badge = '<span class="ip2loc-pill pill-success">' . esc_html__( 'Verified Cloudflare Edge IP', 'ip2location-sentinel' ) . '</span>';
} elseif ( IpResolver::is_sucuri_proxy( $remote_addr ) ) {
	$proxy_status_badge = '<span class="ip2loc-pill pill-success">' . esc_html__( 'Verified Sucuri WAF Node', 'ip2location-sentinel' ) . '</span>';
} elseif ( IpResolver::is_local_proxy( $remote_addr ) ) {
	$proxy_status_badge = '<span class="ip2loc-pill pill-success">' . esc_html__( 'Verified Local/Private Reverse Proxy', 'ip2location-sentinel' ) . '</span>';
} elseif ( IpResolver::is_custom_trusted_proxy( $remote_addr ) ) {
	$proxy_status_badge = '<span class="ip2loc-pill pill-success">' . esc_html__( 'Verified Custom Trusted Proxy', 'ip2location-sentinel' ) . '</span>';
}
?>

<div class="wrap ip2loc-wrap">
	<div class="ip2loc-header-wrap">
		<h1><?php esc_html_e( 'Cache & CDN Settings', 'ip2location-sentinel' ); ?></h1>
		<div class="ip2loc-autosave-badge" id="ip2loc_autosave_badge" style="display:none;">
			<span class="dashicons dashicons-saved"></span>
			<span class="ip2loc-badge-text"><?php esc_html_e( 'All changes saved', 'ip2location-sentinel' ); ?></span>
		</div>
	</div>
	<hr class="wp-header-end">
	<?php Admin::render_plugin_header_notices(); ?>

	<!-- Parent Section Tabs -->
	<nav class="nav-tab-wrapper ip2loc-parent-nav wp-clearfix" style="margin-bottom: 12px;">
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=ip2loc-settings' ) ); ?>" class="nav-tab">
			<?php esc_html_e( 'API & General', 'ip2location-sentinel' ); ?>
		</a>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=ip2loc-cache-cdn' ) ); ?>" class="nav-tab nav-tab-active">
			<?php esc_html_e( 'Cache & CDN Diagnostics', 'ip2location-sentinel' ); ?>
		</a>
	</nav>

	<!-- Child Feature Tabs -->
	<nav class="nav-tab-wrapper ip2loc-tabs wp-clearfix" style="border-bottom: 1px solid #c3c4c7; background: #fff;">
		<a href="#tab-cdn-resolver" class="nav-tab nav-tab-active" data-tab="tab-cdn-resolver">
			<?php esc_html_e( 'IP Resolution & CDN', 'ip2location-sentinel' ); ?>
		</a>
		<a href="#tab-cache-engines" class="nav-tab" data-tab="tab-cache-engines">
			<?php esc_html_e( 'Cache Plugin Status', 'ip2location-sentinel' ); ?>
		</a>
		<a href="#tab-server-headers" class="nav-tab" data-tab="tab-server-headers">
			<?php esc_html_e( 'Server Headers Received', 'ip2location-sentinel' ); ?>
		</a>
	</nav>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="ip2loc_cache_form">
		<input type="hidden" name="action" value="ip2loc_save_settings" />
		<input type="hidden" name="ip2loc_tab" value="cache_cdn" />
		<?php wp_nonce_field( 'ip2loc_save_settings_action', 'ip2loc_nonce' ); ?>

		<!-- TAB 1: CDN & Reverse Proxy IP Detection -->
		<div id="tab-cdn-resolver" class="ip2loc-tab-pane ip2loc-tab-active">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Reverse Proxy & Client IP Resolution', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><label for="ip2loc_cdn_mode"><?php esc_html_e( 'Detection Mode', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<select name="ip2loc[cdn_mode]" id="ip2loc_cdn_mode" style="min-width: 320px;">
									<option value="auto" <?php selected( $cdn_mode, 'auto' ); ?>><?php esc_html_e( 'Auto-Detect (Cloudflare, Sucuri, Fastly, X-Forwarded-For)', 'ip2location-sentinel' ); ?></option>
									<option value="cloudflare" <?php selected( $cdn_mode, 'cloudflare' ); ?>><?php esc_html_e( 'Cloudflare (HTTP_CF_CONNECTING_IP)', 'ip2location-sentinel' ); ?></option>
									<option value="sucuri" <?php selected( $cdn_mode, 'sucuri' ); ?>><?php esc_html_e( 'Sucuri (HTTP_X_SUCURI_CLIENTIP)', 'ip2location-sentinel' ); ?></option>
									<option value="x_forwarded_for" <?php selected( $cdn_mode, 'x_forwarded_for' ); ?>><?php esc_html_e( 'X-Forwarded-For', 'ip2location-sentinel' ); ?></option>
									<option value="remote_addr" <?php selected( $cdn_mode, 'remote_addr' ); ?>><?php esc_html_e( 'Direct Connection (REMOTE_ADDR)', 'ip2location-sentinel' ); ?></option>
								</select>
								<p class="description"><?php esc_html_e( 'Specifies which server header is used to resolve real visitor IPs behind CDNs.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Origin Verification', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[strict_proxy_verification]" value="1" <?php checked( $strict_proxy_verification ); ?> />
									<span class="ip2loc-toggle-text"><strong><?php esc_html_e( 'Enforce Strict Reverse Proxy Origin Verification (Recommended)', 'ip2location-sentinel' ); ?></strong></span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Verifies that incoming connection originates from official Cloudflare / Sucuri CIDR ranges or local reverse proxies before accepting CF-Connecting-IP / X-Forwarded-For. Protects origin against direct IP spoofing attacks if an attacker connects directly to your server IP.', 'ip2location-sentinel' ); ?>
								</p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="ip2loc_trusted_proxies"><?php esc_html_e( 'Custom Trusted Proxies', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<textarea name="ip2loc[trusted_proxies]" id="ip2loc_trusted_proxies" rows="3" class="large-text code" placeholder="10.0.0.0/8&#10;192.168.1.50"><?php echo esc_textarea( $trusted_proxies ); ?></textarea>
								<p class="description"><?php esc_html_e( 'Optional additional proxy IP addresses, wildcards, or CIDR subnet masks (one per line) trusted to send forwarding headers.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Current Connection Status', 'ip2location-sentinel' ); ?></th>
							<td>
								<p>
									<strong><?php esc_html_e( 'Client IP Resolved:', 'ip2location-sentinel' ); ?></strong> <code><?php echo esc_html( $detected_ip ); ?></code>
								</p>
								<p>
									<strong><?php esc_html_e( 'Raw REMOTE_ADDR:', 'ip2location-sentinel' ); ?></strong> <code><?php echo esc_html( $remote_addr ?: '127.0.0.1' ); ?></code> &nbsp; <?php echo $proxy_status_badge; ?>
								</p>
							</td>
						</tr>
					</table>

					<p class="submit" style="margin-top: 20px;">
						<button type="submit" class="button button-primary button-large"><?php esc_html_e( 'Save Cache & CDN Settings', 'ip2location-sentinel' ); ?></button>
					</p>
				</div>
			</div>
		</div>

		<!-- TAB 2: Active Caching Layers Grid -->
		<div id="tab-cache-engines" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Cache Plugin Detection & Invalidation Status', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<div class="ip2loc-grid ip2loc-cache-grid">
						<?php foreach ( $cache_engines as $key => $engine ) : ?>
							<div class="ip2loc-cache-item <?php echo $engine['active'] ? 'cache-active' : 'cache-inactive'; ?>">
								<div class="cache-header">
									<span class="cache-title"><?php echo esc_html( $engine['name'] ); ?></span>
									<span class="cache-badge <?php echo $engine['active'] ? 'badge-on' : 'badge-off'; ?>">
										<?php echo $engine['active'] ? esc_html__( 'Active', 'ip2location-sentinel' ) : esc_html__( 'Supported', 'ip2location-sentinel' ); ?>
									</span>
								</div>
								<p class="cache-type"><?php echo esc_html( $engine['type'] ); ?></p>
								<p class="cache-notes"><?php echo esc_html( $engine['notes'] ); ?></p>
							</div>
						<?php endforeach; ?>
					</div>

					<table class="form-table" style="margin-top: 20px;">
						<tr>
							<th scope="row"><?php esc_html_e( 'Cache Vary Headers', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[enable_cache_vary]" value="1" <?php checked( $enable_cache_vary ); ?> />
									<span class="ip2loc-toggle-text"><strong><?php esc_html_e( 'Send HTTP Vary headers (Vary: Accept-Encoding, X-Forwarded-For, CF-Connecting-IP)', 'ip2location-sentinel' ); ?></strong></span>
								</label>
								<p class="description"><?php esc_html_e( 'Instructs static caches to store separate cached variants depending on client proxy headers.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
					</table>

					<p class="submit" style="margin-top: 20px;">
						<button type="submit" class="button button-primary button-large"><?php esc_html_e( 'Save Cache & CDN Settings', 'ip2location-sentinel' ); ?></button>
					</p>
				</div>
			</div>
		</div>

		<!-- TAB 3: Server Header Diagnostics -->
		<div id="tab-server-headers" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Live Inbound Server Headers', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<div class="ip2loc-table-responsive">
						<table class="widefat striped">
							<thead>
								<tr>
									<th><?php esc_html_e( 'Header / Probe', 'ip2location-sentinel' ); ?></th>
									<th><?php esc_html_e( 'Value / Verification Verdict', 'ip2location-sentinel' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $headers_diag as $h_key => $h_val ) : ?>
									<tr>
										<td><code><?php echo esc_html( $h_key ); ?></code></td>
										<td><code><?php echo esc_html( $h_val ); ?></code></td>
									</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
					</div>
					<p class="description" style="margin-top: 10px;">
						<?php esc_html_e( 'Displays raw inbound connection headers and trusted proxy verification status. If an attacker connects directly to origin server IP and injects spoofed CDN headers, strict origin verification automatically rejects the forged headers and enforces security on the true REMOTE_ADDR.', 'ip2location-sentinel' ); ?>
					</p>
				</div>
			</div>
		</div>
	</form>
</div>
