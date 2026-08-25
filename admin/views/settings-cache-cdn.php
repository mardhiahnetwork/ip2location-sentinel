<?php
/**
 * Admin View: Cache & CDN Compatibility (Native WordPress Tabbed Layout)
 *
 * @package LocaSentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$cdn_mode          = $settings['cdn_mode'] ?? 'auto';
$enable_cache_vary = ! empty( $settings['enable_cache_vary'] );
?>

<div class="wrap ip2loc-wrap">
	<div class="ip2loc-header-wrap">
		<h1><?php esc_html_e( 'Cache & CDN Settings', 'locasentinel' ); ?></h1>
		<div class="ip2loc-autosave-badge" id="ip2loc_autosave_badge" style="display:none;">
			<span class="dashicons dashicons-saved"></span>
			<span class="ip2loc-badge-text"><?php esc_html_e( 'All changes saved', 'locasentinel' ); ?></span>
		</div>
	</div>
	<hr class="wp-header-end">
	<?php \IP2Location\Sentinel\Admin::render_plugin_header_notices(); ?>

	<!-- Native WordPress Tab Navigation -->
	<nav class="nav-tab-wrapper ip2loc-tabs wp-clearfix">
		<a href="#tab-cdn-resolver" class="nav-tab nav-tab-active" data-tab="tab-cdn-resolver">
			<?php esc_html_e( 'IP Resolution & CDN', 'locasentinel' ); ?>
		</a>
		<a href="#tab-cache-engines" class="nav-tab" data-tab="tab-cache-engines">
			<?php esc_html_e( 'Cache Plugin Status', 'locasentinel' ); ?>
		</a>
		<a href="#tab-server-headers" class="nav-tab" data-tab="tab-server-headers">
			<?php esc_html_e( 'Server Headers Received', 'locasentinel' ); ?>
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
					<h2><?php esc_html_e( 'Reverse Proxy & Client IP Resolution', 'locasentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><label for="ip2loc_cdn_mode"><?php esc_html_e( 'Detection Mode', 'locasentinel' ); ?></label></th>
							<td>
								<select name="ip2loc[cdn_mode]" id="ip2loc_cdn_mode" style="min-width: 320px;">
									<option value="auto" <?php selected( $cdn_mode, 'auto' ); ?>><?php esc_html_e( 'Auto-Detect (Cloudflare, Sucuri, Fastly, X-Forwarded-For)', 'locasentinel' ); ?></option>
									<option value="cloudflare" <?php selected( $cdn_mode, 'cloudflare' ); ?>><?php esc_html_e( 'Cloudflare (HTTP_CF_CONNECTING_IP)', 'locasentinel' ); ?></option>
									<option value="sucuri" <?php selected( $cdn_mode, 'sucuri' ); ?>><?php esc_html_e( 'Sucuri (HTTP_X_SUCURI_CLIENTIP)', 'locasentinel' ); ?></option>
									<option value="x_forwarded_for" <?php selected( $cdn_mode, 'x_forwarded_for' ); ?>><?php esc_html_e( 'X-Forwarded-For', 'locasentinel' ); ?></option>
									<option value="remote_addr" <?php selected( $cdn_mode, 'remote_addr' ); ?>><?php esc_html_e( 'Direct Connection (REMOTE_ADDR)', 'locasentinel' ); ?></option>
								</select>
								<p class="description"><?php esc_html_e( 'Specifies which server header is used to resolve real visitor IPs behind CDNs.', 'locasentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Detected IP', 'locasentinel' ); ?></th>
							<td>
								<code><?php echo esc_html( $detected_ip ); ?></code>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>

		<!-- TAB 2: Active Caching Layers Grid -->
		<div id="tab-cache-engines" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Cache Plugin Detection & Invalidation Status', 'locasentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<div class="ip2loc-grid ip2loc-cache-grid">
						<?php foreach ( $cache_engines as $key => $engine ) : ?>
							<div class="ip2loc-cache-item <?php echo $engine['active'] ? 'cache-active' : 'cache-inactive'; ?>">
								<div class="cache-header">
									<span class="cache-title"><?php echo esc_html( $engine['name'] ); ?></span>
									<span class="cache-badge <?php echo $engine['active'] ? 'badge-on' : 'badge-off'; ?>">
										<?php echo $engine['active'] ? esc_html__( 'Active', 'locasentinel' ) : esc_html__( 'Supported', 'locasentinel' ); ?>
									</span>
								</div>
								<p class="cache-type"><?php echo esc_html( $engine['type'] ); ?></p>
								<p class="cache-notes"><?php echo esc_html( $engine['notes'] ); ?></p>
							</div>
						<?php endforeach; ?>
					</div>

					<table class="form-table" style="margin-top: 20px;">
						<tr>
							<th scope="row"><?php esc_html_e( 'Cache Vary Headers', 'locasentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[enable_cache_vary]" value="1" <?php checked( $enable_cache_vary ); ?> />
									<span class="ip2loc-toggle-text"><strong><?php esc_html_e( 'Send HTTP Vary headers (Vary: Accept-Encoding, X-Forwarded-For, CF-Connecting-IP)', 'locasentinel' ); ?></strong></span>
								</label>
								<p class="description"><?php esc_html_e( 'Instructs static caches to store separate cached variants depending on client proxy headers.', 'locasentinel' ); ?></p>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>

		<!-- TAB 3: Server Header Diagnostics -->
		<div id="tab-server-headers" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Live Inbound Server Headers', 'locasentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<div class="ip2loc-table-responsive">
						<table class="widefat striped">
							<thead>
								<tr>
									<th><?php esc_html_e( 'Header', 'locasentinel' ); ?></th>
									<th><?php esc_html_e( 'Value', 'locasentinel' ); ?></th>
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
						<?php esc_html_e( 'Displays raw inbound connection headers reported by your web server. On local development (Laragon/localhost), REMOTE_ADDR is 127.0.0.1. In live production behind Cloudflare, Sucuri, or a reverse proxy, CDN headers like HTTP_CF_CONNECTING_IP will appear here.', 'locasentinel' ); ?>
					</p>
				</div>
			</div>
		</div>
	</form>
</div>
