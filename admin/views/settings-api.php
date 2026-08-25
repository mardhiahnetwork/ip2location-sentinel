<?php
/**
 * Admin View: API Configuration & General Settings (Native WordPress Tabbed Layout)
 *
 * @package LocaSentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$api_key        = $settings['api_key'] ?? '';
$api_timeout    = isset( $settings['api_timeout'] ) ? (int) $settings['api_timeout'] : 4;
$cache_ttl      = isset( $settings['cache_ttl'] ) ? (int) $settings['cache_ttl'] : 86400;
$fail_mode      = $settings['api_fail_mode'] ?? 'open';
$retention_days = isset( $settings['log_retention_days'] ) ? (int) $settings['log_retention_days'] : 30;
$del_on_uninst  = ! empty( $settings['delete_data_on_uninstall'] );
?>

<div class="wrap ip2loc-wrap">
	<div class="ip2loc-header-wrap">
		<h1><?php esc_html_e( 'API & Settings', 'locasentinel' ); ?></h1>
		<div class="ip2loc-autosave-badge" id="ip2loc_autosave_badge" style="display:none;">
			<span class="dashicons dashicons-saved"></span>
			<span class="ip2loc-badge-text"><?php esc_html_e( 'All changes saved', 'locasentinel' ); ?></span>
		</div>
	</div>
	<hr class="wp-header-end">
	<?php \IP2Location\Sentinel\Admin::render_plugin_header_notices(); ?>

	<!-- Native WordPress Tab Navigation -->
	<nav class="nav-tab-wrapper ip2loc-tabs wp-clearfix">
		<a href="#tab-api-key" class="nav-tab nav-tab-active" data-tab="tab-api-key">
			<?php esc_html_e( 'API Credentials', 'locasentinel' ); ?>
		</a>
		<a href="#tab-api-performance" class="nav-tab" data-tab="tab-api-performance">
			<?php esc_html_e( 'Performance & TTL', 'locasentinel' ); ?>
		</a>
		<a href="#tab-data-retention" class="nav-tab" data-tab="tab-data-retention">
			<?php esc_html_e( 'Data Retention & Cleanup', 'locasentinel' ); ?>
		</a>
	</nav>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="ip2loc_api_form" autocomplete="off">
		<!-- Prevent Chrome / browser password manager heuristics from auto-filling credentials -->
		<div style="display:none; opacity:0; position:absolute; left:-9999px;" aria-hidden="true">
			<input type="text" name="fake_username_remembered" tabindex="-1" autocomplete="username" />
			<input type="password" name="fake_password_remembered" tabindex="-1" autocomplete="current-password" />
		</div>
		<input type="hidden" name="action" value="ip2loc_save_settings" />
		<input type="hidden" name="ip2loc_tab" value="api_settings" />
		<?php wp_nonce_field( 'ip2loc_save_settings_action', 'ip2loc_nonce' ); ?>

		<!-- TAB 1: API Configuration -->
		<div id="tab-api-key" class="ip2loc-tab-pane ip2loc-tab-active">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'IP2Location.io Web Service Credentials', 'locasentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><label for="ip2loc_api_key"><?php esc_html_e( 'API Key', 'locasentinel' ); ?> *</label></th>
							<td>
								<div class="ip2loc-inline-test">
									<input type="password" name="ip2loc[api_key]" id="ip2loc_api_key" class="regular-text code" value="<?php echo esc_attr( $api_key ); ?>" placeholder="<?php esc_attr_e( 'Paste your IP2Location.io API key...', 'locasentinel' ); ?>" data-saved-key="<?php echo esc_attr( $api_key ); ?>" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-form-type="other" data-1p-ignore="true" readonly onfocus="this.removeAttribute('readonly');" />
									<button type="button" id="ip2loc_toggle_key_vis" class="button button-secondary">
										<span id="ip2loc_toggle_key_label"><?php esc_html_e( 'Show', 'locasentinel' ); ?></span>
									</button>
									<button type="button" id="ip2loc_btn_test_key" class="button button-primary">
										<?php esc_html_e( 'Test Connection', 'locasentinel' ); ?>
									</button>
								</div>
								<p class="description">
									<?php
									printf(
										/* translators: %s: signup link */
										esc_html__( 'Get a free API key at %s (50,000 free queries/month). Required to enable geo filtering and impossible travel detection.', 'locasentinel' ),
										'<a href="https://www.ip2location.io" target="_blank" rel="noopener noreferrer">ip2location.io</a>'
									);
									?>
								</p>
								<div id="ip2loc_key_test_result" style="margin-top: 10px;"></div>
							</td>
						</tr>
					</table>
				</div>
			</div>

			<!-- IP2Location Error Code Reference -->
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'IP2Location.io Error Code Mapping', 'locasentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<div class="ip2loc-table-responsive">
						<table class="widefat striped">
							<thead>
								<tr>
									<th style="width: 120px;"><?php esc_html_e( 'Code', 'locasentinel' ); ?></th>
									<th><?php esc_html_e( 'API Message', 'locasentinel' ); ?></th>
									<th><?php esc_html_e( 'Handler', 'locasentinel' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<tr>
									<td><code>10000</code></td>
									<td>Invalid API key or insufficient query.</td>
									<td><?php esc_html_e( 'Displays admin notice to update key.', 'locasentinel' ); ?></td>
								</tr>
								<tr>
									<td><code>10001</code></td>
									<td>Invalid IP address.</td>
									<td><?php esc_html_e( 'Validates IP syntax locally.', 'locasentinel' ); ?></td>
								</tr>
								<tr>
									<td><code>10002</code></td>
									<td>Internal server error.</td>
									<td><?php esc_html_e( 'Applies failover mode.', 'locasentinel' ); ?></td>
								</tr>
								<tr>
									<td><code>10003</code></td>
									<td>Invalid language code.</td>
									<td><?php esc_html_e( 'Requests standard output.', 'locasentinel' ); ?></td>
								</tr>
								<tr>
									<td><code>10004</code></td>
									<td>Translation is not available with your plan.</td>
									<td><?php esc_html_e( 'Omits translation param on free plans.', 'locasentinel' ); ?></td>
								</tr>
							</tbody>
						</table>
					</div>
				</div>
			</div>
		</div>

		<!-- TAB 2: Performance & Caching -->
		<div id="tab-api-performance" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'API Timeout & Transient Caching', 'locasentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><label for="ip2loc_api_timeout"><?php esc_html_e( 'Timeout (seconds)', 'locasentinel' ); ?></label></th>
							<td>
								<input type="number" name="ip2loc[api_timeout]" id="ip2loc_api_timeout" class="small-text" value="<?php echo esc_attr( $api_timeout ); ?>" min="2" max="15" />
								<p class="description"><?php esc_html_e( 'Maximum time in seconds to wait for an API response before applying failover.', 'locasentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="ip2loc_cache_ttl"><?php esc_html_e( 'Cache TTL (seconds)', 'locasentinel' ); ?></label></th>
							<td>
								<input type="number" name="ip2loc[cache_ttl]" id="ip2loc_cache_ttl" class="regular-text" value="<?php echo esc_attr( $cache_ttl ); ?>" min="60" step="1" />
								<p class="description"><?php esc_html_e( 'Duration in seconds to cache IP lookups in transients (e.g. 3600 = 1 hour, 86400 = 24 hours, 604800 = 7 days). Default: 86400.', 'locasentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Failover Behavior', 'locasentinel' ); ?></th>
							<td>
								<fieldset>
									<label style="margin-right: 20px;">
										<input type="radio" name="ip2loc[api_fail_mode]" value="open" <?php checked( $fail_mode, 'open' ); ?> />
										<strong><?php esc_html_e( 'Fail-Open (Allow traffic on API error/timeout)', 'locasentinel' ); ?></strong>
									</label>
									<br />
									<label style="margin-top: 6px; display:inline-block;">
										<input type="radio" name="ip2loc[api_fail_mode]" value="safe" <?php checked( $fail_mode, 'safe' ); ?> />
										<strong><?php esc_html_e( 'Fail-Safe (Block traffic on API error/timeout)', 'locasentinel' ); ?></strong>
									</label>
								</fieldset>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>

		<!-- TAB 3: Data Retention & Cleanup -->
		<div id="tab-data-retention" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Data Retention & Database Cleanup', 'locasentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><label for="ip2loc_log_retention_days"><?php esc_html_e( 'Log Retention (Days)', 'locasentinel' ); ?></label></th>
							<td>
								<input type="number" name="ip2loc[log_retention_days]" id="ip2loc_log_retention_days" class="small-text" value="<?php echo esc_attr( $retention_days ); ?>" min="1" max="365" />
								<p class="description"><?php esc_html_e( 'Daily cron automatically purges audit logs older than this threshold.', 'locasentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Delete on Uninstall', 'locasentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[delete_data_on_uninstall]" value="1" <?php checked( $del_on_uninst ); ?> />
									<span class="ip2loc-toggle-text"><strong><?php esc_html_e( 'Delete database tables and all options upon plugin uninstall', 'locasentinel' ); ?></strong></span>
								</label>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>
	</form>
</div>
