<?php
/**
 * Admin View: Dashboard
 *
 * @package IP2Location\Sentinel
 */

use IP2Location\Sentinel\Admin;
use IP2Location\Sentinel\Countries;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$api_key = isset( $settings['api_key'] ) ? trim( $settings['api_key'] ) : '';
$is_api_ready = ! empty( $api_key );
?>

<div class="wrap ip2loc-wrap">
	<h1><?php esc_html_e( 'LocaSentinel Dashboard', 'ip2location-sentinel' ); ?></h1>
	<hr class="wp-header-end">
	<?php Admin::render_plugin_header_notices(); ?>

	<!-- Action Toolbar below title -->
	<div class="ip2loc-action-bar">
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=ip2loc-audit-logs' ) ); ?>" class="button button-secondary">
			<?php esc_html_e( 'View Audit Logs', 'ip2location-sentinel' ); ?>
		</a>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=ip2loc-rules' ) ); ?>" class="button button-primary">
			<?php esc_html_e( 'Manage Rules', 'ip2location-sentinel' ); ?>
		</a>
	</div>

	<!-- Stats Grid (KPI Cards Keep Icons) -->
	<div class="ip2loc-grid ip2loc-stats-grid">
		<div class="ip2loc-stat-card">
			<div class="ip2loc-stat-icon stat-events"><span class="dashicons dashicons-chart-line"></span></div>
			<div class="ip2loc-stat-data">
				<span class="ip2loc-stat-number"><?php echo number_format_i18n( $stats['total_events'] ); ?></span>
				<span class="ip2loc-stat-label"><?php esc_html_e( 'Requests Checked (7d)', 'ip2location-sentinel' ); ?></span>
			</div>
		</div>

		<div class="ip2loc-stat-card">
			<div class="ip2loc-stat-icon stat-blocked"><span class="dashicons dashicons-dismiss"></span></div>
			<div class="ip2loc-stat-data">
				<span class="ip2loc-stat-number"><?php echo number_format_i18n( $stats['total_blocked'] ); ?></span>
				<span class="ip2loc-stat-label"><?php esc_html_e( 'Blocked Requests (7d)', 'ip2location-sentinel' ); ?></span>
			</div>
		</div>

		<div class="ip2loc-stat-card">
			<div class="ip2loc-stat-icon stat-spam"><span class="dashicons dashicons-admin-comments"></span></div>
			<div class="ip2loc-stat-data">
				<span class="ip2loc-stat-number"><?php echo number_format_i18n( $stats['total_spam_blocked'] ); ?></span>
				<span class="ip2loc-stat-label"><?php esc_html_e( 'Spam Comments Blocked', 'ip2location-sentinel' ); ?></span>
			</div>
		</div>

		<div class="ip2loc-stat-card">
			<div class="ip2loc-stat-icon stat-travel"><span class="dashicons dashicons-airplane"></span></div>
			<div class="ip2loc-stat-data">
				<span class="ip2loc-stat-number"><?php echo number_format_i18n( $stats['total_travel_caught'] ); ?></span>
				<span class="ip2loc-stat-label"><?php esc_html_e( 'Impossible Travel Flags', 'ip2location-sentinel' ); ?></span>
			</div>
		</div>
	</div>

	<!-- Main Content Row -->
	<div class="ip2loc-grid ip2loc-two-col">
		<!-- Left: Traffic & Threat Graph -->
		<div class="ip2loc-card ip2loc-chart-card">
			<div class="ip2loc-card-header">
				<h2><?php esc_html_e( 'Activity (Last 7 Days)', 'ip2location-sentinel' ); ?></h2>
			</div>
			<div class="ip2loc-card-body">
				<canvas id="ip2locTrendChart" height="220"></canvas>
			</div>
		</div>

		<!-- Right: Quick Diagnostic IP Lookup -->
		<div class="ip2loc-card">
			<div class="ip2loc-card-header">
				<h2><?php esc_html_e( 'IP Lookup Tool', 'ip2location-sentinel' ); ?></h2>
			</div>
			<div class="ip2loc-card-body">
				<p class="description" style="margin-bottom: 12px;">
					<?php esc_html_e( 'Check the geolocation data and rule verdict for any IP address.', 'ip2location-sentinel' ); ?>
				</p>
				<div class="ip2loc-lookup-form">
					<input type="text" id="ip2loc_test_ip_input" class="regular-text" placeholder="<?php esc_attr_e( 'e.g. 8.8.8.8', 'ip2location-sentinel' ); ?>" value="" />
					<button type="button" id="ip2loc_btn_run_lookup" class="button button-primary">
						<?php esc_html_e( 'Inspect IP', 'ip2location-sentinel' ); ?>
					</button>
				</div>

				<div id="ip2loc_lookup_result" class="ip2loc-lookup-box" style="display:none; margin-top: 15px;"></div>
			</div>
		</div>
	</div>

	<!-- Second Row: Active Modules & Top Blocked Countries -->
	<div class="ip2loc-grid ip2loc-two-col">
		<!-- Module Status -->
		<div class="ip2loc-card">
			<div class="ip2loc-card-header">
				<h2><?php esc_html_e( 'Protection Status', 'ip2location-sentinel' ); ?></h2>
			</div>
			<div class="ip2loc-card-body">
				<ul class="ip2loc-module-list">
					<li>
						<span class="module-status <?php echo ! empty( $settings['protect_comments'] ) ? 'status-active' : 'status-inactive'; ?>"></span>
						<span class="module-title"><?php esc_html_e( 'Comments Anti-Spam', 'ip2location-sentinel' ); ?></span>
						<span class="module-badge"><?php echo ! empty( $settings['protect_comments'] ) ? esc_html__( 'Active', 'ip2location-sentinel' ) : esc_html__( 'Disabled', 'ip2location-sentinel' ); ?></span>
					</li>
					<li>
						<span class="module-status <?php echo ! empty( $settings['protect_xmlrpc'] ) ? 'status-active' : 'status-inactive'; ?>"></span>
						<span class="module-title"><?php esc_html_e( 'XML-RPC Protection', 'ip2location-sentinel' ); ?></span>
						<span class="module-badge"><?php echo ! empty( $settings['protect_xmlrpc'] ) ? esc_html__( 'Active', 'ip2location-sentinel' ) : esc_html__( 'Disabled', 'ip2location-sentinel' ); ?></span>
					</li>
					<li>
						<span class="module-status <?php echo ! empty( $settings['protect_login'] ) ? 'status-active' : 'status-inactive'; ?>"></span>
						<span class="module-title"><?php esc_html_e( 'Login Protection', 'ip2location-sentinel' ); ?></span>
						<span class="module-badge"><?php echo ! empty( $settings['protect_login'] ) ? esc_html__( 'Active', 'ip2location-sentinel' ) : esc_html__( 'Disabled', 'ip2location-sentinel' ); ?></span>
					</li>
					<li>
						<span class="module-status <?php echo ! empty( $settings['enable_impossible_travel'] ) ? 'status-active' : 'status-inactive'; ?>"></span>
						<span class="module-title"><?php esc_html_e( 'Impossible Travel Detection', 'ip2location-sentinel' ); ?></span>
						<span class="module-badge"><?php echo ! empty( $settings['enable_impossible_travel'] ) ? esc_html__( 'Active', 'ip2location-sentinel' ) : esc_html__( 'Disabled', 'ip2location-sentinel' ); ?></span>
					</li>
					<li>
						<span class="module-status <?php echo ! empty( $settings['block_proxies'] ) ? 'status-active' : 'status-inactive'; ?>"></span>
						<span class="module-title"><?php esc_html_e( 'Proxy & VPN Filter', 'ip2location-sentinel' ); ?></span>
						<span class="module-badge"><?php echo ! empty( $settings['block_proxies'] ) ? esc_html__( 'Active', 'ip2location-sentinel' ) : esc_html__( 'Disabled', 'ip2location-sentinel' ); ?></span>
					</li>
				</ul>
			</div>
		</div>

		<!-- Top Blocked Countries -->
		<div class="ip2loc-card">
			<div class="ip2loc-card-header">
				<h2><?php esc_html_e( 'Top Blocked Countries', 'ip2location-sentinel' ); ?></h2>
			</div>
			<div class="ip2loc-card-body">
				<?php if ( ! empty( $stats['top_countries'] ) ) : ?>
					<table class="widefat striped">
						<thead>
							<tr>
								<th><?php esc_html_e( 'Country', 'ip2location-sentinel' ); ?></th>
								<th><?php esc_html_e( 'Code', 'ip2location-sentinel' ); ?></th>
								<th style="text-align:right;"><?php esc_html_e( 'Blocked', 'ip2location-sentinel' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $stats['top_countries'] as $row ) : ?>
								<tr>
									<td>
										<?php echo Countries::get_flag_html( $row['country_code'] ); ?>
										<strong><?php echo esc_html( $row['country_name'] ?: Countries::get_country_name( $row['country_code'] ) ); ?></strong>
									</td>
									<td><code><?php echo esc_html( $row['country_code'] ); ?></code></td>
									<td style="text-align:right;">
										<span class="ip2loc-pill pill-danger"><?php echo number_format_i18n( $row['count'] ); ?></span>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php else : ?>
					<div class="ip2loc-empty-state">
						<p><?php esc_html_e( 'No blocked requests recorded in the last 7 days.', 'ip2location-sentinel' ); ?></p>
					</div>
				<?php endif; ?>
			</div>
		</div>
	</div>
</div>

<script>
window.ip2locDailyTrends = <?php echo wp_json_encode( $stats['daily_trends'] ); ?>;
</script>
