<?php
/**
 * Admin View: Audit Logs
 *
 * @package IP2Location\Sentinel
 */

use IP2Location\Sentinel\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$items        = $log_data['items'];
$total_count  = $log_data['total_count'];
$total_pages  = $log_data['total_pages'];
$current_page = $log_data['page'];
$per_page     = isset( $_GET['per_page'] ) ? max( 1, (int) $_GET['per_page'] ) : 10;
?>

<div class="wrap ip2loc-wrap">
	<h1><?php esc_html_e( 'Audit Logs', 'ip2location-sentinel' ); ?></h1>
	<hr class="wp-header-end">
	<?php Admin::render_plugin_header_notices(); ?>

	<div class="ip2loc-action-bar">
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;">
			<input type="hidden" name="action" value="ip2loc_export_csv" />
			<?php wp_nonce_field( 'ip2loc_export_csv_nonce', 'nonce' ); ?>
			<button type="submit" class="button button-secondary">
				<?php esc_html_e( 'Export CSV', 'ip2location-sentinel' ); ?>
			</button>
		</form>
		<button type="button" id="ip2loc_btn_clear_logs" class="button button-secondary" style="color: #d63638; border-color: #d63638;">
			<?php esc_html_e( 'Clear Logs', 'ip2location-sentinel' ); ?>
		</button>
	</div>

	<!-- Filter Bar -->
	<div class="ip2loc-card ip2loc-filter-card">
		<form id="ip2loc_audit_filter_form" onsubmit="return false;" class="ip2loc-filter-form">
			<div class="filter-item">
				<input type="search" name="s" id="ip2loc_log_search" value="<?php echo esc_attr( $search ); ?>" placeholder="<?php esc_attr_e( 'Search IP, URL, country, method...', 'ip2location-sentinel' ); ?>" class="regular-text" autocomplete="off" />
			</div>

			<div class="filter-item">
				<select name="action_filter" id="ip2loc_log_action">
					<option value=""><?php esc_html_e( 'All Actions', 'ip2location-sentinel' ); ?></option>
					<option value="BLOCKED" <?php selected( $action, 'BLOCKED' ); ?>><?php esc_html_e( 'Blocked', 'ip2location-sentinel' ); ?></option>
					<option value="COMMENT_SPAM_BLOCKED" <?php selected( $action, 'COMMENT_SPAM_BLOCKED' ); ?>><?php esc_html_e( 'Comment Spam Blocked', 'ip2location-sentinel' ); ?></option>
					<option value="IMPOSSIBLE_TRAVEL_FLAGGED" <?php selected( $action, 'IMPOSSIBLE_TRAVEL_FLAGGED' ); ?>><?php esc_html_e( 'Impossible Travel Flagged', 'ip2location-sentinel' ); ?></option>
					<option value="ALLOWED" <?php selected( $action, 'ALLOWED' ); ?>><?php esc_html_e( 'Allowed', 'ip2location-sentinel' ); ?></option>
				</select>
			</div>

			<div class="filter-item">
				<select name="endpoint_filter" id="ip2loc_log_endpoint">
					<option value=""><?php esc_html_e( 'All Endpoints', 'ip2location-sentinel' ); ?></option>
					<option value="XML-RPC" <?php selected( $endpoint, 'XML-RPC' ); ?>><?php esc_html_e( 'XML-RPC', 'ip2location-sentinel' ); ?></option>
					<option value="Login" <?php selected( $endpoint, 'Login' ); ?>><?php esc_html_e( 'Login (wp-login.php)', 'ip2location-sentinel' ); ?></option>
					<option value="Comment" <?php selected( $endpoint, 'Comment' ); ?>><?php esc_html_e( 'Comments', 'ip2location-sentinel' ); ?></option>
					<option value="REST API" <?php selected( $endpoint, 'REST API' ); ?>><?php esc_html_e( 'REST API', 'ip2location-sentinel' ); ?></option>
					<option value="Frontend" <?php selected( $endpoint, 'Frontend' ); ?>><?php esc_html_e( 'Frontend Pages', 'ip2location-sentinel' ); ?></option>
				</select>
			</div>

			<div class="filter-item">
				<select name="per_page" id="ip2loc_log_per_page">
					<option value="10" <?php selected( $per_page, 10 ); ?>><?php esc_html_e( '10 per page', 'ip2location-sentinel' ); ?></option>
					<option value="25" <?php selected( $per_page, 25 ); ?>><?php esc_html_e( '25 per page', 'ip2location-sentinel' ); ?></option>
					<option value="50" <?php selected( $per_page, 50 ); ?>><?php esc_html_e( '50 per page', 'ip2location-sentinel' ); ?></option>
					<option value="100" <?php selected( $per_page, 100 ); ?>><?php esc_html_e( '100 per page', 'ip2location-sentinel' ); ?></option>
					<option value="250" <?php selected( $per_page, 250 ); ?>><?php esc_html_e( '250 per page', 'ip2location-sentinel' ); ?></option>
				</select>
			</div>

			<div class="filter-item">
				<a href="#" id="ip2loc_btn_reset_filters" class="button button-link" style="<?php echo ( ! empty( $search ) || ! empty( $action ) || ! empty( $endpoint ) || $per_page !== 10 ) ? '' : 'display:none;'; ?>">
					<?php esc_html_e( 'Reset Filters', 'ip2location-sentinel' ); ?>
				</a>
			</div>
			<div class="filter-item" id="ip2loc_filter_spinner" style="display:none; align-items:center; gap:4px; font-size:12px; color:#646970;">
				<span class="dashicons dashicons-update" style="animation: ip2loc-spin 1s linear infinite; font-size: 16px; width: 16px; height: 16px; line-height: 16px;"></span>
				<span><?php esc_html_e( 'Filtering...', 'ip2location-sentinel' ); ?></span>
			</div>
		</form>
	</div>

	<!-- Log Table -->
	<div class="ip2loc-card ip2loc-table-responsive" style="padding: 0; position: relative;">
		<table class="widefat striped ip2loc-table" id="ip2loc_audit_logs_table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Timestamp', 'ip2location-sentinel' ); ?></th>
					<th><?php esc_html_e( 'IP Address', 'ip2location-sentinel' ); ?></th>
					<th><?php esc_html_e( 'Location', 'ip2location-sentinel' ); ?></th>
					<th><?php esc_html_e( 'Method & Request URL / Endpoint', 'ip2location-sentinel' ); ?></th>
					<th><?php esc_html_e( 'Action', 'ip2location-sentinel' ); ?></th>
					<th><?php esc_html_e( 'Rule / Reason', 'ip2location-sentinel' ); ?></th>
					<th><?php esc_html_e( 'ASN / Network', 'ip2location-sentinel' ); ?></th>
					<th><?php esc_html_e( 'User', 'ip2location-sentinel' ); ?></th>
					<th style="min-width: 200px;"><?php esc_html_e( 'Device & User-Agent', 'ip2location-sentinel' ); ?></th>
				</tr>
			</thead>
			<tbody id="ip2loc_audit_logs_tbody">
				<?php Admin::render_audit_log_rows( $items ); ?>
			</tbody>
		</table>
	</div>

	<!-- Pagination -->
	<div id="ip2loc_audit_pagination_wrap">
		<?php if ( $total_pages > 1 ) : ?>
			<div class="tablenav bottom" style="margin-top: 12px;">
				<div class="tablenav-pages">
					<span class="displaying-num"><?php echo sprintf( esc_html__( '%s items', 'ip2location-sentinel' ), number_format_i18n( $total_count ) ); ?></span>
					<div class="pagination-links">
						<?php if ( $current_page > 1 ) : ?>
							<a class="first-page button ip2loc-ajax-page" data-paged="1" href="#"><span class="screen-reader-text"><?php esc_html_e( 'First page', 'ip2location-sentinel' ); ?></span><span aria-hidden="true">&laquo;</span></a>
							<a class="prev-page button ip2loc-ajax-page" data-paged="<?php echo ( $current_page - 1 ); ?>" href="#"><span class="screen-reader-text"><?php esc_html_e( 'Previous page', 'ip2location-sentinel' ); ?></span><span aria-hidden="true">&lsaquo;</span></a>
						<?php endif; ?>
						<span class="paging-input">
							<span class="tablenav-paging-text">
								<?php echo esc_html( $current_page ); ?> <?php esc_html_e( 'of', 'ip2location-sentinel' ); ?> <span class="total-pages"><?php echo esc_html( $total_pages ); ?></span>
							</span>
						</span>
						<?php if ( $current_page < $total_pages ) : ?>
							<a class="next-page button ip2loc-ajax-page" data-paged="<?php echo ( $current_page + 1 ); ?>" href="#"><span class="screen-reader-text"><?php esc_html_e( 'Next page', 'ip2location-sentinel' ); ?></span><span aria-hidden="true">&rsaquo;</span></a>
							<a class="last-page button ip2loc-ajax-page" data-paged="<?php echo ( $total_pages ); ?>" href="#"><span class="screen-reader-text"><?php esc_html_e( 'Last page', 'ip2location-sentinel' ); ?></span><span aria-hidden="true">&raquo;</span></a>
						<?php endif; ?>
					</div>
				</div>
			</div>
		<?php endif; ?>
	</div>
</div>
