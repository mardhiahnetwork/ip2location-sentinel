<?php
/**
 * Admin View: Impossible Travel & 2FA Settings (Native WordPress Tabbed Layout)
 *
 * @package LocaSentinel
 */

use IP2Location\Sentinel\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$enabled_travel    = ! empty( $settings['enable_impossible_travel'] );
$speed_threshold   = isset( $settings['impossible_speed_threshold'] ) ? (float) $settings['impossible_speed_threshold'] : 800;
$min_distance      = isset( $settings['impossible_min_distance'] ) ? (float) $settings['impossible_min_distance'] : 300;
$domestic_mode     = $settings['impossible_domestic_mode'] ?? 'mobile_tolerance';
$action_mode       = $settings['impossible_action'] ?? 'otp';
$enable_webhooks   = ! empty( $settings['enable_webhooks'] );
$webhook_url       = $settings['webhook_url'] ?? '';
$webhook_type      = $settings['webhook_type'] ?? 'auto';
$force_otp_no_smtp = ! empty( $settings['force_otp_without_smtp'] );
$webhook_custom_payload = $settings['webhook_custom_payload'] ?? '';
?>

<div class="wrap ip2loc-wrap">
	<div class="ip2loc-header-wrap">
		<h1><?php esc_html_e( 'Impossible Travel & 2FA', 'ip2location-sentinel' ); ?></h1>
		<div class="ip2loc-autosave-badge" id="ip2loc_autosave_badge" style="display:none;">
			<span class="dashicons dashicons-saved"></span>
			<span class="ip2loc-badge-text"><?php esc_html_e( 'All changes saved', 'ip2location-sentinel' ); ?></span>
		</div>
	</div>
	<hr class="wp-header-end">
	<?php Admin::render_plugin_header_notices(); ?>

	<!-- Parent Section Tabs -->
	<nav class="nav-tab-wrapper ip2loc-parent-nav wp-clearfix" style="margin-bottom: 12px;">
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=ip2loc-rules' ) ); ?>" class="nav-tab">
			<?php esc_html_e( 'Geo Rules', 'ip2location-sentinel' ); ?>
		</a>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=ip2loc-endpoints' ) ); ?>" class="nav-tab">
			<?php esc_html_e( 'Endpoint Hardening', 'ip2location-sentinel' ); ?>
		</a>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=ip2loc-impossible-travel' ) ); ?>" class="nav-tab nav-tab-active">
			<?php esc_html_e( 'Impossible Travel & 2FA', 'ip2location-sentinel' ); ?>
		</a>
	</nav>

	<!-- Child Feature Tabs -->
	<nav class="nav-tab-wrapper ip2loc-tabs wp-clearfix" style="border-bottom: 1px solid #c3c4c7; background: #fff;">
		<a href="#tab-impossible-travel" class="nav-tab nav-tab-active"><?php esc_html_e( 'Impossible Travel Engine', 'ip2location-sentinel' ); ?></a>
		<a href="#tab-smtp-status" class="nav-tab"><?php esc_html_e( 'SMTP Mailer Health', 'ip2location-sentinel' ); ?></a>
		<a href="#tab-webhooks" class="nav-tab"><?php esc_html_e( 'Security Webhooks', 'ip2location-sentinel' ); ?></a>
	</nav>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="ip2loc_impossible_form" class="ip2loc-form ip2loc-tabbed-form">
		<input type="hidden" name="action" value="ip2loc_save_settings" />
		<input type="hidden" name="ip2loc_tab" value="impossible_travel" />
		<?php wp_nonce_field( 'ip2loc_settings_nonce', 'nonce' ); ?>

		<!-- TAB 1: Impossible Travel Engine -->
		<div id="tab-impossible-travel" class="ip2loc-tab-pane ip2loc-tab-active">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Impossible Travel Velocity Detection', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><?php esc_html_e( 'Velocity Protection', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[enable_impossible_travel]" id="ip2loc_enable_impossible_travel" value="1" <?php checked( $enabled_travel ); ?> />
									<span class="ip2loc-toggle-text"><strong><?php esc_html_e( 'Enable Impossible Travel Velocity Detection', 'ip2location-sentinel' ); ?></strong></span>
								</label>
								<p class="description"><?php esc_html_e( 'Computes physical velocity between successive user logins using Haversine distance formulas and timestamps.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="ip2loc_impossible_speed_threshold"><?php esc_html_e( 'Speed Threshold (km/h)', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<input type="number" name="ip2loc[impossible_speed_threshold]" id="ip2loc_impossible_speed_threshold" value="<?php echo esc_attr( $speed_threshold ); ?>" min="100" max="2500" step="50" class="small-text" /> km/h
								<p class="description"><?php esc_html_e( 'Standard commercial flight speed is ~800–900 km/h. Logins requiring travel faster than this threshold will trigger verification.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="ip2loc_impossible_min_distance"><?php esc_html_e( 'Minimum Distance (km)', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<input type="number" name="ip2loc[impossible_min_distance]" id="ip2loc_impossible_min_distance" value="<?php echo esc_attr( $min_distance ); ?>" min="50" max="5000" step="25" class="small-text" /> km
								<p class="description"><?php esc_html_e( 'Ignore velocity calculations if physical displacement between two login events is below this distance.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Cellular & Domestic Mode', 'ip2location-sentinel' ); ?></th>
							<td>
								<fieldset>
									<label style="display:block; margin-bottom: 8px;">
										<input type="radio" name="ip2loc[impossible_domestic_mode]" value="mobile_tolerance" <?php checked( $domestic_mode, 'mobile_tolerance' ); ?> />
										<strong><?php esc_html_e( 'Smart Mobile Carrier Tolerance (Recommended)', 'ip2location-sentinel' ); ?></strong>
									</label>

									<label style="display:block; margin-bottom: 8px;">
										<input type="radio" name="ip2loc[impossible_domestic_mode]" value="ignore_domestic" <?php checked( $domestic_mode, 'ignore_domestic' ); ?> />
										<strong><?php esc_html_e( 'Cross-Border Only (Ignore Same-Country Travel)', 'ip2location-sentinel' ); ?></strong>
									</label>

									<label style="display:block;">
										<input type="radio" name="ip2loc[impossible_domestic_mode]" value="strict" <?php checked( $domestic_mode, 'strict' ); ?> />
										<strong><?php esc_html_e( 'Strict Mode', 'ip2location-sentinel' ); ?></strong>
									</label>
								</fieldset>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Action on Detection', 'ip2location-sentinel' ); ?></th>
							<td>
								<fieldset>
									<label style="margin-right: 20px;">
										<input type="radio" name="ip2loc[impossible_action]" value="otp" <?php checked( $action_mode === 'otp' || empty( $action_mode ) ); ?> />
										<strong><?php esc_html_e( 'Require Email One-Time Password (OTP)', 'ip2location-sentinel' ); ?></strong>
									</label>
									<br />
									<label style="margin-top: 6px; display:inline-block;">
										<input type="radio" name="ip2loc[impossible_action]" value="webhook_only" <?php checked( in_array( $action_mode, array( 'webhook', 'webhook_only' ), true ) ); ?> />
										<strong><?php esc_html_e( 'Log and Webhook only (no login challenge)', 'ip2location-sentinel' ); ?></strong>
									</label>
								</fieldset>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>

		<!-- TAB 2: SMTP Mailer Health -->
		<div id="tab-smtp-status" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'SMTP Mailer Health & Safeguards', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<div class="ip2loc-smtp-box <?php echo $smtp_check['is_safe_for_otp'] ? 'smtp-safe' : 'smtp-warning'; ?>">
						<div class="smtp-status-details">
							<h4><?php echo esc_html( $smtp_check['label'] ); ?></h4>
							<p><?php echo esc_html( $smtp_check['recommendation'] ); ?></p>
						</div>
					</div>

					<table class="form-table" style="margin-top: 15px;">
						<tr>
							<th scope="row"><?php esc_html_e( 'Auto-Mute Safeguard', 'ip2location-sentinel' ); ?></th>
							<td>
								<label>
									<input type="checkbox" name="ip2loc[force_otp_without_smtp]" value="1" <?php checked( $force_otp_no_smtp ); ?> />
									<span class="ip2loc-toggle-text"><strong><?php esc_html_e( 'Force Email OTP even without a verified SMTP plugin', 'ip2location-sentinel' ); ?></strong></span>
								</label>
								<p class="description"><?php esc_html_e( 'By default, OTP challenges are muted if no SMTP plugin is active to avoid lockout.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="ip2loc_test_email_recipient"><?php esc_html_e( 'Test Email Delivery', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<div class="ip2loc-inline-test">
									<input type="email" id="ip2loc_test_email_recipient" class="regular-text" value="<?php echo esc_attr( wp_get_current_user()->user_email ); ?>" placeholder="admin@example.com" />
									<button type="button" id="ip2loc_btn_test_smtp" class="button button-secondary">
										<?php esc_html_e( 'Send Test Email', 'ip2location-sentinel' ); ?>
									</button>
								</div>
								<div id="ip2loc_smtp_test_result" style="margin-top: 8px;"></div>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>

		<!-- TAB 3: Webhook Integrations -->
		<div id="tab-webhooks" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Real-Time Security Webhooks', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><?php esc_html_e( 'Webhooks', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[enable_webhooks]" id="ip2loc_enable_webhooks" value="1" <?php checked( $enable_webhooks ); ?> />
									<span class="ip2loc-toggle-text"><strong><?php esc_html_e( 'Send security alerts to external webhook', 'ip2location-sentinel' ); ?></strong></span>
								</label>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="ip2loc_webhook_url"><?php esc_html_e( 'Webhook URL', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<input type="url" name="ip2loc[webhook_url]" id="ip2loc_webhook_url" class="large-text code" placeholder="https://discord.com/api/webhooks/... or https://hooks.slack.com/services/... or https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID>" value="<?php echo esc_attr( $webhook_url ); ?>" />
								<p class="description"><?php esc_html_e( 'Supports Discord, Slack, Telegram bot, or Custom endpoints. You can also include {{variable}} placeholders in URL parameters (e.g. ?ip={{ip}}&user={{user_login}}).', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="ip2loc_webhook_type"><?php esc_html_e( 'Payload Format', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<select name="ip2loc[webhook_type]" id="ip2loc_webhook_type">
									<option value="auto" <?php selected( $webhook_type, 'auto' ); ?>><?php esc_html_e( 'Auto-Detect', 'ip2location-sentinel' ); ?></option>
									<option value="discord" <?php selected( $webhook_type, 'discord' ); ?>><?php esc_html_e( 'Discord Rich Embed', 'ip2location-sentinel' ); ?></option>
									<option value="slack" <?php selected( $webhook_type, 'slack' ); ?>><?php esc_html_e( 'Slack Markdown', 'ip2location-sentinel' ); ?></option>
									<option value="telegram" <?php selected( $webhook_type, 'telegram' ); ?>><?php esc_html_e( 'Telegram Markdown', 'ip2location-sentinel' ); ?></option>
									<option value="custom" <?php selected( $webhook_type, 'custom' ); ?>><?php esc_html_e( 'Custom JSON / Template', 'ip2location-sentinel' ); ?></option>
								</select>
							</td>
						</tr>
						<tr id="ip2loc_row_custom_payload" style="<?php echo ( $webhook_type === 'custom' ) ? '' : 'display:none;'; ?>">
							<th scope="row"><label for="ip2loc_webhook_custom_payload"><?php esc_html_e( 'Custom Payload Template', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<textarea name="ip2loc[webhook_custom_payload]" id="ip2loc_webhook_custom_payload" rows="7" class="large-text code" placeholder="<?php echo esc_attr( "{\n  \"event\": \"{{event_type}}\",\n  \"ip\": \"{{ip}}\",\n  \"country\": \"{{country_name}}\",\n  \"user\": \"{{user_login}}\",\n  \"speed\": \"{{speed_kmh}}\",\n  \"site\": \"{{site_name}}\",\n  \"time\": \"{{timestamp}}\"\n}" ); ?>"><?php echo esc_textarea( $webhook_custom_payload ); ?></textarea>
								<p class="description"><?php esc_html_e( 'Custom JSON template with {{variable}} placeholders. Leave empty to automatically send standard structured JSON payload.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Test Webhook', 'ip2location-sentinel' ); ?></th>
							<td>
								<button type="button" id="ip2loc_btn_test_webhook" class="button button-secondary">
									<?php esc_html_e( 'Send Test Webhook', 'ip2location-sentinel' ); ?>
								</button>
								<div id="ip2loc_webhook_test_result" style="margin-top: 8px;"></div>
							</td>
						</tr>
					</table>

					<!-- Interactive Variable Cheatsheet Palette -->
					<div class="ip2loc-token-palette" style="margin-top: 25px; padding: 16px 20px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px;">
						<h4 style="margin: 0 0 10px 0; color: #1e293b; font-size: 13px; display: flex; align-items: center; gap: 6px;">
							<span class="dashicons dashicons-editor-code" style="color: #2271b1;"></span>
							<?php esc_html_e( 'Supported {{variable}} Template Placeholders', 'ip2location-sentinel' ); ?>
						</h4>
						<p class="description" style="margin-bottom: 12px;">
							<?php esc_html_e( 'Click any variable chip below to copy or insert it into your custom payload or webhook URL:', 'ip2location-sentinel' ); ?>
						</p>

						<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; font-size: 12px;">
							<div>
								<strong style="color: #475569; display:block; margin-bottom: 4px;"><?php esc_html_e( 'Security & Event', 'ip2location-sentinel' ); ?></strong>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{event_type}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{rule_triggered}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{action_taken}}</code>
							</div>
							<div>
								<strong style="color: #475569; display:block; margin-bottom: 4px;"><?php esc_html_e( 'Geo & Network', 'ip2location-sentinel' ); ?></strong>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{ip}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{country_name}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{country_code}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{city_name}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{region_name}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{zip_code}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{asn}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{as_name}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{is_proxy}}</code>
							</div>
							<div>
								<strong style="color: #475569; display:block; margin-bottom: 4px;"><?php esc_html_e( 'Velocity & Travel', 'ip2location-sentinel' ); ?></strong>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{speed_kmh}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{distance_km}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{time_diff_hours}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{location_current}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{location_previous}}</code>
							</div>
							<div>
								<strong style="color: #475569; display:block; margin-bottom: 4px;"><?php esc_html_e( 'User & System', 'ip2location-sentinel' ); ?></strong>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{user_login}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{user_email}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{site_name}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{site_url}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{timestamp}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{http_method}}</code>
								<code class="ip2loc-chip" title="<?php esc_attr_e( 'Click to copy', 'ip2location-sentinel' ); ?>">{{target_endpoint}}</code>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</form>
</div>
