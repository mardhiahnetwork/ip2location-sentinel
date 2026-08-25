<?php
/**
 * Admin View: Endpoint Protection Settings (Native WordPress Tabbed Layout)
 *
 * @package LocaSentinel
 */

use IP2Location\Sentinel\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$protect_comments                      = ! isset( $settings['protect_comments'] ) || ! empty( $settings['protect_comments'] );
$hide_comments_for_restricted_visitors = ! empty( $settings['hide_comments_for_restricted_visitors'] );
$hide_blocked_author_comments          = ! empty( $settings['hide_blocked_author_comments'] );
$protect_xmlrpc                        = ! isset( $settings['protect_xmlrpc'] ) || ! empty( $settings['protect_xmlrpc'] );
$protect_login                         = ! empty( $settings['protect_login'] );
$protect_rest                          = ! empty( $settings['protect_rest_api'] );
$protect_frontend                      = ! empty( $settings['protect_frontend'] );
$block_action                          = $settings['block_action'] ?? 'template';
?>

<div class="wrap ip2loc-wrap">
	<div class="ip2loc-header-wrap">
		<h1><?php esc_html_e( 'Endpoint Protection', 'ip2location-sentinel' ); ?></h1>
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
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=ip2loc-endpoints' ) ); ?>" class="nav-tab nav-tab-active">
			<?php esc_html_e( 'Endpoint Hardening', 'ip2location-sentinel' ); ?>
		</a>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=ip2loc-impossible-travel' ) ); ?>" class="nav-tab">
			<?php esc_html_e( 'Impossible Travel & 2FA', 'ip2location-sentinel' ); ?>
		</a>
	</nav>

	<!-- Child Feature Tabs -->
	<nav class="nav-tab-wrapper ip2loc-tabs wp-clearfix" style="border-bottom: 1px solid #c3c4c7; background: #fff;">
		<a href="#tab-comments" class="nav-tab nav-tab-active" data-tab="tab-comments">
			<?php esc_html_e( 'Comments & Discussions', 'ip2location-sentinel' ); ?>
		</a>
		<a href="#tab-core-endpoints" class="nav-tab" data-tab="tab-core-endpoints">
			<?php esc_html_e( 'Core Endpoints', 'ip2location-sentinel' ); ?>
		</a>
		<a href="#tab-captcha" class="nav-tab" data-tab="tab-captcha">
			<?php esc_html_e( 'Anti-Spam CAPTCHA Challenge', 'ip2location-sentinel' ); ?>
		</a>
		<a href="#tab-block-actions" class="nav-tab" data-tab="tab-block-actions">
			<?php esc_html_e( 'Block Actions & Responses', 'ip2location-sentinel' ); ?>
		</a>
	</nav>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="ip2loc_endpoints_form" autocomplete="off">
		<!-- Prevent Chrome / browser password manager heuristics from auto-filling credentials -->
		<div style="display:none; opacity:0; position:absolute; left:-9999px;" aria-hidden="true">
			<input type="text" name="fake_username_remembered" tabindex="-1" autocomplete="username" />
			<input type="password" name="fake_password_remembered" tabindex="-1" autocomplete="current-password" />
		</div>
		<input type="hidden" name="action" value="ip2loc_save_settings" />
		<input type="hidden" name="ip2loc_tab" value="endpoints" />
		<?php wp_nonce_field( 'ip2loc_save_settings_action', 'ip2loc_nonce' ); ?>

		<!-- TAB 1: Comments & Discussions -->
		<div id="tab-comments" class="ip2loc-tab-pane ip2loc-tab-active">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Comments & Discussion Geo-Defense', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><?php esc_html_e( 'Comment Submissions', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[protect_comments]" value="1" <?php checked( $protect_comments ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Reject comment submissions from restricted locations and anonymous proxies', 'ip2location-sentinel' ); ?></strong>
									</span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Evaluates comment authors against active country and proxy rules before inserting comments into the database.', 'ip2location-sentinel' ); ?>
								</p>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'Hide Comments from Blocked Geos', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[hide_comments_for_restricted_visitors]" value="1" <?php checked( $hide_comments_for_restricted_visitors ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Hide comment section & discussion forms from restricted visitors', 'ip2location-sentinel' ); ?></strong>
									</span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Visitors browsing from restricted countries or anonymous proxies will not see the comment form or existing discussion threads.', 'ip2location-sentinel' ); ?>
								</p>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'Filter Historical Spam Comments', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[hide_blocked_author_comments]" value="1" <?php checked( $hide_blocked_author_comments ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Hide historical comments originally submitted from restricted locations', 'ip2location-sentinel' ); ?></strong>
									</span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Dynamically hides past comments from being rendered on posts if the commenter IP address matches your current geo blocklist or proxy rules.', 'ip2location-sentinel' ); ?>
								</p>
							</td>
						</tr>

						<tr>
							<th scope="row"><label for="ip2loc_comments_blocked_msg"><?php esc_html_e( 'Comment Rejection Notice', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<textarea name="ip2loc[comments_blocked_msg]" id="ip2loc_comments_blocked_msg" rows="2" class="large-text"><?php echo esc_textarea( $settings['comments_blocked_msg'] ?? __( 'Comments from your geographical region or network are not accepted on this website.', 'ip2location-sentinel' ) ); ?></textarea>
								<p class="description">
									<?php esc_html_e( 'Displayed when a comment submission is rejected due to geo or proxy rules.', 'ip2location-sentinel' ); ?>
								</p>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>

		<!-- TAB 2: Core Endpoints -->
		<div id="tab-core-endpoints" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Core Sensitive Endpoints', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><?php esc_html_e( 'Login (wp-login.php)', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[protect_login]" value="1" <?php checked( $protect_login ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Block wp-login.php access from restricted locations', 'ip2location-sentinel' ); ?></strong>
									</span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Protects the WordPress administrative login screen against brute-force attacks from unauthorized territories.', 'ip2location-sentinel' ); ?>
								</p>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'XML-RPC (xmlrpc.php)', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[protect_xmlrpc]" value="1" <?php checked( $protect_xmlrpc ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Block XML-RPC requests from restricted locations and proxies', 'ip2location-sentinel' ); ?></strong>
									</span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Blocks pingbacks and XML-RPC authentication from blocked origins commonly targeted in amplification attacks.', 'ip2location-sentinel' ); ?>
								</p>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'REST API (/wp-json/)', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[protect_rest_api]" value="1" <?php checked( $protect_rest ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Block REST API requests from restricted locations', 'ip2location-sentinel' ); ?></strong>
									</span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Returns a 403 Forbidden WP_Error response for REST endpoints accessed from blocked regions.', 'ip2location-sentinel' ); ?>
								</p>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'Frontend Pages', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[protect_frontend]" value="1" <?php checked( $protect_frontend ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Block public frontend visits from restricted locations', 'ip2location-sentinel' ); ?></strong>
									</span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Restricts all public-facing site pages based on your active Geo Firewall rules.', 'ip2location-sentinel' ); ?>
								</p>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>

		<!-- TAB 3: Anti-Spam CAPTCHA Challenge -->
		<div id="tab-captcha" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Anti-Spam Rate Limiting & CAPTCHA Challenge', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<p class="description" style="margin-bottom: 16px;">
						<?php esc_html_e( 'Protects the entire website against abusive bots, rapid scraping loops, and spam floods with Cloudflare Turnstile, hCaptcha, or Google reCAPTCHA challenges. Solving the challenge grants temporary site-wide clearance for legitimate visitors. Strict Geo Policy: Visitors originating from restricted countries will remain blocked even if the challenge is solved.', 'ip2location-sentinel' ); ?>
					</p>

					<table class="form-table">
						<tr>
							<th scope="row"><?php esc_html_e( 'Enable CAPTCHA Protection', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[enable_captcha]" value="1" <?php checked( ! empty( $settings['enable_captcha'] ) ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Enable Whole-Website Anti-Spam CAPTCHA Protection', 'ip2location-sentinel' ); ?></strong>
									</span>
								</label>
								<p class="description"><?php esc_html_e( 'Protects your entire site from automated floods while maintaining strict geo-restrictions.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'Non-Restricted Geo Spam Defense', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[captcha_challenge_allowed_countries]" value="1" <?php checked( ! isset( $settings['captcha_challenge_allowed_countries'] ) || ! empty( $settings['captcha_challenge_allowed_countries'] ) ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Challenge allowed / non-restricted country visitors if they spam too much', 'ip2location-sentinel' ); ?></strong>
									</span>
								</label>
								<p class="description"><?php esc_html_e( 'When enabled, visitors from permitted countries will still be presented with a CAPTCHA challenge if they send rapid repetitive requests, preventing bot abuse from allowed regions.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>

						<tr>
							<th scope="row"><label for="ip2loc_captcha_rate_limit_hits"><?php esc_html_e( 'Rate Limit Threshold', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
									<span><?php esc_html_e( 'Trigger challenge after', 'ip2location-sentinel' ); ?></span>
									<input type="number" name="ip2loc[captcha_rate_limit_hits]" id="ip2loc_captcha_rate_limit_hits" min="3" max="1000" step="1" style="width: 80px;" value="<?php echo esc_attr( $settings['captcha_rate_limit_hits'] ?? 10 ); ?>" />
									<span><?php esc_html_e( 'requests to the same path within', 'ip2location-sentinel' ); ?></span>
									<input type="number" name="ip2loc[captcha_rate_limit_window]" id="ip2loc_captcha_rate_limit_window" min="5" max="3600" step="5" style="width: 80px;" value="<?php echo esc_attr( $settings['captcha_rate_limit_window'] ?? 60 ); ?>" />
									<span><?php esc_html_e( 'seconds.', 'ip2location-sentinel' ); ?></span>
								</div>
								<p class="description"><?php esc_html_e( 'Default: 10 requests within 60 seconds per unique URL path.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>

						<tr>
							<th scope="row"><label for="ip2loc_captcha_clearance_duration"><?php esc_html_e( 'Clearance Duration', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<div style="display: flex; align-items: center; gap: 8px;">
									<input type="number" name="ip2loc[captcha_clearance_duration]" id="ip2loc_captcha_clearance_duration" min="5" max="1440" step="5" style="width: 80px;" value="<?php echo esc_attr( $settings['captcha_clearance_duration'] ?? 60 ); ?>" />
									<span><?php esc_html_e( 'minutes', 'ip2location-sentinel' ); ?></span>
								</div>
								<p class="description"><?php esc_html_e( 'How long a verified visitor remains exempt from the challenge on that path after solving CAPTCHA (default: 60 minutes).', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'CAPTCHA Provider', 'ip2location-sentinel' ); ?></th>
							<td>
								<?php $provider = $settings['captcha_provider'] ?? 'turnstile'; ?>
								<fieldset>
									<label style="margin-right: 20px;">
										<input type="radio" name="ip2loc[captcha_provider]" value="turnstile" <?php checked( $provider, 'turnstile' ); ?> />
										<strong><?php esc_html_e( 'Cloudflare Turnstile (Recommended - Zero Friction & Privacy Friendly)', 'ip2location-sentinel' ); ?></strong>
									</label>
									<br />
									<label style="margin-top: 8px; display:inline-block; margin-right: 20px;">
										<input type="radio" name="ip2loc[captcha_provider]" value="hcaptcha" <?php checked( $provider, 'hcaptcha' ); ?> />
										<strong><?php esc_html_e( 'hCaptcha', 'ip2location-sentinel' ); ?></strong>
									</label>
									<br />
									<label style="margin-top: 8px; display:inline-block; margin-right: 20px;">
										<input type="radio" name="ip2loc[captcha_provider]" value="recaptcha_v2" <?php checked( $provider, 'recaptcha_v2' ); ?> />
										<strong><?php esc_html_e( 'Google reCAPTCHA v2 (Checkbox)', 'ip2location-sentinel' ); ?></strong>
									</label>
									<br />
									<label style="margin-top: 8px; display:inline-block;">
										<input type="radio" name="ip2loc[captcha_provider]" value="recaptcha_v3" <?php checked( $provider, 'recaptcha_v3' ); ?> />
										<strong><?php esc_html_e( 'Google reCAPTCHA v3 (Invisible)', 'ip2location-sentinel' ); ?></strong>
									</label>
								</fieldset>
							</td>
						</tr>

						<tr>
							<th scope="row"><label for="ip2loc_captcha_site_key"><?php esc_html_e( 'Site Key', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<input type="text" name="ip2loc[captcha_site_key]" id="ip2loc_captcha_site_key" class="regular-text code" value="<?php echo esc_attr( $settings['captcha_site_key'] ?? '' ); ?>" placeholder="<?php esc_attr_e( 'e.g. 0x4AAAAAA...', 'ip2location-sentinel' ); ?>" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-form-type="other" data-1p-ignore="true" readonly onfocus="this.removeAttribute('readonly');" />
								<p class="description"><?php esc_html_e( 'Public site key from your Cloudflare, hCaptcha, or Google reCAPTCHA dashboard.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>

						<tr>
							<th scope="row"><label for="ip2loc_captcha_secret_key"><?php esc_html_e( 'Secret Key', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<div class="ip2loc-inline-test">
									<input type="password" name="ip2loc[captcha_secret_key]" id="ip2loc_captcha_secret_key" class="regular-text code" value="<?php echo esc_attr( $settings['captcha_secret_key'] ?? '' ); ?>" placeholder="<?php esc_attr_e( 'Paste your secret key...', 'ip2location-sentinel' ); ?>" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-form-type="other" data-1p-ignore="true" readonly onfocus="this.removeAttribute('readonly');" />
									<button type="button" id="ip2loc_toggle_captcha_secret" class="button button-secondary">
										<span id="ip2loc_toggle_captcha_secret_label"><?php esc_html_e( 'Show', 'ip2location-sentinel' ); ?></span>
									</button>
								</div>
								<p class="description"><?php esc_html_e( 'Private server secret key used to verify visitor challenge responses securely.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>

		<!-- TAB 4: Block Action & Response Messages -->
		<div id="tab-block-actions" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Block Actions & Response Customization', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><?php esc_html_e( 'Block Action', 'ip2location-sentinel' ); ?></th>
							<td>
								<fieldset>
									<label style="margin-right: 20px;">
										<input type="radio" name="ip2loc[block_action]" value="template" <?php checked( $block_action, 'template' ); ?> />
										<strong><?php esc_html_e( 'Show Native 403 Forbidden page', 'ip2location-sentinel' ); ?></strong>
									</label>
									<br />
									<label style="margin-top: 8px; display:inline-block;">
										<input type="radio" name="ip2loc[block_action]" value="redirect" <?php checked( $block_action, 'redirect' ); ?> />
										<strong><?php esc_html_e( 'Redirect to URL (302)', 'ip2location-sentinel' ); ?></strong>
									</label>
								</fieldset>
							</td>
						</tr>

						<tr id="ip2loc_row_redirect_url" style="<?php echo ( $block_action === 'redirect' ) ? '' : 'display:none;'; ?>">
							<th scope="row"><label for="ip2loc_block_redirect_url"><?php esc_html_e( 'Redirect URL', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<input type="url" name="ip2loc[block_redirect_url]" id="ip2loc_block_redirect_url" class="regular-text" placeholder="https://example.com/blocked" value="<?php echo esc_attr( $settings['block_redirect_url'] ?? '' ); ?>" />
								<p class="description"><?php esc_html_e( 'Target URL where blocked visitors will be redirected.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>

						<tr>
							<th scope="row"><label for="ip2loc_block_page_title"><?php esc_html_e( 'Block Page Title', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<input type="text" name="ip2loc[block_page_title]" id="ip2loc_block_page_title" class="large-text" value="<?php echo esc_attr( $settings['block_page_title'] ?? __( 'Access Restricted (403)', 'ip2location-sentinel' ) ); ?>" />
							</td>
						</tr>

						<tr>
							<th scope="row"><label for="ip2loc_block_page_message"><?php esc_html_e( 'Block Page Message', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<textarea name="ip2loc[block_page_message]" id="ip2loc_block_page_message" rows="3" class="large-text"><?php echo esc_textarea( $settings['block_page_message'] ?? __( 'Access from your IP address or geographical region is restricted by the site security policy.', 'ip2location-sentinel' ) ); ?></textarea>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>
	</form>
</div>
