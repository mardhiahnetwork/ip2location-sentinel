<?php
/**
 * Admin View: Endpoint Protection Settings (Native WordPress Tabbed Layout)
 *
 * @package LocaSentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$settings                              = isset( $settings ) && is_array( $settings ) ? $settings : get_option( 'ip2loc_settings', array() );
if ( ! is_array( $settings ) ) {
	$settings = array();
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
		<div class="ip2loc-header-left">
			<h1><?php esc_html_e( 'Endpoint Protection', 'locasentinel' ); ?></h1>
		</div>
		<div class="ip2loc-header-right">
			<button type="submit" form="ip2loc_endpoints_form" class="button button-primary ip2loc-save-btn" id="ip2loc_save_btn">
				<span class="dashicons dashicons-saved"></span>
				<span class="ip2loc-save-text"><?php esc_html_e( 'Save Changes', 'locasentinel' ); ?></span>
			</button>
		</div>
	</div>
	<hr class="wp-header-end">
	<?php \IP2Location\Sentinel\Admin::render_plugin_header_notices(); ?>

	<!-- Native WordPress Tab Navigation -->
	<nav class="nav-tab-wrapper ip2loc-tabs wp-clearfix">
		<a href="#tab-comments" class="nav-tab nav-tab-active" data-tab="tab-comments">
			<?php esc_html_e( 'Comments & Discussions', 'locasentinel' ); ?>
		</a>
		<a href="#tab-core-endpoints" class="nav-tab" data-tab="tab-core-endpoints">
			<?php esc_html_e( 'Core Endpoints', 'locasentinel' ); ?>
		</a>
		<a href="#tab-captcha" class="nav-tab" data-tab="tab-captcha">
			<?php esc_html_e( 'Anti-Spam CAPTCHA Challenge', 'locasentinel' ); ?>
		</a>
		<a href="#tab-block-actions" class="nav-tab" data-tab="tab-block-actions">
			<?php esc_html_e( 'Block Actions & Responses', 'locasentinel' ); ?>
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
					<h2><?php esc_html_e( 'Comments & Discussion Geo-Defense', 'locasentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><?php esc_html_e( 'Comment Submissions', 'locasentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[protect_comments]" value="1" <?php checked( $protect_comments ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Reject comment submissions from restricted locations and anonymous proxies', 'locasentinel' ); ?></strong>
									</span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Evaluates comment authors against active country and proxy rules before inserting comments into the database.', 'locasentinel' ); ?>
								</p>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'Hide Comments from Blocked Geos', 'locasentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[hide_comments_for_restricted_visitors]" value="1" <?php checked( $hide_comments_for_restricted_visitors ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Hide comment section & discussion forms from restricted visitors', 'locasentinel' ); ?></strong>
									</span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Visitors browsing from restricted countries or anonymous proxies will not see the comment form or existing discussion threads.', 'locasentinel' ); ?>
								</p>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'Filter Historical Spam Comments', 'locasentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[hide_blocked_author_comments]" value="1" <?php checked( $hide_blocked_author_comments ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Hide historical comments originally submitted from restricted locations', 'locasentinel' ); ?></strong>
									</span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Dynamically hides past comments from being rendered on posts if the commenter IP address matches your current geo blocklist or proxy rules.', 'locasentinel' ); ?>
								</p>
							</td>
						</tr>

						<tr>
							<th scope="row"><label for="ip2loc_comments_blocked_msg"><?php esc_html_e( 'Comment Rejection Notice', 'locasentinel' ); ?></label></th>
							<td>
								<textarea name="ip2loc[comments_blocked_msg]" id="ip2loc_comments_blocked_msg" rows="2" class="large-text"><?php echo esc_textarea( $settings['comments_blocked_msg'] ?? __( 'Comments from your geographical region or network are not accepted on this website.', 'locasentinel' ) ); ?></textarea>
								<p class="description">
									<?php esc_html_e( 'Displayed when a comment submission is rejected due to geo or proxy rules.', 'locasentinel' ); ?>
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
					<h2><?php esc_html_e( 'Core Sensitive Endpoints', 'locasentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><?php esc_html_e( 'Login (wp-login.php)', 'locasentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[protect_login]" value="1" <?php checked( $protect_login ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Block wp-login.php access from restricted locations', 'locasentinel' ); ?></strong>
									</span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Protects the WordPress administrative login screen against brute-force attacks from unauthorized territories.', 'locasentinel' ); ?>
								</p>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'XML-RPC (xmlrpc.php)', 'locasentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[protect_xmlrpc]" value="1" <?php checked( $protect_xmlrpc ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Block XML-RPC requests from restricted locations and proxies', 'locasentinel' ); ?></strong>
									</span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Blocks pingbacks and XML-RPC authentication from blocked origins commonly targeted in amplification attacks.', 'locasentinel' ); ?>
								</p>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'REST API (/wp-json/)', 'locasentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[protect_rest_api]" value="1" <?php checked( $protect_rest ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Block REST API requests from restricted locations', 'locasentinel' ); ?></strong>
									</span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Returns a 403 Forbidden WP_Error response for REST endpoints accessed from blocked regions.', 'locasentinel' ); ?>
								</p>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'Frontend Pages', 'locasentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[protect_frontend]" value="1" <?php checked( $protect_frontend ); ?> />
									<span class="ip2loc-toggle-text">
										<strong><?php esc_html_e( 'Block public frontend visits from restricted locations', 'locasentinel' ); ?></strong>
									</span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Restricts all public-facing site pages based on your active Geo Firewall rules.', 'locasentinel' ); ?>
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
					<h2><?php esc_html_e( 'Anti-Spam Rate Limiting & CAPTCHA Challenge', 'locasentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<p class="description" style="margin-bottom: 20px;">
						<?php esc_html_e( 'Protects the website against abusive bots, rapid scraping loops, and spam floods with Cloudflare Turnstile, hCaptcha, or Google reCAPTCHA challenges. Each provider stores its own independent keys, allowing you to configure multiple providers, test them individually in a new tab, or rotate randomly among configured providers without wiping credentials.', 'locasentinel' ); ?>
					</p>

					<?php
					$turnstile_creds    = \IP2Location\Sentinel\Captcha::get_provider_credentials( 'turnstile' );
					$hcaptcha_creds     = \IP2Location\Sentinel\Captcha::get_provider_credentials( 'hcaptcha' );
					$recaptcha_v2_creds = \IP2Location\Sentinel\Captcha::get_provider_credentials( 'recaptcha_v2' );
					$recaptcha_v3_creds = \IP2Location\Sentinel\Captcha::get_provider_credentials( 'recaptcha_v3' );
					$configured_provs   = \IP2Location\Sentinel\Captcha::get_configured_providers();
					$captcha_nonce      = wp_create_nonce( 'ip2loc_test_captcha_nonce' );
					$active_prov_mode   = $settings['captcha_provider'] ?? 'turnstile';
					?>

					<!-- Child Sub-Tab Navigation for CAPTCHA Providers -->
					<div class="ip2loc-subtab-container">
						<div class="ip2loc-subtab-nav">
							<a href="#subtab-captcha-general" class="ip2loc-subtab-link is-active" data-subtab="subtab-captcha-general">
								<span><?php esc_html_e( 'Mode & Rate Limits', 'locasentinel' ); ?></span>
							</a>
							<a href="#subtab-captcha-turnstile" class="ip2loc-subtab-link" data-subtab="subtab-captcha-turnstile">
								<span>Cloudflare Turnstile</span>
							</a>
							<a href="#subtab-captcha-hcaptcha" class="ip2loc-subtab-link" data-subtab="subtab-captcha-hcaptcha">
								<span>hCaptcha</span>
							</a>
							<a href="#subtab-captcha-recaptcha-v2" class="ip2loc-subtab-link" data-subtab="subtab-captcha-recaptcha-v2">
								<span>reCAPTCHA v2</span>
							</a>
							<a href="#subtab-captcha-recaptcha-v3" class="ip2loc-subtab-link" data-subtab="subtab-captcha-recaptcha-v3">
								<span>reCAPTCHA v3</span>
							</a>
						</div>

						<!-- Sub-Tab 1: Mode & Rate Limits -->
						<div id="subtab-captcha-general" class="ip2loc-subtab-pane is-active">
							<table class="form-table">
								<tr>
									<th scope="row"><?php esc_html_e( 'Enable Protection', 'locasentinel' ); ?></th>
									<td>
										<label class="ip2loc-toggle-label">
											<input type="checkbox" name="ip2loc[enable_captcha]" value="1" <?php checked( ! empty( $settings['enable_captcha'] ) ); ?> />
											<span class="ip2loc-toggle-text">
												<strong><?php esc_html_e( 'Enable Whole-Website Anti-Spam CAPTCHA Protection', 'locasentinel' ); ?></strong>
											</span>
										</label>
										<p class="description"><?php esc_html_e( 'Protects your entire site from automated floods while maintaining strict geo-restrictions.', 'locasentinel' ); ?></p>
									</td>
								</tr>

								<tr>
									<th scope="row"><?php esc_html_e( 'Active Provider Mode', 'locasentinel' ); ?></th>
									<td>
										<fieldset>
											<label style="margin-right: 20px; display: block; margin-bottom: 8px;">
												<input type="radio" name="ip2loc[captcha_provider]" value="random" <?php checked( $active_prov_mode, 'random' ); ?> />
												<strong><?php esc_html_e( 'Random', 'locasentinel' ); ?></strong>
												<span class="description" style="display: block; margin-left: 24px; margin-top: 2px;">
													<?php
													if ( ! empty( $configured_provs ) ) {
														echo sprintf( esc_html__( 'Rotates between configured providers (%s). An IP challenge session maintains the assigned provider until solved.', 'locasentinel' ), esc_html( implode( ', ', $configured_provs ) ) );
													} else {
														esc_html_e( 'No providers configured yet. Configure credentials in the sub-tabs below.', 'locasentinel' );
													}
													?>
												</span>
											</label>
											<label style="margin-right: 20px; display: block; margin-bottom: 8px;">
												<input type="radio" name="ip2loc[captcha_provider]" value="turnstile" <?php checked( $active_prov_mode, 'turnstile' ); ?> />
												<strong>Cloudflare Turnstile</strong>
											</label>
											<label style="margin-right: 20px; display: block; margin-bottom: 8px;">
												<input type="radio" name="ip2loc[captcha_provider]" value="hcaptcha" <?php checked( $active_prov_mode, 'hcaptcha' ); ?> />
												<strong>hCaptcha</strong>
											</label>
											<label style="margin-right: 20px; display: block; margin-bottom: 8px;">
												<input type="radio" name="ip2loc[captcha_provider]" value="recaptcha_v2" <?php checked( $active_prov_mode, 'recaptcha_v2' ); ?> />
												<strong>Google reCAPTCHA v2</strong>
											</label>
											<label style="display: block;">
												<input type="radio" name="ip2loc[captcha_provider]" value="recaptcha_v3" <?php checked( $active_prov_mode, 'recaptcha_v3' ); ?> />
												<strong>Google reCAPTCHA v3</strong>
											</label>
										</fieldset>
									</td>
								</tr>

								<tr>
									<th scope="row"><?php esc_html_e( 'Allowed Geo Spam Defense', 'locasentinel' ); ?></th>
									<td>
										<label class="ip2loc-toggle-label">
											<input type="checkbox" name="ip2loc[captcha_challenge_allowed_countries]" value="1" <?php checked( ! isset( $settings['captcha_challenge_allowed_countries'] ) || ! empty( $settings['captcha_challenge_allowed_countries'] ) ); ?> />
											<span class="ip2loc-toggle-text">
												<strong><?php esc_html_e( 'Challenge allowed / non-restricted country visitors if they spam too much', 'locasentinel' ); ?></strong>
											</span>
										</label>
										<p class="description"><?php esc_html_e( 'Presents CAPTCHA challenges to rapid repetitive requests from permitted countries to prevent bot abuse.', 'locasentinel' ); ?></p>
									</td>
								</tr>

								<tr>
									<th scope="row"><label for="ip2loc_captcha_rate_limit_hits"><?php esc_html_e( 'Rate Limit Threshold', 'locasentinel' ); ?></label></th>
									<td>
										<div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
											<span><?php esc_html_e( 'Trigger challenge after', 'locasentinel' ); ?></span>
											<input type="number" name="ip2loc[captcha_rate_limit_hits]" id="ip2loc_captcha_rate_limit_hits" min="3" max="1000" step="1" style="width: 80px;" value="<?php echo esc_attr( $settings['captcha_rate_limit_hits'] ?? 10 ); ?>" />
											<span><?php esc_html_e( 'requests within', 'locasentinel' ); ?></span>
											<input type="number" name="ip2loc[captcha_rate_limit_window]" id="ip2loc_captcha_rate_limit_window" min="5" max="3600" step="5" style="width: 80px;" value="<?php echo esc_attr( $settings['captcha_rate_limit_window'] ?? 60 ); ?>" />
											<span><?php esc_html_e( 'seconds.', 'locasentinel' ); ?></span>
										</div>
									</td>
								</tr>

								<tr>
									<th scope="row"><label for="ip2loc_captcha_clearance_duration"><?php esc_html_e( 'Clearance Duration', 'locasentinel' ); ?></label></th>
									<td>
										<div style="display: flex; align-items: center; gap: 8px;">
											<input type="number" name="ip2loc[captcha_clearance_duration]" id="ip2loc_captcha_clearance_duration" min="5" max="1440" step="5" style="width: 80px;" value="<?php echo esc_attr( $settings['captcha_clearance_duration'] ?? 60 ); ?>" />
											<span><?php esc_html_e( 'minutes (default: 60 min)', 'locasentinel' ); ?></span>
										</div>
									</td>
								</tr>
							</table>
						</div>

						<!-- Sub-Tab 2: Cloudflare Turnstile -->
						<div id="subtab-captcha-turnstile" class="ip2loc-subtab-pane">
							<table class="form-table">
								<tr>
									<th scope="row"><label for="ip2loc_turnstile_site"><?php esc_html_e( 'Site Key', 'locasentinel' ); ?></label></th>
									<td>
										<input type="text" name="ip2loc[captcha_turnstile_site_key]" id="ip2loc_turnstile_site" class="regular-text code" value="<?php echo esc_attr( $turnstile_creds['site_key'] ); ?>" placeholder="" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-form-type="other" readonly onfocus="this.removeAttribute('readonly');" />
										<p class="description"><?php esc_html_e( 'Cloudflare Turnstile Site Key.', 'locasentinel' ); ?></p>
									</td>
								</tr>
								<tr>
									<th scope="row"><label for="ip2loc_turnstile_secret"><?php esc_html_e( 'Secret Key', 'locasentinel' ); ?></label></th>
									<td>
										<div class="ip2loc-inline-test">
											<input type="password" name="ip2loc[captcha_turnstile_secret_key]" id="ip2loc_turnstile_secret" class="regular-text code" value="<?php echo esc_attr( $turnstile_creds['secret_key'] ); ?>" placeholder="" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-form-type="other" readonly onfocus="this.removeAttribute('readonly');" />
											<button type="button" class="button button-secondary ip2loc-toggle-secret-btn" data-target="ip2loc_turnstile_secret">
												<span><?php esc_html_e( 'Show', 'locasentinel' ); ?></span>
											</button>
										</div>
										<p class="description"><?php esc_html_e( 'Cloudflare Turnstile Secret Key.', 'locasentinel' ); ?></p>
									</td>
								</tr>
								<tr>
									<th scope="row"><?php esc_html_e( 'Live Testing', 'locasentinel' ); ?></th>
									<td>
										<a href="<?php echo esc_url( admin_url( 'admin-post.php?action=ip2loc_test_captcha&provider=turnstile&_wpnonce=' . $captcha_nonce ) ); ?>" target="_blank" rel="noopener noreferrer" class="button button-secondary">
											<?php esc_html_e( 'Test Turnstile', 'locasentinel' ); ?>
										</a>
										<p class="description"><?php esc_html_e( 'Opens a standalone test probe in a new tab to verify Turnstile keys.', 'locasentinel' ); ?></p>
									</td>
								</tr>
							</table>
						</div>

						<!-- Sub-Tab 3: hCaptcha -->
						<div id="subtab-captcha-hcaptcha" class="ip2loc-subtab-pane">
							<table class="form-table">
								<tr>
									<th scope="row"><label for="ip2loc_hcaptcha_site"><?php esc_html_e( 'Site Key', 'locasentinel' ); ?></label></th>
									<td>
										<input type="text" name="ip2loc[captcha_hcaptcha_site_key]" id="ip2loc_hcaptcha_site" class="regular-text code" value="<?php echo esc_attr( $hcaptcha_creds['site_key'] ); ?>" placeholder="" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-form-type="other" readonly onfocus="this.removeAttribute('readonly');" />
										<p class="description"><?php esc_html_e( 'hCaptcha Site Key from your dashboard.', 'locasentinel' ); ?></p>
									</td>
								</tr>
								<tr>
									<th scope="row"><label for="ip2loc_hcaptcha_secret"><?php esc_html_e( 'Secret Key', 'locasentinel' ); ?></label></th>
									<td>
										<div class="ip2loc-inline-test">
											<input type="password" name="ip2loc[captcha_hcaptcha_secret_key]" id="ip2loc_hcaptcha_secret" class="regular-text code" value="<?php echo esc_attr( $hcaptcha_creds['secret_key'] ); ?>" placeholder="" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-form-type="other" readonly onfocus="this.removeAttribute('readonly');" />
											<button type="button" class="button button-secondary ip2loc-toggle-secret-btn" data-target="ip2loc_hcaptcha_secret">
												<span><?php esc_html_e( 'Show', 'locasentinel' ); ?></span>
											</button>
										</div>
										<p class="description"><?php esc_html_e( 'hCaptcha Secret Key.', 'locasentinel' ); ?></p>
									</td>
								</tr>
								<tr>
									<th scope="row"><?php esc_html_e( 'Live Testing', 'locasentinel' ); ?></th>
									<td>
										<a href="<?php echo esc_url( admin_url( 'admin-post.php?action=ip2loc_test_captcha&provider=hcaptcha&_wpnonce=' . $captcha_nonce ) ); ?>" target="_blank" rel="noopener noreferrer" class="button button-secondary">
											<?php esc_html_e( 'Test hCaptcha', 'locasentinel' ); ?>
										</a>
										<p class="description"><?php esc_html_e( 'Opens a standalone test probe in a new tab to verify hCaptcha keys.', 'locasentinel' ); ?></p>
									</td>
								</tr>
							</table>
						</div>

						<!-- Sub-Tab 4: Google reCAPTCHA v2 -->
						<div id="subtab-captcha-recaptcha-v2" class="ip2loc-subtab-pane">
							<table class="form-table">
								<tr>
									<th scope="row"><label for="ip2loc_recaptcha_v2_site"><?php esc_html_e( 'Site Key', 'locasentinel' ); ?></label></th>
									<td>
										<input type="text" name="ip2loc[captcha_recaptcha_v2_site_key]" id="ip2loc_recaptcha_v2_site" class="regular-text code" value="<?php echo esc_attr( $recaptcha_v2_creds['site_key'] ); ?>" placeholder="" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-form-type="other" readonly onfocus="this.removeAttribute('readonly');" />
										<p class="description"><?php esc_html_e( 'Google reCAPTCHA v2 Site Key.', 'locasentinel' ); ?></p>
									</td>
								</tr>
								<tr>
									<th scope="row"><label for="ip2loc_recaptcha_v2_secret"><?php esc_html_e( 'Secret Key', 'locasentinel' ); ?></label></th>
									<td>
										<div class="ip2loc-inline-test">
											<input type="password" name="ip2loc[captcha_recaptcha_v2_secret_key]" id="ip2loc_recaptcha_v2_secret" class="regular-text code" value="<?php echo esc_attr( $recaptcha_v2_creds['secret_key'] ); ?>" placeholder="" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-form-type="other" readonly onfocus="this.removeAttribute('readonly');" />
											<button type="button" class="button button-secondary ip2loc-toggle-secret-btn" data-target="ip2loc_recaptcha_v2_secret">
												<span><?php esc_html_e( 'Show', 'locasentinel' ); ?></span>
											</button>
										</div>
										<p class="description"><?php esc_html_e( 'Google reCAPTCHA v2 Secret Key.', 'locasentinel' ); ?></p>
									</td>
								</tr>
								<tr>
									<th scope="row"><?php esc_html_e( 'Live Testing', 'locasentinel' ); ?></th>
									<td>
										<a href="<?php echo esc_url( admin_url( 'admin-post.php?action=ip2loc_test_captcha&provider=recaptcha_v2&_wpnonce=' . $captcha_nonce ) ); ?>" target="_blank" rel="noopener noreferrer" class="button button-secondary">
											<?php esc_html_e( 'Test reCAPTCHA v2', 'locasentinel' ); ?>
										</a>
										<p class="description"><?php esc_html_e( 'Opens a standalone test probe in a new tab to verify reCAPTCHA v2 keys.', 'locasentinel' ); ?></p>
									</td>
								</tr>
							</table>
						</div>

						<!-- Sub-Tab 5: Google reCAPTCHA v3 -->
						<div id="subtab-captcha-recaptcha-v3" class="ip2loc-subtab-pane">
							<table class="form-table">
								<tr>
									<th scope="row"><label for="ip2loc_recaptcha_v3_site"><?php esc_html_e( 'Site Key', 'locasentinel' ); ?></label></th>
									<td>
										<input type="text" name="ip2loc[captcha_recaptcha_v3_site_key]" id="ip2loc_recaptcha_v3_site" class="regular-text code" value="<?php echo esc_attr( $recaptcha_v3_creds['site_key'] ); ?>" placeholder="" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-form-type="other" readonly onfocus="this.removeAttribute('readonly');" />
										<p class="description"><?php esc_html_e( 'Google reCAPTCHA v3 Site Key.', 'locasentinel' ); ?></p>
									</td>
								</tr>
								<tr>
									<th scope="row"><label for="ip2loc_recaptcha_v3_secret"><?php esc_html_e( 'Secret Key', 'locasentinel' ); ?></label></th>
									<td>
										<div class="ip2loc-inline-test">
											<input type="password" name="ip2loc[captcha_recaptcha_v3_secret_key]" id="ip2loc_recaptcha_v3_secret" class="regular-text code" value="<?php echo esc_attr( $recaptcha_v3_creds['secret_key'] ); ?>" placeholder="" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-form-type="other" readonly onfocus="this.removeAttribute('readonly');" />
											<button type="button" class="button button-secondary ip2loc-toggle-secret-btn" data-target="ip2loc_recaptcha_v3_secret">
												<span><?php esc_html_e( 'Show', 'locasentinel' ); ?></span>
											</button>
										</div>
										<p class="description"><?php esc_html_e( 'Google reCAPTCHA v3 Secret Key.', 'locasentinel' ); ?></p>
									</td>
								</tr>
								<tr>
									<th scope="row"><label for="ip2loc_recaptcha_v3_score"><?php esc_html_e( 'Minimum Score Threshold', 'locasentinel' ); ?></label></th>
									<td>
										<div style="display: flex; align-items: center; gap: 8px;">
											<input type="number" name="ip2loc[captcha_recaptcha_v3_score]" id="ip2loc_recaptcha_v3_score" min="0.1" max="1.0" step="0.05" style="width: 80px;" value="<?php echo esc_attr( $recaptcha_v3_creds['score'] ); ?>" />
											<span><?php esc_html_e( '(0.1 to 1.0, default: 0.5)', 'locasentinel' ); ?></span>
										</div>
									</td>
								</tr>
								<tr>
									<th scope="row"><?php esc_html_e( 'Live Testing', 'locasentinel' ); ?></th>
									<td>
										<a href="<?php echo esc_url( admin_url( 'admin-post.php?action=ip2loc_test_captcha&provider=recaptcha_v3&_wpnonce=' . $captcha_nonce ) ); ?>" target="_blank" rel="noopener noreferrer" class="button button-secondary">
											<?php esc_html_e( 'Test reCAPTCHA v3', 'locasentinel' ); ?>
										</a>
										<p class="description"><?php esc_html_e( 'Opens a standalone test probe in a new tab to verify reCAPTCHA v3 score evaluation.', 'locasentinel' ); ?></p>
									</td>
								</tr>
							</table>
						</div>
					</div>
				</div>
			</div>
		</div>

		<!-- TAB 4: Block Action & Response Messages -->
		<div id="tab-block-actions" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Block Actions & Response Customization', 'locasentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><?php esc_html_e( 'Block Action', 'locasentinel' ); ?></th>
							<td>
								<fieldset>
									<label style="margin-right: 20px;">
										<input type="radio" name="ip2loc[block_action]" value="template" <?php checked( $block_action, 'template' ); ?> />
										<strong><?php esc_html_e( 'Show Native 403 Forbidden page', 'locasentinel' ); ?></strong>
									</label>
									<br />
									<label style="margin-top: 8px; display:inline-block;">
										<input type="radio" name="ip2loc[block_action]" value="redirect" <?php checked( $block_action, 'redirect' ); ?> />
										<strong><?php esc_html_e( 'Redirect to URL (302)', 'locasentinel' ); ?></strong>
									</label>
								</fieldset>
							</td>
						</tr>

						<tr id="ip2loc_row_redirect_url" style="<?php echo ( $block_action === 'redirect' ) ? '' : 'display:none;'; ?>">
							<th scope="row"><label for="ip2loc_block_redirect_url"><?php esc_html_e( 'Redirect URL', 'locasentinel' ); ?></label></th>
							<td>
								<input type="url" name="ip2loc[block_redirect_url]" id="ip2loc_block_redirect_url" class="regular-text" placeholder="https://example.com/blocked" value="<?php echo esc_attr( $settings['block_redirect_url'] ?? '' ); ?>" />
								<p class="description"><?php esc_html_e( 'Target URL where blocked visitors will be redirected.', 'locasentinel' ); ?></p>
							</td>
						</tr>

						<tr>
							<th scope="row"><label for="ip2loc_block_page_title"><?php esc_html_e( 'Block Page Title', 'locasentinel' ); ?></label></th>
							<td>
								<input type="text" name="ip2loc[block_page_title]" id="ip2loc_block_page_title" class="large-text" value="<?php echo esc_attr( $settings['block_page_title'] ?? __( 'Access Restricted (403)', 'locasentinel' ) ); ?>" />
							</td>
						</tr>

						<tr>
							<th scope="row"><label for="ip2loc_block_page_message"><?php esc_html_e( 'Block Page Message', 'locasentinel' ); ?></label></th>
							<td>
								<textarea name="ip2loc[block_page_message]" id="ip2loc_block_page_message" rows="3" class="large-text"><?php echo esc_textarea( $settings['block_page_message'] ?? __( 'Access from your IP address or geographical region is restricted by the site security policy.', 'locasentinel' ) ); ?></textarea>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>
	</form>
</div>
