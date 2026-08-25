<?php
/**
 * Admin View: Geo Firewall Rules (Native WordPress Tabbed Layout)
 *
 * @package LocaSentinel
 */

use IP2Location\Sentinel\Admin;
use IP2Location\Sentinel\Countries;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$selected_countries = isset( $settings['countries'] ) && is_array( $settings['countries'] ) ? $settings['countries'] : array();
$country_mode       = $settings['country_mode'] ?? 'blacklist';
$total_countries    = count( $countries );
$selected_count     = count( $selected_countries );
$is_simplified_init = ( $selected_count > 10 || ( $selected_count === $total_countries && $total_countries > 0 ) );
?>

<div class="wrap ip2loc-wrap">
	<div class="ip2loc-header-wrap">
		<h1><?php esc_html_e( 'Geo Firewall Rules', 'ip2location-sentinel' ); ?></h1>
		<div class="ip2loc-autosave-badge" id="ip2loc_autosave_badge" style="display:none;">
			<span class="dashicons dashicons-saved"></span>
			<span class="ip2loc-badge-text"><?php esc_html_e( 'All changes saved', 'ip2location-sentinel' ); ?></span>
		</div>
	</div>
	<hr class="wp-header-end">
	<?php Admin::render_plugin_header_notices(); ?>

	<!-- Parent Section Tabs -->
	<nav class="nav-tab-wrapper ip2loc-parent-nav wp-clearfix" style="margin-bottom: 12px;">
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=ip2loc-rules' ) ); ?>" class="nav-tab nav-tab-active">
			<?php esc_html_e( 'Geo Rules', 'ip2location-sentinel' ); ?>
		</a>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=ip2loc-endpoints' ) ); ?>" class="nav-tab">
			<?php esc_html_e( 'Endpoint Hardening', 'ip2location-sentinel' ); ?>
		</a>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=ip2loc-impossible-travel' ) ); ?>" class="nav-tab">
			<?php esc_html_e( 'Impossible Travel & 2FA', 'ip2location-sentinel' ); ?>
		</a>
	</nav>

	<!-- Child Feature Tabs -->
	<nav class="nav-tab-wrapper ip2loc-tabs wp-clearfix" style="border-bottom: 1px solid #c3c4c7; background: #fff;">
		<a href="#tab-countries" class="nav-tab nav-tab-active" data-tab="tab-countries">
			<?php esc_html_e( 'Country Rules', 'ip2location-sentinel' ); ?>
		</a>
		<a href="#tab-granular" class="nav-tab" data-tab="tab-granular">
			<?php esc_html_e( 'Region, City, Zip & ASN', 'ip2location-sentinel' ); ?>
		</a>
		<a href="#tab-threats" class="nav-tab" data-tab="tab-threats">
			<?php esc_html_e( 'Proxy & Bot Defense', 'ip2location-sentinel' ); ?>
		</a>
		<a href="#tab-ip-lists" class="nav-tab" data-tab="tab-ip-lists">
			<?php esc_html_e( 'IP Exceptions', 'ip2location-sentinel' ); ?>
		</a>
	</nav>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="ip2loc_rules_form">
		<input type="hidden" name="action" value="ip2loc_save_settings" />
		<input type="hidden" name="ip2loc_tab" value="rules" />
		<?php wp_nonce_field( 'ip2loc_save_settings_action', 'ip2loc_nonce' ); ?>

		<!-- TAB 1: Country Rules -->
		<div id="tab-countries" class="ip2loc-tab-pane ip2loc-tab-active">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Country Geolocation Rules', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><?php esc_html_e( 'Mode', 'ip2location-sentinel' ); ?></th>
							<td>
								<fieldset>
									<label style="margin-right: 20px;">
										<input type="radio" name="ip2loc[country_mode]" value="blacklist" <?php checked( $country_mode, 'blacklist' ); ?> />
										<strong><?php esc_html_e( 'Blocklist', 'ip2location-sentinel' ); ?></strong>
										<span class="description">(<?php esc_html_e( 'Block selected countries, allow all others', 'ip2location-sentinel' ); ?>)</span>
									</label>
									<br />
									<label style="margin-top: 6px; display:inline-block;">
										<input type="radio" name="ip2loc[country_mode]" value="whitelist" <?php checked( $country_mode, 'whitelist' ); ?> />
										<strong><?php esc_html_e( 'Allowlist', 'ip2location-sentinel' ); ?></strong>
										<span class="description">(<?php esc_html_e( 'Allow only selected countries, block all others', 'ip2location-sentinel' ); ?>)</span>
									</label>
								</fieldset>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="ip2loc_countries_select"><?php esc_html_e( 'Countries', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<div class="ip2loc-preset-bar">
									<span class="ip2loc-preset-label"><?php esc_html_e( 'Presets:', 'ip2location-sentinel' ); ?></span>
									<button type="button" class="button button-small ip2loc-preset-btn" data-preset="NA"><?php esc_html_e( 'North America', 'ip2location-sentinel' ); ?></button>
									<button type="button" class="button button-small ip2loc-preset-btn" data-preset="SA"><?php esc_html_e( 'South America', 'ip2location-sentinel' ); ?></button>
									<button type="button" class="button button-small ip2loc-preset-btn" data-preset="EU"><?php esc_html_e( 'European Union', 'ip2location-sentinel' ); ?></button>
									<button type="button" class="button button-small ip2loc-preset-btn" data-preset="ASEAN"><?php esc_html_e( 'ASEAN', 'ip2location-sentinel' ); ?></button>
									<button type="button" class="button button-small ip2loc-preset-btn" data-preset="GCC"><?php esc_html_e( 'Middle East', 'ip2location-sentinel' ); ?></button>
									<button type="button" class="button button-small ip2loc-preset-btn" data-preset="APAC"><?php esc_html_e( 'Asia-Pacific', 'ip2location-sentinel' ); ?></button>
									<button type="button" class="button button-small ip2loc-preset-btn" data-preset="HIGH_RISK_SPAM"><?php esc_html_e( 'Common Spam Origins', 'ip2location-sentinel' ); ?></button>
									<button type="button" class="button button-small ip2loc-preset-btn" data-action="select_all"><?php esc_html_e( 'Select All', 'ip2location-sentinel' ); ?></button>
									<button type="button" class="button button-small ip2loc-preset-btn" data-action="deselect_all"><?php esc_html_e( 'Clear', 'ip2location-sentinel' ); ?></button>
								</div>

								<div id="ip2loc_countries_select_wrap">
									<select name="ip2loc[countries][]" id="ip2loc_countries_select" class="ip2loc-select2" multiple="multiple" style="width: 100%; max-width: 700px;" data-placeholder="<?php esc_attr_e( 'Search country name or code...', 'ip2location-sentinel' ); ?>">
										<?php
										// Put selected countries first, then unselected
										$selected_opts   = array();
										$unselected_opts = array();
										foreach ( $countries as $code => $country_label ) {
											if ( in_array( $code, $selected_countries, true ) ) {
												$selected_opts[ $code ] = $country_label;
											} else {
												$unselected_opts[ $code ] = $country_label;
											}
										}
										$all_ordered = $selected_opts + $unselected_opts;

										foreach ( $all_ordered as $code => $country_label ) :
											$is_sel = in_array( $code, $selected_countries, true );
											?>
											<option value="<?php echo esc_attr( $code ); ?>" data-flag="<?php echo esc_url( Countries::get_flag_url( $code ) ); ?>" <?php selected( $is_sel ); ?>>
												<?php echo esc_html( $country_label ); ?>
											</option>
										<?php endforeach; ?>
									</select>
								</div>
								<p class="description"><?php esc_html_e( 'Select one or more countries to apply the filtering mode.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>

		<!-- TAB 2: Granular Rules -->
		<div id="tab-granular" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Region, City, Zip & ASN Rules', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><label for="ip2loc_blocked_regions"><?php esc_html_e( 'Block by Region / State', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<textarea name="ip2loc[blocked_regions]" id="ip2loc_blocked_regions" rows="3" class="large-text code" placeholder="Sabah&#10;California&#10;Bavaria"><?php echo esc_textarea( $settings['blocked_regions'] ?? '' ); ?></textarea>
								<p class="description"><?php esc_html_e( 'One per line or comma-separated.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="ip2loc_blocked_cities"><?php esc_html_e( 'Block by City', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<textarea name="ip2loc[blocked_cities]" id="ip2loc_blocked_cities" rows="3" class="large-text code" placeholder="Kota Kinabalu&#10;Moscow&#10;Shenzhen"><?php echo esc_textarea( $settings['blocked_cities'] ?? '' ); ?></textarea>
								<p class="description"><?php esc_html_e( 'One per line or comma-separated.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="ip2loc_blocked_zips"><?php esc_html_e( 'Block by Zip / Postal Code', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<textarea name="ip2loc[blocked_zips]" id="ip2loc_blocked_zips" rows="3" class="large-text code" placeholder="88000&#10;90210&#10;10001"><?php echo esc_textarea( $settings['blocked_zips'] ?? '' ); ?></textarea>
								<p class="description"><?php esc_html_e( 'One per line or comma-separated.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="ip2loc_blocked_asns"><?php esc_html_e( 'Block by ASN / Organization', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<textarea name="ip2loc[blocked_asns]" id="ip2loc_blocked_asns" rows="3" class="large-text code" placeholder="9534&#10;AS13335&#10;Binariang Berhad&#10;DigitalOcean"><?php echo esc_textarea( $settings['blocked_asns'] ?? '' ); ?></textarea>
								<p class="description"><?php esc_html_e( 'Enter ASN numbers (e.g. 9534) or organization names (e.g. DigitalOcean).', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>

		<!-- TAB 3: Threats & Bots -->
		<div id="tab-threats" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Proxy & Anonymous Network Defense', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><?php esc_html_e( 'Proxy & VPN Blocking', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[block_proxies]" value="1" <?php checked( ! empty( $settings['block_proxies'] ) ); ?> />
									<span class="ip2loc-toggle-text"><strong><?php esc_html_e( 'Block proxies, VPNs, TOR nodes, and hosting data centers (is_proxy == true)', 'ip2location-sentinel' ); ?></strong></span>
								</label>
								<p class="description"><?php esc_html_e( 'Identifies and blocks traffic routed through anonymous proxies and hosting data center ranges.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
					</table>
				</div>
			</div>

			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'Extended & Custom Crawler Allowlist', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<p class="description" style="margin-bottom: 15px;">
						<?php esc_html_e( 'Exempt legitimate search engines, social media previewers, SEO monitors, AI scrapers, or custom crawlers from geo-blocking rules.', 'ip2location-sentinel' ); ?>
					</p>

					<table class="form-table">
						<tr>
							<th scope="row"><?php esc_html_e( 'Major Search Engines', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[allow_search_bots]" value="1" <?php checked( ! empty( $settings['allow_search_bots'] ) ); ?> />
									<span class="ip2loc-toggle-text"><strong><?php esc_html_e( 'Allow Search Engine Crawlers', 'ip2location-sentinel' ); ?></strong></span>
								</label>
								<p class="description"><?php esc_html_e( 'Googlebot, Bingbot, Yahoo! Slurp, Baiduspider, YandexBot, DuckDuckBot, Applebot, Naver Yeti, Sogou, Seznam.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Anti-Spoofing (rDNS)', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[bot_rdns_verify]" value="1" <?php checked( ! empty( $settings['bot_rdns_verify'] ) ); ?> />
									<span class="ip2loc-toggle-text"><strong><?php esc_html_e( 'Verify genuine search bots via Reverse DNS (rDNS)', 'ip2location-sentinel' ); ?></strong></span>
								</label>
								<p class="description"><?php esc_html_e( 'Performs reverse DNS lookups on search bot requests to prevent malicious actors from spoofing Googlebot / Bingbot User-Agents.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Social Media Previewers', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[allow_social_bots]" value="1" <?php checked( ! empty( $settings['allow_social_bots'] ) ); ?> />
									<span class="ip2loc-toggle-text"><strong><?php esc_html_e( 'Allow Social Media Link Unfurling', 'ip2location-sentinel' ); ?></strong></span>
								</label>
								<p class="description"><?php esc_html_e( 'Facebook / Meta (facebookexternalhit), Twitterbot (X), LinkedIn, Pinterest, WhatsApp, Telegram, Discord, Slack.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'SEO & Uptime Monitors', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[allow_seo_bots]" value="1" <?php checked( ! empty( $settings['allow_seo_bots'] ) ); ?> />
									<span class="ip2loc-toggle-text"><strong><?php esc_html_e( 'Allow SEO Tools & Uptime Monitors', 'ip2location-sentinel' ); ?></strong></span>
								</label>
								<p class="description"><?php esc_html_e( 'AhrefsBot, SemrushBot, Moz / Rogerbot, Screaming Frog, UptimeRobot, Pingdom, Site24x7, StatusCake.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'AI & LLM Crawlers', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[allow_ai_bots]" value="1" <?php checked( ! empty( $settings['allow_ai_bots'] ) ); ?> />
									<span class="ip2loc-toggle-text"><strong><?php esc_html_e( 'Allow AI & LLM Crawlers', 'ip2location-sentinel' ); ?></strong></span>
								</label>
								<p class="description"><?php esc_html_e( 'GPTBot, ChatGPT-User, ClaudeBot, Anthropic AI, PerplexityBot, Google-Extended, ByteDance Bytespider, CCBot.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Feed & RSS Readers', 'ip2location-sentinel' ); ?></th>
							<td>
								<label class="ip2loc-toggle-label">
									<input type="checkbox" name="ip2loc[allow_feed_bots]" value="1" <?php checked( ! empty( $settings['allow_feed_bots'] ) ); ?> />
									<span class="ip2loc-toggle-text"><strong><?php esc_html_e( 'Allow RSS & Feed Aggregators', 'ip2location-sentinel' ); ?></strong></span>
								</label>
								<p class="description"><?php esc_html_e( 'Feedly, Inoreader, NewsBlur, Google Feedfetcher.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="ip2loc_allowed_crawlers_custom"><?php esc_html_e( 'Custom Crawler Patterns', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<textarea name="ip2loc[allowed_crawlers_custom]" id="ip2loc_allowed_crawlers_custom" rows="4" class="large-text code" placeholder="MyCustomBot&#10;UptimeKuma&#10;Stripe-Webhook&#10;/^HealthChecker/i"><?php echo esc_textarea( $settings['allowed_crawlers_custom'] ?? '' ); ?></textarea>
								<p class="description"><?php esc_html_e( 'Enter custom User-Agent substrings or regular expressions (e.g. /^MyBot/i). One per line or comma-separated.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>

		<!-- TAB 4: IP Exceptions -->
		<div id="tab-ip-lists" class="ip2loc-tab-pane">
			<div class="ip2loc-card">
				<div class="ip2loc-card-header">
					<h2><?php esc_html_e( 'IP Allowlist & Blocklist Exceptions', 'ip2location-sentinel' ); ?></h2>
				</div>
				<div class="ip2loc-card-body">
					<table class="form-table">
						<tr>
							<th scope="row"><label for="ip2loc_whitelist_ips"><?php esc_html_e( 'IP Allowlist', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<textarea name="ip2loc[whitelist_ips]" id="ip2loc_whitelist_ips" rows="3" class="large-text code" placeholder="127.0.0.1&#10;192.168.1.0/24&#10;203.0.113.*"><?php echo esc_textarea( $settings['whitelist_ips'] ?? "127.0.0.1\n::1" ); ?></textarea>
								<p class="description"><?php esc_html_e( 'Supports single IPs, CIDR ranges, and wildcards (*). Always bypasses firewall checks.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="ip2loc_blacklist_ips"><?php esc_html_e( 'IP Blocklist', 'ip2location-sentinel' ); ?></label></th>
							<td>
								<textarea name="ip2loc[blacklist_ips]" id="ip2loc_blacklist_ips" rows="3" class="large-text code" placeholder="198.51.100.0/24&#10;203.0.113.50"><?php echo esc_textarea( $settings['blacklist_ips'] ?? '' ); ?></textarea>
								<p class="description"><?php esc_html_e( 'Always blocked across all endpoints.', 'ip2location-sentinel' ); ?></p>
							</td>
						</tr>
					</table>
				</div>
			</div>
		</div>
	</form>
</div>

<script>
window.ip2locPresetGroups = <?php echo wp_json_encode( $presets ); ?>;
</script>
