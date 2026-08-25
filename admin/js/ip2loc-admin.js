/**
 * IP2Location Sentinel Admin JavaScript Controller
 *
 * @package IP2Location_Sentinel
 */

(function($) {
	'use strict';

	$(document).ready(function() {

		// 1. Initialize Select2 on Country Picker with Local Flag Badges
		var $countrySelect = $('#ip2loc_countries_select');

		function formatCountryOption(state) {
			if (!state.id) return state.text;
			var flagUrl = $(state.element).data('flag');
			if (!flagUrl && state.id) {
				var code = state.id.toLowerCase();
				flagUrl = (window.ip2locAdminData && window.ip2locAdminData.flags_url) ? (window.ip2locAdminData.flags_url + code + '.svg') : '';
			}
			if (flagUrl) {
				var $opt = $('<span><img src="' + flagUrl + '" class="ip2loc-select2-flag" width="16" height="12" style="margin-right:6px;vertical-align:-1px;border-radius:1px;box-shadow:0 0 1px rgba(0,0,0,.4);" /> <span></span></span>');
				$opt.find('span').text(state.text);
				return $opt;
			}
			return state.text;
		}

		if ($.fn.select2 && $countrySelect.length) {
			$countrySelect.select2({
				placeholder: $countrySelect.data('placeholder') || 'Search country name or code...',
				allowClear: true,
				width: '100%',
				templateResult: formatCountryOption,
				templateSelection: formatCountryOption
			});
		}

		// 2. Preset Country Group Selectors
		$('.ip2loc-preset-btn').on('click', function(e) {
			e.preventDefault();
			var action = $(this).data('action');
			var presetKey = $(this).data('preset');

			if (action === 'select_all') {
				$countrySelect.find('option').prop('selected', true);
				$countrySelect.trigger('change');
			} else if (action === 'deselect_all') {
				$countrySelect.val(null);
				$countrySelect.trigger('change');
			} else if (presetKey && window.ip2locPresetGroups && window.ip2locPresetGroups[presetKey]) {
				var targetCountries = window.ip2locPresetGroups[presetKey].countries || [];
				var currentVals = $countrySelect.val() || [];
				var merged = Array.from(new Set(currentVals.concat(targetCountries)));
				$countrySelect.val(merged);
				$countrySelect.trigger('change');
			}
		});

		// 3. WordPress Native Tab Navigation with Real-Time & Tab Auto-Save
		var $activeForm = $('form[id^="ip2loc_"]');
		var lastSavedSnapshot = $activeForm.length ? $activeForm.serialize() : '';
		var isFormDirty = false;
		var autoSaveTimer = null;
		var badgeFadeTimer = null;

		function updateAutoSaveBadge(state, message) {
			var $badge = $('#ip2loc_autosave_badge');
			if (!$badge.length) return;

			clearTimeout(badgeFadeTimer);

			var $icon = $badge.find('.dashicons');
			var $text = $badge.find('.ip2loc-badge-text');

			if (state === 'saving') {
				$badge.removeClass('is-error').addClass('is-saving');
				$icon.removeClass('dashicons-saved dashicons-warning').addClass('dashicons-update');
				$text.text(message || 'Saving changes...');
				$badge.stop(true, true).css('display', 'inline-flex').hide().fadeIn(150);
			} else if (state === 'saved') {
				$badge.removeClass('is-saving is-error');
				$icon.removeClass('dashicons-update dashicons-warning').addClass('dashicons-saved');
				$text.text(message || 'All changes saved');
				$badge.stop(true, true).css('display', 'inline-flex');

				// Auto-disappear after 2.5 seconds
				badgeFadeTimer = setTimeout(function() {
					$badge.fadeOut(400);
				}, 2500);
			} else if (state === 'error') {
				$badge.removeClass('is-saving').addClass('is-error');
				$icon.removeClass('dashicons-update dashicons-saved').addClass('dashicons-warning');
				$text.text(message || 'Error saving changes');
				$badge.stop(true, true).css('display', 'inline-flex');

				// Auto-disappear after 4 seconds
				badgeFadeTimer = setTimeout(function() {
					$badge.fadeOut(400);
				}, 4000);
			} else if (state === 'hide') {
				$badge.stop(true, true).fadeOut(200);
			}
		}

		function performAutoSave(callback) {
			var $form = $('form[id^="ip2loc_"]');
			if (!$form.length || !window.ip2locAdminData) {
				if (callback) callback();
				return;
			}

			var currentSnapshot = $form.serialize();
			if (!isFormDirty && currentSnapshot === lastSavedSnapshot) {
				if (callback) callback();
				return;
			}

			updateAutoSaveBadge('saving', 'Saving changes...');

			var formData = $form.serializeArray();
			formData.push({ name: 'action', value: 'ip2loc_auto_save_settings' });
			formData.push({ name: 'nonce', value: ip2locAdminData.nonce });

			$.ajax({
				url: ip2locAdminData.ajax_url,
				type: 'POST',
				data: $.param(formData),
				dataType: 'json',
				success: function(res) {
					if (res && res.success) {
						lastSavedSnapshot = currentSnapshot;
						isFormDirty = false;
						updateAutoSaveBadge('saved', 'All changes saved');
					} else {
						updateAutoSaveBadge('error', res && res.data && res.data.message ? res.data.message : 'Error saving');
					}
					if (callback) callback(res);
				},
				error: function() {
					updateAutoSaveBadge('error', 'Network error');
					if (callback) callback();
				}
			});
		}

		// Trigger auto-save on input changes (debounced for text/inputs, immediate for toggles)
		$(document).on('change', 'form[id^="ip2loc_"] input[type="checkbox"], form[id^="ip2loc_"] input[type="radio"], form[id^="ip2loc_"] select', function() {
			var currentSnapshot = $('form[id^="ip2loc_"]').serialize();
			if (currentSnapshot !== lastSavedSnapshot) {
				isFormDirty = true;
				clearTimeout(autoSaveTimer);
				autoSaveTimer = setTimeout(function() {
					performAutoSave();
				}, 300);
			}
		});

		$(document).on('input', 'form[id^="ip2loc_"] input[type="text"], form[id^="ip2loc_"] input[type="number"], form[id^="ip2loc_"] input[type="password"], form[id^="ip2loc_"] input[type="url"], form[id^="ip2loc_"] input[type="email"], form[id^="ip2loc_"] textarea', function() {
			var currentSnapshot = $('form[id^="ip2loc_"]').serialize();
			if (currentSnapshot !== lastSavedSnapshot) {
				isFormDirty = true;
				updateAutoSaveBadge('saving', 'Unsaved changes...');
				clearTimeout(autoSaveTimer);
				autoSaveTimer = setTimeout(function() {
					performAutoSave();
				}, 1200);
			}
		});

		// Tab Switching Controller
		function switchTab(targetId, $tabLink) {
			if (!targetId) return;
			var cleanId = targetId.replace(/^#/, '');
			var $targetContent = $('#' + cleanId);

			if ($targetContent.length) {
				var $wrapper = $tabLink ? $tabLink.closest('.nav-tab-wrapper') : $('.nav-tab-wrapper');
				$wrapper.find('.nav-tab').removeClass('nav-tab-active');
				if ($tabLink) {
					$tabLink.addClass('nav-tab-active');
				} else {
					$('.nav-tab-wrapper a.nav-tab[data-tab="' + cleanId + '"], .nav-tab-wrapper a.nav-tab[href="#' + cleanId + '"]').addClass('nav-tab-active');
				}

				// Switch visible panes
				$('.ip2loc-tab-pane, .ip2loc-tab-content').removeClass('ip2loc-tab-active').hide();
				$targetContent.addClass('ip2loc-tab-active').show();

				// Ensure Select2 / charts re-render correct dimensions
				if ($.fn.select2 && $('#ip2loc_countries_select').length) {
					$('#ip2loc_countries_select').trigger('change.select2');
				}
				$(window).trigger('resize');

				if (window.history && window.history.replaceState) {
					window.history.replaceState(null, null, '#' + cleanId);
				}
			}
		}

		$(document).on('click', '.nav-tab-wrapper a.nav-tab', function(e) {
			e.preventDefault();
			var $clickedTab = $(this);
			var tabTarget = $clickedTab.data('tab') || ($clickedTab.attr('href') ? $clickedTab.attr('href').replace(/^.*#/, '') : '');

			// Auto-Save pending changes before switching
			if (isFormDirty) {
				performAutoSave(function() {
					switchTab(tabTarget, $clickedTab);
				});
			} else {
				switchTab(tabTarget, $clickedTab);
			}
		});

		// Auto-open tab based on URL hash on page load
		if (window.location.hash) {
			var hashId = window.location.hash.substring(1);
			switchTab(hashId, null);
		}

		// 4. Toggle Redirect URL Row based on Action selection
		$('input[name="ip2loc[block_action]"]').on('change', function() {
			if ($(this).val() === 'redirect') {
				$('#ip2loc_row_redirect_url').slideDown(200);
			} else {
				$('#ip2loc_row_redirect_url').slideUp(200);
			}
		});

		// 4. API Key Show/Hide Password Toggle
		var $keyInput     = $('#ip2loc_api_key');
		var $toggleKeyBtn = $('#ip2loc_toggle_key_vis');
		var $toggleLabel  = $('#ip2loc_toggle_key_label');

		if ($keyInput.length && $toggleKeyBtn.length) {
			$toggleKeyBtn.on('click', function(e) {
				e.preventDefault();
				if ($keyInput.attr('type') === 'password') {
					$keyInput.attr('type', 'text');
					$toggleLabel.text('Hide');
				} else {
					$keyInput.attr('type', 'password');
					$toggleLabel.text('Show');
				}
			});
		}

		// Toggle CAPTCHA Secret Key Visibility
		var $captchaSecretInput = $('#ip2loc_captcha_secret_key');
		var $toggleCaptchaBtn   = $('#ip2loc_toggle_captcha_secret');
		var $toggleCaptchaLabel = $('#ip2loc_toggle_captcha_secret_label');

		if ($captchaSecretInput.length && $toggleCaptchaBtn.length) {
			$toggleCaptchaBtn.on('click', function(e) {
				e.preventDefault();
				if ($captchaSecretInput.attr('type') === 'password') {
					$captchaSecretInput.attr('type', 'text');
					$toggleCaptchaLabel.text('Hide');
				} else {
					$captchaSecretInput.attr('type', 'password');
					$toggleCaptchaLabel.text('Show');
				}
			});
		}

		// 5. Test API Key AJAX
		$('#ip2loc_btn_test_key').on('click', function(e) {
			e.preventDefault();
			var $btn = $(this);
			var $result = $('#ip2loc_key_test_result');
			var $keyInput = $('#ip2loc_api_key');
			var apiKey = $keyInput.val().trim();

			if (!apiKey) {
				$result.html('<div class="notice notice-error inline" style="margin:6px 0;padding:8px 12px;"><p>Please enter an API key first.</p></div>');
				return;
			}

			$btn.prop('disabled', true).text(ip2locAdminData.testing_text);
			$result.empty();

			$.ajax({
				url: ip2locAdminData.ajax_url,
				type: 'POST',
				dataType: 'json',
				data: {
					action: 'ip2loc_test_api_key',
					nonce: ip2locAdminData.nonce,
					api_key: apiKey
				},
				success: function(response) {
					$btn.prop('disabled', false).text('Test Connection');
					if (response.success) {
						$keyInput.attr('data-verified-key', apiKey);
						var d = response.data.data || {};
						var html = '<div class="notice notice-success inline" style="margin:6px 0;padding:10px 14px;">';
						html += '<p><strong>' + response.data.message + '</strong></p>';
						if (d.country_name) {
							html += '<p style="font-size:12px;color:#1e293b;margin:4px 0 0 0;">Verified Query: <code>' + (d.ip || '8.8.8.8') + '</code> &rarr; ' + d.country_name + ' (' + (d.country_code || '') + '), City: ' + (d.city_name || 'N/A') + ', ASN: ' + (d.asn || 'N/A') + '</p>';
						}
						html += '</div>';
						$result.html(html);
					} else {
						$keyInput.removeAttr('data-verified-key');
						$result.html('<div class="notice notice-error inline" style="margin:6px 0;padding:10px 14px;"><p><strong>' + (response.data.message || 'Connection failed.') + '</strong></p></div>');
					}
				},
				error: function() {
					$btn.prop('disabled', false).text('Test Connection');
					$keyInput.removeAttr('data-verified-key');
					$result.html('<div class="notice notice-error inline" style="margin:6px 0;padding:10px 14px;"><p>Network communication error occurred.</p></div>');
				}
			});
		});

		// Enforce Test Connection Before Saving API Key
		$('#ip2loc_api_form').on('submit', function(e) {
			var $keyInput = $('#ip2loc_api_key');
			if ($keyInput.length) {
				var enteredKey = $keyInput.val().trim();
				var savedKey   = ($keyInput.data('saved-key') || '').toString().trim();
				var verifiedKey = ($keyInput.attr('data-verified-key') || '').toString().trim();

				// If key is entered/modified and not tested successfully yet
				if (enteredKey && enteredKey !== savedKey && enteredKey !== verifiedKey) {
					e.preventDefault();
					$('#ip2loc_key_test_result').html(
						'<div class="notice notice-warning inline" style="margin:6px 0;padding:10px 14px;">' +
						'<p><strong>Please click "Test Connection" to verify your API key before saving.</strong></p>' +
						'</div>'
					);
					$keyInput.focus();
					$('html, body').animate({ scrollTop: $keyInput.offset().top - 120 }, 200);
					return false;
				}
			}
		});

		// 6. Test SMTP AJAX
		$('#ip2loc_btn_test_smtp').on('click', function(e) {
			e.preventDefault();
			var $btn = $(this);
			var $result = $('#ip2loc_smtp_test_result');
			var email = $('#ip2loc_test_email_recipient').val().trim();

			$btn.prop('disabled', true).text(ip2locAdminData.sending_text);
			$result.empty();

			$.ajax({
				url: ip2locAdminData.ajax_url,
				type: 'POST',
				dataType: 'json',
				data: {
					action: 'ip2loc_test_smtp',
					nonce: ip2locAdminData.nonce,
					email: email
				},
				success: function(response) {
					$btn.prop('disabled', false).html('<span class="dashicons dashicons-email"></span> Send Test Email');
					if (response.success) {
						$result.html('<div class="notice notice-success inline" style="margin:6px 0;padding:8px 12px;"><p>' + response.data.message + '</p></div>');
					} else {
						$result.html('<div class="notice notice-error inline" style="margin:6px 0;padding:8px 12px;"><p>' + (response.data.message || 'Email delivery failed.') + '</p></div>');
					}
				},
				error: function() {
					$btn.prop('disabled', false).html('<span class="dashicons dashicons-email"></span> Send Test Email');
					$result.html('<div class="notice notice-error inline" style="margin:6px 0;padding:8px 12px;"><p>Server error during email test.</p></div>');
				}
			});
		});

		// 7. Test Webhook AJAX & Custom Payload Handlers
		$(document).on('change', '#ip2loc_webhook_type', function() {
			if ($(this).val() === 'custom') {
				$('#ip2loc_row_custom_payload').slideDown(200);
			} else {
				$('#ip2loc_row_custom_payload').slideUp(200);
			}
		});

		// Variable Chip Click-to-Copy & Insert
		$(document).on('click', '.ip2loc-chip', function() {
			var text = $(this).text().trim();
			var $chip = $(this);

			// Copy to clipboard
			if (navigator.clipboard && navigator.clipboard.writeText) {
				navigator.clipboard.writeText(text).then(function() {
					$chip.addClass('chip-copied');
					setTimeout(function() {
						$chip.removeClass('chip-copied');
					}, 1200);
				});
			}

			// If custom payload textarea is visible, insert at cursor
			var $textarea = $('#ip2loc_webhook_custom_payload');
			if ($textarea.length && $textarea.is(':visible')) {
				var el = $textarea[0];
				var start = el.selectionStart;
				var end = el.selectionEnd;
				var val = el.value;
				el.value = val.substring(0, start) + text + val.substring(end);
				el.selectionStart = el.selectionEnd = start + text.length;
				$textarea.trigger('input').focus();
			}
		});

		$('#ip2loc_btn_test_webhook').on('click', function(e) {
			e.preventDefault();
			var $btn = $(this);
			var $result = $('#ip2loc_webhook_test_result');
			var url = $('#ip2loc_webhook_url').val().trim();
			var type = $('#ip2loc_webhook_type').val();
			var customPayload = $('#ip2loc_webhook_custom_payload').val() || '';

			if (!url) {
				$result.html('<div class="notice notice-error inline" style="margin:6px 0;padding:8px 12px;"><p>Please enter a Webhook URL first.</p></div>');
				return;
			}

			$btn.prop('disabled', true).text(ip2locAdminData.sending_text);
			$result.empty();

			$.ajax({
				url: ip2locAdminData.ajax_url,
				type: 'POST',
				dataType: 'json',
				data: {
					action: 'ip2loc_test_webhook',
					nonce: ip2locAdminData.nonce,
					url: url,
					type: type,
					custom_payload: customPayload
				},
				success: function(response) {
					$btn.prop('disabled', false).html('<span class="dashicons dashicons-share-alt"></span> Send Test Webhook Alert');
					if (response.success) {
						$result.html('<div class="notice notice-success inline" style="margin:6px 0;padding:8px 12px;"><p>' + response.data.message + '</p></div>');
					} else {
						$result.html('<div class="notice notice-error inline" style="margin:6px 0;padding:8px 12px;"><p>' + (response.data.message || 'Webhook dispatch failed.') + '</p></div>');
					}
				},
				error: function() {
					$btn.prop('disabled', false).html('<span class="dashicons dashicons-share-alt"></span> Send Test Webhook Alert');
					$result.html('<div class="notice notice-error inline" style="margin:6px 0;padding:8px 12px;"><p>Failed to communicate with webhook.</p></div>');
				}
			});
		});

		// 8. Live IP Lookup Diagnostic Tool
		$('#ip2loc_btn_run_lookup').on('click', function(e) {
			e.preventDefault();
			var $btn = $(this);
			var $box = $('#ip2loc_lookup_result');
			var ipVal = $('#ip2loc_test_ip_input').val().trim();

			$btn.prop('disabled', true).text(ip2locAdminData.testing_text);
			$box.hide().empty();

			$.ajax({
				url: ip2locAdminData.ajax_url,
				type: 'POST',
				dataType: 'json',
				data: {
					action: 'ip2loc_lookup_ip',
					nonce: ip2locAdminData.nonce,
					ip: ipVal
				},
				success: function(response) {
					$btn.prop('disabled', false).html('<span class="dashicons dashicons-search" style="margin-top:3px;"></span> Inspect IP');
					if (response.success) {
						var g = response.data.geo;
						var ev = response.data.evaluation;
						var verdictBadge = ev.blocked
							? '<span class="ip2loc-pill pill-danger">REJECTED / BLOCKED</span>'
							: '<span class="ip2loc-pill pill-success">ALLOWED / PASSED</span>';

						var html = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #e2e8f0;">';
						html += '<div><strong>IP:</strong> <code>' + g.ip + '</code></div>';
						html += '<div><strong>Firewall Verdict:</strong> ' + verdictBadge + '</div>';
						html += '</div>';

						html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:13px;">';
						html += '<div><strong>Country:</strong> ' + (g.country_name || 'N/A') + ' (' + (g.country_code || '') + ')</div>';
						html += '<div><strong>Region / City:</strong> ' + (g.region_name || 'N/A') + ' / ' + (g.city_name || 'N/A') + '</div>';
						html += '<div><strong>Zip Code:</strong> ' + (g.zip_code || 'N/A') + '</div>';
						html += '<div><strong>ASN / ISP:</strong> AS' + (g.asn || '0') + ' (' + (g.as || 'N/A') + ')</div>';
						html += '<div><strong>Proxy / VPN:</strong> ' + (g.is_proxy ? '<span style="color:#ef4444;font-weight:700;">YES</span>' : '<span style="color:#10b981;font-weight:700;">NO</span>') + '</div>';
						html += '<div><strong>Policy Reason:</strong> <em>' + ev.reason + '</em></div>';
						html += '</div>';

						$box.html(html).slideDown(200);
					} else {
						$box.html('<div class="notice notice-error inline" style="margin:0;padding:8px 12px;"><p>' + (response.data.message || 'Lookup failed.') + '</p></div>').slideDown(200);
					}
				},
				error: function() {
					$btn.prop('disabled', false).html('<span class="dashicons dashicons-search" style="margin-top:3px;"></span> Inspect IP');
					$box.html('<div class="notice notice-error inline" style="margin:0;padding:8px 12px;"><p>Server error during IP lookup.</p></div>').slideDown(200);
				}
			});
		});

		// 8. Audit Logs Live Real-Time POST Filtering & Pagination (Zero GET Requests)
		var searchDebounceTimer = null;
		var currentLogPaged = 1;

		function loadAuditLogs(paged) {
			if (typeof paged !== 'undefined') {
				currentLogPaged = paged;
			}

			var $form = $('#ip2loc_audit_filter_form');
			if (!$form.length || !window.ip2locAdminData) return;

			var s = $('#ip2loc_log_search').val() || '';
			var action = $('#ip2loc_log_action').val() || '';
			var endpoint = $('#ip2loc_log_endpoint').val() || '';
			var perPage = $('#ip2loc_log_per_page').val() || 10;

			var $spinner = $('#ip2loc_filter_spinner');
			var $resetBtn = $('#ip2loc_btn_reset_filters');
			var $tbody = $('#ip2loc_audit_logs_tbody');
			var $paginationWrap = $('#ip2loc_audit_pagination_wrap');

			$spinner.css('display', 'inline-flex');
			$tbody.css('opacity', '0.5');

			if (s !== '' || action !== '' || endpoint !== '' || parseInt(perPage, 10) !== 10) {
				$resetBtn.show();
			} else {
				$resetBtn.hide();
			}

			$.ajax({
				url: ip2locAdminData.ajax_url,
				type: 'POST',
				dataType: 'json',
				data: {
					action: 'ip2loc_filter_audit_logs',
					nonce: ip2locAdminData.nonce,
					s: s,
					action_filter: action,
					endpoint_filter: endpoint,
					per_page: perPage,
					paged: currentLogPaged
				},
				success: function(res) {
					$spinner.hide();
					$tbody.css('opacity', '1');
					if (res && res.success) {
						$tbody.html(res.data.html_tbody);
						$paginationWrap.html(res.data.html_pagination);
					}
				},
				error: function() {
					$spinner.hide();
					$tbody.css('opacity', '1');
				}
			});
		}

		// Trigger on select change
		$(document).on('change', '#ip2loc_log_action, #ip2loc_log_endpoint, #ip2loc_log_per_page', function() {
			loadAuditLogs(1);
		});

		// Trigger on search input (debounced)
		$(document).on('input', '#ip2loc_log_search', function() {
			clearTimeout(searchDebounceTimer);
			searchDebounceTimer = setTimeout(function() {
				loadAuditLogs(1);
			}, 350);
		});

		// Pagination click
		$(document).on('click', '.ip2loc-ajax-page', function(e) {
			e.preventDefault();
			var targetPaged = $(this).data('paged');
			if (targetPaged) {
				loadAuditLogs(targetPaged);
			}
		});

		// Reset filters
		$(document).on('click', '#ip2loc_btn_reset_filters', function(e) {
			e.preventDefault();
			$('#ip2loc_log_search').val('');
			$('#ip2loc_log_action').val('');
			$('#ip2loc_log_endpoint').val('');
			$('#ip2loc_log_per_page').val('10');
			loadAuditLogs(1);
		});

		// 9. Clear All Logs
		$('#ip2loc_btn_clear_logs').on('click', function(e) {
			e.preventDefault();
			if (!confirm(ip2locAdminData.confirm_clear)) {
				return;
			}

			$.ajax({
				url: ip2locAdminData.ajax_url,
				type: 'POST',
				dataType: 'json',
				data: {
					action: 'ip2loc_clear_logs',
					nonce: ip2locAdminData.nonce
				},
				success: function(response) {
					if (response.success) {
						window.location.reload();
					} else {
						alert(response.data.message || 'Failed to clear logs.');
					}
				}
			});
		});

		// 10. Dismiss Admin Notice
		$(document).on('click', '.ip2loc-admin-notice .notice-dismiss', function() {
			$.ajax({
				url: ip2locAdminData.ajax_url,
				type: 'POST',
				data: {
					action: 'ip2loc_dismiss_notice',
					nonce: ip2locAdminData.nonce
				}
			});
		});

		// 11. Chart.js Initialization on Dashboard
		var chartCanvas = document.getElementById('ip2locTrendChart');
		if (chartCanvas && typeof Chart !== 'undefined') {
			var trendsData = window.ip2locDailyTrends || [];
			var labels = [];
			var totalCounts = [];
			var blockedCounts = [];

			// If empty trend data, build last 7 days placeholder
			if (trendsData.length === 0) {
				for (var i = 6; i >= 0; i--) {
					var d = new Date();
					d.setDate(d.getDate() - i);
					labels.push(d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }));
					totalCounts.push(0);
					blockedCounts.push(0);
				}
			} else {
				trendsData.forEach(function(item) {
					labels.push(item.date_val);
					totalCounts.push(parseInt(item.total, 10) || 0);
					blockedCounts.push(parseInt(item.blocked, 10) || 0);
				});
			}

			new Chart(chartCanvas, {
				type: 'line',
				data: {
					labels: labels,
					datasets: [
						{
							label: 'Total Requests',
							data: totalCounts,
							borderColor: '#3b82f6',
							backgroundColor: 'rgba(59, 130, 246, 0.1)',
							borderWidth: 2,
							fill: true,
							tension: 0.3
						},
						{
							label: 'Blocked Threats',
							data: blockedCounts,
							borderColor: '#ef4444',
							backgroundColor: 'rgba(239, 68, 68, 0.1)',
							borderWidth: 2,
							fill: true,
							tension: 0.3
						}
					]
				},
				options: {
					responsive: true,
					maintainAspectRatio: false,
					plugins: {
						legend: {
							position: 'top',
							labels: {
								boxWidth: 12,
								font: { size: 12 }
							}
						}
					},
					scales: {
						y: {
							beginAtZero: true,
							ticks: {
								precision: 0
							}
						}
					}
				}
			});
		}

	});
})(jQuery);
