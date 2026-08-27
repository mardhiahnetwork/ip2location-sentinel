<?php
/**
 * Plugin Uninstall Cleanup Handler
 *
 * Triggered only when the plugin is uninstalled via WordPress Admin.
 *
 * @package IP2Location_Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

$settings = get_option( 'ip2loc_settings', array() );

// Only delete database and settings if user enabled "Delete Data on Uninstall"
if ( ! empty( $settings['delete_data_on_uninstall'] ) ) {
	global $wpdb;

	// 1. Drop Custom Tables
	$table_name    = $wpdb->prefix . 'ip2location_logs';
	$captcha_table = $wpdb->prefix . 'ip2location_captcha_locks';
	$wpdb->query( "DROP TABLE IF EXISTS {$table_name}" );
	$wpdb->query( "DROP TABLE IF EXISTS {$captcha_table}" );

	// 2. Delete Plugin Options
	delete_option( 'ip2loc_settings' );
	delete_option( 'ip2loc_last_api_error' );
	delete_option( 'ip2loc_notice_dismissed' );

	// 3. Delete Transients
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_ip2loc_%' OR option_name LIKE '_transient_timeout_ip2loc_%'" );

	// 4. Delete User Meta
	$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE '_ip2loc_%'" );

	// 5. Unschedule Cron
	$timestamp = wp_next_scheduled( 'ip2loc_daily_maintenance_cron' );
	if ( $timestamp ) {
		wp_unschedule_event( $timestamp, 'ip2loc_daily_maintenance_cron' );
	}
}
