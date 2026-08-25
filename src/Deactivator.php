<?php
/**
 * Plugin Deactivation Handler
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Deactivator {

	/**
	 * Run deactivation cleanup tasks.
	 */
	public static function deactivate(): void {
		$timestamp = wp_next_scheduled( 'ip2loc_daily_maintenance_cron' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'ip2loc_daily_maintenance_cron' );
		}
	}
}
