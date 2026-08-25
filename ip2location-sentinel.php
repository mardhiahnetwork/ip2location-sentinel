<?php
/**
 * Plugin Name:       IP2Location Sentinel – Geo-Security & Fraud Prevention
 * Plugin URI:        https://www.ip2location.io
 * Description:       Geo-blocking firewall, impossible travel 2FA verification, comment spam filtering, and proxy detection powered by IP2Location.io.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Mardhiah Air Network
 * Author URI:        mailto:mardhiahnetwork@gmail.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       ip2location-sentinel
 * Domain Path:       /languages
 *
 * @package           IP2Location_Sentinel
 * @author            Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Plugin Constants
define( 'IP2LOC_VERSION', '1.0.0' );
define( 'IP2LOC_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'IP2LOC_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'IP2LOC_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );

/**
 * PSR-4 Compliant Autoloader for IP2Location\Sentinel namespace
 */
spl_autoload_register(
	function ( $class ) {
		$prefix   = 'IP2Location\\Sentinel\\';
		$base_dir = IP2LOC_PLUGIN_DIR . 'src/';

		$len = strlen( $prefix );
		if ( strncmp( $prefix, $class, $len ) !== 0 ) {
			return;
		}

		$relative_class = substr( $class, $len );
		$file           = $base_dir . str_replace( '\\', '/', $relative_class ) . '.php';

		if ( file_exists( $file ) ) {
			require_once $file;
		}
	}
);

use IP2Location\Sentinel\Activator;
use IP2Location\Sentinel\Deactivator;
use IP2Location\Sentinel\CacheCompat;
use IP2Location\Sentinel\Firewall;
use IP2Location\Sentinel\ImpossibleTravel;
use IP2Location\Sentinel\Admin;
use IP2Location\Sentinel\Logger;

/**
 * Activation & Deactivation Hooks
 */
register_activation_hook( __FILE__, array( Activator::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( Deactivator::class, 'deactivate' ) );

/**
 * Initialize Plugin Components
 */
function ip2loc_sentinel_init() {
	// Load Text Domain
	load_plugin_textdomain( 'ip2location-sentinel', false, dirname( IP2LOC_PLUGIN_BASENAME ) . '/languages' );

	// Initialize Caching Compatibility Layer
	CacheCompat::init();

	// Initialize Security Firewall Interceptors
	Firewall::init();

	// Initialize Impossible Travel & 2FA Engine
	ImpossibleTravel::init();

	// Initialize Admin Dashboard and Settings
	if ( is_admin() ) {
		Admin::init();
	}

	// Register cron maintenance action
	add_action( 'ip2loc_daily_maintenance_cron', 'ip2loc_run_daily_maintenance' );
}
add_action( 'plugins_loaded', 'ip2loc_sentinel_init', 5 );

/**
 * Daily Maintenance Cron Callback
 */
function ip2loc_run_daily_maintenance() {
	$settings = get_option( 'ip2loc_settings', array() );
	$days     = isset( $settings['log_retention_days'] ) ? (int) $settings['log_retention_days'] : 30;
	Logger::prune_logs( $days );
}

/**
 * Add Settings Link to Plugins Table
 *
 * @param array $links
 * @return array
 */
function ip2loc_add_action_links( $links ) {
	$plugin_links = array(
		'<a href="' . esc_url( admin_url( 'admin.php?page=ip2location-sentinel' ) ) . '">' . esc_html__( 'Dashboard', 'ip2location-sentinel' ) . '</a>',
		'<a href="' . esc_url( admin_url( 'admin.php?page=ip2loc-settings' ) ) . '">' . esc_html__( 'Settings', 'ip2location-sentinel' ) . '</a>',
	);
	return array_merge( $plugin_links, $links );
}
add_filter( 'plugin_action_links_' . IP2LOC_PLUGIN_BASENAME, 'ip2loc_add_action_links' );
