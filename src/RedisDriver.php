<?php
/**
 * Redis Auto-Detection & High-Performance In-Memory Cache Driver
 *
 * Automatically detects and connects to Redis when available, falling back
 * gracefully to WordPress Transients and DB when Redis is unavailable.
 *
 * @package IP2Location\Sentinel
 * @author  Mardhiah Air Network <mardhiahnetwork@gmail.com>
 */

namespace IP2Location\Sentinel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class RedisDriver {

	/**
	 * Redis instance.
	 *
	 * @var \Redis|null
	 */
	private static $redis = null;

	/**
	 * Connection status cache.
	 *
	 * @var bool|null
	 */
	private static $is_connected = null;

	/**
	 * Check if Redis is available and connected.
	 *
	 * @return bool
	 */
	public static function is_available(): bool {
		if ( null !== self::$is_connected ) {
			return self::$is_connected;
		}

		if ( ! extension_loaded( 'redis' ) || ! class_exists( '\Redis' ) ) {
			self::$is_connected = false;
			return false;
		}

		try {
			$host    = defined( 'WP_REDIS_HOST' ) ? WP_REDIS_HOST : '127.0.0.1';
			$port    = defined( 'WP_REDIS_PORT' ) ? (int) WP_REDIS_PORT : 6379;
			$auth    = defined( 'WP_REDIS_PASSWORD' ) ? WP_REDIS_PASSWORD : null;
			$timeout = 0.2; // 200ms ultra-fast connection timeout

			$client = new \Redis();
			$connected = @$client->connect( $host, $port, $timeout );

			if ( $connected ) {
				if ( ! empty( $auth ) ) {
					@$client->auth( $auth );
				}
				self::$redis        = $client;
				self::$is_connected = true;
				return true;
			}
		} catch ( \Throwable $e ) {
			// Redis unavailable or failed
		}

		self::$is_connected = false;
		return false;
	}

	/**
	 * Get detailed Redis status information.
	 *
	 * @return array
	 */
	public static function get_status(): array {
		$available = self::is_available();
		$host      = defined( 'WP_REDIS_HOST' ) ? WP_REDIS_HOST : '127.0.0.1';
		$port      = defined( 'WP_REDIS_PORT' ) ? (int) WP_REDIS_PORT : 6379;

		return array(
			'available' => $available,
			'host'      => $host,
			'port'      => $port,
			'label'     => $available ? sprintf( __( 'Auto-Connected (%s:%d)', 'locasentinel' ), $host, $port ) : __( 'Disabled / Not Available (Using WP Transients)', 'locasentinel' ),
		);
	}

	/**
	 * Get value from Redis or fallback to transient.
	 *
	 * @param string $key
	 * @return mixed
	 */
	public static function get( string $key ) {
		if ( self::is_available() && self::$redis ) {
			try {
				$val = self::$redis->get( 'ip2loc:' . $key );
				if ( false !== $val ) {
					$unserialized = @unserialize( $val );
					return false !== $unserialized || $val === 'b:0;' ? $unserialized : $val;
				}
				return false;
			} catch ( \Throwable $e ) {
				// Fallback to transient
			}
		}

		return function_exists( 'get_transient' ) ? get_transient( 'ip2loc_' . $key ) : false;
	}

	/**
	 * Set value in Redis with TTL or fallback to transient.
	 *
	 * @param string $key
	 * @param mixed  $value
	 * @param int    $ttl
	 * @return bool
	 */
	public static function set( string $key, $value, int $ttl = 86400 ): bool {
		if ( self::is_available() && self::$redis ) {
			try {
				$serialized = is_scalar( $value ) ? (string) $value : serialize( $value );
				return self::$redis->setex( 'ip2loc:' . $key, $ttl, $serialized );
			} catch ( \Throwable $e ) {
				// Fallback
			}
		}

		return function_exists( 'set_transient' ) ? set_transient( 'ip2loc_' . $key, $value, $ttl ) : false;
	}

	/**
	 * Increment a counter in Redis or fallback to transient.
	 *
	 * @param string $key
	 * @param int    $ttl
	 * @return int New count value.
	 */
	public static function incr( string $key, int $ttl = 60 ): int {
		if ( self::is_available() && self::$redis ) {
			try {
				$redis_key = 'ip2loc:' . $key;
				$new_val   = self::$redis->incr( $redis_key );
				if ( (int) $new_val === 1 ) {
					self::$redis->expire( $redis_key, $ttl );
				}
				return (int) $new_val;
			} catch ( \Throwable $e ) {
				// Fallback
			}
		}

		if ( ! function_exists( 'get_transient' ) || ! function_exists( 'set_transient' ) ) {
			return 1;
		}

		$current = (int) get_transient( 'ip2loc_' . $key );
		$new_val = $current + 1;
		set_transient( 'ip2loc_' . $key, $new_val, $ttl );
		return $new_val;
	}

	/**
	 * Delete key from Redis and transient.
	 *
	 * @param string $key
	 * @return bool
	 */
	public static function delete( string $key ): bool {
		if ( self::is_available() && self::$redis ) {
			try {
				self::$redis->del( 'ip2loc:' . $key );
			} catch ( \Throwable $e ) {
				// Ignore
			}
		}

		return function_exists( 'delete_transient' ) ? delete_transient( 'ip2loc_' . $key ) : false;
	}
}
