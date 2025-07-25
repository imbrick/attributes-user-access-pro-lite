<?php

namespace Attributes\Security;

use Attributes\Core\Settings;

/**
 * IP Manager Class
 *
 * Manages IP-based security features including:
 * - Rate limiting for authentication actions
 * - IP blocking for malicious actors
 * - IP-based access controls
 * - Geolocation filtering
 *
 * @package Attributes\Security
 * @since   1.0.0
 */
class IP_Manager
{
    /**
     * Core settings instance.
     *
     * @since  1.0.0
     * @access private
     * @var    Settings
     */
    private Settings $settings;

    /**
     * Rate limiting configuration.
     *
     * @since  1.0.0
     * @access private
     * @var    array
     */
    private array $rate_limits = [];

    /**
     * IP whitelist.
     *
     * @since  1.0.0
     * @access private
     * @var    array
     */
    private array $whitelist = [];

    /**
     * IP blacklist.
     *
     * @since  1.0.0
     * @access private
     * @var    array
     */
    private array $blacklist = [];

    /**
     * Country code whitelist.
     *
     * @since  1.0.0
     * @access private
     * @var    array
     */
    private array $country_whitelist = [];

    /**
     * Country code blacklist.
     *
     * @since  1.0.0
     * @access private
     * @var    array
     */
    private array $country_blacklist = [];

    /**
     * Cached client IP.
     *
     * @since  1.0.0
     * @access private
     * @var    string|null
     */
    private ?string $client_ip = null;

    /**
     * Cached client country code.
     *
     * @since  1.0.0
     * @access private
     * @var    string|null
     */
    private ?string $client_country = null;

    /**
     * Constructor.
     *
     * Initialize IP manager with settings.
     *
     * @since 1.0.0
     * @param Settings $settings Core settings instance.
     */
    public function __construct(Settings $settings)
    {
        $this->settings = $settings;
        $this->attrua_init_configurations();
        $this->attrua_init_hooks();
    }

    /**
     * Initialize IP configuration.
     *
     * Loads configuration settings for rate limiting, IP lists, and country restrictions.
     *
     * @since  1.0.0
     * @access private
     * @return void
     */
    private function attrua_init_configurations(): void
    {
        // Load rate limiting configurations
        $this->rate_limits = [
            'login' => [
                'attempts' => (int) $this->settings->attrua_get('security.login_max_attempts', 5),
                'timeframe' => (int) $this->settings->attrua_get('security.login_timeframe', 300), // 5 minutes
                'lockout' => (int) $this->settings->attrua_get('security.login_lockout_duration', 900) // 15 minutes
            ],
            'register' => [
                'attempts' => (int) $this->settings->attrua_get('security.register_max_attempts', 3),
                'timeframe' => (int) $this->settings->attrua_get('security.register_timeframe', 3600), // 1 hour
                'lockout' => (int) $this->settings->attrua_get('security.register_lockout_duration', 86400) // 24 hours
            ],
            'reset_request' => [
                'attempts' => (int) $this->settings->attrua_get('security.reset_request_max_attempts', 3),
                'timeframe' => (int) $this->settings->attrua_get('security.reset_request_timeframe', 3600), // 1 hour
                'lockout' => (int) $this->settings->attrua_get('security.reset_request_lockout_duration', 3600) // 1 hour
            ],
            'reset_password' => [
                'attempts' => (int) $this->settings->attrua_get('security.reset_password_max_attempts', 3),
                'timeframe' => (int) $this->settings->attrua_get('security.reset_password_timeframe', 1800), // 30 minutes
                'lockout' => (int) $this->settings->attrua_get('security.reset_password_lockout_duration', 3600) // 1 hour
            ]
        ];

        // Load IP whitelist and blacklist
        $whitelist_string = $this->settings->attrua_get('security.ip_whitelist', '');
        $this->whitelist = $this->attrua_parse_ip_list($whitelist_string);

        $blacklist_string = $this->settings->attrua_get('security.ip_blacklist', '');
        $this->blacklist = $this->attrua_parse_ip_list($blacklist_string);

        // Load country whitelist and blacklist
        $country_whitelist_string = $this->settings->attrua_get('security.country_whitelist', '');
        $this->country_whitelist = array_map('trim', array_filter(explode(',', $country_whitelist_string)));

        $country_blacklist_string = $this->settings->attrua_get('security.country_blacklist', '');
        $this->country_blacklist = array_map('trim', array_filter(explode(',', $country_blacklist_string)));
    }

    /**
     * Initialize WordPress hooks.
     *
     * Sets up filters and actions for IP management.
     *
     * @since  1.0.0
     * @access private
     * @return void
     */
    private function attrua_init_hooks(): void
    {
        // Check for IP blocking early
        add_action('init', [$this, 'attrua_check_ip_access'], 1);

        // Clean up expired records periodically
        add_action('wp_scheduled_delete', [$this, 'attrua_cleanup_expired_records']);

        // Register REST API endpoints for admin interface
        add_action('rest_api_init', [$this, 'attrua_register_rest_routes']);
    }

    /**
     * Register REST API routes.
     *
     * Sets up REST API endpoints for admin features like IP blocking.
     *
     * @since  1.0.0
     * @access public
     * @return void
     */
    public function attrua_register_rest_routes(): void
    {
        register_rest_route('attributes-user-access/v1', '/security/ip-block', [
            'methods' => 'POST',
            'callback' => [$this, 'attrua_rest_block_ip'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
            'args' => [
                'ip' => [
                    'required' => true,
                    'sanitize_callback' => 'sanitize_text_field'
                ],
                'reason' => [
                    'sanitize_callback' => 'sanitize_text_field'
                ]
            ]
        ]);

        register_rest_route('attributes-user-access/v1', '/security/ip-unblock', [
            'methods' => 'POST',
            'callback' => [$this, 'attrua_rest_unblock_ip'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
            'args' => [
                'ip' => [
                    'required' => true,
                    'sanitize_callback' => 'sanitize_text_field'
                ]
            ]
        ]);
    }

    /**
     * REST API callback for blocking an IP.
     *
     * @since  1.0.0
     * @param  \WP_REST_Request $request REST API request.
     * @return \WP_REST_Response Response object.
     */
    public function attrua_rest_block_ip(\WP_REST_Request $request): \WP_REST_Response
    {
        $ip = $request->get_param('ip');
        $reason = $request->get_param('reason') ?: '';

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Invalid IP address format', 'attributes-user-access-pro-lite')
            ], 400);
        }

        $this->attrua_block_ip($ip, $reason);

        return new \WP_REST_Response([
            'success' => true,
            'message' => sprintf(__('IP address %s has been blocked', 'attributes-user-access-pro-lite'), $ip)
        ]);
    }

    /**
     * REST API callback for unblocking an IP.
     *
     * @since  1.0.0
     * @param  \WP_REST_Request $request REST API request.
     * @return \WP_REST_Response Response object.
     */
    public function attrua_rest_unblock_ip(\WP_REST_Request $request): \WP_REST_Response
    {
        $ip = $request->get_param('ip');

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('Invalid IP address format', 'attributes-user-access-pro-lite')
            ], 400);
        }

        $this->attrua_unblock_ip($ip);

        return new \WP_REST_Response([
            'success' => true,
            'message' => sprintf(__('IP address %s has been unblocked', 'attributes-user-access-pro-lite'), $ip)
        ]);
    }

    /**
     * Check IP access restrictions.
     *
     * Validates current client IP against whitelist, blacklist, and country restrictions.
     * Blocks access if IP is not allowed.
     *
     * @since  1.0.0
     * @access public
     * @return void
     */
    public function attrua_check_ip_access(): void
    {
        // Skip check for logged-in administrators
        if (current_user_can('manage_options')) {
            return;
        }

        // Get client IP
        $client_ip = $this->attrua_get_client_ip();

        // Skip if IP cannot be determined
        if (empty($client_ip)) {
            return;
        }

        // Always allow whitelisted IPs
        if ($this->attrua_is_whitelisted($client_ip)) {
            return;
        }

        // Block blacklisted IPs
        if ($this->attrua_is_blacklisted($client_ip)) {
            $this->attrua_handle_blocked_ip('blacklisted');
            return;
        }

        // Check country restrictions if enabled
        if ($this->settings->attrua_get('security.country_restrictions_enabled', false)) {
            $country_code = $this->attrua_get_country_code($client_ip);

            // Skip if country cannot be determined
            if (!empty($country_code)) {
                // Check whitelist (if not empty)
                if (!empty($this->country_whitelist) && !in_array($country_code, $this->country_whitelist)) {
                    $this->attrua_handle_blocked_ip('country_not_whitelisted');
                    return;
                }

                // Check blacklist
                if (in_array($country_code, $this->country_blacklist)) {
                    $this->attrua_handle_blocked_ip('country_blacklisted');
                    return;
                }
            }
        }
    }

    /**
     * Handle blocked IP.
     *
     * Manages how to respond to blocked IPs, including custom pages or error codes.
     *
     * @since  1.0.0
     * @access private
     * @param  string $reason Reason for blocking.
     * @return void
     */
    private function attrua_handle_blocked_ip(string $reason): void
    {
        // Log the blocking event
        $this->attrua_log_ip_block($reason);

        // Determine response type
        $block_response = $this->settings->attrua_get('security.ip_block_response', 'standard');

        switch ($block_response) {
            case 'custom_page':
                $page_id = (int) $this->settings->attrua_get('security.ip_block_page', 0);
                if ($page_id > 0) {
                    wp_safe_redirect(get_permalink($page_id));
                    exit;
                }
                // Fall through to standard if page doesn't exist

            case '403':
                status_header(403);
                nocache_headers();
                echo '<h1>' . esc_html('Access Denied', 'attributes-user-access-pro-lite') . '</h1>';
                echo '<p>' . esc_html('Your access to this site has been restricted.', 'attributes-user-access-pro-lite') . '</p>';
                exit;

            case '404':
                status_header(404);
                nocache_headers();
                echo '<h1>' . esc_html('Not Found', 'attributes-user-access-pro-lite') . '</h1>';
                echo '<p>' . esc_html('The requested page could not be found.', 'attributes-user-access-pro-lite') . '</p>';
                exit;

            case 'standard':
            default:
                wp_die(
                    __('Your access to this site has been restricted.', 'attributes-user-access-pro-lite'),
                    __('Access Denied', 'attributes-user-access-pro-lite'),
                    ['response' => 403]
                );
        }
    }

    /**
     * Get client IP address.
     *
     * Determines the client's IP address, handling proxies and load balancers.
     * Caches the result for performance.
     *
     * @since  1.0.0
     * @access public
     * @return string Client IP address.
     */
    public function attrua_get_client_ip(): string
    {
        // Return cached value if already determined
        if ($this->client_ip !== null) {
            return $this->client_ip;
        }

        $ip = '';
        $ip_sources = [
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ];

        // Let settings determine which IP sources to trust
        $trusted_proxies = (bool) $this->settings->attrua_get('security.trust_proxies', false);
        if (!$trusted_proxies) {
            $ip_sources = ['REMOTE_ADDR']; // Only trust direct connection
        }

        // Check each IP source
        foreach ($ip_sources as $key) {
            if (!empty($_SERVER[$key])) {
                $value = sanitize_text_field(wp_unslash($_SERVER[$key]));

                // Handle comma-separated list (e.g., for X-Forwarded-For)
                if (strpos($value, ',') !== false) {
                    $ips = explode(',', $value);
                    $ip = trim($ips[0]);
                } else {
                    $ip = $value;
                }

                // If valid IP found, break the loop
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    break;
                }
            }
        }

        // Default to unknown if no valid IP found
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            $ip = '0.0.0.0';
        }

        // Cache the result
        $this->client_ip = $ip;

        return $ip;
    }

    /**
     * Check if an IP is whitelisted.
     *
     * Validates if an IP address is in the whitelist, supporting CIDR notation.
     *
     * @since  1.0.0
     * @access public
     * @param  string $ip IP address to check.
     * @return bool Whether the IP is whitelisted.
     */
    public function attrua_is_whitelisted(string $ip): bool
    {
        return $this->attrua_ip_in_list($ip, $this->whitelist);
    }

    /**
     * Check if an IP is blacklisted.
     *
     * Validates if an IP address is in the blacklist, supporting CIDR notation.
     *
     * @since  1.0.0
     * @access public
     * @param  string $ip IP address to check.
     * @return bool Whether the IP is blacklisted.
     */
    public function attrua_is_blacklisted(string $ip): bool
    {
        return $this->attrua_ip_in_list($ip, $this->blacklist);
    }

    /**
     * Check if IP is in a list.
     *
     * Determines if an IP address is in a given list, supporting CIDR notation.
     *
     * @since  1.0.0
     * @access private
     * @param  string $ip   IP address to check.
     * @param  array  $list List of IPs or CIDR ranges.
     * @return bool Whether the IP is in the list.
     */
    private function attrua_ip_in_list(string $ip, array $list): bool
    {
        // Validate IP format first
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // Convert IP to integer
        $ip_long = ip2long($ip);

        // Check against each entry in the list
        foreach ($list as $entry) {
            // Single IP address
            if (strpos($entry, '/') === false) {
                if ($ip === $entry) {
                    return true;
                }
                continue;
            }

            // CIDR notation (IP range)
            list($range, $netmask) = explode('/', $entry, 2);

            // Validate CIDR format
            if (!filter_var($range, FILTER_VALIDATE_IP) || !is_numeric($netmask) || $netmask < 0 || $netmask > 32) {
                continue;
            }

            // Convert range to integer
            $range_long = ip2long($range);

            // Calculate subnet mask
            $mask = ~((1 << (32 - (int)$netmask)) - 1);

            // Check if IP is in range
            if (($ip_long & $mask) === ($range_long & $mask)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parse IP list from string.
     *
     * Converts a comma or newline separated list of IPs into an array.
     *
     * @since  1.0.0
     * @access private
     * @param  string $list_string String containing IPs.
     * @return array Parsed and validated IP list.
     */
    private function attrua_parse_ip_list(string $list_string): array
    {
        // Replace newlines with commas, then split by comma
        $list_string = str_replace(["\r\n", "\n", "\r"], ',', $list_string);
        $items = explode(',', $list_string);

        // Trim and filter items
        $result = [];
        foreach ($items as $item) {
            $item = trim($item);

            // Skip empty items
            if (empty($item)) {
                continue;
            }

            // Single IP
            if (strpos($item, '/') === false) {
                if (filter_var($item, FILTER_VALIDATE_IP)) {
                    $result[] = $item;
                }
                continue;
            }

            // CIDR notation
            list($ip, $cidr) = explode('/', $item, 2);
            if (
                filter_var(trim($ip), FILTER_VALIDATE_IP) &&
                is_numeric(trim($cidr)) &&
                (int)trim($cidr) >= 0 &&
                (int)trim($cidr) <= 32
            ) {
                $result[] = trim($ip) . '/' . trim($cidr);
            }
        }

        return $result;
    }

    /**
     * Get country code from IP address.
     *
     * Uses various methods to determine the country of an IP address.
     * May use local GeoIP database, WordPress filters, or external APIs.
     *
     * @since  1.0.0
     * @access public
     * @param  string $ip IP address.
     * @return string Two-letter country code or empty string if unknown.
     */
    public function attrua_get_country_code(string $ip): string
    {
        // Return cached value if already determined
        if ($this->client_country !== null && $ip === $this->client_ip) {
            return $this->client_country;
        }

        // Allow plugins to provide country code
        $country_code = apply_filters('attrua_ip_country_code', '', $ip);
        if (!empty($country_code)) {
            // Cache if this is the client IP
            if ($ip === $this->client_ip) {
                $this->client_country = $country_code;
            }
            return $country_code;
        }

        // Try built-in GeoIP database if available
        if (function_exists('geoip_country_code_by_name')) {
            $code = geoip_country_code_by_name($ip);
            if ($code !== false) {
                // Cache if this is the client IP
                if ($ip === $this->client_ip) {
                    $this->client_country = $code;
                }
                return $code;
            }
        }

        // Try to use the IP-API service if external APIs are allowed
        $use_external_api = (bool) $this->settings->attrua_get('security.use_external_geoip', false);
        if ($use_external_api) {
            $response = wp_remote_get("http://ip-api.com/json/{$ip}?fields=countryCode", [
                'timeout' => 5,
                'user-agent' => 'WordPress/attributes-user-access-pro-lite'
            ]);

            if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
                $data = json_decode(wp_remote_retrieve_body($response), true);
                if (isset($data['countryCode']) && !empty($data['countryCode'])) {
                    $code = $data['countryCode'];
                    // Cache if this is the client IP
                    if ($ip === $this->client_ip) {
                        $this->client_country = $code;
                    }
                    return $code;
                }
            }
        }

        // Could not determine country
        return '';
    }

    /**
     * Record an action for rate limiting.
     *
     * Tracks authentication actions for rate limiting purposes.
     *
     * @since  1.0.0
     * @access public
     * @param  string $action Action type (login, register, reset_request, etc.).
     * @param  string $ip     Optional. IP address to record. Default is client IP.
     * @return void
     */
    public function attrua_record_action(string $action, string $ip = ''): void
    {
        // Skip if rate limiting is not configured for this action
        if (!isset($this->rate_limits[$action])) {
            return;
        }

        // Use client IP if not specified
        if (empty($ip)) {
            $ip = $this->attrua_get_client_ip();
        }

        // Get current records for this action
        $records = get_transient("attrua_rate_limit_{$action}_{$ip}");
        if (!is_array($records)) {
            $records = [];
        }

        // Add current timestamp
        $records[] = time();

        // Store updated records
        set_transient("attrua_rate_limit_{$action}_{$ip}", $records, DAY_IN_SECONDS);

        // Check if this triggers a lockout
        $this->attrua_maybe_create_lockout($action, $ip, count($records));
    }

    /**
     * Check if an action can be performed based on rate limits.
     *
     * Determines if an authentication action is allowed based on rate limiting rules.
     *
     * @since  1.0.0
     * @access public
     * @param  string $action Action type (login, register, reset_request, etc.).
     * @param  string $ip     Optional. IP address to check. Default is client IP.
     * @return bool Whether the action is allowed.
     */
    public function attrua_can_perform_action(string $action, string $ip = ''): bool
    {
        // Skip check if rate limiting is not configured for this action
        if (!isset($this->rate_limits[$action])) {
            return true;
        }

        // Use client IP if not specified
        if (empty($ip)) {
            $ip = $this->attrua_get_client_ip();
        }

        // Always allow whitelisted IPs
        if ($this->attrua_is_whitelisted($ip)) {
            return true;
        }

        // Check if IP is currently locked out
        $lockout = get_transient("attrua_lockout_{$action}_{$ip}");
        if ($lockout !== false) {
            return false;
        }

        // Get current records for this action
        $records = get_transient("attrua_rate_limit_{$action}_{$ip}");
        if (!is_array($records)) {
            return true; // No records found
        }

        // Filter records within the current timeframe
        $timeframe = $this->rate_limits[$action]['timeframe'];
        $cutoff = time() - $timeframe;
        $recent_records = array_filter($records, function ($timestamp) use ($cutoff) {
            return $timestamp >= $cutoff;
        });

        // Check if attempts exceed the limit
        $max_attempts = $this->rate_limits[$action]['attempts'];
        return count($recent_records) < $max_attempts;
    }

    /**
     * Create a lockout if rate limit is exceeded.
     *
     * Creates a lockout if the number of actions exceeds the limit.
     *
     * @since  1.0.0
     * @access private
     * @param  string $action   Action type.
     * @param  string $ip       IP address.
     * @param  int    $attempts Current number of attempts.
     * @return void
     */
    private function attrua_maybe_create_lockout(string $action, string $ip, int $attempts): void
    {
        // Skip if rate limiting is not configured for this action
        if (!isset($this->rate_limits[$action])) {
            return;
        }

        // Get rate limit configuration
        $max_attempts = $this->rate_limits[$action]['attempts'];
        $timeframe = $this->rate_limits[$action]['timeframe'];
        $lockout_duration = $this->rate_limits[$action]['lockout'];

        // Check if attempts exceed the limit
        if ($attempts >= $max_attempts) {
            // Filter records within the current timeframe to confirm
            $records = get_transient("attrua_rate_limit_{$action}_{$ip}");
            if (!is_array($records)) {
                return; // No records found
            }

            $cutoff = time() - $timeframe;
            $recent_records = array_filter($records, function ($timestamp) use ($cutoff) {
                return $timestamp >= $cutoff;
            });

            if (count($recent_records) >= $max_attempts) {
                // Create lockout
                set_transient("attrua_lockout_{$action}_{$ip}", time(), $lockout_duration);

                // Log the lockout
                $this->attrua_log_lockout($action, $ip, $lockout_duration);
            }
        }
    }

    /**
     * Block an IP address.
     *
     * Adds an IP to the blacklist with an optional reason.
     *
     * @since  1.0.0
     * @access public
     * @param  string $ip     IP address to block.
     * @param  string $reason Optional reason for blocking.
     * @return bool Whether the IP was blocked successfully.
     */
    public function attrua_block_ip(string $ip, string $reason = ''): bool
    {
        // Validate IP format
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // Check if IP is already blacklisted
        if ($this->attrua_is_blacklisted($ip)) {
            return true; // Already blocked
        }

        // Add to blacklist
        $this->blacklist[] = $ip;

        // Update setting
        $blacklist_string = implode(',', $this->blacklist);
        $updated = $this->settings->attrua_update('security.ip_blacklist', $blacklist_string);

        // Log the blocking
        if ($updated) {
            $this->attrua_log_ip_block('manual_block', $ip, $reason);
        }

        return $updated;
    }

    /**
     * Unblock an IP address.
     *
     * Removes an IP from the blacklist.
     *
     * @since  1.0.0
     * @access public
     * @param  string $ip IP address to unblock.
     * @return bool Whether the IP was unblocked successfully.
     */
    public function attrua_unblock_ip(string $ip): bool
    {
        // Validate IP format
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // Check if IP is in the blacklist
        $key = array_search($ip, $this->blacklist);
        if ($key === false) {
            return true; // Not blocked
        }

        // Remove from blacklist
        unset($this->blacklist[$key]);
        $this->blacklist = array_values($this->blacklist); // Re-index array

        // Update setting
        $blacklist_string = implode(',', $this->blacklist);
        $updated = $this->settings->attrua_update('security.ip_blacklist', $blacklist_string);

        // Log the unblocking
        if ($updated) {
            $this->attrua_log_ip_unblock($ip);
        }

        return $updated;
    }

    /**
     * Log IP blocking event.
     *
     * Records information about IP blocking for audit purposes.
     *
     * @since  1.0.0
     * @access private
     * @param  string $reason Reason for blocking.
     * @param  string $ip     Optional. IP address that was blocked. Default is client IP.
     * @param  string $note   Optional. Additional notes about the blocking.
     * @return void
     */
    private function attrua_log_ip_block(string $reason, string $ip = '', string $note = ''): void
    {
        if (empty($ip)) {
            $ip = $this->attrua_get_client_ip();
        }

        $log_data = [
            'time' => current_time('mysql'),
            'ip' => $ip,
            'reason' => $reason,
            'note' => $note,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        ];

        // Add country information if available
        $country = $this->attrua_get_country_code($ip);
        if (!empty($country)) {
            $log_data['country'] = $country;
        }

        // Use WordPress options table for log storage
        $logs = get_option('attrua_ip_block_log', []);
        $logs[] = $log_data;

        // Limit log size to prevent excessive storage
        if (count($logs) > 1000) {
            array_shift($logs);
        }

        update_option('attrua_ip_block_log', $logs);

        /**
         * Action: attrua_ip_blocked
         * 
         * Fires after an IP address is blocked.
         * 
         * @param array $log_data Details about the blocking event.
         */
        do_action('attrua_ip_blocked', $log_data);
    }

    /**
     * Log IP unblocking event.
     *
     * Records information about IP unblocking for audit purposes.
     *
     * @since  1.0.0
     * @access private
     * @param  string $ip IP address that was unblocked.
     * @return void
     */
    private function attrua_log_ip_unblock(string $ip): void
    {
        $log_data = [
            'time' => current_time('mysql'),
            'ip' => $ip,
            'action' => 'unblock',
            'user_id' => get_current_user_id()
        ];

        // Use WordPress options table for log storage
        $logs = get_option('attrua_ip_unblock_log', []);
        $logs[] = $log_data;

        // Limit log size
        if (count($logs) > 1000) {
            array_shift($logs);
        }

        update_option('attrua_ip_unblock_log', $logs);

        /**
         * Action: attrua_ip_unblocked
         * 
         * Fires after an IP address is unblocked.
         * 
         * @param array $log_data Details about the unblocking event.
         */
        do_action('attrua_ip_unblocked', $log_data);
    }

    /**
     * Log rate limit lockout event.
     *
     * Records information about lockouts for audit purposes.
     *
     * @since  1.0.0
     * @access private
     * @param  string $action    Action type that triggered the lockout.
     * @param  string $ip        IP address that was locked out.
     * @param  int    $duration  Lockout duration in seconds.
     * @return void
     */
    private function attrua_log_lockout(string $action, string $ip, int $duration): void
    {
        $log_data = [
            'time' => current_time('mysql'),
            'ip' => $ip,
            'action' => $action,
            'duration' => $duration,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        ];

        // Add country information if available
        $country = $this->attrua_get_country_code($ip);
        if (!empty($country)) {
            $log_data['country'] = $country;
        }

        // Use WordPress options table for log storage
        $logs = get_option('attrua_lockout_log', []);
        $logs[] = $log_data;

        // Limit log size
        if (count($logs) > 1000) {
            array_shift($logs);
        }

        update_option('attrua_lockout_log', $logs);

        /**
         * Action: attrua_lockout_created
         * 
         * Fires after a rate limit lockout is created.
         * 
         * @param array $log_data Details about the lockout event.
         */
        do_action('attrua_lockout_created', $log_data);
    }

    /**
     * Clean up expired rate limiting records.
     *
     * Removes old rate limiting records to keep the database clean.
     *
     * @since  1.0.0
     * @access public
     * @return void
     */
    public function attrua_cleanup_expired_records(): void
    {
        global $wpdb;

        // Clean up expired transients related to rate limiting
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM $wpdb->options
                WHERE option_name LIKE %s
                AND option_value < %d",
                $wpdb->esc_like('_transient_timeout_attrua_rate_limit_') . '%',
                time()
            )
        );

        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM $wpdb->options
                WHERE option_name LIKE %s
                AND option_name NOT IN (
                    SELECT CONCAT('_transient_', SUBSTRING(option_name, %d))
                    FROM $wpdb->options
                    WHERE option_name LIKE %s
                )",
                $wpdb->esc_like('_transient_attrua_rate_limit_') . '%',
                strlen('_transient_timeout_') + 1,
                $wpdb->esc_like('_transient_timeout_attrua_rate_limit_') . '%'
            )
        );

        // Clean up expired lockouts
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM $wpdb->options
                WHERE option_name LIKE %s
                AND option_value < %d",
                $wpdb->esc_like('_transient_timeout_attrua_lockout_') . '%',
                time()
            )
        );

        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM $wpdb->options
                WHERE option_name LIKE %s
                AND option_name NOT IN (
                    SELECT CONCAT('_transient_', SUBSTRING(option_name, %d))
                    FROM $wpdb->options
                    WHERE option_name LIKE %s
                )",
                $wpdb->esc_like('_transient_attrua_lockout_') . '%',
                strlen('_transient_timeout_') + 1,
                $wpdb->esc_like('_transient_timeout_attrua_lockout_') . '%'
            )
        );
    }

    /**
     * Get all current lockouts.
     *
     * Retrieves information about currently active lockouts.
     *
     * @since  1.0.0
     * @access public
     * @return array Array of active lockouts with IP, action, and expiry time.
     */
    public function attrua_get_active_lockouts(): array
    {
        global $wpdb;

        $lockouts = [];

        // Query transients for lockouts
        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT option_name, option_value FROM $wpdb->options
                WHERE option_name LIKE %s",
                $wpdb->esc_like('_transient_timeout_attrua_lockout_') . '%'
            )
        );

        foreach ($results as $result) {
            // Extract IP and action from transient name
            $transient_name = str_replace('_transient_timeout_attrua_lockout_', '', $result->option_name);
            $parts = explode('_', $transient_name, 2);

            if (count($parts) === 2) {
                $action = $parts[0];
                $ip = $parts[1];

                $lockouts[] = [
                    'ip' => $ip,
                    'action' => $action,
                    'expires' => (int) $result->option_value
                ];
            }
        }

        return $lockouts;
    }
}
