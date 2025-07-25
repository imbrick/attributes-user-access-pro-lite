<?php

namespace Attributes\Security;

use Attributes\Core\Settings;

/**
 * Security Audit Log Class
 *
 * Provides comprehensive security event logging capabilities including:
 * - Authentication activities (login, logout, password resets)
 * - Security events (failed logins, lockouts, suspicious activity)
 * - Administrative changes to security settings
 * - Export and retention management
 *
 * @package Attributes\Security
 * @since   1.0.0
 */
class Audit_Log
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
     * Whether audit logging is enabled.
     *
     * @since  1.0.0
     * @access private
     * @var    bool
     */
    private bool $logging_enabled = true;

    /**
     * Log retention period in days.
     *
     * @since  1.0.0
     * @access private
     * @var    int
     */
    private int $retention_days = 30;

    /**
     * Event types with descriptions.
     *
     * @since  1.0.0
     * @access private
     * @var    array
     */
    private array $event_types = [];

    /**
     * Database table name.
     *
     * @since  1.0.0
     * @access private
     * @var    string
     */
    private string $table_name = '';

    /**
     * IP manager instance for IP information.
     *
     * @since  1.0.0
     * @access private
     * @var    IP_Manager|null
     */
    private ?IP_Manager $ip_manager = null;

    /**
     * Constructor.
     *
     * Initialize audit log with settings.
     *
     * @since 1.0.0
     * @param Settings $settings Core settings instance.
     */
    public function __construct(Settings $settings)
    {
        global $wpdb;

        $this->settings = $settings;
        $this->table_name = $wpdb->prefix . 'attrua_audit_log';

        // Load configurations
        $this->logging_enabled = (bool) $this->settings->attrua_get('security.audit_logging_enabled', true);
        $this->retention_days = (int) $this->settings->attrua_get('security.audit_log_retention', 30);

        // Initialize IP manager if possible
        $this->ip_manager = class_exists('\\Attributes\\Security\\IP_Manager') ? new IP_Manager($settings) : null;

        // Initialize event types
        $this->attrua_init_event_types();

        // Initialize hooks
        $this->attrua_init_hooks();
    }

    /**
     * Initialize event types.
     *
     * Defines all available event types with descriptions.
     *
     * @since  1.0.0
     * @access private
     * @return void
     */
    private function attrua_init_event_types(): void
    {
        $this->event_types = [
            // Authentication events
            'login_success' => __('Successful login', 'attributes-user-access-pro-lite'),
            'login_failed' => __('Failed login attempt', 'attributes-user-access-pro-lite'),
            'logout' => __('User logout', 'attributes-user-access-pro-lite'),
            'password_reset_request' => __('Password reset requested', 'attributes-user-access-pro-lite'),
            'password_reset_success' => __('Password reset successful', 'attributes-user-access-pro-lite'),
            'password_reset_failed' => __('Password reset failed', 'attributes-user-access-pro-lite'),

            // User management events
            'user_registered' => __('New user registration', 'attributes-user-access-pro-lite'),
            'user_deleted' => __('User account deleted', 'attributes-user-access-pro-lite'),
            'user_role_changed' => __('User role changed', 'attributes-user-access-pro-lite'),

            // Security events
            'login_rate_limited' => __('Login rate limit reached', 'attributes-user-access-pro-lite'),
            'reset_rate_limited' => __('Password reset rate limit reached', 'attributes-user-access-pro-lite'),
            'reset_invalid_user' => __('Password reset for invalid user', 'attributes-user-access-pro-lite'),
            'reset_invalid_token' => __('Invalid password reset token used', 'attributes-user-access-pro-lite'),
            'reset_email_sent' => __('Password reset email sent', 'attributes-user-access-pro-lite'),
            'reset_email_failed' => __('Failed to send password reset email', 'attributes-user-access-pro-lite'),
            'suspicious_activity' => __('Suspicious activity detected', 'attributes-user-access-pro-lite'),

            // IP management events
            'ip_blocked' => __('IP address blocked', 'attributes-user-access-pro-lite'),
            'ip_unblocked' => __('IP address unblocked', 'attributes-user-access-pro-lite'),
            'country_blocked' => __('Access blocked by country', 'attributes-user-access-pro-lite'),

            // Admin events
            'settings_changed' => __('Security settings changed', 'attributes-user-access-pro-lite'),
            'logs_exported' => __('Audit logs exported', 'attributes-user-access-pro-lite'),
            'logs_cleared' => __('Audit logs cleared', 'attributes-user-access-pro-lite')
        ];

        /**
         * Filter: attrua_audit_event_types
         * 
         * Allows adding or modifying audit event types.
         *
         * @param array $event_types Array of event types with descriptions.
         */
        $this->event_types = apply_filters('attrua_audit_event_types', $this->event_types);
    }

    /**
     * Initialize WordPress hooks.
     *
     * Sets up actions and filters for audit logging.
     *
     * @since  1.0.0
     * @access private
     * @return void
     */
    private function attrua_init_hooks(): void
    {
        // Schedule cleanup of old logs
        if (!wp_next_scheduled('attrua_audit_log_cleanup')) {
            wp_schedule_event(time(), 'daily', 'attrua_audit_log_cleanup');
        }
        add_action('attrua_audit_log_cleanup', [$this, 'attrua_cleanup_old_logs']);

        // Register REST API endpoints for admin interface
        add_action('rest_api_init', [$this, 'attrua_register_rest_routes']);

        // Plugin activation and deactivation
        register_activation_hook(ATTRUA_FILE, [$this, 'attrua_create_log_table']);
        register_deactivation_hook(ATTRUA_FILE, [$this, 'attrua_unschedule_cleanup']);

        // Core WordPress authentication hooks
        add_action('wp_login', [$this, 'attrua_log_login'], 10, 2);
        add_action('wp_login_failed', [$this, 'attrua_log_login_failed']);
        add_action('wp_logout', [$this, 'attrua_log_logout']);
        add_action('user_register', [$this, 'attrua_log_user_registered']);
        add_action('delete_user', [$this, 'attrua_log_user_deleted']);
        add_action('set_user_role', [$this, 'attrua_log_role_changed'], 10, 3);
    }

    /**
     * Register REST API routes.
     *
     * Sets up REST API endpoints for audit log management.
     *
     * @since  1.0.0
     * @access public
     * @return void
     */
    public function attrua_register_rest_routes(): void
    {
        register_rest_route('attributes-user-access/v1', '/audit-log', [
            'methods' => 'GET',
            'callback' => [$this, 'attrua_rest_get_logs'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
            'args' => [
                'page' => [
                    'default' => 1,
                    'sanitize_callback' => 'absint'
                ],
                'per_page' => [
                    'default' => 20,
                    'sanitize_callback' => 'absint'
                ],
                'event_type' => [
                    'sanitize_callback' => 'sanitize_text_field'
                ],
                'user_id' => [
                    'sanitize_callback' => 'absint'
                ],
                'ip' => [
                    'sanitize_callback' => 'sanitize_text_field'
                ],
                'date_from' => [
                    'sanitize_callback' => 'sanitize_text_field'
                ],
                'date_to' => [
                    'sanitize_callback' => 'sanitize_text_field'
                ]
            ]
        ]);

        register_rest_route('attributes-user-access/v1', '/audit-log/export', [
            'methods' => 'GET',
            'callback' => [$this, 'attrua_rest_export_logs'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            }
        ]);

        register_rest_route('attributes-user-access/v1', '/audit-log/clear', [
            'methods' => 'POST',
            'callback' => [$this, 'attrua_rest_clear_logs'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            }
        ]);
    }

    /**
     * REST API callback for getting logs.
     *
     * @since  1.0.0
     * @param  \WP_REST_Request $request REST API request.
     * @return \WP_REST_Response Response object.
     */
    public function attrua_rest_get_logs(\WP_REST_Request $request): \WP_REST_Response
    {
        $page = $request->get_param('page');
        $per_page = $request->get_param('per_page');
        $event_type = $request->get_param('event_type');
        $user_id = $request->get_param('user_id');
        $ip = $request->get_param('ip');
        $date_from = $request->get_param('date_from');
        $date_to = $request->get_param('date_to');

        $filters = [];
        if (!empty($event_type)) {
            $filters['event_type'] = $event_type;
        }
        if (!empty($user_id)) {
            $filters['user_id'] = $user_id;
        }
        if (!empty($ip)) {
            $filters['ip'] = $ip;
        }
        if (!empty($date_from)) {
            $filters['date_from'] = $date_from;
        }
        if (!empty($date_to)) {
            $filters['date_to'] = $date_to;
        }

        $logs = $this->attrua_get_logs($page, $per_page, $filters);
        $total = $this->attrua_count_logs($filters);

        return new \WP_REST_Response([
            'logs' => $logs,
            'total' => $total,
            'pages' => ceil($total / $per_page)
        ]);
    }

    /**
     * REST API callback for exporting logs.
     *
     * @since  1.0.0
     * @param  \WP_REST_Request $request REST API request.
     * @return \WP_REST_Response Response object.
     */
    public function attrua_rest_export_logs(\WP_REST_Request $request): \WP_REST_Response
    {
        $format = $request->get_param('format') ?: 'csv';
        $logs = $this->attrua_get_logs(1, 10000); // Get all logs (limit to 10000 for performance)

        if (empty($logs)) {
            return new \WP_REST_Response([
                'success' => false,
                'message' => __('No logs available to export', 'attributes-user-access-pro-lite')
            ], 404);
        }

        $data = '';

        if ($format === 'json') {
            $data = wp_json_encode($logs);
        } else {
            // Default to CSV
            $csv_headers = [
                'ID',
                'Time',
                'Event Type',
                'Description',
                'User ID',
                'Username',
                'IP Address',
                'Country',
                'User Agent',
                'Additional Data'
            ];

            // Build CSV content
            $data = implode(',', $csv_headers) . "\n";

            foreach ($logs as $log) {
                $row = [
                    $log->id,
                    $log->time,
                    $log->event_type,
                    $this->event_types[$log->event_type] ?? $log->event_type,
                    $log->user_id,
                    $log->username,
                    $log->ip,
                    $log->country,
                    '"' . str_replace('"', '""', $log->user_agent) . '"',
                    '"' . str_replace('"', '""', $log->data) . '"'
                ];

                $data .= implode(',', $row) . "\n";
            }
        }

        // Log the export event
        $this->attrua_log_event('logs_exported', [
            'format' => $format,
            'count' => count($logs)
        ]);

        return new \WP_REST_Response([
            'success' => true,
            'data' => base64_encode($data),
            'format' => $format,
            'filename' => 'attrua-audit-log-' . date('Y-m-d') . '.' . $format
        ]);
    }

    /**
     * REST API callback for clearing logs.
     *
     * @since  1.0.0
     * @param  \WP_REST_Request $request REST API request.
     * @return \WP_REST_Response Response object.
     */
    public function attrua_rest_clear_logs(\WP_REST_Request $request): \WP_REST_Response
    {
        global $wpdb;

        $older_than = $request->get_param('older_than');
        $result = false;

        if (!empty($older_than) && is_numeric($older_than)) {
            // Clear logs older than specified days
            $date = date('Y-m-d H:i:s', strtotime("-{$older_than} days"));
            $result = $wpdb->query(
                $wpdb->prepare(
                    "DELETE FROM {$this->table_name} WHERE time < %s",
                    $date
                )
            );
        } else {
            // Clear all logs
            $result = $wpdb->query("TRUNCATE TABLE {$this->table_name}");
        }

        // Log the clear event
        $this->attrua_log_event('logs_cleared', [
            'older_than' => $older_than,
            'cleared_by' => get_current_user_id()
        ]);

        return new \WP_REST_Response([
            'success' => $result !== false,
            'message' => $result !== false
                ? __('Audit logs cleared successfully', 'attributes-user-access-pro-lite')
                : __('Failed to clear audit logs', 'attributes-user-access-pro-lite')
        ]);
    }

    /**
     * Create log database table.
     *
     * Creates the database table for storing audit logs.
     *
     * @since  1.0.0
     * @access public
     * @return void
     */
    public function attrua_create_log_table(): void
    {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$this->table_name} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            time datetime NOT NULL,
            event_type varchar(50) NOT NULL,
            user_id bigint(20) DEFAULT NULL,
            username varchar(60) DEFAULT NULL,
            ip varchar(45) DEFAULT NULL,
            country char(2) DEFAULT NULL,
            user_agent text DEFAULT NULL,
            data longtext DEFAULT NULL,
            PRIMARY KEY  (id),
            KEY event_type (event_type),
            KEY user_id (user_id),
            KEY ip (ip),
            KEY time (time)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    /**
     * Unschedule cleanup task.
     *
     * Removes the scheduled cleanup task when plugin is deactivated.
     *
     * @since  1.0.0
     * @access public
     * @return void
     */
    public function attrua_unschedule_cleanup(): void
    {
        wp_clear_scheduled_hook('attrua_audit_log_cleanup');
    }

    /**
     * Cleanup old logs.
     *
     * Removes logs older than the retention period.
     *
     * @since  1.0.0
     * @access public
     * @return int Number of logs deleted.
     */
    public function attrua_cleanup_old_logs(): int
    {
        global $wpdb;

        // Skip if retention is set to 0 (keep forever)
        if ($this->retention_days <= 0) {
            return 0;
        }

        $date = date('Y-m-d H:i:s', strtotime("-{$this->retention_days} days"));

        return $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$this->table_name} WHERE time < %s",
                $date
            )
        );
    }

    /**
     * Log a security event.
     *
     * Records a security event to the audit log.
     *
     * @since  1.0.0
     * @access public
     * @param  string $event_type Type of event (must be defined in $event_types).
     * @param  array  $data       Additional data to log.
     * @return int|false The ID of the inserted log entry, or false on failure.
     */
    public function attrua_log_event(string $event_type, array $data = []): int|false
    {
        global $wpdb;

        // Skip if logging is disabled
        if (!$this->logging_enabled) {
            return false;
        }

        // Skip if event type is not recognized
        if (!isset($this->event_types[$event_type])) {
            // Allow unknown events if explicitly enabled
            $allow_unknown = (bool) $this->settings->attrua_get('security.audit_log_unknown_events', false);
            if (!$allow_unknown) {
                return false;
            }
        }

        // Get current user information
        $user_id = get_current_user_id();
        $username = '';

        if ($user_id > 0) {
            $user = get_userdata($user_id);
            $username = $user ? $user->user_login : '';
        } elseif (isset($data['username'])) {
            $username = $data['username'];
            unset($data['username']); // Remove from data to avoid duplication
        }

        // Get IP address
        $ip = '';
        if (isset($data['ip'])) {
            $ip = $data['ip'];
            unset($data['ip']); // Remove from data to avoid duplication
        } elseif ($this->ip_manager) {
            $ip = $this->ip_manager->attrua_get_client_ip();
        }

        // Get country code
        $country = '';
        if (isset($data['country'])) {
            $country = $data['country'];
            unset($data['country']); // Remove from data to avoid duplication
        } elseif ($this->ip_manager && !empty($ip)) {
            $country = $this->ip_manager->attrua_get_country_code($ip);
        }

        // Get user agent
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        // Insert log entry
        $result = $wpdb->insert(
            $this->table_name,
            [
                'time' => current_time('mysql'),
                'event_type' => $event_type,
                'user_id' => $user_id,
                'username' => $username,
                'ip' => $ip,
                'country' => $country,
                'user_agent' => $user_agent,
                'data' => wp_json_encode($data)
            ],
            [
                '%s', // time
                '%s', // event_type
                '%d', // user_id
                '%s', // username
                '%s', // ip
                '%s', // country
                '%s', // user_agent
                '%s'  // data
            ]
        );

        if ($result === false) {
            return false;
        }

        return $wpdb->insert_id;
    }

    /**
     * Get logs from the database.
     *
     * Retrieves audit logs with pagination and filtering.
     *
     * @since  1.0.0
     * @access public
     * @param  int   $page      Page number.
     * @param  int   $per_page  Items per page.
     * @param  array $filters   Optional. Filters to apply.
     * @return array Array of log objects.
     */
    public function attrua_get_logs(int $page = 1, int $per_page = 20, array $filters = []): array
    {
        global $wpdb;

        $page = max(1, $page);
        $per_page = max(1, $per_page);
        $offset = ($page - 1) * $per_page;

        $where = [];
        $query_params = [];

        // Apply filters
        if (!empty($filters['event_type'])) {
            $where[] = 'event_type = %s';
            $query_params[] = $filters['event_type'];
        }

        if (!empty($filters['user_id'])) {
            $where[] = 'user_id = %d';
            $query_params[] = $filters['user_id'];
        }

        if (!empty($filters['ip'])) {
            $where[] = 'ip = %s';
            $query_params[] = $filters['ip'];
        }

        if (!empty($filters['date_from'])) {
            $where[] = 'time >= %s';
            $query_params[] = $filters['date_from'] . ' 00:00:00';
        }

        if (!empty($filters['date_to'])) {
            $where[] = 'time <= %s';
            $query_params[] = $filters['date_to'] . ' 23:59:59';
        }

        // Build WHERE clause
        $where_clause = '';
        if (!empty($where)) {
            $where_clause = 'WHERE ' . implode(' AND ', $where);
        }

        // Prepare query
        $query = "SELECT * FROM {$this->table_name} $where_clause ORDER BY time DESC LIMIT %d OFFSET %d";
        $query_params[] = $per_page;
        $query_params[] = $offset;

        // Execute query
        $logs = $wpdb->get_results(
            $wpdb->prepare($query, $query_params)
        );

        // Parse JSON data
        foreach ($logs as $log) {
            if (!empty($log->data)) {
                $log->data = json_decode($log->data, true);
            } else {
                $log->data = [];
            }
        }

        return $logs;
    }

    /**
     * Count logs with filters.
     *
     * Counts the total number of logs that match the given filters.
     *
     * @since  1.0.0
     * @access public
     * @param  array $filters Optional. Filters to apply.
     * @return int Total number of matching logs.
     */
    public function attrua_count_logs(array $filters = []): int
    {
        global $wpdb;

        $where = [];
        $query_params = [];

        // Apply filters
        if (!empty($filters['event_type'])) {
            $where[] = 'event_type = %s';
            $query_params[] = $filters['event_type'];
        }

        if (!empty($filters['user_id'])) {
            $where[] = 'user_id = %d';
            $query_params[] = $filters['user_id'];
        }

        if (!empty($filters['ip'])) {
            $where[] = 'ip = %s';
            $query_params[] = $filters['ip'];
        }

        if (!empty($filters['date_from'])) {
            $where[] = 'time >= %s';
            $query_params[] = $filters['date_from'] . ' 00:00:00';
        }

        if (!empty($filters['date_to'])) {
            $where[] = 'time <= %s';
            $query_params[] = $filters['date_to'] . ' 23:59:59';
        }

        // Build WHERE clause
        $where_clause = '';
        if (!empty($where)) {
            $where_clause = 'WHERE ' . implode(' AND ', $where);
        }

        // Prepare query
        $query = "SELECT COUNT(*) FROM {$this->table_name} $where_clause";

        // Execute query
        return (int) $wpdb->get_var(
            $wpdb->prepare($query, $query_params)
        );
    }

    /**
     * Log successful login.
     *
     * Records a successful login event.
     *
     * @since  1.0.0
     * @access public
     * @param  string   $user_login Username.
     * @param  \WP_User $user       User object.
     * @return void
     */
    public function attrua_log_login(string $user_login, $user): void
    {
        $this->attrua_log_event('login_success', [
            'user_id' => $user->ID,
            'username' => $user->user_login,
            'roles' => $user->roles
        ]);
    }

    /**
     * Log failed login.
     *
     * Records a failed login attempt.
     *
     * @since  1.0.0
     * @access public
     * @param  string $username Username.
     * @return void
     */
    public function attrua_log_login_failed(string $username): void
    {
        $this->attrua_log_event('login_failed', [
            'username' => $username
        ]);
    }

    /**
     * Log user logout.
     *
     * Records a user logout event.
     *
     * @since  1.0.0
     * @access public
     * @return void
     */
    public function attrua_log_logout(): void
    {
        $user_id = get_current_user_id();
        if ($user_id > 0) {
            $user = get_userdata($user_id);
            $this->attrua_log_event('logout', [
                'user_id' => $user_id,
                'username' => $user ? $user->user_login : '',
                'roles' => $user ? $user->roles : []
            ]);
        }
    }

    /**
     * Log user registration.
     *
     * Records a new user registration event.
     *
     * @since  1.0.0
     * @access public
     * @param  int $user_id User ID.
     * @return void
     */
    public function attrua_log_user_registered(int $user_id): void
    {
        $user = get_userdata($user_id);
        if ($user) {
            $this->attrua_log_event('user_registered', [
                'user_id' => $user_id,
                'username' => $user->user_login,
                'email' => $user->user_email,
                'roles' => $user->roles
            ]);
        }
    }

    /**
     * Log user deletion.
     *
     * Records a user deletion event.
     *
     * @since  1.0.0
     * @access public
     * @param  int $user_id User ID.
     * @return void
     */
    public function attrua_log_user_deleted(int $user_id): void
    {
        $user = get_userdata($user_id);
        if ($user) {
            $this->attrua_log_event('user_deleted', [
                'user_id' => $user_id,
                'username' => $user->user_login,
                'email' => $user->user_email,
                'roles' => $user->roles,
                'deleted_by' => get_current_user_id()
            ]);
        }
    }

    /**
     * Log user role change.
     *
     * Records a user role change event.
     *
     * @since  1.0.0
     * @access public
     * @param  int    $user_id  User ID.
     * @param  string $new_role New role.
     * @param  array  $old_roles Old roles.
     * @return void
     */
    public function attrua_log_role_changed(int $user_id, string $new_role, array $old_roles): void
    {
        $user = get_userdata($user_id);
        if ($user) {
            $this->attrua_log_event('user_role_changed', [
                'user_id' => $user_id,
                'username' => $user->user_login,
                'old_roles' => $old_roles,
                'new_role' => $new_role,
                'changed_by' => get_current_user_id()
            ]);
        }
    }

    /**
     * Get event types.
     *
     * Returns all registered event types with descriptions.
     *
     * @since  1.0.0
     * @access public
     * @return array Event types.
     */
    public function attrua_get_event_types(): array
    {
        return $this->event_types;
    }

    /**
     * Check if audit logging is enabled.
     *
     * @since  1.0.0
     * @access public
     * @return bool Whether audit logging is enabled.
     */
    public function attrua_is_logging_enabled(): bool
    {
        return $this->logging_enabled;
    }

    /**
     * Get log retention period.
     *
     * @since  1.0.0
     * @access public
     * @return int Retention period in days.
     */
    public function attrua_get_retention_days(): int
    {
        return $this->retention_days;
    }
}
