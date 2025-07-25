<?php

namespace Attributes\Pro\Security;

use Attributes\Pro\License\License_Manager;

/**
 * Password Policy Class
 *
 * Manages password requirements, expiration, history, and validation.
 * Implements configurable security policies for user passwords.
 *
 * @package Attributes\Pro\Security
 * @since 1.0.0
 */
class Password_Policy
{
    /**
     * Singleton instance
     *
     * @var Password_Policy|null
     */
    private static ?Password_Policy $instance = null;

    /**
     * Flag indicating if policy is enabled
     *
     * @var bool
     */
    private bool $is_enabled = false;

    /**
     * Password policy settings
     *
     * @var array
     */
    private array $settings = [];

    /**
     * Get singleton instance
     *
     * @return self
     */
    public static function instance(): self
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor
     */
    private function __construct()
    {
        // Only initialize if license is active
        if (!License_Manager::instance()->is_active()) {
            return;
        }

        $this->init();
    }

    /**
     * Initialize password policy
     */
    private function init(): void
    {
        // Get settings
        $this->settings = get_option('attrua_pro_password_policy', []);
        $this->is_enabled = !empty($this->settings['enabled']);

        if (!$this->is_enabled) {
            return;
        }

        // Hook into user registration and password reset
        add_filter('registration_errors', [$this, 'validate_registration_password'], 10, 3);
        add_filter('user_profile_update_errors', [$this, 'validate_password_update'], 10, 3);
        add_filter('password_reset_errors', [$this, 'validate_password_reset'], 10, 3);

        // Handle password expiration
        add_action('wp_login', [$this, 'check_password_expiration'], 10, 2);
        add_action('user_register', [$this, 'set_password_timestamp'], 10, 1);
        add_action('password_reset', [$this, 'set_password_timestamp'], 10, 1);
        add_action('profile_update', [$this, 'handle_profile_update'], 10, 2);

        // Add password history when enabled
        if (!empty($this->settings['enable_history'])) {
            add_action('after_password_reset', [$this, 'update_password_history'], 10, 2);
            add_action('profile_update', [$this, 'check_password_history'], 10, 2);
        }

        // Expiration notification system
        if (!empty($this->settings['enable_expiration'])) {
            add_action('attrua_pro_daily_tasks', [$this, 'send_expiration_notifications']);

            // Schedule daily check if not already scheduled
            if (!wp_next_scheduled('attrua_pro_daily_tasks')) {
                wp_schedule_event(time(), 'daily', 'attrua_pro_daily_tasks');
            }
        }

        // Register settings
        add_action('admin_init', [$this, 'register_settings']);

        // Add settings tab
        add_filter('attrua_admin_tabs', [$this, 'add_settings_tab']);
        add_action('attrua_admin_settings_content', [$this, 'render_settings_content'], 10, 1);
    }

    /**
     * Validate password during registration
     *
     * @param \WP_Error $errors Error object
     * @param string $sanitized_user_login User login
     * @param string $user_email User email
     * @return \WP_Error Error object with any new errors
     */
    public function validate_registration_password(\WP_Error $errors, string $sanitized_user_login, string $user_email): \WP_Error
    {
        if (!isset($_POST['user_pass']) || empty($_POST['user_pass'])) {
            return $errors;
        }

        $password = $_POST['user_pass'];
        $validation_result = $this->validate_password($password, $sanitized_user_login, $user_email);

        if (is_wp_error($validation_result)) {
            foreach ($validation_result->get_error_codes() as $code) {
                $errors->add($code, $validation_result->get_error_message($code));
            }
        }

        return $errors;
    }

    /**
     * Validate password during profile update
     *
     * @param \WP_Error $errors Error object
     * @param bool $update Whether this is an update
     * @param \stdClass $user User object
     * @return \WP_Error Error object with any new errors
     */
    public function validate_password_update(\WP_Error $errors, bool $update, \stdClass $user): \WP_Error
    {
        if (!isset($user->user_pass) || empty($user->user_pass)) {
            return $errors;
        }

        $validation_result = $this->validate_password($user->user_pass, $user->user_login, $user->user_email);

        if (is_wp_error($validation_result)) {
            foreach ($validation_result->get_error_codes() as $code) {
                $errors->add($code, $validation_result->get_error_message($code));
            }
        }

        return $errors;
    }

    /**
     * Validate password during password reset
     *
     * @param \WP_Error $errors Error object
     * @param \WP_User $user User object
     * @param string $new_pass New password
     * @return \WP_Error Error object with any new errors 
     */
    public function validate_password_reset(\WP_Error $errors, \WP_User $user, string $new_pass): \WP_Error
    {
        $validation_result = $this->validate_password($new_pass, $user->user_login, $user->user_email);

        if (is_wp_error($validation_result)) {
            foreach ($validation_result->get_error_codes() as $code) {
                $errors->add($code, $validation_result->get_error_message($code));
            }
        }

        return $errors;
    }

    /**
     * Check password expiration on login
     *
     * @param string $user_login Username
     * @param \WP_User $user User object
     */
    public function check_password_expiration(string $user_login, \WP_User $user): void
    {
        if (empty($this->settings['enable_expiration'])) {
            return;
        }

        // Skip check for specific user roles if configured
        $excluded_roles = $this->settings['excluded_roles'] ?? [];

        if (!empty($excluded_roles)) {
            $user_roles = $user->roles;
            $is_excluded = false;

            foreach ($user_roles as $role) {
                if (in_array($role, $excluded_roles)) {
                    $is_excluded = true;
                    break;
                }
            }

            if ($is_excluded) {
                return;
            }
        }

        // Get last password change timestamp
        $last_update = get_user_meta($user->ID, 'attrua_pro_password_timestamp', true);

        if (empty($last_update)) {
            // Set current time as baseline if not recorded
            $this->set_password_timestamp($user);
            return;
        }

        // Calculate expiration parameters
        $expiration_days = intval($this->settings['expiration_days'] ?? 90);
        $grace_period = intval($this->settings['grace_period'] ?? 3);

        $expiration_time = $last_update + ($expiration_days * DAY_IN_SECONDS);
        $hard_expiration_time = $expiration_time + ($grace_period * DAY_IN_SECONDS);
        $current_time = time();

        // Check if password has expired
        if ($current_time > $expiration_time) {
            // Check if within grace period
            if ($current_time <= $hard_expiration_time) {
                // Redirect to password reset page with notice
                update_user_meta($user->ID, 'attrua_pro_password_expired', '1');

                // Get password reset URL
                $reset_url = $this->get_password_reset_url($user);

                wp_redirect($reset_url);
                exit;
            } else {
                // Hard expiration - log user out and show message
                wp_logout();

                // Redirect to login page with message
                $login_url = wp_login_url();
                $login_url = add_query_arg('password_expired', '1', $login_url);

                wp_redirect($login_url);
                exit;
            }
        }
    }

    /**
     * Set password timestamp when user password is updated
     *
     * @param \WP_User|int $user User object or ID
     */
    public function set_password_timestamp($user): void
    {
        $user_id = ($user instanceof \WP_User) ? $user->ID : (int) $user;

        if (!$user_id) {
            return;
        }

        // Store timestamp of password update
        update_user_meta($user_id, 'attrua_pro_password_timestamp', time());

        // Clear expiration flag if it exists
        delete_user_meta($user_id, 'attrua_pro_password_expired');
    }

    /**
     * Handle profile update to detect password changes
     *
     * @param int $user_id User ID
     * @param \WP_User $old_user_data Old user data
     */
    public function handle_profile_update(int $user_id, \WP_User $old_user_data): void
    {
        // Check if this is a POST request with a password change
        if (!isset($_POST['pass1']) || empty($_POST['pass1'])) {
            return;
        }

        // Set password update timestamp
        $this->set_password_timestamp($user_id);

        // Send password change notification if enabled
        if (!empty($this->settings['notify_on_reset'])) {
            $this->send_password_change_notification($user_id);
        }
    }

    /**
     * Update password history when password is changed
     *
     * @param \WP_User $user User object
     * @param string $new_password New password
     */
    public function update_password_history(\WP_User $user, string $new_password): void
    {
        if (empty($this->settings['enable_history'])) {
            return;
        }

        $history_size = intval($this->settings['history_size'] ?? 5);

        // Get current password history
        $password_history = get_user_meta($user->ID, 'attrua_pro_password_history', true);

        if (empty($password_history) || !is_array($password_history)) {
            $password_history = [];
        }

        // Add current password hash to history
        $password_hash = wp_hash_password($new_password);

        // Add as most recent with timestamp
        array_unshift($password_history, [
            'hash' => $password_hash,
            'time' => time()
        ]);

        // Trim history to configured size
        if (count($password_history) > $history_size) {
            $password_history = array_slice($password_history, 0, $history_size);
        }

        // Save updated history
        update_user_meta($user->ID, 'attrua_pro_password_history', $password_history);
    }

    /**
     * Check password history during profile update
     *
     * @param int $user_id User ID
     * @param \WP_User $old_user_data Old user data
     */
    public function check_password_history(int $user_id, \WP_User $old_user_data): void
    {
        // Only continue if password history is enabled
        if (empty($this->settings['enable_history'])) {
            return;
        }

        // Check if this is a POST request with a password change
        if (!isset($_POST['pass1']) || empty($_POST['pass1'])) {
            return;
        }

        $new_password = $_POST['pass1'];

        // Get password history
        $password_history = get_user_meta($user_id, 'attrua_pro_password_history', true);

        if (empty($password_history) || !is_array($password_history)) {
            return;
        }

        // Check if new password matches any in history
        foreach ($password_history as $entry) {
            if (wp_check_password($new_password, $entry['hash'])) {
                // Password found in history, show error message
                add_action('user_profile_update_errors', function ($errors) {
                    $errors->add(
                        'password_in_history',
                        __('The new password has been used recently. Please choose a different password.', 'attributes-user-access-pro-lite')
                    );
                });
                break;
            }
        }
    }

    /**
     * Send password expiration notification emails
     */
    public function send_expiration_notifications(): void
    {
        // Only proceed if expiration is enabled
        if (empty($this->settings['enable_expiration'])) {
            return;
        }

        $expiration_days = intval($this->settings['expiration_days'] ?? 90);
        $warning_days = intval($this->settings['expiration_warning'] ?? 7);

        // Calculate timestamp thresholds
        $now = time();
        $warning_threshold = $now + ($warning_days * DAY_IN_SECONDS);
        $expiration_threshold = $now - ($expiration_days * DAY_IN_SECONDS);

        // Get users with passwords that will expire soon
        $users = get_users([
            'meta_query' => [
                [
                    'key' => 'attrua_pro_password_timestamp',
                    'value' => $expiration_threshold,
                    'compare' => '>',
                    'type' => 'NUMERIC'
                ],
                [
                    'key' => 'attrua_pro_password_timestamp',
                    'value' => $warning_threshold - ($expiration_days * DAY_IN_SECONDS),
                    'compare' => '<',
                    'type' => 'NUMERIC'
                ],
                [
                    'key' => 'attrua_pro_password_expiry_notified',
                    'compare' => 'NOT EXISTS'
                ]
            ]
        ]);

        // Send notifications to each user
        foreach ($users as $user) {
            $this->send_expiration_warning($user);

            // Mark user as notified
            update_user_meta($user->ID, 'attrua_pro_password_expiry_notified', '1');
        }
    }

    /**
     * Send password expiration warning email to user
     *
     * @param \WP_User $user User object
     * @return bool Whether email was sent successfully
     */
    private function send_expiration_warning(\WP_User $user): bool
    {
        // Get email settings
        $email_settings = get_option('attrua_pro_email_settings', []);

        if (empty($email_settings['password_expiry']['enabled'])) {
            return false;
        }

        // Calculate days until expiration
        $last_update = get_user_meta($user->ID, 'attrua_pro_password_timestamp', true);
        $expiration_days = intval($this->settings['expiration_days'] ?? 90);
        $expiration_time = $last_update + ($expiration_days * DAY_IN_SECONDS);
        $days_remaining = ceil(($expiration_time - time()) / DAY_IN_SECONDS);

        // Prepare email content
        $subject = $email_settings['password_expiry']['subject'] ?? __('Your Password Will Expire Soon - {site_name}', 'attributes-user-access-pro-lite');
        $content = $email_settings['password_expiry']['content'] ?? __("Hello {user_display_name},\n\nYour password for {site_name} will expire in {days_remaining} days.\n\nPlease visit {password_change_url} to update your password before it expires.\n\nRegards,\n{site_name} Team", 'attributes-user-access-pro-lite');

        // Replace placeholders
        $site_name = get_bloginfo('name');
        $password_change_url = add_query_arg('action', 'attrua_pro_password_change', wp_login_url());

        $subject = str_replace(
            ['{site_name}', '{user_login}', '{user_display_name}', '{user_email}'],
            [$site_name, $user->user_login, $user->display_name, $user->user_email],
            $subject
        );

        $content = str_replace(
            ['{site_name}', '{site_url}', '{days_remaining}', '{password_change_url}', '{user_login}', '{user_display_name}', '{user_email}'],
            [$site_name, home_url(), $days_remaining, $password_change_url, $user->user_login, $user->display_name, $user->user_email],
            $content
        );

        // Set email headers
        $headers = ['Content-Type: text/html; charset=UTF-8'];

        if (!empty($email_settings['from_name']) && !empty($email_settings['from_email'])) {
            $headers[] = 'From: ' . $email_settings['from_name'] . ' <' . $email_settings['from_email'] . '>';
        }

        // Send email
        return wp_mail($user->user_email, $subject, nl2br($content), $headers);
    }

    /**
     * Send notification when password is changed
     *
     * @param int $user_id User ID
     * @return bool Whether email was sent successfully
     */
    private function send_password_change_notification(int $user_id): bool
    {
        $user = get_userdata($user_id);

        if (!$user) {
            return false;
        }

        // Get email settings
        $email_settings = get_option('attrua_pro_email_settings', []);

        if (empty($email_settings['password_changed']['enabled'])) {
            return false;
        }

        // Prepare email content
        $subject = $email_settings['password_changed']['subject'] ?? __('Your Password Has Been Changed - {site_name}', 'attributes-user-access-pro-lite');
        $content = $email_settings['password_changed']['content'] ?? __("Hello {user_display_name},\n\nThis notice confirms that your password was changed on {site_name}.\n\nIf you did not change your password, please contact the site administrator immediately.\n\nRegards,\n{site_name} Team", 'attributes-user-access-pro-lite');

        // Replace placeholders
        $site_name = get_bloginfo('name');
        $login_url = wp_login_url();

        $subject = str_replace(
            ['{site_name}', '{user_login}', '{user_display_name}', '{user_email}'],
            [$site_name, $user->user_login, $user->display_name, $user->user_email],
            $subject
        );

        $content = str_replace(
            ['{site_name}', '{site_url}', '{login_url}', '{user_login}', '{user_display_name}', '{user_email}'],
            [$site_name, home_url(), $login_url, $user->user_login, $user->display_name, $user->user_email],
            $content
        );

        // Set email headers
        $headers = ['Content-Type: text/html; charset=UTF-8'];

        if (!empty($email_settings['from_name']) && !empty($email_settings['from_email'])) {
            $headers[] = 'From: ' . $email_settings['from_name'] . ' <' . $email_settings['from_email'] . '>';
        }

        // Send email
        return wp_mail($user->user_email, $subject, nl2br($content), $headers);
    }

    /**
     * Get password reset URL
     *
     * @param \WP_User $user User object
     * @return string Password reset URL
     */
    private function get_password_reset_url(\WP_User $user): string
    {
        $key = get_password_reset_key($user);

        if (is_wp_error($key)) {
            return wp_login_url();
        }

        // Check for custom reset page
        $pages = get_option('attrua_pro_pages_options', []);
        $custom_reset_page = isset($pages['reset']) ? get_permalink($pages['reset']) : '';

        if ($custom_reset_page) {
            return add_query_arg(
                [
                    'key' => $key,
                    'login' => rawurlencode($user->user_login),
                    'expired' => '1'
                ],
                $custom_reset_page
            );
        }

        // Fall back to WordPress default
        return network_site_url("wp-login.php?action=rp&key=$key&login=" . rawurlencode($user->user_login) . "&expired=1", 'login');
    }

    /**
     * Validate password against policy requirements
     *
     * @param string $password Password to validate
     * @param string $username Username (for comparison check)
     * @param string $email Email address (for comparison check)
     * @return true|\WP_Error True if valid, WP_Error otherwise
     */
    public function validate_password(string $password, string $username = '', string $email = '')
    {
        $errors = new \WP_Error();

        // Minimum length check
        $min_length = intval($this->settings['min_length'] ?? 8);
        if (strlen($password) < $min_length) {
            $errors->add(
                'password_too_short',
                sprintf(
                    /* translators: %d: Minimum password length */
                    __('Password must be at least %d characters long.', 'attributes-user-access-pro-lite'),
                    $min_length
                )
            );
        }

        // Character type requirements
        if (!empty($this->settings['require_uppercase']) && !preg_match('/[A-Z]/', $password)) {
            $errors->add(
                'password_no_uppercase',
                __('Password must include at least one uppercase letter (A-Z).', 'attributes-user-access-pro-lite')
            );
        }

        if (!empty($this->settings['require_lowercase']) && !preg_match('/[a-z]/', $password)) {
            $errors->add(
                'password_no_lowercase',
                __('Password must include at least one lowercase letter (a-z).', 'attributes-user-access-pro-lite')
            );
        }

        if (!empty($this->settings['require_numbers']) && !preg_match('/[0-9]/', $password)) {
            $errors->add(
                'password_no_number',
                __('Password must include at least one number (0-9).', 'attributes-user-access-pro-lite')
            );
        }

        if (!empty($this->settings['require_special']) && !preg_match('/[^a-zA-Z0-9]/', $password)) {
            $errors->add(
                'password_no_special',
                __('Password must include at least one special character (e.g., !@#$%^&*).', 'attributes-user-access-pro-lite')
            );
        }

        // Check if password contains username
        if (!empty($this->settings['disallow_username']) && !empty($username)) {
            if (stripos($password, $username) !== false) {
                $errors->add(
                    'password_contains_username',
                    __('Password must not contain your username.', 'attributes-user-access-pro-lite')
                );
            }
        }

        // Check if password contains email address
        if (!empty($this->settings['disallow_email']) && !empty($email)) {
            // Extract username part of email
            $email_username = substr($email, 0, strpos($email, '@'));

            if (stripos($password, $email_username) !== false || stripos($password, $email) !== false) {
                $errors->add(
                    'password_contains_email',
                    __('Password must not contain your email address.', 'attributes-user-access-pro-lite')
                );
            }
        }

        // Check against common password list if enabled
        if (!empty($this->settings['check_common'])) {
            if ($this->is_common_password($password)) {
                $errors->add(
                    'password_common',
                    __('This password is too common. Please choose a more secure password.', 'attributes-user-access-pro-lite')
                );
            }
        }

        // Return errors if any, otherwise true
        return $errors->has_errors() ? $errors : true;
    }

    /**
     * Check if password is in common passwords list
     *
     * @param string $password Password to check
     * @return bool Whether password is common
     */
    private function is_common_password(string $password): bool
    {
        // Normalize password for checking
        $password = strtolower(trim($password));

        // Get common passwords file
        $common_passwords_file = ATTRUA_PRO_PATH . 'data/common-passwords.php';

        if (!file_exists($common_passwords_file)) {
            return false;
        }

        // Load common passwords
        $common_passwords = include $common_passwords_file;

        return in_array($password, $common_passwords);
    }

    /**
     * Register settings
     */
    public function register_settings(): void
    {
        register_setting(
            'attrua_pro_password_policy',
            'attrua_pro_password_policy',
            [
                'type' => 'array',
                'sanitize_callback' => [$this, 'sanitize_settings'],
                'default' => [
                    'enabled' => false,
                    'min_length' => 8,
                    'require_uppercase' => false,
                    'require_lowercase' => false,
                    'require_numbers' => false,
                    'require_special' => false,
                    'disallow_username' => false,
                    'disallow_email' => false,
                    'check_common' => false,
                    'enable_expiration' => false,
                    'expiration_days' => 90,
                    'expiration_warning' => 7,
                    'grace_period' => 3,
                    'enable_history' => false,
                    'history_size' => 5,
                    'reset_expiration' => 24,
                    'notify_on_reset' => false,
                    'notify_admin' => false
                ]
            ]
        );
    }

    /**
     * Sanitize settings
     * 
     * @param array $input Settings input
     * @return array Sanitized settings
     */
    public function sanitize_settings($input): array
    {
        if (!is_array($input)) {
            return [];
        }

        $sanitized = [];

        // Boolean settings
        $boolean_settings = [
            'enabled',
            'require_uppercase',
            'require_lowercase',
            'require_numbers',
            'require_special',
            'disallow_username',
            'disallow_email',
            'check_common',
            'enable_expiration',
            'enable_history',
            'notify_on_reset',
            'notify_admin'
        ];

        foreach ($boolean_settings as $key) {
            $sanitized[$key] = !empty($input[$key]);
        }

        // Integer settings with limits
        $sanitized['min_length'] = isset($input['min_length']) ?
            min(64, max(4, intval($input['min_length']))) : 8;

        $sanitized['expiration_days'] = isset($input['expiration_days']) ?
            min(365, max(1, intval($input['expiration_days']))) : 90;

        $sanitized['expiration_warning'] = isset($input['expiration_warning']) ?
            min(30, max(1, intval($input['expiration_warning']))) : 7;

        $sanitized['grace_period'] = isset($input['grace_period']) ?
            min(30, max(0, intval($input['grace_period']))) : 3;

        $sanitized['history_size'] = isset($input['history_size']) ?
            min(24, max(1, intval($input['history_size']))) : 5;

        $sanitized['reset_expiration'] = isset($input['reset_expiration']) ?
            min(72, max(1, intval($input['reset_expiration']))) : 24;

        return $sanitized;
    }

    /**
     * Add settings tab
     *
     * @param array $tabs Existing tabs
     * @return array Modified tabs
     */
    public function add_settings_tab(array $tabs): array
    {
        $tabs['passwords'] = __('Password Policy', 'attributes-user-access-pro-lite');
        return $tabs;
    }

    /**
     * Render settings content
     *
     * @param bool $has_premium_features Whether premium features are active
     */
    public function render_settings_content(bool $has_premium_features): void
    {
        if (!$has_premium_features || !isset($_GET['tab']) || $_GET['tab'] !== 'passwords') {
            return;
        }

        // Load password policy settings template
        require_once ATTRUA_PRO_PATH . 'display/tabs/password-policy-tab.php';
    }
}
