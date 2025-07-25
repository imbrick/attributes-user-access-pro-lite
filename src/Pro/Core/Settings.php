<?php

/**
 * Security Settings Handler
 * Handles the saving of all security-related settings from a single form
 * 
 * @package Attributes\Pro\Core
 */

namespace Attributes\Pro\Core;

/**
 * Settings class
 */
class Settings
{
    /**
     * Initialize the settings handler
     */
    public static function init()
    {
        add_action('admin_init', [self::class, 'register_settings']);
        add_action('admin_post_attrua_save_security_settings', [self::class, 'save_security_settings']);
    }


    /**
     * Register all settings
     */
    public function register_settings(): void
    {
        // General security settings
        register_setting(
            'attrua_pro_security',
            'attrua_pro_security_settings',
            [
                'type' => 'array',
                'sanitize_callback' => [self::class, 'sanitize_security_settings'],
                'default' => [
                    'mode' => 'normal',
                    'max_login_attempts' => 5,
                    'lockout_duration' => 15,
                    'progressive_lockouts' => true,
                    'enable_ip_blocking' => true,
                    'ip_whitelist' => '',
                    'ip_blacklist' => '',
                    'enable_logging' => true,
                    'log_retention' => 30,
                ]
            ]
        );

        // Register security settings
        register_setting(
            'attrua_pro_security',
            'attrua_pro_security_settings',
            [
                'sanitize_callback' => ['\Attributes\Pro\Core\Setting', 'sanitize_security_settings'],
                'default' => []
            ]
        );

        register_setting(
            'attrua_pro_security',
            'attrua_pro_2fa_settings',
            [
                'sanitize_callback' => ['\Attributes\Pro\Core\Setting', 'sanitize_2fa_settings'],
                'default' => []
            ]
        );

        register_setting(
            'attrua_pro_security',
            'attrua_pro_recaptcha_settings',
            [
                'sanitize_callback' => ['\Attributes\Pro\Core\Setting', 'sanitize_recaptcha_settings'],
                'default' => []
            ]
        );

        // Register password policy settings
        register_setting(
            'attrua_pro_password_policy',
            'attrua_pro_password_policy',
            [
                'sanitize_callback' => [$this, 'sanitize_password_policy'],
                'default' => []
            ]
        );

        // Register email settings
        register_setting(
            'attrua_pro_email_settings',
            'attrua_pro_email_settings',
            [
                'sanitize_callback' => [$this, 'sanitize_email_settings'],
                'default' => []
            ]
        );

        // Register integration settings
        register_setting(
            'attrua_pro_integration',
            'attrua_pro_surecart_settings',
            [
                'sanitize_callback' => [$this, 'sanitize_integration_settings'],
                'default' => []
            ]
        );

        // Two-factor authentication settings
        register_setting(
            'attrua_pro_security',
            'attrua_pro_2fa_settings',
            [
                'type' => 'array',
                'sanitize_callback' => [self::class, 'sanitize_2fa_settings'],
                'default' => [
                    'enabled' => false,
                    'method' => 'email',
                    'excluded_roles' => ['subscriber'],
                ]
            ]
        );

        // reCAPTCHA settings
        register_setting(
            'attrua_pro_security',
            'attrua_pro_recaptcha_settings',
            [
                'type' => 'array',
                'sanitize_callback' => [self::class, 'sanitize_recaptcha_settings'],
                'default' => [
                    'enabled' => false,
                    'version' => 'v2',
                    'site_key' => '',
                    'secret_key' => '',
                    'forms' => [
                        'login' => true,
                        'register' => true,
                        'lost_password' => true,
                    ],
                ]
            ]
        );
    }

    /**
     * Save all security settings from a single form submission
     */
    public static function save_security_settings()
    {
        // Check nonce
        if (!isset($_POST['attrua_pro_security_nonce']) || !wp_verify_nonce($_POST['attrua_pro_security_nonce'], 'attrua_pro_security_nonce')) {
            wp_die(__('Security check failed.', 'attributes-user-access-pro-lite'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have permission to change these settings.', 'attributes-user-access-pro-lite'));
        }

        // Save general security settings
        if (isset($_POST['attrua_pro_security_settings'])) {
            $security_settings = self::sanitize_security_settings($_POST['attrua_pro_security_settings']);
            update_option('attrua_pro_security_settings', $security_settings);
        }

        // Save 2FA settings
        if (isset($_POST['attrua_pro_2fa_settings'])) {
            $two_factor_settings = self::sanitize_2fa_settings($_POST['attrua_pro_2fa_settings']);
            update_option('attrua_pro_2fa_settings', $two_factor_settings);
        }

        // Save reCAPTCHA settings
        if (isset($_POST['attrua_pro_recaptcha_settings'])) {
            $recaptcha_settings = self::sanitize_recaptcha_settings($_POST['attrua_pro_recaptcha_settings']);
            update_option('attrua_pro_recaptcha_settings', $recaptcha_settings);
        }

        // Redirect back to the security settings page
        wp_redirect(admin_url('admin.php?page=attributes-user-access&tab=security&settings-updated=true'));
        exit;
    }

    /**
     * Sanitize general security settings
     *
     * @param array $input The input array
     * @return array The sanitized array
     */
    public static function sanitize_security_settings($input)
    {
        $sanitized = [];

        // Security mode
        $valid_modes = ['none', 'normal', 'strict', 'custom'];
        $sanitized['mode'] = in_array($input['mode'] ?? 'normal', $valid_modes) ? $input['mode'] : 'normal';

        // Login attempts
        $sanitized['max_login_attempts'] = isset($input['max_login_attempts'])
            ? absint($input['max_login_attempts'])
            : 5;

        // Lockout duration
        $sanitized['lockout_duration'] = isset($input['lockout_duration'])
            ? absint($input['lockout_duration'])
            : 15;

        // Boolean settings
        $boolean_settings = [
            'progressive_lockouts',
            'enable_ip_blocking',
            'enable_logging',
        ];

        foreach ($boolean_settings as $key) {
            $sanitized[$key] = !empty($input[$key]);
        }

        // IP lists
        $sanitized['ip_whitelist'] = isset($input['ip_whitelist'])
            ? sanitize_textarea_field($input['ip_whitelist'])
            : '';

        $sanitized['ip_blacklist'] = isset($input['ip_blacklist'])
            ? sanitize_textarea_field($input['ip_blacklist'])
            : '';

        // Log retention
        $sanitized['log_retention'] = isset($input['log_retention'])
            ? absint($input['log_retention'])
            : 30;

        return $sanitized;
    }

    /**
     * Sanitize 2FA settings
     *
     * @param array $input The input array
     * @return array The sanitized array
     */
    public static function sanitize_2fa_settings($input)
    {
        $sanitized = [];

        // Enabled state
        $sanitized['enabled'] = !empty($input['enabled']);

        // Method
        $valid_methods = ['email', 'totp', 'sms'];
        $sanitized['method'] = in_array($input['method'] ?? 'email', $valid_methods) ? $input['method'] : 'email';

        // Excluded roles
        $sanitized['excluded_roles'] = [];
        if (isset($input['excluded_roles']) && is_array($input['excluded_roles'])) {
            // Ensure all roles are valid
            $all_roles = array_keys(wp_roles()->get_names());
            foreach ($input['excluded_roles'] as $role) {
                if (in_array($role, $all_roles)) {
                    $sanitized['excluded_roles'][] = $role;
                }
            }
        }

        return $sanitized;
    }

    /**
     * Sanitize reCAPTCHA settings
     *
     * @param array $input The input array
     * @return array The sanitized array
     */
    public static function sanitize_recaptcha_settings($input)
    {
        $sanitized = [];

        // Enabled state
        $sanitized['enabled'] = !empty($input['enabled']);

        // Version
        $valid_versions = ['v2', 'v2_invisible', 'v3'];
        $sanitized['version'] = in_array($input['version'] ?? 'v2', $valid_versions) ? $input['version'] : 'v2';

        // API keys
        $sanitized['site_key'] = isset($input['site_key'])
            ? sanitize_text_field($input['site_key'])
            : '';

        $sanitized['secret_key'] = isset($input['secret_key'])
            ? sanitize_text_field($input['secret_key'])
            : '';

        // Forms
        $sanitized['forms'] = [];
        $form_types = ['login', 'register', 'lost_password'];

        foreach ($form_types as $form) {
            $sanitized['forms'][$form] = !empty($input['forms'][$form]);
        }

        return $sanitized;
    }



    /**
     * Check if SureCart is active
     *
     * @return bool Whether SureCart is active
     */
    private function is_surecart_active(): bool
    {
        return defined('SURECART_PLUGIN_FILE') && function_exists('sc_fs');
    }

    /**
     * Register settings
     */
    /*public function register_settings(): void {
        // Register all needed settings for different tabs
        register_setting('attrua_pro_license', 'attrua_pro_license_key');
        register_setting('attrua_pro_security', 'attrua_pro_security_settings');
        register_setting('attrua_pro_security', 'attrua_pro_2fa_settings');
        register_setting('attrua_pro_security', 'attrua_pro_recaptcha_settings');
        register_setting('attrua_pro_password_policy', 'attrua_pro_password_policy');
        register_setting('attrua_pro_email_settings', 'attrua_pro_email_settings');
        register_setting('attrua_pro_integration', 'attrua_pro_surecart_settings');
    }*/

    /**
     * Sanitize password policy settings
     *
     * @param array $input The input array to sanitize
     * @return array The sanitized array
     */
    public function sanitize_password_policy(array $input): array
    {
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
            'notify_on_reset',
            'notify_admin',
            'enable_expiration',
            'enable_history'
        ];

        foreach ($boolean_settings as $key) {
            $sanitized[$key] = !empty($input[$key]);
        }

        // Numeric settings with defaults
        $numeric_settings = [
            'min_length' => 8,
            'reset_expiration' => 24,
            'expiration_days' => 90,
            'expiration_warning' => 7,
            'grace_period' => 3,
            'history_size' => 5
        ];

        foreach ($numeric_settings as $key => $default) {
            $sanitized[$key] = isset($input[$key]) ? absint($input[$key]) : $default;
        }

        return $sanitized;
    }

    /**
     * Sanitize email settings
     *
     * @param array $input The input array to sanitize
     * @return array The sanitized array
     */
    public function sanitize_email_settings(array $input): array
    {
        $sanitized = [];

        // Basic settings
        $sanitized['from_name'] = isset($input['from_name']) ? sanitize_text_field($input['from_name']) : get_bloginfo('name');
        $sanitized['from_email'] = isset($input['from_email']) ? sanitize_email($input['from_email']) : get_option('admin_email');

        // Template
        $valid_templates = ['default', 'branded', 'plain'];
        $sanitized['template'] = in_array($input['template'] ?? 'default', $valid_templates) ? $input['template'] : 'default';

        // Branded template settings
        $sanitized['header_color'] = isset($input['header_color']) ? sanitize_hex_color($input['header_color']) : '#2271b1';
        $sanitized['logo_url'] = isset($input['logo_url']) ? esc_url_raw($input['logo_url']) : '';

        // Admin notification recipients
        $sanitized['admin_recipients'] = isset($input['admin_recipients']) ? sanitize_text_field($input['admin_recipients']) : get_option('admin_email');

        // Admin notification settings
        $admin_notification_settings = ['admin_new_user', 'admin_failed_login', 'admin_lockout', 'admin_blocked_ip'];
        foreach ($admin_notification_settings as $key) {
            $sanitized[$key] = !empty($input[$key]);
        }

        // Email templates
        $email_templates = ['welcome_email', 'reset_email', 'password_changed', 'password_expiry'];
        foreach ($email_templates as $template) {
            if (isset($input[$template]) && is_array($input[$template])) {
                $sanitized[$template] = [
                    'enabled' => !empty($input[$template]['enabled']),
                    'subject' => isset($input[$template]['subject']) ? sanitize_text_field($input[$template]['subject']) : '',
                    'content' => isset($input[$template]['content']) ? sanitize_textarea_field($input[$template]['content']) : ''
                ];
            } else {
                $sanitized[$template] = [
                    'enabled' => false,
                    'subject' => '',
                    'content' => ''
                ];
            }
        }

        return $sanitized;
    }

    /**
     * Sanitize integration settings
     *
     * @param array $input The input array to sanitize
     * @return array The sanitized array
     */
    public function sanitize_integration_settings(array $input): array
    {
        $sanitized = [];

        // Boolean settings
        $boolean_settings = [
            'enabled',
            'auto_create_users',
            'sync_users_to_customers',
            'send_welcome_email',
            'add_custom_fields'
        ];

        foreach ($boolean_settings as $key) {
            $sanitized[$key] = !empty($input[$key]);
        }

        // Default role
        $sanitized['default_role'] = 'subscriber';
        if (isset($input['default_role'])) {
            $valid_roles = array_keys(wp_roles()->get_names());
            if (in_array($input['default_role'], $valid_roles)) {
                $sanitized['default_role'] = $input['default_role'];
            }
        }

        // Product role mapping
        $sanitized['product_role_mapping'] = [];
        $sanitized['product_mapping'] = [];

        if (!empty($input['product_role_mapping']) && is_array($input['product_role_mapping'])) {
            foreach ($input['product_role_mapping'] as $product_id => $roles) {
                $sanitized_product_id = sanitize_text_field($product_id);
                $sanitized_roles = [];

                if (is_array($roles)) {
                    $valid_roles = array_keys(wp_roles()->get_names());
                    foreach ($roles as $role) {
                        if (in_array($role, $valid_roles)) {
                            $sanitized_roles[] = $role;
                        }
                    }
                }

                if (!empty($sanitized_roles)) {
                    $sanitized['product_role_mapping'][$sanitized_product_id] = $sanitized_roles;
                }
            }
        }

        // Product mapping
        if (!empty($input['product_mapping']) && is_array($input['product_mapping'])) {
            foreach ($input['product_mapping'] as $product_id => $data) {
                $sanitized_product_id = sanitize_text_field($product_id);

                if (isset($data['name'])) {
                    $sanitized['product_mapping'][$sanitized_product_id] = [
                        'name' => sanitize_text_field($data['name'])
                    ];
                }
            }
        }

        // Custom fields
        $sanitized['custom_fields'] = [];

        if (!empty($input['custom_fields']) && is_array($input['custom_fields'])) {
            foreach ($input['custom_fields'] as $index => $field) {
                $sanitized_field = [
                    'id' => isset($field['id']) ? sanitize_key($field['id']) : '',
                    'label' => isset($field['label']) ? sanitize_text_field($field['label']) : '',
                    'type' => 'text',
                    'required' => !empty($field['required'])
                ];

                // Sanitize field type
                $valid_types = ['text', 'textarea', 'select', 'checkbox'];
                if (isset($field['type']) && in_array($field['type'], $valid_types)) {
                    $sanitized_field['type'] = $field['type'];
                }

                // Only add field if it has an ID and label
                if (!empty($sanitized_field['id']) && !empty($sanitized_field['label'])) {
                    $sanitized['custom_fields'][] = $sanitized_field;
                }
            }
        }

        return $sanitized;
    }
}

// Initialize the settingsCore
Settings::init();
