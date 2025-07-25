<?php

namespace Attributes\Pro\Core;

/**
 * Plugin Constants
 * 
 * Provides a centralized location for all plugin constants.
 * This improves maintainability and ensures consistency across the plugin.
 * 
 * @package Attributes\Pro\Core
 * @since 1.0.0
 */
class Constants
{
    /**
     * Plugin version
     * 
     * @var string
     */
    const VERSION = ATTRUA_PRO_VERSION;

    /**
     * Plugin file path
     * 
     * @var string
     */
    const FILE = ATTRUA_PRO_FILE;

    /**
     * Plugin directory path
     * 
     * @var string
     */
    const PATH = ATTRUA_PRO_PATH;

    /**
     * Plugin URL
     * 
     * @var string
     */
    const URL = ATTRUA_PRO_URL;

    /**
     * Plugin basename
     * 
     * @var string
     */
    const BASENAME = ATTRUA_PRO_BASENAME;

    /**
     * SureCart license API token
     * 
     * @var string
     */
    const LICENSE_TOKEN = 'pt_8vw2f8kwGBG3jbsJqgYUAS5B';

    /**
     * Plugin slug for license
     * 
     * @var string
     */
    const PLUGIN_SLUG = 'attributes-user-access-pro-lite';

    /**
     * License key option name
     * 
     * @var string
     */
    const LICENSE_KEY_OPTION = 'attrua_pro_license_key';

    /**
     * License data option name
     * 
     * @var string
     */
    const LICENSE_DATA_OPTION = 'attrua_pro_license_data';

    /**
     * License last check option name
     * 
     * @var string
     */
    const LICENSE_LAST_CHECK_OPTION = 'attrua_pro_license_last_check';

    /**
     * License check interval in seconds (24 hours)
     * 
     * @var int
     */
    const LICENSE_CHECK_INTERVAL = 86400;

    /**
     * Security settings option name
     * 
     * @var string
     */
    const SECURITY_SETTINGS_OPTION = 'attrua_pro_security_settings';

    /**
     * Two-factor authentication settings option name
     * 
     * @var string
     */
    const TWO_FACTOR_SETTINGS_OPTION = 'attrua_pro_2fa_settings';

    /**
     * reCAPTCHA settings option name
     * 
     * @var string
     */
    const RECAPTCHA_SETTINGS_OPTION = 'attrua_pro_recaptcha_settings';

    /**
     * Password policy settings option name
     * 
     * @var string
     */
    const PASSWORD_POLICY_OPTION = 'attrua_pro_password_policy';

    /**
     * Email settings option name
     * 
     * @var string
     */
    const EMAIL_SETTINGS_OPTION = 'attrua_pro_email_settings';

    /**
     * Integration settings option name
     * 
     * @var string
     */
    const INTEGRATION_SETTINGS_OPTION = 'attrua_pro_integration_settings';

    /**
     * Pages settings option name
     * 
     * @var string
     */
    const PAGES_SETTINGS_OPTION = 'attrua_pro_pages_options';

    /**
     * IP block list option name
     * 
     * @var string
     */
    const IP_BLOCK_LIST_OPTION = 'attrua_pro_ip_block_list';

    /**
     * IP allow list option name
     * 
     * @var string
     */
    const IP_ALLOW_LIST_OPTION = 'attrua_pro_ip_allow_list';

    /**
     * Security audit log option name
     * 
     * @var string
     */
    const SECURITY_AUDIT_LOG_OPTION = 'attrua_pro_security_audit_log';

    /**
     * Maximum audit log entries to keep
     * 
     * @var int
     */
    const MAX_AUDIT_LOG_ENTRIES = 1000;

    /**
     * Available two-factor authentication methods
     * 
     * @var array
     */
    const TWO_FACTOR_METHODS = [
        'email' => 'Email Code',
        'totp' => 'Authenticator App',
        'recovery' => 'Recovery Codes'
    ];

    /**
     * Default minimum password length
     * 
     * @var int
     */
    const DEFAULT_MIN_PASSWORD_LENGTH = 8;

    /**
     * Default password expiration in days (0 = never)
     * 
     * @var int
     */
    const DEFAULT_PASSWORD_EXPIRATION = 0;

    /**
     * Default number of recovery codes to generate
     * 
     * @var int
     */
    const DEFAULT_RECOVERY_CODES_COUNT = 10;

    /**
     * Text domain for translations
     * 
     * @var string
     */
    const TEXT_DOMAIN = 'attributes-user-access-pro-lite';

    /**
     * Get the name with prefix
     * 
     * Generates a prefixed name for options, hooks, etc.
     * 
     * @param string $name The name to prefix
     * @return string The prefixed name
     */
    public static function get_prefixed_name(string $name): string
    {
        return 'attrua_pro_' . $name;
    }

    /**
     * Get available email templates
     * 
     * @return array Available email templates
     */
    public static function get_email_templates(): array
    {
        return [
            'default' => __('Default', self::TEXT_DOMAIN),
            'branded' => __('Branded', self::TEXT_DOMAIN),
            'plain' => __('Plain Text', self::TEXT_DOMAIN)
        ];
    }

    /**
     * Get email notification types
     * 
     * @return array Email notification types
     */
    public static function get_email_types(): array
    {
        return [
            'welcome' => __('Welcome Email', self::TEXT_DOMAIN),
            'password_reset' => __('Password Reset', self::TEXT_DOMAIN),
            'two_factor' => __('Two-Factor Authentication', self::TEXT_DOMAIN),
            'account_locked' => __('Account Locked', self::TEXT_DOMAIN),
            'admin_notification' => __('Admin Notification', self::TEXT_DOMAIN)
        ];
    }
}
