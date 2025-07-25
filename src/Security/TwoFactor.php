<?php
namespace Attributes\Pro\Security;

use Attributes\Pro\Core\Constants;

/**
 * Two-Factor Authentication Handler
 * 
 * Implements two-factor authentication functionality with multiple methods:
 * - Email one-time codes
 * - Time-based one-time passwords (TOTP) via authenticator apps
 * - Recovery codes for backup access
 * 
 * @package Attributes\Pro\Security
 * @since 1.0.0
 */
class TwoFactor {
    /**
     * Singleton instance
     * 
     * @var TwoFactor|null
     */
    private static ?TwoFactor $instance = null;
    
    /**
     * Settings array
     * 
     * @var array
     */
    private array $settings;
    
    /**
     * Current user's 2FA status
     * 
     * @var array|null
     */
    private ?array $user_2fa_status = null;
    
    /**
     * Get singleton instance
     * 
     * @return TwoFactor Instance
     */
    public static function instance(): self {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        
        return self::$instance;
    }
    
    /**
     * Constructor
     */
    private function __construct() {
        $this->settings = get_option(Constants::TWO_FACTOR_SETTINGS_OPTION, []);
        
        if ($this->is_enabled()) {
            $this->init_hooks();
        }
    }
    
    /**
     * Initialize hooks
     */
    private function init_hooks(): void {
        // Add authentication filter
        add_filter('authenticate', [$this, 'authenticate'], 30, 3);
        
        // Add AJAX handlers for 2FA verification
        add_action('wp_ajax_nopriv_attrua_verify_2fa', [$this, 'handle_verify_2fa']);
        
        // Add user profile fields
        add_action('show_user_profile', [$this, 'add_profile_fields']);
        add_action('edit_user_profile', [$this, 'add_profile_fields']);
        
        // Save user profile fields
        add_action('personal_options_update', [$this, 'save_profile_fields']);
        add_action('edit_user_profile_update', [$this, 'save_profile_fields']);
        
        // Register scripts and styles
        add_action('wp_enqueue_scripts', [$this, 'enqueue_scripts']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_scripts']);
        
        // Add settings section
        add_action('attrua_pro_security_settings', [$this, 'render_settings']);
        add_action('attrua_pro_save_security_settings', [$this, 'save_settings']);
    }
    
    /**
     * Check if 2FA is enabled globally
     * 
     * @return bool Whether 2FA is enabled
     */
    public function is_enabled(): bool {
        return !empty($this->settings['enabled']) && $this->settings['enabled'] === 'yes';
    }
    
    /**
     * Authentication filter
     * 
     * @param \WP_User|null|\WP_Error $user WP_User if the user is authenticated
     * @param string $username Username or email
     * @param string $password Password
     * @return \WP_User|null|\WP_Error WP_User or WP_Error
     */
    public function authenticate($user, string $username, string $password) {
        // Only process if we have a valid user and 2FA is enabled
        if (!is_a($user, 'WP_User') || !$this->is_enabled()) {
            return $user;
        }
        
        // Check if user needs 2FA
        if ($this->user_needs_2fa($user->ID)) {
            // Set up session for 2FA process
            $this->setup_2fa_session($user);
            
            // Return error to show 2FA form
            return new \WP_Error(
                'attrua_2fa_required',
                __('Two-factor authentication is required.', Constants::TEXT_DOMAIN),
                ['user_id' => $user->ID]
            );
        }
        
        return $user;
    }
    
    /**
     * Setup 2FA session
     * 
     * @param \WP_User $user User object
     */
    private function setup_2fa_session(\WP_User $user): void {
        $session_id = wp_generate_password(32, false);
        $expiration = time() + 600; // 10 minutes
        
        // Store in transient
        set_transient(
            'attrua_2fa_' . $session_id,
            [
                'user_id' => $user->ID,
                'expires' => $expiration
            ],
            600 // 10 minutes
        );
        
        // Set cookie with session ID
        setcookie(
            'attrua_2fa_session',
            $session_id,
            $expiration,
            COOKIEPATH,
            COOKIE_DOMAIN,
            is_ssl(),
            true
        );
        
        // Generate and send code if using email method
        if ($this->get_user_preferred_method($user->ID) === 'email') {
            $this->generate_and_send_email_code($user);
        }
    }
    
    /**
     * Check if user needs 2FA
     * 
     * @param int $user_id User ID
     * @return bool Whether user needs 2FA
     */
    public function user_needs_2fa(int $user_id): bool {
        // Check if user has 2FA enabled
        $user_2fa = $this->get_user_2fa_status($user_id);
        
        if (!empty($user_2fa['enabled']) && $user_2fa['enabled'] === 'yes') {
            return true;
        }
        
        // Check if user role requires 2FA
        $required_roles = $this->settings['required_roles'] ?? [];
        $user = get_userdata($user_id);
        
        if (!$user) {
            return false;
        }
        
        foreach ($user->roles as $role) {
            if (in_array($role, $required_roles)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Get user 2FA status
     * 
     * @param int $user_id User ID
     * @return array 2FA status array
     */
    public function get_user_2fa_status(int $user_id): array {
        // Return cached status if available
        if ($this->user_2fa_status !== null) {
            return $this->user_2fa_status;
        }
        
        // Get from user meta
        $user_2fa = get_user_meta($user_id, 'attrua_2fa_status', true);
        
        if (!is_array($user_2fa)) {
            $user_2fa = [];
        }
        
        $this->user_2fa_status = $user_2fa;
        
        return $user_2fa;
    }
    
    /**
     * Get user preferred 2FA method
     * 
     * @param int $user_id User ID
     * @return string Preferred method (email, totp, recovery)
     */
    public function get_user_preferred_method(int $user_id): string {
        $user_2fa = $this->get_user_2fa_status($user_id);
        
        return $user_2fa['preferred_method'] ?? 'email';
    }
    
    /**
     * Generate and send email code
     * 
     * @param \WP_User $user User object
     * @return bool Whether the email was sent
     */
    private function generate_and_send_email_code(\WP_User $user): bool {
        // Generate code
        $code = sprintf('%06d', wp_rand(0, 999999));
        
        // Store code
        update_user_meta($user->ID, 'attrua_2fa_email_code', [
            'code' => $code,
            'expires' => time() + 600 // 10 minutes
        ]);
        
        // Send email
        $subject = sprintf(
            __('[%s] Your two-factor authentication code', Constants::TEXT_DOMAIN),
            get_bloginfo('name')
        );
        
        $message = sprintf(
            __("Hello %s,\n\nYour two-factor authentication code is: %s\n\nThe code will expire in 10 minutes.\n\nRegards,\n%s", Constants::TEXT_DOMAIN),
            $user->display_name,
            $code,
            get_bloginfo('name')
        );
        
        $headers = ['Content-Type: text/plain; charset=UTF-8'];
        
        return wp_mail($user->user_email, $subject, $message, $headers);
    }
    
    /**
     * Verify email code
     * 
     * @param int $user_id User ID
     * @param string $code Code to verify
     * @return bool Whether code is valid
     */
    public function verify_email_code(int $user_id, string $code): bool {
        $stored = get_user_meta($user_id, 'attrua_2fa_email_code', true);
        
        if (!is_array($stored) || empty($stored['code']) || empty($stored['expires'])) {
            return false;
        }
        
        // Check if code has expired
        if ($stored['expires'] < time()) {
            return false;
        }
        
        // Compare codes
        return $stored['code'] === $code;
    }
    
    /**
     * Verify TOTP code
     * 
     * @param int $user_id User ID
     * @param string $code Code to verify
     * @return bool Whether code is valid
     */
    public function verify_totp_code(int $user_id, string $code): bool {
        $user_2fa = $this->get_user_2fa_status($user_id);
        
        if (empty($user_2fa['totp_secret'])) {
            return false;
        }
        
        // Verify TOTP code using the TOTP library
        require_once ATTRUA_PRO_PATH . 'vendor/autoload.php';
        
        try {
            $totp = new \OTPHP\TOTP(
                $user_2fa['totp_secret'],
                ['algorithm' => 'sha1', 'period' => 30, 'digits' => 6]
            );
            
            return $totp->verify($code);
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Verify recovery code
     * 
     * @param int $user_id User ID
     * @param string $code Code to verify
     * @return bool Whether code is valid
     */
    public function verify_recovery_code(int $user_id, string $code): bool {
        $user_2fa = $this->get_user_2fa_status($user_id);
        
        if (empty($user_2fa['recovery_codes'])) {
            return false;
        }
        
        // Check if code exists in recovery codes
        $found_key = array_search($code, $user_2fa['recovery_codes']);
        
        if ($found_key === false) {
            return false;
        }
        
        // Remove used code
        unset($user_2fa['recovery_codes'][$found_key]);
        
        // Re-index array
        $user_2fa['recovery_codes'] = array_values($user_2fa['recovery_codes']);
        
        // Update user meta
        update_user_meta($user_id, 'attrua_2fa_status', $user_2fa);
        $this->user_2fa_status = $user_2fa;
        
        return true;
    }
    
    /**
     * Handle 2FA verification AJAX
     */
    public function handle_verify_2fa(): void {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'attrua_2fa_nonce')) {
            wp_send_json_error([
                'message' => __('Security check failed.', Constants::TEXT_DOMAIN)
            ]);
        }
        
        // Get session
        $session_id = $_COOKIE['attrua_2fa_session'] ?? '';
        
        if (empty($session_id)) {
            wp_send_json_error([
                'message' => __('Authentication session expired. Please login again.', Constants::TEXT_DOMAIN)
            ]);
        }
        
        $session = get_transient('attrua_2fa_' . $session_id);
        
        if (!$session || $session['expires'] < time()) {
            wp_send_json_error([
                'message' => __('Authentication session expired. Please login again.', Constants::TEXT_DOMAIN)
            ]);
        }
        
        $user_id = $session['user_id'];
        $method = isset($_POST['method']) ? sanitize_text_field($_POST['method']) : '';
        $code = isset($_POST['code']) ? sanitize_text_field($_POST['code']) : '';
        
        // Verify code based on method
        $verified = false;
        
        switch ($method) {
            case 'email':
                $verified = $this->verify_email_code($user_id, $code);
                break;
                
            case 'totp':
                $verified = $this->verify_totp_code($user_id, $code);
                break;
                
            case 'recovery':
                $verified = $this->verify_recovery_code($user_id, $code);
                break;
        }
        
        if (!$verified) {
            wp_send_json_error([
                'message' => __('Invalid verification code. Please try again.', Constants::TEXT_DOMAIN)
            ]);
        }
        
        // Code is valid, log the user in
        $user = get_user_by('id', $user_id);
        
        if (!$user) {
            wp_send_json_error([
                'message' => __('User not found.', Constants::TEXT_DOMAIN)
            ]);
        }
        
        // Clean up 2FA session
        delete_transient('attrua_2fa_' . $session_id);
        setcookie('attrua_2fa_session', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN);
        
        if ($method === 'email') {
            delete_user_meta($user_id, 'attrua_2fa_email_code');
        }
        
        // Set auth cookie
        wp_set_auth_cookie($user_id, true);
        
        // Log 2FA success
        do_action('attrua_pro_security_event', '2fa_success', $user_id, [
            'method' => $method,
            'ip' => $_SERVER['REMOTE_ADDR']
        ]);
        
        wp_send_json_success([
            'message' => __('Authentication successful. Redirecting...', Constants::TEXT_DOMAIN),
            'redirect' => admin_url()
        ]);
    }
    
    /**
     * Generate TOTP secret
     * 
     * @return string Generated secret
     */
    private function generate_totp_secret(): string {
        require_once ATTRUA_PRO_PATH . 'vendor/autoload.php';
        
        $totp = \OTPHP\TOTP::create();
        return $totp->getSecret();
    }
    
    /**
     * Generate recovery codes
     * 
     * @param int $count Number of codes to generate
     * @return array Generated codes
     */
    private function generate_recovery_codes(int $count = 10): array {
        $codes = [];
        
        for ($i = 0; $i < $count; $i++) {
            $codes[] = strtoupper(substr(wp_generate_password(10, false), 0, 5) . '-' . substr(wp_generate_password(10, false), 0, 5));
        }
        
        return $codes;
    }
    
    /**
     * Add 2FA fields to user profile
     * 
     * @param \WP_User $user User object
     */
    public function add_profile_fields(\WP_User $user): void {
        // Only show if 2FA is enabled
        if (!$this->is_enabled()) {
            return;
        }
        
        $user_2fa = $this->get_user_2fa_status($user->ID);
        $is_enabled = !empty($user_2fa['enabled']) && $user_2fa['enabled'] === 'yes';
        $preferred_method = $user_2fa['preferred_method'] ?? 'email';
        $has_totp = !empty($user_2fa['totp_secret']);
        $recovery_codes = $user_2fa['recovery_codes'] ?? [];
        
        // Get available methods
        $available_methods = Constants::TWO_FACTOR_METHODS;
        
        // Get if 2FA is required for this user
        $is_required = $this->is_required_for_user($user->ID);
        
        include ATTRUA_PRO_PATH . 'templates/admin/user-profile-2fa.php';
    }
    
    /**
     * Check if 2FA is required for user
     * 
     * @param int $user_id User ID
     * @return bool Whether 2FA is required
     */
    public function is_required_for_user(int $user_id): bool {
        $required_roles = $this->settings['required_roles'] ?? [];
        
        if (empty($required_roles)) {
            return false;
        }
        
        $user = get_userdata($user_id);
        
        if (!$user) {
            return false;
        }
        
        foreach ($user->roles as $role) {
            if (in_array($role, $required_roles)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Save 2FA fields from user profile
     * 
     * @param int $user_id User ID
     */
    public function save_profile_fields(int $user_id): void {
        // Check permissions
        if (!current_user_can('edit_user', $user_id) || !$this->is_enabled()) {
            return;
        }
        
        // Get current settings
        $user_2fa = $this->get_user_2fa_status($user_id);
        
        // Check if enabling/disabling
        if (isset($_POST['attrua_2fa_enabled'])) {
            $user_2fa['enabled'] = 'yes';
        } else {
            // Don't allow disabling if required for user's role
            if (!$this->is_required_for_user($user_id)) {
                $user_2fa['enabled'] = 'no';
            }
        }
        
        // Set preferred method
        if (isset($_POST['attrua_2fa_method'])) {
            $method = sanitize_text_field($_POST['attrua_2fa_method']);
            
            if (array_key_exists($method, Constants::TWO_FACTOR_METHODS)) {
                $user_2fa['preferred_method'] = $method;
            }
        }
        
        // Handle TOTP setup
        if (isset($_POST['attrua_2fa_setup_totp']) && $_POST['attrua_2fa_setup_totp'] === 'yes') {
            $user_2fa['totp_secret'] = $this->generate_totp_secret();
        } else if (isset($_POST['attrua_2fa_remove_totp']) && $_POST['attrua_2fa_remove_totp'] === 'yes') {
            unset($user_2fa['totp_secret']);
        }
        
        // Handle recovery codes generation
        if (isset($_POST['attrua_2fa_generate_recovery']) && $_POST['attrua_2fa_generate_recovery'] === 'yes') {
            $user_2fa['recovery_codes'] = $this->generate_recovery_codes(Constants::DEFAULT_RECOVERY_CODES_COUNT);
        }
        
        // Save settings
        update_user_meta($user_id, 'attrua_2fa_status', $user_2fa);
        $this->user_2fa_status = $user_2fa;
        
        // Log event
        do_action('attrua_pro_security_event', '2fa_settings_updated', $user_id, [
            'enabled' => $user_2fa['enabled'],
            'method' => $user_2fa['preferred_method'] ?? 'email'
        ]);
    }
    
    /**
     * Enqueue frontend scripts
     */
    public function enqueue_scripts(): void {
        if (!$this->is_enabled()) {
            return;
        }
        
        wp_enqueue_style(
            'attrua-2fa-css',
            ATTRUA_PRO_URL . 'assets/css/two-factor.css',
            [],
            ATTRUA_PRO_VERSION
        );
        
        wp_enqueue_script(
            'attrua-2fa-js',
            ATTRUA_PRO_URL . 'assets/js/two-factor.js',
            ['jquery'],
            ATTRUA_PRO_VERSION,
            true
        );
        
        wp_localize_script('attrua-2fa-js', 'attrua2FA', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('attrua_2fa_nonce'),
            'i18n' => [
                'verifying' => __('Verifying...', Constants::TEXT_DOMAIN),
                'error' => __('Error', Constants::TEXT_DOMAIN),
                'success' => __('Success', Constants::TEXT_DOMAIN)
            ]
        ]);
    }
    
    /**
     * Enqueue admin scripts
     * 
     * @param string $hook Current admin page
     */
    public function enqueue_admin_scripts(string $hook): void {
        if (!$this->is_enabled() || ($hook !== 'profile.php' && $hook !== 'user-edit.php')) {
            return;
        }
        
        wp_enqueue_style(
            'attrua-2fa-admin-css',
            ATTRUA_PRO_URL . 'assets/css/two-factor-admin.css',
            [],
            ATTRUA_PRO_VERSION
        );
        
        wp_enqueue_script(
            'attrua-2fa-admin-js',
            ATTRUA_PRO_URL . 'assets/js/two-factor-admin.js',
            ['jquery'],
            ATTRUA_PRO_VERSION,
            true
        );
        
        wp_localize_script('attrua-2fa-admin-js', 'attrua2FAAdmin', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('attrua_2fa_admin_nonce'),
            'i18n' => [
                'confirm_generate' => __('This will generate new recovery codes and invalidate any existing ones. Continue?', Constants::TEXT_DOMAIN),
                'confirm_disable' => __('Are you sure you want to disable two-factor authentication?', Constants::TEXT_DOMAIN)
            ]
        ]);
    }
    
    /**
     * Render settings section in admin
     * 
     * @param array $settings Current settings array
     */
    public function render_settings(array $settings): void {
        $two_factor_settings = $this->settings;
        $enabled = !empty($two_factor_settings['enabled']) && $two_factor_settings['enabled'] === 'yes';
        $required_roles = $two_factor_settings['required_roles'] ?? [];
        $all_roles = wp_roles()->get_names();
        $available_methods = Constants::TWO_FACTOR_METHODS;
        $allowed_methods = $two_factor_settings['allowed_methods'] ?? array_keys($available_methods);
        
        include ATTRUA_PRO_PATH . 'templates/admin/two-factor-settings.php';
    }
    
    /**
     * Save settings from admin
     * 
     * @param array $input Form input
     * @return array Sanitized settings
     */
    public function save_settings(array $input): array {
        $settings = [];
        
        // Enabled setting
        $settings['enabled'] = isset($input['two_factor_enabled']) ? 'yes' : 'no';
        
        // Required roles
        $settings['required_roles'] = [];
        
        if (isset($input['two_factor_required_roles']) && is_array($input['two_factor_required_roles'])) {
            foreach ($input['two_factor_required_roles'] as $role) {
                $settings['required_roles'][] = sanitize_text_field($role);
            }
        }
        
        // Allowed methods
        $settings['allowed_methods'] = [];
        $available_methods = array_keys(Constants::TWO_FACTOR_METHODS);
        
        if (isset($input['two_factor_allowed_methods']) && is_array($input['two_factor_allowed_methods'])) {
            foreach ($input['two_factor_allowed_methods'] as $method) {
                if (in_array($method, $available_methods)) {
                    $settings['allowed_methods'][] = $method;
                }
            }
        }
        
        // Fallback to all methods if none selected
        if (empty($settings['allowed_methods'])) {
            $settings['allowed_methods'] = $available_methods;
        }
        
        // Update internal settings
        $this->settings = $settings;
        
        // Save to options
        update_option(Constants::TWO_FACTOR_SETTINGS_OPTION, $settings);
        
        return $settings;
    }
    
    /**
     * Get QR code URL for TOTP
     * 
     * @param int $user_id User ID
     * @return string QR code URL
     */
    public function get_totp_qr_code_url(int $user_id): string {
        $user_2fa = $this->get_user_2fa_status($user_id);
        
        if (empty($user_2fa['totp_secret'])) {
            return '';
        }
        
        require_once ATTRUA_PRO_PATH . 'vendor/autoload.php';
        
        try {
            $user = get_userdata($user_id);
            
            if (!$user) {
                return '';
            }
            
            $totp = new \OTPHP\TOTP(
                $user_2fa['totp_secret'],
                ['algorithm' => 'sha1', 'period' => 30, 'digits' => 6]
            );
            
            $totp->setLabel($user->user_email);
            $totp->setIssuer(get_bloginfo('name'));
            
            return $totp->getProvisioningUri();
        } catch (\Exception $e) {
            return '';
        }
    }
    
    /**
     * Check if a method is allowed
     * 
     * @param string $method Method to check
     * @return bool Whether method is allowed
     */
    public function is_method_allowed(string $method): bool {
        if (!$this->is_enabled()) {
            return false;
        }
        
        $allowed_methods = $this->settings['allowed_methods'] ?? array_keys(Constants::TWO_FACTOR_METHODS);
        
        return in_array($method, $allowed_methods);
    }
    
    /**
     * Get available methods for user
     * 
     * @param int $user_id User ID
     * @return array Available methods
     */
    public function get_available_methods_for_user(int $user_id): array {
        $user_2fa = $this->get_user_2fa_status($user_id);
        $allowed_methods = $this->settings['allowed_methods'] ?? array_keys(Constants::TWO_FACTOR_METHODS);
        $available_methods = [];
        
        foreach ($allowed_methods as $method) {
            // Email is always available
            if ($method === 'email') {
                $available_methods[$method] = Constants::TWO_FACTOR_METHODS[$method];
                continue;
            }
            
            // TOTP requires secret
            if ($method === 'totp' && !empty($user_2fa['totp_secret'])) {
                $available_methods[$method] = Constants::TWO_FACTOR_METHODS[$method];
                continue;
            }
            
            // Recovery requires codes
            if ($method === 'recovery' && !empty($user_2fa['recovery_codes'])) {
                $available_methods[$method] = Constants::TWO_FACTOR_METHODS[$method];
                continue;
            }
        }
        
        return $available_methods;
    }
    
    /**
     * Render 2FA form
     * 
     * @param int $user_id User ID
     * @return string HTML form
     */
    public function render_2fa_form(int $user_id): string {
        $available_methods = $this->get_available_methods_for_user($user_id);
        $preferred_method = $this->get_user_preferred_method($user_id);
        
        // Default to email if preferred method not available
        if (!isset($available_methods[$preferred_method])) {
            $preferred_method = 'email';
        }
        
        ob_start();
        include ATTRUA_PRO_PATH . 'templates/front/forms/two-factor-form.php';
        return ob_get_clean();
    }
    
    /**
     * Force enable 2FA for a user
     * 
     * @param int $user_id User ID
     * @param string $method Preferred method
     * @return bool Success status
     */
    public function force_enable_for_user(int $user_id, string $method = 'email'): bool {
        if (!$this->is_enabled()) {
            return false;
        }
        
        // Get current settings
        $user_2fa = $this->get_user_2fa_status($user_id);
        
        // Enable 2FA
        $user_2fa['enabled'] = 'yes';
        
        // Set preferred method
        if (array_key_exists($method, Constants::TWO_FACTOR_METHODS)) {
            $user_2fa['preferred_method'] = $method;
        } else {
            $user_2fa['preferred_method'] = 'email';
        }
        
        // Generate TOTP secret if not exists and method is TOTP
        if ($method === 'totp' && empty($user_2fa['totp_secret'])) {
            $user_2fa['totp_secret'] = $this->generate_totp_secret();
        }
        
        // Generate recovery codes if not exists
        if (empty($user_2fa['recovery_codes'])) {
            $user_2fa['recovery_codes'] = $this->generate_recovery_codes(Constants::DEFAULT_RECOVERY_CODES_COUNT);
        }
        
        // Save settings
        update_user_meta($user_id, 'attrua_2fa_status', $user_2fa);
        $this->user_2fa_status = $user_2fa;
        
        // Log event
        do_action('attrua_pro_security_event', '2fa_forced_enable', $user_id, [
            'method' => $user_2fa['preferred_method']
        ]);
        
        return true;
    }
    
    /**
     * Disable 2FA for a user
     * 
     * @param int $user_id User ID
     * @return bool Success status
     */
    public function disable_for_user(int $user_id): bool {
        // Check if required for user's role
        if ($this->is_required_for_user($user_id)) {
            return false;
        }
        
        // Get current settings
        $user_2fa = $this->get_user_2fa_status($user_id);
        
        // Disable 2FA
        $user_2fa['enabled'] = 'no';
        
        // Save settings
        update_user_meta($user_id, 'attrua_2fa_status', $user_2fa);
        $this->user_2fa_status = $user_2fa;
        
        // Log event
        do_action('attrua_pro_security_event', '2fa_disabled', $user_id, []);
        
        return true;
    }
    
    /**
     * Check if user has 2FA enabled
     * 
     * @param int $user_id User ID
     * @return bool Whether 2FA is enabled for user
     */
    public function is_enabled_for_user(int $user_id): bool {
        $user_2fa = $this->get_user_2fa_status($user_id);
        
        return !empty($user_2fa['enabled']) && $user_2fa['enabled'] === 'yes';
    }
}