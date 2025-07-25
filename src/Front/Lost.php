<?php

namespace Attributes\Pro\Front;

use Attributes\Pro\License\License_Manager;

/**
 * Lost Password Handler Class
 *
 * Manages the lost password functionality including form rendering,
 * request processing, and security measures for password recovery workflows.
 *
 * @package Attributes\Pro\Front
 * @since 1.0.0
 */
class Lost
{
    /**
     * Settings storage
     *
     * @var array Configuration settings for the lost password functionality
     */
    private array $settings = [];

    /**
     * Constructor
     * 
     * Initializes the lost password handler, setting up hooks and configuration
     * only if a valid license is detected to ensure feature gating.
     */
    public function __construct()
    {
        // Only initialize if license is active
        if (!License_Manager::instance()->is_active()) {
            return;
        }

        $this->init();
    }

    /**
     * Initialize lost password functionality
     * 
     * Sets up required hooks, loads settings, and configures the lost password
     * workflow integration points with WordPress core.
     *
     * @return void
     */
    private function init(): void
    {
        // Load settings
        $this->settings = get_option('attrua_pro_pages_options', []);

        // Register shortcode for lost password form
        add_shortcode('attributes_lost_password_form', [$this, 'render_lost_password_form']);

        // Handle form submission
        add_action('init', [$this, 'handle_lost_password_request']);

        // Filter the lost password URL to use custom page if configured
        add_filter('lostpassword_url', [$this, 'custom_lostpassword_url'], 10, 2);

        // Add settings page content
        add_action('attrua_admin_settings_content', [$this, 'render_settings_content'], 20, 1);

        // Custom retrieval processing
        add_action('retrieve_password', [$this, 'custom_retrieve_password_notification']);

        // Add security checks to lost password form
        add_action('lostpassword_post', [$this, 'validate_lost_password_request'], 10, 1);

        // Filter lost password errors
        add_filter('lostpassword_errors', [$this, 'custom_lostpassword_errors'], 10, 1);
    }

    /**
     * Render lost password form via shortcode
     * 
     * Generates the HTML for the custom lost password form with enhanced
     * security features and user experience improvements over the default
     * WordPress implementation.
     *
     * @param array $atts Shortcode attributes for customizing form appearance and behavior
     * @param string $content Shortcode content (unused but required for shortcode API)
     * @return string Generated HTML for the lost password form
     */
    public function render_lost_password_form(array $atts = [], string $content = ''): string
    {
        // Parse shortcode attributes
        $args = shortcode_atts([
            'redirect' => '',
            'form_id' => 'attrua_lost_password_form',
            'label_username' => __('Username or Email', 'attributes-user-access-pro-lite'),
            'label_submit' => __('Get New Password', 'attributes-user-access-pro-lite'),
            'intro_text' => __('Please enter your username or email address. You will receive a link to create a new password via email.', 'attributes-user-access-pro-lite'),
        ], $atts);

        // Get any error or success messages
        $error_message = $this->get_error_message();
        $success_message = $this->get_success_message();

        // Start output buffering
        ob_start();

        // Include lost password form template
        require $this->get_template_path('front/forms/lost-form.php');

        // Return the generated HTML
        return ob_get_clean();
    }

    /**
     * Handle lost password form submission
     * 
     * Processes the submitted form data, performs validation, and initiates
     * the password reset workflow with appropriate security measures.
     *
     * @return void
     */
    public function handle_lost_password_request(): void
    {
        if (!isset($_POST['attrua_lost_password_submit'])) {
            return;
        }

        // Verify nonce
        if (
            !isset($_POST['attrua_lost_password_nonce']) ||
            !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['attrua_lost_password_nonce'])), 'attrua_lost_password')
        ) {
            wp_die(esc_html('Security check failed.', 'attributes-user-access-pro-lite'));
        }

        // Start session if not started
        if (!session_id()) {
            session_start();
        }

        // Get and sanitize user input
        $user_login = isset($_POST['user_login']) ? sanitize_text_field(wp_unslash($_POST['user_login'])) : '';

        // Basic validation
        if (empty($user_login)) {
            $this->set_error_message(__('Please enter a username or email address.', 'attributes-user-access-pro-lite'));
            return;
        }

        // Check for reCAPTCHA if enabled
        $recaptcha_settings = get_option('attrua_pro_recaptcha_settings', []);
        $recaptcha_enabled = !empty($recaptcha_settings['enabled']) && !empty($recaptcha_settings['forms']['lost_password']);

        if ($recaptcha_enabled) {
            $recaptcha_component = null;

            // Try to get reCAPTCHA component from Pro class
            if (function_exists('ATTRUA_PRO_init')) {
                $pro = ATTRUA_PRO_init();
                $recaptcha_component = $pro->get_component('recaptcha');
            }

            if ($recaptcha_component && !$recaptcha_component->verify_recaptcha()) {
                $this->set_error_message(__('reCAPTCHA verification failed. Please try again.', 'attributes-user-access-pro-lite'));
                return;
            }
        }

        // Check for user by username or email
        $user_data = $this->get_user_by_login_or_email($user_login);

        if (!$user_data) {
            $this->set_error_message(__('Invalid username or email address.', 'attributes-user-access-pro-lite'));
            return;
        }

        // Rate limit checks - prevent brute force attacks
        if ($this->is_rate_limited($user_login)) {
            $this->set_error_message(__('Too many password reset attempts. Please try again later.', 'attributes-user-access-pro-lite'));
            return;
        }

        // Generate and send reset key
        $this->send_password_reset_key($user_data);

        // Set success message
        $this->set_success_message(__('Check your email for the confirmation link.', 'attributes-user-access-pro-lite'));

        // Redirect to same page with success message
        wp_safe_redirect(add_query_arg(['reset' => 'requested'], wp_get_referer()));
        exit;
    }

    /**
     * Custom retrieve password notification
     * 
     * Overrides the default WordPress password retrieval email with a customized
     * version that supports templating and improved security measures.
     *
     * @param string $user_login Username for the user
     * @return void
     */
    public function custom_retrieve_password_notification(string $user_login): void
    {
        // Get user data
        $user_data = $this->get_user_by_login_or_email($user_login);

        if (!$user_data) {
            return;
        }

        // Get reset key
        $key = get_password_reset_key($user_data);

        if (is_wp_error($key)) {
            return;
        }

        // Get email settings
        $email_settings = get_option('attrua_pro_email_settings', []);

        if (empty($email_settings['reset_email']['enabled'])) {
            // If custom emails are not enabled, use default WordPress behavior
            return;
        }

        // Get email content from settings
        $subject = $email_settings['reset_email']['subject'] ?? __('Password Reset for {site_name}', 'attributes-user-access-pro-lite');
        $content = $email_settings['reset_email']['content'] ?? __("Hello {user_display_name},\n\nA password reset was requested for your account on {site_name}.\n\nTo reset your password, please visit the following link:\n{reset_url}\n\nThis link will expire in {reset_expiry} hours.\n\nIf you did not request this password reset, please ignore this email.\n\nRegards,\n{site_name} Team", 'attributes-user-access-pro-lite');

        // Prepare reset URL
        $reset_url = $this->get_reset_url($user_data, $key);

        // Password policy settings
        $password_policy = get_option('attrua_pro_password_policy', []);
        $reset_expiry = isset($password_policy['reset_expiration']) ? intval($password_policy['reset_expiration']) : 24;

        // Replace placeholders
        $site_name = get_bloginfo('name');

        $subject = str_replace(
            ['{site_name}', '{user_login}', '{user_display_name}', '{user_email}'],
            [$site_name, $user_data->user_login, $user_data->display_name, $user_data->user_email],
            $subject
        );

        $content = str_replace(
            ['{site_name}', '{site_url}', '{reset_url}', '{user_login}', '{user_display_name}', '{user_email}', '{reset_expiry}'],
            [$site_name, home_url(), $reset_url, $user_data->user_login, $user_data->display_name, $user_data->user_email, $reset_expiry],
            $content
        );

        // Email template
        $template = $email_settings['template'] ?? 'default';
        $email_html = $this->format_email_content($content, $template);

        // Set email headers
        $headers = ['Content-Type: text/html; charset=UTF-8'];

        if (!empty($email_settings['from_name']) && !empty($email_settings['from_email'])) {
            $headers[] = 'From: ' . $email_settings['from_name'] . ' <' . $email_settings['from_email'] . '>';
        }

        // Send custom email
        $sent = wp_mail($user_data->user_email, $subject, $email_html, $headers);

        // Prevent WordPress from sending its default email
        if ($sent) {
            add_filter('allow_password_reset', '__return_false', 999);
        }
    }

    /**
     * Format email content based on template
     * 
     * Applies the selected email template formatting to the content,
     * supporting various template styles (default, branded, plain).
     *
     * @param string $content Raw email content
     * @param string $template Template identifier (default, branded, plain)
     * @return string Formatted email content with template applied
     */
    private function format_email_content(string $content, string $template): string
    {
        switch ($template) {
            case 'branded':
                // Use branded email template
                ob_start();
                include $this->get_template_path('emails/branded.php');
                return ob_get_clean();

            case 'plain':
                // Convert newlines to <br> tags but otherwise keep plain
                return nl2br($content);

            case 'default':
            default:
                // Use default template
                ob_start();
                include $this->get_template_path('emails/default.php');
                return ob_get_clean();
        }
    }

    /**
     * Get password reset URL
     * 
     * Constructs the URL for the password reset page, using a custom page
     * if configured or falling back to the WordPress default.
     *
     * @param \WP_User $user User object
     * @param string $key Password reset key
     * @return string Password reset URL
     */
    private function get_reset_url(\WP_User $user, string $key): string
    {
        // Check for custom reset page
        $reset_page_id = $this->settings['reset'] ?? null;

        if ($reset_page_id) {
            // Use custom reset page
            $reset_url = get_permalink($reset_page_id);

            // Add required query parameters
            return add_query_arg(
                [
                    'key' => $key,
                    'login' => rawurlencode($user->user_login)
                ],
                $reset_url
            );
        }

        // Fall back to WordPress default
        return network_site_url("wp-login.php?action=rp&key=$key&login=" . rawurlencode($user->user_login), 'login');
    }

    /**
     * Custom lost password URL
     * 
     * Filters the WordPress lost password URL to use a custom page when configured.
     *
     * @param string $lostpassword_url Default WordPress lost password URL
     * @param string $redirect Redirect URL after password reset
     * @return string Custom or default lost password URL
     */
    public function custom_lostpassword_url(string $lostpassword_url, string $redirect): string
    {
        // Check if we have a custom lost password page
        $lost_page_id = $this->settings['lost'] ?? null;

        if ($lost_page_id) {
            $lost_url = get_permalink($lost_page_id);

            // Add redirect parameter if provided
            if (!empty($redirect)) {
                $lost_url = add_query_arg('redirect_to', urlencode($redirect), $lost_url);
            }

            return $lost_url;
        }

        return $lostpassword_url;
    }

    /**
     * Validate lost password request with enhanced security checks
     * 
     * Applies additional security validation beyond WordPress defaults,
     * including rate limiting, IP validation, and custom rules.
     *
     * @param \WP_Error $errors WordPress error object
     * @return void
     */
    public function validate_lost_password_request(\WP_Error $errors): void
    {
        // Get user login/email
        $user_login = isset($_POST['user_login']) ? sanitize_text_field(wp_unslash($_POST['user_login'])) : '';

        if (empty($user_login)) {
            $errors->add('empty_username', __('Please enter a username or email address.', 'attributes-user-access-pro-lite'));
            return;
        }

        // Check for user by username or email
        $user_data = $this->get_user_by_login_or_email($user_login);

        if (!$user_data) {
            $errors->add('invalid_username', __('Invalid username or email address.', 'attributes-user-access-pro-lite'));
            return;
        }

        // Rate limit checks
        if ($this->is_rate_limited($user_login)) {
            $errors->add('rate_limited', __('Too many password reset attempts. Please try again later.', 'attributes-user-access-pro-lite'));
            return;
        }

        // Track request for rate limiting
        $this->log_reset_attempt($user_login);
    }

    /**
     * Customize lost password errors
     * 
     * Provides more user-friendly error messages for the lost password form
     * while maintaining security through ambiguous messaging when appropriate.
     *
     * @param \WP_Error $errors WordPress error object
     * @return \WP_Error Modified errors object
     */
    public function custom_lostpassword_errors(\WP_Error $errors): \WP_Error
    {
        // Replace generic WordPress error messages with more user-friendly ones
        // while maintaining security through ambiguity where appropriate

        // Get all error codes
        $codes = $errors->get_error_codes();

        // Handle common error codes
        if (in_array('invalid_email', $codes)) {
            $errors->remove('invalid_email');
            $errors->add('invalid_email', __('The email address entered is not valid.', 'attributes-user-access-pro-lite'));
        }

        if (in_array('invalidcombo', $codes)) {
            $errors->remove('invalidcombo');
            $errors->add('invalidcombo', __('There is no account with that username or email address.', 'attributes-user-access-pro-lite'));
        }

        return $errors;
    }

    /**
     * Check if user is rate limited for password reset attempts
     * 
     * Implements rate limiting for password reset requests to prevent
     * brute force attacks and account enumeration.
     *
     * @param string $user_login Username or email
     * @return bool Whether user is currently rate limited
     */
    private function is_rate_limited(string $user_login): bool
    {
        // Get IP address
        $ip = $this->get_client_ip();

        // Get security settings
        $security_settings = get_option('attrua_pro_security_settings', []);
        $max_attempts = isset($security_settings['max_reset_attempts']) ? intval($security_settings['max_reset_attempts']) : 3;
        $lockout_duration = isset($security_settings['reset_lockout_duration']) ? intval($security_settings['reset_lockout_duration']) : 15;

        // Check attempt count by IP
        $ip_attempts = get_transient('attrua_pro_reset_attempts_ip_' . md5($ip));

        if ($ip_attempts && $ip_attempts >= $max_attempts) {
            return true;
        }

        // Check attempt count by username/email
        $user_attempts = get_transient('attrua_pro_reset_attempts_user_' . md5($user_login));

        if ($user_attempts && $user_attempts >= $max_attempts) {
            return true;
        }

        return false;
    }

    /**
     * Log password reset attempt for rate limiting
     * 
     * Records password reset attempts to implement rate limiting and
     * detect potential brute force attacks.
     *
     * @param string $user_login Username or email
     * @return void
     */
    private function log_reset_attempt(string $user_login): void
    {
        // Get IP address
        $ip = $this->get_client_ip();

        // Get security settings
        $security_settings = get_option('attrua_pro_security_settings', []);
        $lockout_duration = isset($security_settings['reset_lockout_duration']) ? intval($security_settings['reset_lockout_duration']) : 15;

        // Increment IP attempt count
        $ip_attempts = get_transient('attrua_pro_reset_attempts_ip_' . md5($ip));
        $ip_attempts = $ip_attempts ? $ip_attempts + 1 : 1;
        set_transient('attrua_pro_reset_attempts_ip_' . md5($ip), $ip_attempts, $lockout_duration * MINUTE_IN_SECONDS);

        // Increment user attempt count
        $user_attempts = get_transient('attrua_pro_reset_attempts_user_' . md5($user_login));
        $user_attempts = $user_attempts ? $user_attempts + 1 : 1;
        set_transient('attrua_pro_reset_attempts_user_' . md5($user_login), $user_attempts, $lockout_duration * MINUTE_IN_SECONDS);

        // Log to audit log if available
        if (function_exists('ATTRUA_PRO_init')) {
            $pro = ATTRUA_PRO_init();
            $audit_log = $pro->get_component('audit_log');

            if ($audit_log) {
                $audit_log->log_event('password_reset_attempt', [
                    'user_login' => $user_login,
                    'ip' => $ip,
                    'attempt' => $user_attempts
                ]);
            }
        }
    }

    /**
     * Get client IP address with proxy support
     * 
     * Safely extracts the client's IP address with support for common
     * proxy headers and security considerations.
     *
     * @return string Client IP address
     */
    private function get_client_ip(): string
    {
        $ip = $_SERVER['REMOTE_ADDR'];

        // Check for proxy headers
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && filter_var($_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP)) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif (isset($_SERVER['HTTP_CLIENT_IP']) && filter_var($_SERVER['HTTP_CLIENT_IP'], FILTER_VALIDATE_IP)) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        }

        return $ip;
    }

    /**
     * Get user by login or email
     * 
     * Retrieves user data from WordPress based on either username or email.
     *
     * @param string $user_login Username or email
     * @return \WP_User|false User object or false if not found
     */
    private function get_user_by_login_or_email(string $user_login)
    {
        if (is_email($user_login)) {
            return get_user_by('email', $user_login);
        } else {
            return get_user_by('login', $user_login);
        }
    }

    /**
     * Get template path
     * 
     * Determines the appropriate template path, supporting theme overrides
     * and fallback to plugin defaults.
     *
     * @param string $template Template path relative to template directory
     * @return string Full path to template file
     */
    private function get_template_path(string $template): string
    {
        // Check theme for template override
        $theme_template = locate_template([
            'attributes/' . $template,
            'attributes-user-access/' . $template,
            'attributes-user-access-pro-lite/' . $template
        ]);

        if ($theme_template) {
            return $theme_template;
        }

        // Fall back to plugin template
        return ATTRUA_PRO_PATH . 'templates/' . $template;
    }

    /**
     * Get error message from session
     * 
     * Retrieves and clears any error message stored in the session.
     *
     * @return string Error message or empty string if none
     */
    private function get_error_message(): string
    {
        if (!session_id()) {
            session_start();
        }

        $message = '';

        if (isset($_SESSION['attrua_pro_lost_password_error'])) {
            $message = $_SESSION['attrua_pro_lost_password_error'];
            unset($_SESSION['attrua_pro_lost_password_error']);
        }

        return $message;
    }

    /**
     * Set error message in session
     * 
     * Stores an error message in the session for display on next page load.
     *
     * @param string $message Error message
     * @return void
     */
    private function set_error_message(string $message): void
    {
        if (!session_id()) {
            session_start();
        }

        $_SESSION['attrua_pro_lost_password_error'] = $message;
    }

    /**
     * Get success message based on query parameter
     * 
     * Checks for success indicator in query string and returns appropriate message.
     *
     * @return string Success message or empty string if none
     */
    private function get_success_message(): string
    {
        if (isset($_GET['reset']) && $_GET['reset'] === 'requested') {
            return __('Check your email for the confirmation link.', 'attributes-user-access-pro-lite');
        }

        return '';
    }

    /**
     * Set success message in session
     * 
     * Stores a success message in the session for display on next page load.
     *
     * @param string $message Success message
     * @return void
     */
    private function set_success_message(string $message): void
    {
        if (!session_id()) {
            session_start();
        }

        $_SESSION['attrua_pro_lost_password_success'] = $message;
    }

    /**
     * Render settings content in admin interface
     *
     * @param bool $has_premium_features Whether premium features are available
     * @return void
     */
    public function render_settings_content(bool $has_premium_features): void
    {
        if (!$has_premium_features || !isset($_GET['tab']) || $_GET['tab'] !== 'pages') {
            return;
        }

        // Settings content is handled by the pages tab, but we hook here
        // to potentially add lost password specific settings
    }
}
