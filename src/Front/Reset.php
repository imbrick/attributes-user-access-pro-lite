<?php

namespace Attributes\Front;

use Attributes\Core\Settings;
use Attributes\Security\IP_Manager;
use Attributes\Security\Audit_Log;
use Attributes\Security\Recaptcha;

/**
 * Password Reset Handler Class
 *
 * Manages enhanced password reset functionality with improved security,
 * token management, and customized user experience.
 *
 * @package Attributes\Front
 * @since   1.0.0
 */
class Reset
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
     * IP Manager instance for security checks.
     *
     * @since  1.0.0
     * @access private
     * @var    IP_Manager|null
     */
    private ?IP_Manager $ip_manager;

    /**
     * Audit Log instance for security logging.
     *
     * @since  1.0.0
     * @access private
     * @var    Audit_Log|null
     */
    private ?Audit_Log $audit_log;

    /**
     * Recaptcha instance for bot prevention.
     *
     * @since  1.0.0
     * @access private
     * @var    Recaptcha|null
     */
    private ?Recaptcha $recaptcha;

    /**
     * Reset token validity duration in seconds.
     * 
     * Default: 1 hour (3600 seconds)
     *
     * @since  1.0.0
     * @access private
     * @var    int
     */
    private int $token_expiry = 3600;

    /**
     * Constructor.
     *
     * Initialize the reset handler and set up required hooks.
     *
     * @since 1.0.0
     * @param Settings $settings Core settings instance.
     */
    public function __construct(Settings $settings)
    {
        $this->settings = $settings;

        // Initialize security components if available
        $this->ip_manager = class_exists('\\Attributes\\Security\\IP_Manager') ? new IP_Manager($settings) : null;
        $this->audit_log = class_exists('\\Attributes\\Security\\Audit_Log') ? new Audit_Log($settings) : null;
        $this->recaptcha = class_exists('\\Attributes\\Security\\Recaptcha') ? new Recaptcha($settings) : null;

        // Override token expiry from settings if specified
        $custom_expiry = (int) $this->settings->attrua_get('security.reset_token_expiry', 0);
        if ($custom_expiry > 0) {
            $this->token_expiry = $custom_expiry;
        }

        $this->attrua_init_hooks();
    }

    /**
     * Initialize WordPress hooks.
     *
     * Sets up all necessary action and filter hooks for reset functionality.
     *
     * @since  1.0.0
     * @access private
     * @return void
     */
    private function attrua_init_hooks(): void
    {
        // Shortcode registration
        add_shortcode('attributes_reset_form', [$this, 'attrua_render_reset_form']);

        // Form processing
        add_action('init', [$this, 'attrua_handle_reset_request']);
        add_action('init', [$this, 'attrua_handle_reset_password']);

        // Email customization
        add_filter('retrieve_password_message', [$this, 'attrua_customize_reset_email'], 10, 4);
        add_filter('retrieve_password_title', [$this, 'attrua_customize_reset_email_subject'], 10, 1);

        // Page redirection
        add_action('init', [$this, 'attrua_reset_page_redirect']);

        // Add custom template redirects for reset flow
        add_action('template_redirect', [$this, 'attrua_maybe_redirect_reset_flow']);
    }

    /**
     * Get template path.
     * 
     * Checks for template in theme directory before using plugin default.
     *
     * @param string $template Template file to load
     * @return string Full path to template file
     */
    private function attrua_get_template_path(string $template): string
    {
        // Look for template in theme directory
        $theme_template = locate_template([
            'attributes/' . $template,
            'attributes-user-access/' . $template
        ]);

        // Return theme template if found, otherwise use plugin default
        if ($theme_template) {
            return $theme_template;
        }

        return ATTRUA_PATH . 'templates/' . $template;
    }

    /**
     * Render reset form via shortcode.
     *
     * Generates and returns the HTML for the password reset form, including error messages
     * and success notifications.
     *
     * @since  1.0.0
     * @param  array  $atts    Shortcode attributes.
     * @param  string $content Shortcode content.
     * @return string Generated HTML for the reset form.
     */
    public function attrua_render_reset_form(array $atts = [], string $content = ''): string
    {
        // Early return for logged-in users with redirect
        if (is_user_logged_in()) {
            $redirect = $this->settings->attrua_get('redirects.reset_logged_in', '');
            if (empty($redirect)) {
                $redirect = home_url();
            }

            wp_safe_redirect($redirect);
            exit;
        }

        // Parse shortcode attributes
        $args = shortcode_atts([
            'redirect' => '',
            'form_id' => 'attrua_reset_form',
            'label_username' => __('Username or Email', 'attributes-user-access-pro-lite'),
            'label_reset' => __('Reset Password', 'attributes-user-access-pro-lite'),
            'label_new_password' => __('New Password', 'attributes-user-access-pro-lite'),
            'label_confirm_password' => __('Confirm Password', 'attributes-user-access-pro-lite'),
            'label_submit' => __('Set New Password', 'attributes-user-access-pro-lite'),
            'value_username' => '',
            'use_recaptcha' => $this->settings->attrua_get('security.recaptcha_reset', false)
        ], $atts);

        // Check if we're in reset mode or request mode
        $token = isset($_GET['token']) ? sanitize_text_field(wp_unslash($_GET['token'])) : '';
        $login = isset($_GET['login']) ? sanitize_text_field(wp_unslash($_GET['login'])) : '';

        $reset_mode = !empty($token) && !empty($login);
        $args['reset_mode'] = $reset_mode;

        // Validate token if in reset mode
        if ($reset_mode) {
            $token_valid = $this->attrua_validate_token($login, $token);

            if (!$token_valid) {
                return $this->attrua_render_error_message(
                    __('Invalid or expired password reset link. Please request a new password reset.', 'attributes-user-access-pro-lite')
                );
            }

            $args['token'] = $token;
            $args['login'] = $login;
        }

        // Get any error or success messages
        $messages = $this->attrua_get_messages();

        // Start output buffering
        ob_start();

        // Include the reset form template
        include $this->attrua_get_template_path('front/forms/reset-form.php');

        // Return the generated HTML
        return ob_get_clean();
    }

    /**
     * Handle password reset request.
     *
     * Processes the initial password reset request, validates the input,
     * and sends the password reset email if valid.
     *
     * @since  1.0.0
     * @access public
     * @return void
     */
    public function attrua_handle_reset_request(): void
    {
        if (!isset($_POST['attrua_reset_request_submit'])) {
            return;
        }

        // Verify nonce
        if (
            !isset($_POST['attrua_reset_nonce']) ||
            !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['attrua_reset_nonce'])), 'attrua_reset')
        ) {
            $this->attrua_set_error_message(__('Security check failed.', 'attributes-user-access-pro-lite'));
            return;
        }

        // Check for rate limiting if IP Manager is available
        if ($this->ip_manager && !$this->ip_manager->attrua_can_perform_action('reset_request')) {
            $this->attrua_set_error_message(__('Too many password reset attempts. Please try again later.', 'attributes-user-access-pro-lite'));

            // Log the rate limit event
            if ($this->audit_log) {
                $this->audit_log->attrua_log_event('reset_rate_limited', [
                    'ip' => $this->ip_manager->attrua_get_client_ip(),
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
                ]);
            }

            return;
        }

        // Verify reCAPTCHA if enabled
        if ($this->recaptcha && $this->settings->attrua_get('security.recaptcha_reset', false)) {
            $recaptcha_response = isset($_POST['g-recaptcha-response']) ?
                sanitize_text_field(wp_unslash($_POST['g-recaptcha-response'])) : '';

            if (!$this->recaptcha->attrua_verify($recaptcha_response)) {
                $this->attrua_set_error_message(__('CAPTCHA verification failed. Please try again.', 'attributes-user-access-pro-lite'));
                return;
            }
        }

        // Get and sanitize user login or email
        $user_login = isset($_POST['user_login']) ? sanitize_text_field(wp_unslash($_POST['user_login'])) : '';

        if (empty($user_login)) {
            $this->attrua_set_error_message(__('Please enter a username or email address.', 'attributes-user-access-pro-lite'));
            return;
        }

        // Try to get user by email or login
        $user = get_user_by('email', $user_login);
        if (!$user) {
            $user = get_user_by('login', $user_login);
        }

        if (!$user) {
            // Security best practice: Don't reveal whether a user exists
            $this->attrua_set_success_message(__('If your username or email address exists in our database, you will receive a password recovery link at your email address.', 'attributes-user-access-pro-lite'));

            // Log the failed attempt if audit logging is enabled
            if ($this->audit_log) {
                $this->audit_log->attrua_log_event('reset_invalid_user', [
                    'attempted_login' => $user_login,
                    'ip' => $this->ip_manager ? $this->ip_manager->attrua_get_client_ip() : 'Unknown'
                ]);
            }

            return;
        }

        // Generate custom token with expiry
        $token = $this->attrua_generate_reset_token($user->ID);

        // Store token in user meta with expiry timestamp
        $expiry = time() + $this->token_expiry;
        update_user_meta($user->ID, 'attrua_reset_token', [
            'token' => $token,
            'expiry' => $expiry
        ]);

        // Get reset page URL
        $reset_page_id = $this->settings->attrua_get('pages.reset');
        $reset_url = $reset_page_id ? get_permalink($reset_page_id) : wp_lostpassword_url();

        // Add token and login parameters
        $reset_url = add_query_arg([
            'token' => $token,
            'login' => rawurlencode($user->user_login)
        ], $reset_url);

        // Send password reset email using WordPress function
        $sent = $this->attrua_send_password_reset_email($user, $reset_url);

        if ($sent) {
            $this->attrua_set_success_message(__('Check your email for a password reset link.', 'attributes-user-access-pro-lite'));

            // Log successful reset request
            if ($this->audit_log) {
                $this->audit_log->attrua_log_event('reset_email_sent', [
                    'user_id' => $user->ID,
                    'username' => $user->user_login,
                    'token_expiry' => date('Y-m-d H:i:s', $expiry)
                ]);
            }

            // Record the action for rate limiting
            if ($this->ip_manager) {
                $this->ip_manager->attrua_record_action('reset_request');
            }
        } else {
            $this->attrua_set_error_message(__('There was an error sending the email. Please try again later or contact support.', 'attributes-user-access-pro-lite'));

            // Log email sending failure
            if ($this->audit_log) {
                $this->audit_log->attrua_log_event('reset_email_failed', [
                    'user_id' => $user->ID,
                    'username' => $user->user_login
                ]);
            }
        }
    }

    /**
     * Handle password reset form submission.
     *
     * Processes the password reset form submission, validates the token and passwords,
     * and updates the user's password if valid.
     *
     * @since  1.0.0
     * @access public
     * @return void
     */
    public function attrua_handle_reset_password(): void
    {
        if (!isset($_POST['attrua_reset_password_submit'])) {
            return;
        }

        // Verify nonce
        if (
            !isset($_POST['attrua_reset_nonce']) ||
            !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['attrua_reset_nonce'])), 'attrua_reset')
        ) {
            $this->attrua_set_error_message(__('Security check failed.', 'attributes-user-access-pro-lite'));
            return;
        }

        // Check for rate limiting if IP Manager is available
        if ($this->ip_manager && !$this->ip_manager->attrua_can_perform_action('reset_password')) {
            $this->attrua_set_error_message(__('Too many password reset attempts. Please try again later.', 'attributes-user-access-pro-lite'));

            // Log the rate limit event
            if ($this->audit_log) {
                $this->audit_log->attrua_log_event('reset_rate_limited', [
                    'ip' => $this->ip_manager->attrua_get_client_ip(),
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
                ]);
            }

            return;
        }

        // Verify reCAPTCHA if enabled
        if ($this->recaptcha && $this->settings->attrua_get('security.recaptcha_reset', false)) {
            $recaptcha_response = isset($_POST['g-recaptcha-response']) ?
                sanitize_text_field(wp_unslash($_POST['g-recaptcha-response'])) : '';

            if (!$this->recaptcha->attrua_verify($recaptcha_response)) {
                $this->attrua_set_error_message(__('CAPTCHA verification failed. Please try again.', 'attributes-user-access-pro-lite'));
                return;
            }
        }

        // Get and sanitize form data
        $token = isset($_POST['token']) ? sanitize_text_field(wp_unslash($_POST['token'])) : '';
        $login = isset($_POST['login']) ? sanitize_text_field(wp_unslash($_POST['login'])) : '';
        $password = isset($_POST['password']) ? wp_unslash($_POST['password']) : '';
        $confirm_password = isset($_POST['confirm_password']) ? wp_unslash($_POST['confirm_password']) : '';

        // Validate inputs
        if (empty($token) || empty($login)) {
            $this->attrua_set_error_message(__('Invalid password reset request.', 'attributes-user-access-pro-lite'));
            return;
        }

        if (empty($password)) {
            $this->attrua_set_error_message(__('Please enter a password.', 'attributes-user-access-pro-lite'));
            return;
        }

        if ($password !== $confirm_password) {
            $this->attrua_set_error_message(__('Passwords do not match.', 'attributes-user-access-pro-lite'));
            return;
        }

        // Get user by login
        $user = get_user_by('login', $login);
        if (!$user) {
            $this->attrua_set_error_message(__('Invalid username or token.', 'attributes-user-access-pro-lite'));
            return;
        }

        // Validate token
        if (!$this->attrua_validate_token($login, $token)) {
            $this->attrua_set_error_message(__('Your password reset link has expired. Please request a new one.', 'attributes-user-access-pro-lite'));

            // Log invalid token attempt
            if ($this->audit_log) {
                $this->audit_log->attrua_log_event('reset_invalid_token', [
                    'user_id' => $user->ID,
                    'username' => $user->user_login,
                    'ip' => $this->ip_manager ? $this->ip_manager->attrua_get_client_ip() : 'Unknown'
                ]);
            }

            return;
        }

        // Password complexity validation
        $password_validation = $this->attrua_validate_password_complexity($password);
        if ($password_validation !== true) {
            $this->attrua_set_error_message($password_validation);
            return;
        }

        // Update user password
        reset_password($user, $password);

        // Clear reset token
        delete_user_meta($user->ID, 'attrua_reset_token');

        // Log successful password reset
        if ($this->audit_log) {
            $this->audit_log->attrua_log_event('password_reset_success', [
                'user_id' => $user->ID,
                'username' => $user->user_login,
                'ip' => $this->ip_manager ? $this->ip_manager->attrua_get_client_ip() : 'Unknown'
            ]);
        }

        // Record the action for rate limiting
        if ($this->ip_manager) {
            $this->ip_manager->attrua_record_action('reset_password');
        }

        // Set success message and redirect to login page
        $login_page_id = $this->settings->attrua_get('pages.login');
        $redirect_url = $login_page_id ? get_permalink($login_page_id) : wp_login_url();
        $redirect_url = add_query_arg('password-reset', 'true', $redirect_url);

        wp_safe_redirect($redirect_url);
        exit;
    }

    /**
     * Validates password complexity requirements.
     *
     * @since  1.0.0
     * @param  string $password The password to validate.
     * @return true|string True if valid, error message string if invalid.
     */
    private function attrua_validate_password_complexity(string $password)
    {
        // Check password length
        $min_length = (int) $this->settings->attrua_get('security.password_min_length', 8);
        if (strlen($password) < $min_length) {
            return sprintf(
                __('Password must be at least %d characters long.', 'attributes-user-access-pro-lite'),
                $min_length
            );
        }

        // Check complexity requirements
        $require_uppercase = (bool) $this->settings->attrua_get('security.password_require_uppercase', false);
        $require_lowercase = (bool) $this->settings->attrua_get('security.password_require_lowercase', false);
        $require_number = (bool) $this->settings->attrua_get('security.password_require_number', false);
        $require_special = (bool) $this->settings->attrua_get('security.password_require_special', false);

        if ($require_uppercase && !preg_match('/[A-Z]/', $password)) {
            return __('Password must include at least one uppercase letter.', 'attributes-user-access-pro-lite');
        }

        if ($require_lowercase && !preg_match('/[a-z]/', $password)) {
            return __('Password must include at least one lowercase letter.', 'attributes-user-access-pro-lite');
        }

        if ($require_number && !preg_match('/[0-9]/', $password)) {
            return __('Password must include at least one number.', 'attributes-user-access-pro-lite');
        }

        if ($require_special && !preg_match('/[^a-zA-Z0-9]/', $password)) {
            return __('Password must include at least one special character.', 'attributes-user-access-pro-lite');
        }

        // Check against common passwords if enabled
        $check_common = (bool) $this->settings->attrua_get('security.password_check_common', false);
        if ($check_common) {
            $common_passwords_file = ATTRUA_PATH . 'data/common-passwords.php';
            if (file_exists($common_passwords_file)) {
                $common_passwords = include $common_passwords_file;
                if (in_array(strtolower($password), $common_passwords, true)) {
                    return __('This password is too common. Please choose a more secure password.', 'attributes-user-access-pro-lite');
                }
            }
        }

        return true;
    }

    /**
     * Generates a secure reset token.
     *
     * @since  1.0.0
     * @param  int $user_id User ID.
     * @return string Secure reset token.
     */
    private function attrua_generate_reset_token(int $user_id): string
    {
        $token_length = (int) $this->settings->attrua_get('security.token_length', 32);
        $token_length = max(32, $token_length); // Ensure minimum length of 32

        // Generate token with user-specific data and random bytes
        $token_data = $user_id . time() . wp_generate_password($token_length, true, true);

        // Use WordPress's nonce mechanism for token generation
        return wp_hash($token_data, 'nonce');
    }

    /**
     * Validates a reset token for a user.
     *
     * @since  1.0.0
     * @param  string $login User login.
     * @param  string $token Token to validate.
     * @return bool Whether the token is valid.
     */
    private function attrua_validate_token(string $login, string $token): bool
    {
        $user = get_user_by('login', $login);
        if (!$user) {
            return false;
        }

        $stored_data = get_user_meta($user->ID, 'attrua_reset_token', true);
        if (empty($stored_data) || !is_array($stored_data)) {
            return false;
        }

        // Check if token matches and hasn't expired
        if (
            isset($stored_data['token'], $stored_data['expiry']) &&
            hash_equals($stored_data['token'], $token) &&
            time() < $stored_data['expiry']
        ) {
            return true;
        }

        return false;
    }

    /**
     * Customize password reset email message.
     *
     * @since  1.0.0
     * @param  string  $message    Default email message.
     * @param  string  $key        Password reset key.
     * @param  string  $user_login User login.
     * @param  WP_User $user_data  User data.
     * @return string Customized email message.
     */
    public function attrua_customize_reset_email(string $message, string $key, string $user_login, $user_data): string
    {
        // Check if we're handling our custom reset flow
        $custom_token = get_user_meta($user_data->ID, 'attrua_reset_token', true);
        if (!empty($custom_token) && is_array($custom_token) && isset($custom_token['token'])) {
            // Get reset page URL
            $reset_page_id = $this->settings->attrua_get('pages.reset');
            $reset_url = $reset_page_id ? get_permalink($reset_page_id) : '';

            if (!empty($reset_url)) {
                // Add token and login parameters
                $reset_url = add_query_arg([
                    'token' => $custom_token['token'],
                    'login' => rawurlencode($user_login)
                ], $reset_url);

                // Get email template type
                $email_type = $this->settings->attrua_get('emails.template_type', 'default');

                // Load appropriate email template
                ob_start();
                include $this->attrua_get_template_path("emails/{$email_type}.php");
                $message = ob_get_clean();

                // Replace tokens in the template
                $site_name = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);
                $message = str_replace('{site_name}', $site_name, $message);
                $message = str_replace('{username}', $user_login, $message);
                $message = str_replace('{reset_link}', $reset_url, $message);
                $message = str_replace('{expiry_time}', human_time_diff(time(), $custom_token['expiry']), $message);

                return $message;
            }
        }

        // Fall back to WordPress default message
        return $message;
    }

    /**
     * Customize password reset email subject.
     *
     * @since  1.0.0
     * @param  string $subject Default email subject.
     * @return string Customized email subject.
     */
    public function attrua_customize_reset_email_subject(string $subject): string
    {
        $custom_subject = $this->settings->attrua_get('emails.reset_subject', '');

        if (!empty($custom_subject)) {
            $site_name = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);
            $subject = str_replace('{site_name}', $site_name, $custom_subject);
            return $subject;
        }

        return $subject;
    }

    /**
     * Send password reset email.
     *
     * @since  1.0.0
     * @param  WP_User $user      User object.
     * @param  string  $reset_url Reset URL.
     * @return bool Whether the email was sent successfully.
     */
    private function attrua_send_password_reset_email($user, string $reset_url): bool
    {
        $site_name = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);

        $subject = $this->settings->attrua_get(
            'emails.reset_subject',
            sprintf(__('[%s] Password Reset', 'attributes-user-access-pro-lite'), $site_name)
        );
        $subject = str_replace('{site_name}', $site_name, $subject);

        // Get email template type
        $email_type = $this->settings->attrua_get('emails.template_type', 'default');

        // Load appropriate email template
        ob_start();
        include $this->attrua_get_template_path("emails/{$email_type}.php");
        $message = ob_get_clean();

        // Replace tokens in the template
        $message = str_replace('{site_name}', $site_name, $message);
        $message = str_replace('{username}', $user->user_login, $message);
        $message = str_replace('{reset_link}', $reset_url, $message);

        $token_data = get_user_meta($user->ID, 'attrua_reset_token', true);
        $expiry_time = isset($token_data['expiry']) ? human_time_diff(time(), $token_data['expiry']) : '1 hour';
        $message = str_replace('{expiry_time}', $expiry_time, $message);

        // Send email
        $headers = ['Content-Type: text/html; charset=UTF-8'];

        return wp_mail($user->user_email, $subject, $message, $headers);
    }

    /**
     * Set error message in session.
     *
     * @since  1.0.0
     * @param  string $message Error message.
     * @return void
     */
    private function attrua_set_error_message(string $message): void
    {
        if (!session_id()) {
            session_start();
        }

        $_SESSION['attrua_reset_error'] = $message;
    }

    /**
     * Set success message in session.
     *
     * @since  1.0.0
     * @param  string $message Success message.
     * @return void
     */
    private function attrua_set_success_message(string $message): void
    {
        if (!session_id()) {
            session_start();
        }

        $_SESSION['attrua_reset_success'] = $message;
    }

    /**
     * Get messages from session.
     *
     * @since  1.0.0
     * @return array Array of error and success messages.
     */
    private function attrua_get_messages(): array
    {
        if (!session_id()) {
            session_start();
        }

        $messages = [
            'error' => isset($_SESSION['attrua_reset_error']) ? $_SESSION['attrua_reset_error'] : '',
            'success' => isset($_SESSION['attrua_reset_success']) ? $_SESSION['attrua_reset_success'] : ''
        ];

        // Clear messages after retrieving
        unset($_SESSION['attrua_reset_error'], $_SESSION['attrua_reset_success']);

        return $messages;
    }

    /**
     * Render error message.
     *
     * @since  1.0.0
     * @param  string $message Error message.
     * @return string Formatted error message HTML.
     */
    private function attrua_render_error_message(string $message): string
    {
        return sprintf(
            '<div class="attrua-form-wrapper"><div class="attrua-message-container error">%s</div></div>',
            wp_kses_post($message)
        );
    }

    /**
     * Redirect WordPress reset page to custom page.
     * 
     * Handles redirection of the default WordPress password reset page
     * to the custom reset page when enabled.
     *
     * @since  1.0.0
     * @access public
     * @return void
     */
    public function attrua_reset_page_redirect(): void
    {
        if (is_admin()) {
            return;
        }

        // Check if redirection is enabled
        $redirect_enabled = $this->settings->attrua_get('redirects.reset', false);
        if (!$redirect_enabled) {
            return;
        }

        // Get custom reset page
        $reset_page_id = $this->settings->attrua_get('pages.reset');
        if (!$reset_page_id) {
            return;
        }

        // Check if current request is for wp-login.php
        $request_uri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        if (strpos($request_uri, 'wp-login.php') === false) {
            return;
        }

        // Get query parameters
        $query_params = [];
        $query_string = isset($_SERVER['QUERY_STRING']) ? sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING'])) : '';
        parse_str($query_string, $query_params);

        // Only redirect for lost password action
        if (!isset($query_params['action']) || $query_params['action'] !== 'lostpassword') {
            return;
        }

        // Don't redirect POST requests
        if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
            return;
        }

        // Redirect to custom reset page
        wp_safe_redirect(get_permalink($reset_page_id));
        exit;
    }

    /**
     * Handle custom template redirects for the reset password flow.
     * 
     * Ensures proper page routing for password reset steps including
     * token verification and form display.
     *
     * @since  1.0.0
     * @access public
     * @return void
     */
    public function attrua_maybe_redirect_reset_flow(): void
    {
        // Check if we're on the reset page
        $reset_page_id = $this->settings->attrua_get('pages.reset');
        if (!$reset_page_id || !is_page($reset_page_id)) {
            return;
        }

        // Handle expired or invalid tokens
        $token = isset($_GET['token']) ? sanitize_text_field(wp_unslash($_GET['token'])) : '';
        $login = isset($_GET['login']) ? sanitize_text_field(wp_unslash($_GET['login'])) : '';

        if (!empty($token) && !empty($login)) {
            $token_valid = $this->attrua_validate_token($login, $token);

            if (!$token_valid) {
                // Invalid token, redirect to reset request page
                wp_safe_redirect(remove_query_arg(['token', 'login'], get_permalink($reset_page_id)));
                exit;
            }
        }
    }

    /**
     * Check if password contains any part of user data.
     *
     * Helps prevent passwords that include personal information like username,
     * email, first name, or last name which can make passwords more vulnerable.
     *
     * @since  1.0.0
     * @param  string  $password The password to check.
     * @param  WP_User $user     User object.
     * @return bool Whether the password contains user data.
     */
    private function attrua_password_contains_user_data(string $password, $user): bool
    {
        if (!$user) {
            return false;
        }

        // Convert password to lowercase for case-insensitive comparison
        $password_lower = strtolower($password);

        // Get user data to check against
        $user_data = [
            $user->user_login,
            $user->user_email,
            $user->display_name
        ];

        // Get first and last name if they exist
        $first_name = get_user_meta($user->ID, 'first_name', true);
        $last_name = get_user_meta($user->ID, 'last_name', true);

        if (!empty($first_name)) {
            $user_data[] = $first_name;
        }

        if (!empty($last_name)) {
            $user_data[] = $last_name;
        }

        // Check if password contains any user data
        foreach ($user_data as $data) {
            if (empty($data)) {
                continue;
            }

            $data_lower = strtolower($data);

            // Check for data with length > 3 to avoid false positives on short names
            if (strlen($data_lower) > 3 && strpos($password_lower, $data_lower) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get reset page ID.
     *
     * Retrieves the ID of the custom reset page if set.
     *
     * @since  1.0.0
     * @access private
     * @return int|null Page ID or null if not set.
     */
    private function attrua_get_reset_page(): ?int
    {
        return $this->settings->attrua_get('pages.reset');
    }
}
