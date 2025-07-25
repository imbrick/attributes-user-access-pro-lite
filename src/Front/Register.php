<?php

namespace Attributes\Pro\Front;

use Attributes\Pro\License\License_Manager;

/**
 * Registration Handler Class
 *
 * Manages user registration forms and processes with customizable fields.
 *
 * @package Attributes\Pro\Front
 * @since 1.0.0
 */
class Register
{
    /**
     * Settings storage
     *
     * @var array
     */
    private array $settings = [];

    /**
     * Constructor
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
     * Initialize registration functionality
     */
    private function init(): void
    {
        // Get settings
        $this->settings = get_option('attrua_pro_registration_settings', []);

        // Register shortcode
        add_shortcode('attributes_register_form', [$this, 'render_register_form']);

        // Handle form submission
        add_action('init', [$this, 'handle_registration']);

        // Add registration page settings
        add_action('attrua_admin_settings_content', [$this, 'render_settings_content'], 20, 1);

        // Register AJAX handlers for checking username/email availability
        add_action('wp_ajax_nopriv_attrua_pro_check_username', [$this, 'check_username_availability']);
        add_action('wp_ajax_nopriv_attrua_pro_check_email', [$this, 'check_email_availability']);
    }

    /**
     * Render registration form via shortcode
     *
     * @param array $atts Shortcode attributes
     * @param string $content Shortcode content
     * @return string Generated HTML for registration form
     */
    public function render_register_form(array $atts = [], string $content = ''): string
    {
        // Early return for logged-in users
        if (is_user_logged_in()) {
            return sprintf(
                '<p>%s <a href="%s">%s</a></p>',
                esc_html('You are already registered and logged in.', 'attributes-user-access-pro-lite'),
                esc_url(wp_logout_url(get_permalink())),
                esc_html('Logout', 'attributes-user-access-pro-lite')
            );
        }

        // Check if registration is allowed
        if (!get_option('users_can_register')) {
            return sprintf(
                '<p>%s</p>',
                esc_html('Registration is currently disabled.', 'attributes-user-access-pro-lite')
            );
        }

        // Parse shortcode attributes
        $args = shortcode_atts([
            'redirect' => '',
            'form_id' => 'attrua_register_form',
            'label_username' => __('Username', 'attributes-user-access-pro-lite'),
            'label_email' => __('Email', 'attributes-user-access-pro-lite'),
            'label_password' => __('Password', 'attributes-user-access-pro-lite'),
            'label_password_confirm' => __('Confirm Password', 'attributes-user-access-pro-lite'),
            'label_submit' => __('Register', 'attributes-user-access-pro-lite'),
            'show_password_strength' => true,
            'custom_fields' => ''
        ], $atts);

        // Parse custom fields
        $custom_fields = $this->parse_custom_fields($args['custom_fields']);

        // Get any error or success messages
        $error_message = $this->get_error_message();
        $success_message = $this->get_success_message();

        // Start output buffering
        ob_start();

        // Include registration form template
        require $this->get_template_path('front/forms/register-form.php');

        // Return the generated HTML
        return ob_get_clean();
    }

    /**
     * Handle registration form submission
     */
    public function handle_registration(): void
    {
        if (!isset($_POST['attrua_register_submit'])) {
            return;
        }

        // Verify nonce
        if (
            !isset($_POST['attrua_register_nonce']) ||
            !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['attrua_register_nonce'])), 'attrua_register')
        ) {
            wp_die(esc_html('Security check failed.', 'attributes-user-access-pro-lite'));
        }

        // Start session if not started
        if (!session_id()) {
            session_start();
        }

        // Get and sanitize form data
        $username = isset($_POST['user_login']) ? sanitize_user(wp_unslash($_POST['user_login'])) : '';
        $email = isset($_POST['user_email']) ? sanitize_email(wp_unslash($_POST['user_email'])) : '';
        $password = isset($_POST['user_pass']) ? wp_unslash($_POST['user_pass']) : '';
        $password_confirm = isset($_POST['user_pass_confirm']) ? wp_unslash($_POST['user_pass_confirm']) : '';

        // Basic validation
        if (empty($username)) {
            $this->set_error_message(__('Please enter a username.', 'attributes-user-access-pro-lite'));
            return;
        }

        if (empty($email) || !is_email($email)) {
            $this->set_error_message(__('Please enter a valid email address.', 'attributes-user-access-pro-lite'));
            return;
        }

        if (empty($password)) {
            $this->set_error_message(__('Please enter a password.', 'attributes-user-access-pro-lite'));
            return;
        }

        if ($password !== $password_confirm) {
            $this->set_error_message(__('Passwords do not match.', 'attributes-user-access-pro-lite'));
            return;
        }

        // Username and email validation
        if (username_exists($username)) {
            $this->set_error_message(__('This username is already registered.', 'attributes-user-access-pro-lite'));
            return;
        }

        if (email_exists($email)) {
            $this->set_error_message(__('This email address is already registered.', 'attributes-user-access-pro-lite'));
            return;
        }

        // Check password strength if required
        if (!empty($this->settings['min_password_strength'])) {
            $strength = $this->check_password_strength($password);

            if ($strength < intval($this->settings['min_password_strength'])) {
                $this->set_error_message(__('Please choose a stronger password.', 'attributes-user-access-pro-lite'));
                return;
            }
        }

        // Prepare user data
        $user_data = [
            'user_login' => $username,
            'user_email' => $email,
            'user_pass' => $password,
            'role' => get_option('default_role', 'subscriber')
        ];

        // Optional first and last name
        if (isset($_POST['first_name']) && !empty($_POST['first_name'])) {
            $user_data['first_name'] = sanitize_text_field(wp_unslash($_POST['first_name']));
        }

        if (isset($_POST['last_name']) && !empty($_POST['last_name'])) {
            $user_data['last_name'] = sanitize_text_field(wp_unslash($_POST['last_name']));
        }

        // Allow filtering of user data
        $user_data = apply_filters('attrua_pro_registration_user_data', $user_data, $_POST);

        // Create user
        $user_id = wp_insert_user($user_data);

        if (is_wp_error($user_id)) {
            $this->set_error_message($user_id->get_error_message());
            return;
        }

        // Save custom field data
        $this->save_custom_fields($user_id);

        // Fire action for successful registration
        do_action('attrua_pro_user_registered', $user_id, $user_data);

        // Determine if we should automatically log the user in
        $auto_login = !empty($this->settings['auto_login']);

        if ($auto_login) {
            wp_set_auth_cookie($user_id, false);
            do_action('wp_login', $username, get_userdata($user_id));
        }

        // Set success message
        $this->set_success_message(__('Registration successful!', 'attributes-user-access-pro-lite'));

        // Redirect if specified
        if (!empty($_POST['redirect_to'])) {
            wp_safe_redirect(esc_url_raw(wp_unslash($_POST['redirect_to'])));
            exit;
        }

        // Otherwise, redirect back to registration page with success message
        wp_safe_redirect(add_query_arg('registration', 'success', wp_get_referer()));
        exit;
    }

    /**
     * Check username availability via AJAX
     */
    public function check_username_availability(): void
    {
        // Verify nonce
        check_ajax_referer('attrua_pro_check_username');

        $username = isset($_POST['username']) ? sanitize_user(wp_unslash($_POST['username'])) : '';

        if (empty($username)) {
            wp_send_json_error(['message' => __('Please enter a username.', 'attributes-user-access-pro-lite')]);
        }

        // Check if username is valid
        if (!validate_username($username)) {
            wp_send_json_error(['message' => __('This username is not valid.', 'attributes-user-access-pro-lite')]);
        }

        // Check if username exists
        if (username_exists($username)) {
            wp_send_json_error(['message' => __('This username is already taken.', 'attributes-user-access-pro-lite')]);
        }

        wp_send_json_success(['message' => __('This username is available.', 'attributes-user-access-pro-lite')]);
    }

    /**
     * Check email availability via AJAX
     */
    public function check_email_availability(): void
    {
        // Verify nonce
        check_ajax_referer('attrua_pro_check_email');

        $email = isset($_POST['email']) ? sanitize_email(wp_unslash($_POST['email'])) : '';

        if (empty($email)) {
            wp_send_json_error(['message' => __('Please enter an email address.', 'attributes-user-access-pro-lite')]);
        }

        // Check if email is valid
        if (!is_email($email)) {
            wp_send_json_error(['message' => __('This email address is not valid.', 'attributes-user-access-pro-lite')]);
        }

        // Check if email exists
        if (email_exists($email)) {
            wp_send_json_error(['message' => __('This email address is already registered.', 'attributes-user-access-pro-lite')]);
        }

        wp_send_json_success(['message' => __('This email address is available.', 'attributes-user-access-pro-lite')]);
    }

    /**
     * Check password strength
     *
     * @param string $password Password to check
     * @return int Strength level (0-4)
     */
    private function check_password_strength(string $password): int
    {
        // Calculate password strength
        // This is a simplified version - in production, use WordPress's password strength meter
        $length = strlen($password);
        $has_lowercase = preg_match('/[a-z]/', $password);
        $has_uppercase = preg_match('/[A-Z]/', $password);
        $has_number = preg_match('/[0-9]/', $password);
        $has_special = preg_match('/[^a-zA-Z0-9]/', $password);

        $strength = 0;

        if ($length >= 8) $strength++;
        if ($has_lowercase && $has_uppercase) $strength++;
        if ($has_number) $strength++;
        if ($has_special) $strength++;

        return $strength;
    }

    /**
     * Parse custom fields from shortcode attribute
     *
     * @param string $custom_fields_str Custom fields string
     * @return array Parsed custom fields
     */
    private function parse_custom_fields(string $custom_fields_str): array
    {
        if (empty($custom_fields_str)) {
            return [];
        }

        $fields = [];
        $fields_str = explode(',', $custom_fields_str);

        foreach ($fields_str as $field_str) {
            $field_parts = explode(':', trim($field_str));
            $field_name = $field_parts[0] ?? '';
            $field_type = $field_parts[1] ?? 'text';
            $field_required = isset($field_parts[2]) && $field_parts[2] === 'required';

            if (!empty($field_name)) {
                $fields[] = [
                    'name' => $field_name,
                    'type' => $field_type,
                    'required' => $field_required
                ];
            }
        }

        return $fields;
    }

    /**
     * Save custom field data
     *
     * @param int $user_id User ID
     */
    private function save_custom_fields(int $user_id): void
    {
        // Get list of allowed custom fields
        $allowed_fields = $this->get_allowed_custom_fields();

        if (empty($allowed_fields)) {
            return;
        }

        foreach ($allowed_fields as $field) {
            $field_name = $field['name'];

            if (isset($_POST[$field_name]) && !empty($_POST[$field_name])) {
                $field_value = sanitize_text_field(wp_unslash($_POST[$field_name]));
                update_user_meta($user_id, $field_name, $field_value);
            }
        }
    }

    /**
     * Get allowed custom fields
     *
     * @return array Allowed custom fields
     */
    private function get_allowed_custom_fields(): array
    {
        // Get custom fields from settings
        $custom_fields = isset($this->settings['custom_fields']) ? $this->settings['custom_fields'] : [];

        // Allow filtering of allowed custom fields
        return apply_filters('attrua_pro_allowed_custom_fields', $custom_fields);
    }

    /**
     * Get template path
     *
     * @param string $template Template path
     * @return string Full template path
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
     * Get error message
     *
     * @return string Error message
     */
    private function get_error_message(): string
    {
        if (!session_id()) {
            session_start();
        }

        $message = '';

        if (isset($_SESSION['attrua_pro_register_error'])) {
            $message = $_SESSION['attrua_pro_register_error'];
            unset($_SESSION['attrua_pro_register_error']);
        }

        return $message;
    }

    /**
     * Set error message
     *
     * @param string $message Error message
     */
    private function set_error_message(string $message): void
    {
        if (!session_id()) {
            session_start();
        }

        $_SESSION['attrua_pro_register_error'] = $message;
    }

    /**
     * Get success message
     *
     * @return string Success message
     */
    private function get_success_message(): string
    {
        if (isset($_GET['registration']) && $_GET['registration'] === 'success') {
            return __('Registration successful!', 'attributes-user-access-pro-lite');
        }

        return '';
    }

    /**
     * Render settings content
     *
     * @param bool $has_premium_features Whether premium features are active
     */
    public function render_settings_content(bool $has_premium_features): void
    {
        if (!$has_premium_features || !isset($_GET['tab']) || $_GET['tab'] !== 'pages') {
            return;
        }

        // Load registration settings template
        require_once ATTRUA_PRO_PATH . 'display/tabs/pages-settings-tab.php';
    }
}
