<?php

/**
 * Template for the reset password form
 *
 * This template provides two views:
 * 1. Password reset request form (username/email input)
 * 2. New password entry form (after clicking reset link)
 *
 * @package Attributes\Front
 * @since   1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Ensure $args is set
if (!isset($args)) {
    $args = [];
}

// Start session if not already started
if (!session_id()) {
    session_start();
}

// Get error and success messages
$messages = isset($messages) ? $messages : ['error' => '', 'success' => ''];
$error_message = $messages['error'];
$success_message = $messages['success'];

// Determine which form to show
$reset_mode = isset($args['reset_mode']) ? $args['reset_mode'] : false;
?>

<div class="attrua-form-wrapper">
    <!-- Messages Container -->
    <?php if (!empty($error_message)): ?>
        <div class="attrua-message-container error visible">
            <div class="attrua-message">
                <?php echo wp_kses_post($error_message); ?>
            </div>
        </div>
    <?php endif; ?>

    <?php if (!empty($success_message)): ?>
        <div class="attrua-message-container success visible">
            <div class="attrua-message">
                <?php echo wp_kses_post($success_message); ?>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($reset_mode): ?>
        <!-- Password Reset Form (New Password Entry) -->
        <form id="<?php echo esc_attr($args['form_id']); ?>_reset"
            class="attrua-reset-form"
            method="post"
            action="">

            <?php wp_nonce_field('attrua_reset', 'attrua_reset_nonce'); ?>
            <input type="hidden" name="attrua_reset_password_submit" value="1">
            <input type="hidden" name="token" value="<?php echo esc_attr($args['token']); ?>">
            <input type="hidden" name="login" value="<?php echo esc_attr($args['login']); ?>">

            <!-- New Password Field -->
            <div class="attrua-form-row">
                <label for="attrua_new_password">
                    <?php echo esc_html($args['label_new_password']); ?>
                    <span class="required">*</span>
                </label>
                <div class="attrua-password-field">
                    <input type="password"
                        name="password"
                        id="attrua_new_password"
                        class="attrua-input"
                        required
                        autocomplete="new-password">
                    <button type="button"
                        class="attrua-toggle-password"
                        aria-label="<?php esc_attr_e('Toggle password visibility', 'attributes-user-access-pro-lite'); ?>">
                        <span class="ti ti-eye"></span>
                    </button>
                </div>
                <div class="attrua-field-error"></div>
            </div>

            <!-- Confirm Password Field -->
            <div class="attrua-form-row">
                <label for="attrua_confirm_password">
                    <?php echo esc_html($args['label_confirm_password']); ?>
                    <span class="required">*</span>
                </label>
                <div class="attrua-password-field">
                    <input type="password"
                        name="confirm_password"
                        id="attrua_confirm_password"
                        class="attrua-input"
                        required
                        autocomplete="new-password">
                    <button type="button"
                        class="attrua-toggle-password"
                        aria-label="<?php esc_attr_e('Toggle password visibility', 'attributes-user-access-pro-lite'); ?>">
                        <span class="ti ti-eye"></span>
                    </button>
                </div>
                <div class="attrua-field-error"></div>
            </div>

            <!-- Password Requirements -->
            <?php
            $min_length = (int) apply_filters('attrua_password_min_length', 8);
            $require_uppercase = (bool) apply_filters('attrua_password_require_uppercase', false);
            $require_lowercase = (bool) apply_filters('attrua_password_require_lowercase', false);
            $require_number = (bool) apply_filters('attrua_password_require_number', false);
            $require_special = (bool) apply_filters('attrua_password_require_special', false);

            if ($min_length > 0 || $require_uppercase || $require_lowercase || $require_number || $require_special):
            ?>
                <div class="attrua-password-requirements">
                    <h5><?php esc_html('Password Requirements', 'attributes-user-access-pro-lite'); ?></h5>
                    <ul>
                        <?php if ($min_length > 0): ?>
                            <li class="requirement-length" data-min="<?php echo esc_attr($min_length); ?>">
                                <?php printf(esc_html('At least %d characters long', 'attributes-user-access-pro-lite'), $min_length); ?>
                            </li>
                        <?php endif; ?>

                        <?php if ($require_uppercase): ?>
                            <li class="requirement-uppercase">
                                <?php esc_html('Must include at least one uppercase letter', 'attributes-user-access-pro-lite'); ?>
                            </li>
                        <?php endif; ?>

                        <?php if ($require_lowercase): ?>
                            <li class="requirement-lowercase">
                                <?php esc_html('Must include at least one lowercase letter', 'attributes-user-access-pro-lite'); ?>
                            </li>
                        <?php endif; ?>

                        <?php if ($require_number): ?>
                            <li class="requirement-number">
                                <?php esc_html('Must include at least one number', 'attributes-user-access-pro-lite'); ?>
                            </li>
                        <?php endif; ?>

                        <?php if ($require_special): ?>
                            <li class="requirement-special">
                                <?php esc_html('Must include at least one special character', 'attributes-user-access-pro-lite'); ?>
                            </li>
                        <?php endif; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <?php if (!empty($args['use_recaptcha']) && $args['use_recaptcha']): ?>
                <!-- reCAPTCHA -->
                <div class="attrua-form-row">
                    <div class="g-recaptcha" data-sitekey="<?php echo esc_attr(apply_filters('attrua_recaptcha_site_key', '')); ?>"></div>
                </div>
            <?php endif; ?>

            <!-- Submit Button -->
            <div class="attrua-form-row">
                <button type="submit"
                    class="attrua-submit-button"
                    data-loading-text="<?php esc_attr_e('Setting new password...', 'attributes-user-access-pro-lite'); ?>">
                    <?php echo esc_html($args['label_submit']); ?>
                </button>
            </div>

            <?php
            /**
             * Hook for adding custom fields to reset password form
             *
             * @since 1.0.0
             */
            do_action('attrua_reset_password_form_fields');
            ?>
        </form>
    <?php else: ?>
        <!-- Password Reset Request Form -->
        <form id="<?php echo esc_attr($args['form_id']); ?>_request"
            class="attrua-reset-form"
            method="post"
            action="">

            <?php wp_nonce_field('attrua_reset', 'attrua_reset_nonce'); ?>
            <input type="hidden" name="attrua_reset_request_submit" value="1">

            <div class="attrua-form-description">
                <?php esc_html('Enter your username or email address and we\'ll send you a link to reset your password.', 'attributes-user-access-pro-lite'); ?>
            </div>

            <!-- Username/Email Field -->
            <div class="attrua-form-row">
                <label for="attrua_user_login">
                    <?php echo esc_html($args['label_username']); ?>
                    <span class="required">*</span>
                </label>
                <input type="text"
                    name="user_login"
                    id="attrua_user_login"
                    class="attrua-input"
                    value="<?php echo esc_attr($args['value_username']); ?>"
                    required>
                <div class="attrua-field-error"></div>
            </div>

            <?php if (!empty($args['use_recaptcha']) && $args['use_recaptcha']): ?>
                <!-- reCAPTCHA -->
                <div class="attrua-form-row">
                    <div class="g-recaptcha" data-sitekey="<?php echo esc_attr(apply_filters('attrua_recaptcha_site_key', '')); ?>"></div>
                </div>
            <?php endif; ?>

            <!-- Submit Button -->
            <div class="attrua-form-row">
                <button type="submit"
                    class="attrua-submit-button"
                    data-loading-text="<?php esc_attr_e('Sending reset link...', 'attributes-user-access-pro-lite'); ?>">
                    <?php echo esc_html($args['label_reset']); ?>
                </button>
            </div>

            <?php
            /**
             * Hook for adding custom fields to reset request form
             *
             * @since 1.0.0
             */
            do_action('attrua_reset_request_form_fields');
            ?>
        </form>

        <!-- Login Link -->
        <div class="attrua-form-links">
            <?php
            $login_page_id = apply_filters('attrua_login_page_id', 0);
            if ($login_page_id) {
                printf(
                    '<a href="%s">%s</a>',
                    esc_url(get_permalink($login_page_id)),
                    esc_html('Back to login', 'attributes-user-access-pro-lite')
                );
            } else {
                printf(
                    '<a href="%s">%s</a>',
                    esc_url(wp_login_url()),
                    esc_html('Back to login', 'attributes-user-access-pro-lite')
                );
            }
            ?>
        </div>
    <?php endif; ?>

    <?php
    /**
     * Hook for adding content after reset form
     *
     * @since 1.0.0
     */
    do_action('attrua_after_reset_form');
    ?>
</div>

<?php
// Add reCAPTCHA script if enabled
if (!empty($args['use_recaptcha']) && $args['use_recaptcha']):
?>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
<?php endif; ?>