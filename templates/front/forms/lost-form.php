<?php

/**
 * Template for the lost password form
 *
 * Provides the HTML structure for the lost password functionality with
 * integrated security features and a responsive, accessible interface.
 * This template supports customization via shortcode attributes and
 * integrates with the Pro version's security components.
 *
 * @package Attributes\Pro\Front
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Ensure $args is set
if (!isset($args)) {
    $args = [];
}

// Get redirect URL
$redirect_to = !empty($args['redirect']) ? $args['redirect'] : '';

// Get potential error and success messages
$error_message = isset($error_message) ? $error_message : '';
$success_message = isset($success_message) ? $success_message : '';

// Get reCAPTCHA settings
$recaptcha_settings = get_option('attrua_pro_recaptcha_settings', []);
$recaptcha_enabled = !empty($recaptcha_settings['enabled']) && !empty($recaptcha_settings['forms']['lost_password']);
$recaptcha_version = $recaptcha_settings['version'] ?? 'v2';
?>

<div class="attrua-form-wrapper">
    <!-- Introduction Text -->
    <?php if (!empty($args['intro_text'])): ?>
        <div class="attrua-form-description">
            <?php echo esc_html($args['intro_text']); ?>
        </div>
    <?php endif; ?>

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

    <!-- Lost Password Form -->
    <?php if (empty($success_message)): ?>
        <form id="<?php echo esc_attr($args['form_id']); ?>"
            class="attrua-lost-password-form"
            method="post"
            action="">

            <?php wp_nonce_field('attrua_lost_password', 'attrua_lost_password_nonce'); ?>
            <input type="hidden" name="attrua_lost_password_submit" value="1">

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
                    required
                    autocomplete="username">
                <div class="attrua-field-error" id="user-login-error"></div>
            </div>

            <!-- reCAPTCHA (if enabled) -->
            <?php if ($recaptcha_enabled && !empty($recaptcha_settings['site_key'])): ?>
                <div class="attrua-form-row">
                    <?php if ($recaptcha_version === 'v2'): ?>
                        <div class="g-recaptcha" data-sitekey="<?php echo esc_attr($recaptcha_settings['site_key']); ?>"></div>
                    <?php elseif ($recaptcha_version === 'v2_invisible'): ?>
                        <div class="g-recaptcha"
                            data-sitekey="<?php echo esc_attr($recaptcha_settings['site_key']); ?>"
                            data-callback="onRecaptchaSuccess"
                            data-size="invisible"></div>
                    <?php else: // v3 
                    ?>
                        <input type="hidden" name="recaptcha_response" id="recaptchaResponse">
                    <?php endif; ?>
                    <div class="attrua-field-error" id="recaptcha-error"></div>
                </div>
            <?php endif; ?>

            <!-- Submit Button -->
            <div class="attrua-form-row">
                <button type="submit"
                    class="attrua-submit-button">
                    <?php echo esc_html($args['label_submit']); ?>
                </button>
            </div>

            <?php if (!empty($redirect_to)): ?>
                <input type="hidden" name="redirect_to" value="<?php echo esc_url($redirect_to); ?>">
            <?php endif; ?>

            <!-- Additional Links -->
            <div class="attrua-form-links">
                <a href="<?php echo esc_url(wp_login_url()); ?>">
                    <?php esc_html('Back to login', 'attributes-user-access-pro-lite'); ?>
                </a>

                <?php if (get_option('users_can_register')): ?>
                    <span class="attrua-link-separator">|</span>
                    <?php
                    // Check if we have a custom registration page
                    $registration_page_id = get_option('attrua_pro_pages_options', [])['register'] ?? null;
                    $register_url = $registration_page_id ? get_permalink($registration_page_id) : wp_registration_url();
                    ?>
                    <a href="<?php echo esc_url($register_url); ?>">
                        <?php esc_html('Register', 'attributes-user-access-pro-lite'); ?>
                    </a>
                <?php endif; ?>
            </div>

            <?php
            /**
             * Hook for adding custom fields to lost password form
             *
             * @since 1.0.0
             */
            do_action('attrua_pro_lost_password_form_fields');
            ?>
        </form>
    <?php endif; ?>

    <?php
    /**
     * Hook for adding content after lost password form
     *
     * @since 1.0.0
     */
    do_action('attrua_pro_after_lost_password_form');
    ?>
</div>

<?php if ($recaptcha_enabled): ?>
    <?php if ($recaptcha_version === 'v2' || $recaptcha_version === 'v2_invisible'): ?>
        <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <?php else: // v3 
    ?>
        <script src="https://www.google.com/recaptcha/api.js?render=<?php echo esc_attr($recaptcha_settings['site_key']); ?>"></script>
        <script>
            grecaptcha.ready(function() {
                grecaptcha.execute('<?php echo esc_js($recaptcha_settings['site_key']); ?>', {
                        action: 'lost_password'
                    })
                    .then(function(token) {
                        document.getElementById('recaptchaResponse').value = token;
                    });
            });
        </script>
    <?php endif; ?>
<?php endif; ?>

<script>
    jQuery(document).ready(function($) {
        // Form validation
        $('.attrua-lost-password-form').on('submit', function(e) {
            let isValid = true;
            const userLogin = $('#attrua_user_login').val().trim();

            // Validate username/email field
            if (!userLogin) {
                $('#user-login-error').text('<?php esc_html('Please enter a username or email address', 'attributes-user-access-pro-lite'); ?>').addClass('error');
                isValid = false;
            } else {
                $('#user-login-error').text('').removeClass('error');
            }

            if (!isValid) {
                e.preventDefault();
            }
        });

        // Clear error when user starts typing
        $('#attrua_user_login').on('input', function() {
            $('#user-login-error').text('').removeClass('error');
        });

        <?php if ($recaptcha_version === 'v2_invisible'): ?>
            // Handle invisible reCAPTCHA
            function onRecaptchaSuccess(token) {
                $('.attrua-lost-password-form').submit();
            }

            $('.attrua-lost-password-form').on('submit', function(e) {
                if (!grecaptcha.getResponse()) {
                    e.preventDefault();
                    grecaptcha.execute();
                }
            });
        <?php endif; ?>
    });
</script>