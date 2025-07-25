<?php

/**
 * Template for the registration form
 *
 * This template handles the rendering of the registration form with proper
 * security measures and error handling.
 *
 * @package Attributes\Pro\Front
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

// Get redirect URL
$redirect_to = !empty($args['redirect']) ? $args['redirect'] : '';

// Custom fields
$custom_fields = isset($custom_fields) ? $custom_fields : [];

// Get messages
$error_message = isset($error_message) ? $error_message : '';
$success_message = isset($success_message) ? $success_message : '';

// Password strength requirements
$password_policy = get_option('attrua_pro_password_policy', []);
$show_password_strength = !empty($args['show_password_strength']);
$min_length = !empty($password_policy['enabled']) ? intval($password_policy['min_length'] ?? 8) : 0;
$require_uppercase = !empty($password_policy['enabled']) && !empty($password_policy['require_uppercase']);
$require_lowercase = !empty($password_policy['enabled']) && !empty($password_policy['require_lowercase']);
$require_numbers = !empty($password_policy['enabled']) && !empty($password_policy['require_numbers']);
$require_special = !empty($password_policy['enabled']) && !empty($password_policy['require_special']);
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

    <!-- Registration Form -->
    <form id="<?php echo esc_attr($args['form_id']); ?>"
        class="attrua-register-form"
        method="post"
        action="">

        <?php wp_nonce_field('attrua_register', 'attrua_register_nonce'); ?>
        <input type="hidden" name="attrua_register_submit" value="1">

        <!-- Username Field -->
        <div class="attrua-form-row">
            <label for="attrua_username">
                <?php echo esc_html($args['label_username']); ?>
                <span class="required">*</span>
            </label>
            <input type="text"
                name="user_login"
                id="attrua_username"
                class="attrua-input"
                required
                autocomplete="username">
            <div class="attrua-field-error" id="username-error"></div>
        </div>

        <!-- Email Field -->
        <div class="attrua-form-row">
            <label for="attrua_email">
                <?php echo esc_html($args['label_email']); ?>
                <span class="required">*</span>
            </label>
            <input type="email"
                name="user_email"
                id="attrua_email"
                class="attrua-input"
                required
                autocomplete="email">
            <div class="attrua-field-error" id="email-error"></div>
        </div>

        <!-- Password Field -->
        <div class="attrua-form-row">
            <label for="attrua_password">
                <?php echo esc_html($args['label_password']); ?>
                <span class="required">*</span>
            </label>
            <div class="attrua-password-field">
                <input type="password"
                    name="user_pass"
                    id="attrua_password"
                    class="attrua-input"
                    required
                    autocomplete="new-password">
                <button type="button"
                    class="attrua-toggle-password"
                    aria-label="<?php esc_attr_e('Toggle password visibility', 'attributes-user-access-pro-lite'); ?>">
                    <span class="ti ti-eye"></span>
                </button>
            </div>
            <div class="attrua-field-error" id="password-error"></div>

            <?php if ($show_password_strength): ?>
                <div class="attrua-password-strength">
                    <div class="attrua-strength-meter">
                        <div class="attrua-strength-meter-fill" data-strength="0"></div>
                    </div>
                    <span class="attrua-strength-text"><?php esc_html('Password strength: Very Weak', 'attributes-user-access-pro-lite'); ?></span>
                </div>

                <div class="attrua-password-requirements">
                    <h5><?php esc_html('Password requirements:', 'attributes-user-access-pro-lite'); ?></h5>
                    <ul>
                        <?php if ($min_length): ?>
                            <li class="requirement" data-requirement="length">
                                <?php printf(esc_html('At least %d characters long', 'attributes-user-access-pro-lite'), $min_length); ?>
                            </li>
                        <?php endif; ?>

                        <?php if ($require_uppercase): ?>
                            <li class="requirement" data-requirement="uppercase">
                                <?php esc_html('Contains uppercase letters (A-Z)', 'attributes-user-access-pro-lite'); ?>
                            </li>
                        <?php endif; ?>

                        <?php if ($require_lowercase): ?>
                            <li class="requirement" data-requirement="lowercase">
                                <?php esc_html('Contains lowercase letters (a-z)', 'attributes-user-access-pro-lite'); ?>
                            </li>
                        <?php endif; ?>

                        <?php if ($require_numbers): ?>
                            <li class="requirement" data-requirement="number">
                                <?php esc_html('Contains numbers (0-9)', 'attributes-user-access-pro-lite'); ?>
                            </li>
                        <?php endif; ?>

                        <?php if ($require_special): ?>
                            <li class="requirement" data-requirement="special">
                                <?php esc_html('Contains special characters (!@#$%^&*...)', 'attributes-user-access-pro-lite'); ?>
                            </li>
                        <?php endif; ?>
                    </ul>
                </div>
            <?php endif; ?>
        </div>

        <!-- Password Confirmation Field -->
        <div class="attrua-form-row">
            <label for="attrua_password_confirm">
                <?php echo esc_html($args['label_password_confirm']); ?>
                <span class="required">*</span>
            </label>
            <div class="attrua-password-field">
                <input type="password"
                    name="user_pass_confirm"
                    id="attrua_password_confirm"
                    class="attrua-input"
                    required
                    autocomplete="new-password">
                <button type="button"
                    class="attrua-toggle-password"
                    aria-label="<?php esc_attr_e('Toggle password visibility', 'attributes-user-access-pro-lite'); ?>">
                    <span class="ti ti-eye"></span>
                </button>
            </div>
            <div class="attrua-field-error" id="password-confirm-error"></div>
        </div>

        <!-- Custom Fields -->
        <?php if (!empty($custom_fields)): ?>
            <?php foreach ($custom_fields as $field): ?>
                <div class="attrua-form-row">
                    <label for="attrua_<?php echo esc_attr($field['name']); ?>">
                        <?php echo esc_html(ucfirst($field['name'])); ?>
                        <?php if (!empty($field['required'])): ?>
                            <span class="required">*</span>
                        <?php endif; ?>
                    </label>

                    <?php switch ($field['type']):
                        case 'text': ?>
                            <input type="text"
                                name="<?php echo esc_attr($field['name']); ?>"
                                id="attrua_<?php echo esc_attr($field['name']); ?>"
                                class="attrua-input"
                                <?php echo !empty($field['required']) ? 'required' : ''; ?>>
                        <?php break;

                        case 'textarea': ?>
                            <textarea name="<?php echo esc_attr($field['name']); ?>"
                                id="attrua_<?php echo esc_attr($field['name']); ?>"
                                class="attrua-input"
                                rows="4"
                                <?php echo !empty($field['required']) ? 'required' : ''; ?>></textarea>
                        <?php break;

                        case 'checkbox': ?>
                            <label class="attrua-checkbox-label">
                                <input type="checkbox"
                                    name="<?php echo esc_attr($field['name']); ?>"
                                    id="attrua_<?php echo esc_attr($field['name']); ?>"
                                    value="1"
                                    <?php echo !empty($field['required']) ? 'required' : ''; ?>>
                                <span><?php echo esc_html(ucfirst($field['name'])); ?></span>
                            </label>
                        <?php break;

                        case 'select':
                            // Options would need to be defined elsewhere or passed in field config
                            $options = !empty($field['options']) ? $field['options'] : [];
                        ?>
                            <select name="<?php echo esc_attr($field['name']); ?>"
                                id="attrua_<?php echo esc_attr($field['name']); ?>"
                                class="attrua-input"
                                <?php echo !empty($field['required']) ? 'required' : ''; ?>>
                                <option value=""><?php esc_html('-- Select --', 'attributes-user-access-pro-lite'); ?></option>
                                <?php foreach ($options as $value => $label): ?>
                                    <option value="<?php echo esc_attr($value); ?>"><?php echo esc_html($label); ?></option>
                                <?php endforeach; ?>
                            </select>
                        <?php break;

                        default: ?>
                            <input type="text"
                                name="<?php echo esc_attr($field['name']); ?>"
                                id="attrua_<?php echo esc_attr($field['name']); ?>"
                                class="attrua-input"
                                <?php echo !empty($field['required']) ? 'required' : ''; ?>>
                    <?php endswitch; ?>

                    <div class="attrua-field-error"></div>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>

        <!-- reCAPTCHA (if enabled) -->
        <?php
        $recaptcha_settings = get_option('attrua_pro_recaptcha_settings', []);
        $recaptcha_enabled = !empty($recaptcha_settings['enabled']) && !empty($recaptcha_settings['forms']['register']);

        if ($recaptcha_enabled && !empty($recaptcha_settings['site_key'])):
            $recaptcha_version = $recaptcha_settings['version'] ?? 'v2';
        ?>
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

        <?php
        /**
         * Hook for adding custom fields to registration form
         *
         * @since 1.0.0
         */
        do_action('attrua_pro_register_form_fields');
        ?>
    </form>

    <?php
    /**
     * Hook for adding content after registration form
     *
     * @since 1.0.0
     */
    do_action('attrua_pro_after_register_form');
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
                        action: 'register'
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
        // Password toggle functionality
        $('.attrua-toggle-password').on('click', function(e) {
            e.preventDefault();

            const $field = $(this).closest('.attrua-password-field');
            const $input = $field.find('input');
            const $icon = $(this).find('.ti');

            // Toggle input type
            const isPassword = $input.attr('type') === 'password';
            $input.attr('type', isPassword ? 'text' : 'password');

            // Update icon
            $icon
                .removeClass(isPassword ? 'ti-eye' : 'ti-eye-off')
                .addClass(isPassword ? 'ti-eye-off' : 'ti-eye');
        });

        <?php if ($show_password_strength): ?>
            // Password strength meter
            const $passwordInput = $('#attrua_password');
            const $strengthMeter = $('.attrua-strength-meter-fill');
            const $strengthText = $('.attrua-strength-text');
            const requirements = {
                length: <?php echo $min_length ?: 8; ?>,
                uppercase: <?php echo $require_uppercase ? 'true' : 'false'; ?>,
                lowercase: <?php echo $require_lowercase ? 'true' : 'false'; ?>,
                number: <?php echo $require_numbers ? 'true' : 'false'; ?>,
                special: <?php echo $require_special ? 'true' : 'false'; ?>
            };

            $passwordInput.on('input', function() {
                const password = $(this).val();
                const strength = calculatePasswordStrength(password);
                const strengthLabels = [
                    '<?php esc_html('Very Weak', 'attributes-user-access-pro-lite'); ?>',
                    '<?php esc_html('Weak', 'attributes-user-access-pro-lite'); ?>',
                    '<?php esc_html('Medium', 'attributes-user-access-pro-lite'); ?>',
                    '<?php esc_html('Strong', 'attributes-user-access-pro-lite'); ?>',
                    '<?php esc_html('Very Strong', 'attributes-user-access-pro-lite'); ?>'
                ];

                // Update strength meter
                $strengthMeter.attr('data-strength', strength);
                $strengthText.text('<?php esc_html('Password strength', 'attributes-user-access-pro-lite'); ?>: ' + strengthLabels[strength]);

                // Update requirements list
                updateRequirements(password);
            });

            function calculatePasswordStrength(password) {
                if (!password) return 0;

                let score = 0;

                // Length
                if (password.length >= requirements.length) score++;
                if (password.length >= requirements.length + 4) score++;

                // Complexity
                if (/[A-Z]/.test(password)) score++;
                if (/[a-z]/.test(password)) score++;
                if (/[0-9]/.test(password)) score++;
                if (/[^A-Za-z0-9]/.test(password)) score++;

                return Math.min(Math.floor(score / 2), 4);
            }

            function updateRequirements(password) {
                // Check each requirement
                $('.requirement').each(function() {
                    const $requirement = $(this);
                    const type = $requirement.data('requirement');

                    let met = false;

                    switch (type) {
                        case 'length':
                            met = password.length >= requirements.length;
                            break;
                        case 'uppercase':
                            met = /[A-Z]/.test(password);
                            break;
                        case 'lowercase':
                            met = /[a-z]/.test(password);
                            break;
                        case 'number':
                            met = /[0-9]/.test(password);
                            break;
                        case 'special':
                            met = /[^A-Za-z0-9]/.test(password);
                            break;
                    }

                    if (met) {
                        $requirement.addClass('met');
                    } else {
                        $requirement.removeClass('met');
                    }
                });
            }
        <?php endif; ?>

        // Realtime username and email validation
        $('#attrua_username').on('blur', function() {
            const username = $(this).val();

            if (!username) return;

            $.ajax({
                url: '<?php echo esc_js(admin_url('admin-ajax.php')); ?>',
                type: 'POST',
                data: {
                    action: 'attrua_pro_check_username',
                    username: username,
                    _ajax_nonce: '<?php echo esc_js(wp_create_nonce('attrua_pro_check_username')); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        $('#username-error').text('').removeClass('error');
                    } else {
                        $('#username-error').text(response.data.message).addClass('error');
                    }
                }
            });
        });

        $('#attrua_email').on('blur', function() {
            const email = $(this).val();

            if (!email) return;

            $.ajax({
                url: '<?php echo esc_js(admin_url('admin-ajax.php')); ?>',
                type: 'POST',
                data: {
                    action: 'attrua_pro_check_email',
                    email: email,
                    _ajax_nonce: '<?php echo esc_js(wp_create_nonce('attrua_pro_check_email')); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        $('#email-error').text('').removeClass('error');
                    } else {
                        $('#email-error').text(response.data.message).addClass('error');
                    }
                }
            });
        });

        // Password confirmation validation
        $('#attrua_password_confirm').on('input', function() {
            const password = $('#attrua_password').val();
            const confirmPassword = $(this).val();

            if (confirmPassword && password !== confirmPassword) {
                $('#password-confirm-error').text('<?php esc_html('Passwords do not match', 'attributes-user-access-pro-lite'); ?>').addClass('error');
            } else {
                $('#password-confirm-error').text('').removeClass('error');
            }
        });

        // Form submission validation
        $('.attrua-register-form').on('submit', function(e) {
            let isValid = true;

            // Check password confirmation
            const password = $('#attrua_password').val();
            const confirmPassword = $('#attrua_password_confirm').val();

            if (password !== confirmPassword) {
                $('#password-confirm-error').text('<?php esc_html('Passwords do not match', 'attributes-user-access-pro-lite'); ?>').addClass('error');
                isValid = false;
            }

            // Check for error messages
            $('.attrua-field-error.error').each(function() {
                isValid = false;
            });

            if (!isValid) {
                e.preventDefault();
            }
        });
    });
</script>