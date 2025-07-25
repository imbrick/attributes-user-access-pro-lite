<?php

/**
 * Password Policy Settings Tab Template
 *
 * @package Attributes\Pro\Display\Tabs
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Get current settings
$settings = get_option('attrua_pro_password_policy', []);
?>

<div class="attrua-settings-section">
    <div class="attrua-section-header">
        <h2><?php esc_html('Password Policy Settings', 'attributes-user-access-pro-lite'); ?></h2>
        <p class="description">
            <?php esc_html('Configure password requirements and expiration policies to enhance security.', 'attributes-user-access-pro-lite'); ?>
        </p>
    </div>

    <form method="post" action="options.php" id="attrua-password-policy-form">
        <?php settings_fields('attrua_pro_password_policy'); ?>
        <?php wp_nonce_field('attrua_pro_password_policy_nonce', 'attrua_pro_password_policy_nonce'); ?>

        <h3><?php esc_html('General Settings', 'attributes-user-access-pro-lite'); ?></h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html('Enable Password Policy', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="attrua_pro_password_policy[enabled]" value="1" <?php checked(!empty($settings['enabled'])); ?> />
                        <?php esc_html('Enable password policy enforcement', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html('Enforce password requirements for all users.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
        </table>

        <h3><?php esc_html('Password Complexity', 'attributes-user-access-pro-lite'); ?></h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html('Minimum Length', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <input type="number" name="attrua_pro_password_policy[min_length]" value="<?php echo esc_attr($settings['min_length'] ?? 8); ?>" min="4" max="64" />
                    <p class="description">
                        <?php esc_html('Minimum number of characters required for passwords.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('Character Requirements', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label style="display: block; margin-bottom: 8px;">
                        <input type="checkbox" name="attrua_pro_password_policy[require_uppercase]" value="1" <?php checked(!empty($settings['require_uppercase'])); ?> />
                        <?php esc_html('Require uppercase letters (A-Z)', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <label style="display: block; margin-bottom: 8px;">
                        <input type="checkbox" name="attrua_pro_password_policy[require_lowercase]" value="1" <?php checked(!empty($settings['require_lowercase'])); ?> />
                        <?php esc_html('Require lowercase letters (a-z)', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <label style="display: block; margin-bottom: 8px;">
                        <input type="checkbox" name="attrua_pro_password_policy[require_numbers]" value="1" <?php checked(!empty($settings['require_numbers'])); ?> />
                        <?php esc_html('Require numbers (0-9)', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <label style="display: block; margin-bottom: 8px;">
                        <input type="checkbox" name="attrua_pro_password_policy[require_special]" value="1" <?php checked(!empty($settings['require_special'])); ?> />
                        <?php esc_html('Require special characters (!@#$%^&*...)', 'attributes-user-access-pro-lite'); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('Disallowed Values', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label style="display: block; margin-bottom: 8px;">
                        <input type="checkbox" name="attrua_pro_password_policy[disallow_username]" value="1" <?php checked(!empty($settings['disallow_username'])); ?> />
                        <?php esc_html('Disallow username in password', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <label style="display: block; margin-bottom: 8px;">
                        <input type="checkbox" name="attrua_pro_password_policy[disallow_email]" value="1" <?php checked(!empty($settings['disallow_email'])); ?> />
                        <?php esc_html('Disallow email address in password', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <label style="display: block; margin-bottom: 8px;">
                        <input type="checkbox" name="attrua_pro_password_policy[check_common]" value="1" <?php checked(!empty($settings['check_common'])); ?> />
                        <?php esc_html('Check against common password list', 'attributes-user-access-pro-lite'); ?>
                    </label>
                </td>
            </tr>
        </table>

        <h3><?php esc_html('Password Reset Behavior', 'attributes-user-access-pro-lite'); ?></h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html('Reset Token Expiration', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <input type="number" name="attrua_pro_password_policy[reset_expiration]" value="<?php echo esc_attr($settings['reset_expiration'] ?? 24); ?>" min="1" max="72" />
                    <span><?php esc_html('hours', 'attributes-user-access-pro-lite'); ?></span>
                    <p class="description">
                        <?php esc_html('Number of hours before password reset links expire.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('Reset Notifications', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="attrua_pro_password_policy[notify_on_reset]" value="1" <?php checked(!empty($settings['notify_on_reset'])); ?> />
                        <?php esc_html('Notify users when their password is changed', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html('Send an email notification when a password is changed or reset.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('Admin Notifications', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="attrua_pro_password_policy[notify_admin]" value="1" <?php checked(!empty($settings['notify_admin'])); ?> />
                        <?php esc_html('Notify admin on suspicious password reset activity', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html('Send a notification to the site administrator when multiple password reset attempts are detected.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
        </table>

        <h3><?php esc_html('Password Expiration', 'attributes-user-access-pro-lite'); ?></h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html('Enable Expiration', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="attrua_pro_password_policy[enable_expiration]" value="1" <?php checked(!empty($settings['enable_expiration'])); ?> id="enable-expiration" />
                        <?php esc_html('Enable password expiration', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html('Force users to change their passwords periodically.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr class="expiration-setting" <?php echo empty($settings['enable_expiration']) ? 'style="display: none;"' : ''; ?>>
                <th scope="row"><?php esc_html('Expiration Period', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <input type="number" name="attrua_pro_password_policy[expiration_days]" value="<?php echo esc_attr($settings['expiration_days'] ?? 90); ?>" min="1" max="365" />
                    <span><?php esc_html('days', 'attributes-user-access-pro-lite'); ?></span>
                    <p class="description">
                        <?php esc_html('Number of days before passwords expire and must be changed.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr class="expiration-setting" <?php echo empty($settings['enable_expiration']) ? 'style="display: none;"' : ''; ?>>
                <th scope="row"><?php esc_html('Expiration Warning', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <input type="number" name="attrua_pro_password_policy[expiration_warning]" value="<?php echo esc_attr($settings['expiration_warning'] ?? 7); ?>" min="1" max="30" />
                    <span><?php esc_html('days before expiration', 'attributes-user-access-pro-lite'); ?></span>
                    <p class="description">
                        <?php esc_html('Number of days before expiration to start showing warnings.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr class="expiration-setting" <?php echo empty($settings['enable_expiration']) ? 'style="display: none;"' : ''; ?>>
                <th scope="row"><?php esc_html('Grace Period', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <input type="number" name="attrua_pro_password_policy[grace_period]" value="<?php echo esc_attr($settings['grace_period'] ?? 3); ?>" min="0" max="30" />
                    <span><?php esc_html('days', 'attributes-user-access-pro-lite'); ?></span>
                    <p class="description">
                        <?php esc_html('Number of days after expiration during which users can still log in but will be immediately redirected to password reset.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
        </table>

        <h3><?php esc_html('Password History', 'attributes-user-access-pro-lite'); ?></h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html('Enable Password History', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="attrua_pro_password_policy[enable_history]" value="1" <?php checked(!empty($settings['enable_history'])); ?> id="enable-history" />
                        <?php esc_html('Enable password history', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html('Prevent users from reusing previous passwords.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr class="history-setting" <?php echo empty($settings['enable_history']) ? 'style="display: none;"' : ''; ?>>
                <th scope="row"><?php esc_html('Password History Size', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <input type="number" name="attrua_pro_password_policy[history_size]" value="<?php echo esc_attr($settings['history_size'] ?? 5); ?>" min="1" max="24" />
                    <p class="description">
                        <?php esc_html('Number of previous passwords to remember and prevent reuse.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
        </table>

        <?php submit_button(__('Save Password Policy', 'attributes-user-access-pro-lite')); ?>
    </form>
</div>

<script>
    jQuery(document).ready(function($) {
        // Toggle expiration settings visibility
        $('#enable-expiration').on('change', function() {
            if ($(this).is(':checked')) {
                $('.expiration-setting').show();
            } else {
                $('.expiration-setting').hide();
            }
        });

        // Toggle history settings visibility
        $('#enable-history').on('change', function() {
            if ($(this).is(':checked')) {
                $('.history-setting').show();
            } else {
                $('.history-setting').hide();
            }
        });
    });
</script>