<?php

/**
 * Security Settings Tab Template
 *
 * @package Attributes\Pro\Display\Tabs
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Get current settings
$settings = get_option('attrua_pro_security_settings', []);
$two_factor_settings = get_option('attrua_pro_2fa_settings', []);
$recaptcha_settings = get_option('attrua_pro_recaptcha_settings', []);
?>

<div class="attrua-settings-section">
    <div class="attrua-section-header">
        <h2><?php esc_html('Security Settings', 'attributes-user-access-pro-lite'); ?></h2>
        <p class="description">
            <?php esc_html('Configure security settings for authentication and user access.', 'attributes-user-access-pro-lite'); ?>
        </p>
    </div>

    <form method="post" action="options.php" id="attrua-security-settings-form">
        <?php settings_fields('attrua_pro_security'); ?>
        <?php wp_nonce_field('attrua_pro_security_nonce', 'attrua_pro_security_nonce'); ?>

        <h3><?php esc_html('General Security', 'attributes-user-access-pro-lite'); ?></h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html('Security Mode', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <select name="attrua_pro_security_settings[mode]" id="attrua_security_mode">
                        <option value="none" <?php selected($settings['mode'] ?? 'normal', 'none'); ?>>
                            <?php esc_html('None', 'attributes-user-access-pro-lite'); ?>
                        </option>
                        <option value="normal" <?php selected($settings['mode'] ?? 'normal', 'normal'); ?>>
                            <?php esc_html('Normal', 'attributes-user-access-pro-lite'); ?>
                        </option>
                        <option value="strict" <?php selected($settings['mode'] ?? 'normal', 'strict'); ?>>
                            <?php esc_html('Strict', 'attributes-user-access-pro-lite'); ?>
                        </option>
                        <option value="custom" <?php selected($settings['mode'] ?? 'normal', 'custom'); ?>>
                            <?php esc_html('Custom', 'attributes-user-access-pro-lite'); ?>
                        </option>
                    </select>
                    <p class="description">
                        <?php esc_html('Select security mode for login and authentication processes.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                    <div id="security_mode_description" class="attrua-security-mode-info">
                        <div class="attrua-security-mode-none" <?php echo ($settings['mode'] ?? 'normal') === 'none' ? '' : 'style="display:none;"'; ?>>
                            <p><?php esc_html('Basic WordPress security only. No additional security measures will be applied.', 'attributes-user-access-pro-lite'); ?></p>
                        </div>
                        <div class="attrua-security-mode-normal" <?php echo ($settings['mode'] ?? 'normal') === 'normal' ? '' : 'style="display:none;"'; ?>>
                            <p><?php esc_html('Recommended security settings with login protection and IP-based throttling.', 'attributes-user-access-pro-lite'); ?></p>
                        </div>
                        <div class="attrua-security-mode-strict" <?php echo ($settings['mode'] ?? 'normal') === 'strict' ? '' : 'style="display:none;"'; ?>>
                            <p><?php esc_html('Maximum security with aggressive throttling, IP blocking, and enforced 2FA.', 'attributes-user-access-pro-lite'); ?></p>
                        </div>
                        <div class="attrua-security-mode-custom" <?php echo ($settings['mode'] ?? 'normal') === 'custom' ? '' : 'style="display:none;"'; ?>>
                            <p><?php esc_html('Custom security settings. Configure each option individually below.', 'attributes-user-access-pro-lite'); ?></p>
                        </div>
                    </div>
                </td>
            </tr>
        </table>

        <div id="attrua_custom_security_settings" class="attrua-custom-settings-container" <?php echo ($settings['mode'] ?? 'normal') === 'custom' ? '' : 'style="display:none;"'; ?>>
            <h3><?php esc_html('Login Protection', 'attributes-user-access-pro-lite'); ?></h3>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html('Login Attempts', 'attributes-user-access-pro-lite'); ?></th>
                    <td>
                        <label>
                            <input type="number" name="attrua_pro_security_settings[max_login_attempts]" value="<?php echo esc_attr($settings['max_login_attempts'] ?? 5); ?>" min="1" max="20" />
                            <?php esc_html('attempts', 'attributes-user-access-pro-lite'); ?>
                        </label>
                        <p class="description">
                            <?php esc_html('Maximum number of failed login attempts before throttling.', 'attributes-user-access-pro-lite'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html('Lockout Duration', 'attributes-user-access-pro-lite'); ?></th>
                    <td>
                        <label>
                            <input type="number" name="attrua_pro_security_settings[lockout_duration]" value="<?php echo esc_attr($settings['lockout_duration'] ?? 15); ?>" min="1" max="1440" />
                            <?php esc_html('minutes', 'attributes-user-access-pro-lite'); ?>
                        </label>
                        <p class="description">
                            <?php esc_html('Duration of lockout after maximum failed attempts.', 'attributes-user-access-pro-lite'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html('Progressive Lockouts', 'attributes-user-access-pro-lite'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="attrua_pro_security_settings[progressive_lockouts]" value="1" <?php checked(!empty($settings['progressive_lockouts'])); ?> />
                            <?php esc_html('Enable progressive lockouts', 'attributes-user-access-pro-lite'); ?>
                        </label>
                        <p class="description">
                            <?php esc_html('Increase lockout duration for repeat offenders.', 'attributes-user-access-pro-lite'); ?>
                        </p>
                    </td>
                </tr>
            </table>

            <h3><?php esc_html('IP Management', 'attributes-user-access-pro-lite'); ?></h3>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html('IP Blocking', 'attributes-user-access-pro-lite'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="attrua_pro_security_settings[enable_ip_blocking]" value="1" <?php checked(!empty($settings['enable_ip_blocking'])); ?> />
                            <?php esc_html('Enable IP blocking', 'attributes-user-access-pro-lite'); ?>
                        </label>
                        <p class="description">
                            <?php esc_html('Block login attempts from suspicious IP addresses.', 'attributes-user-access-pro-lite'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html('IP Whitelist', 'attributes-user-access-pro-lite'); ?></th>
                    <td>
                        <textarea name="attrua_pro_security_settings[ip_whitelist]" rows="3" cols="50" class="large-text code"><?php echo esc_textarea($settings['ip_whitelist'] ?? ''); ?></textarea>
                        <p class="description">
                            <?php esc_html('Enter IP addresses to whitelist, one per line. These IPs will never be blocked.', 'attributes-user-access-pro-lite'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html('IP Blacklist', 'attributes-user-access-pro-lite'); ?></th>
                    <td>
                        <textarea name="attrua_pro_security_settings[ip_blacklist]" rows="3" cols="50" class="large-text code"><?php echo esc_textarea($settings['ip_blacklist'] ?? ''); ?></textarea>
                        <p class="description">
                            <?php esc_html('Enter IP addresses to blacklist, one per line. These IPs will always be blocked.', 'attributes-user-access-pro-lite'); ?>
                        </p>
                    </td>
                </tr>
            </table>
        </div>

        <h3><?php esc_html('Two-Factor Authentication', 'attributes-user-access-pro-lite'); ?></h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html('Enable 2FA', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="attrua_pro_2fa_settings[enabled]" value="1" <?php checked(!empty($two_factor_settings['enabled'])); ?> />
                        <?php esc_html('Enable two-factor authentication', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html('Require a second verification step during login.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('2FA Method', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <select name="attrua_pro_2fa_settings[method]">
                        <option value="email" <?php selected($two_factor_settings['method'] ?? 'email', 'email'); ?>>
                            <?php esc_html('Email', 'attributes-user-access-pro-lite'); ?>
                        </option>
                        <option value="totp" <?php selected($two_factor_settings['method'] ?? 'email', 'totp'); ?>>
                            <?php esc_html('TOTP (Google Authenticator, Authy)', 'attributes-user-access-pro-lite'); ?>
                        </option>
                        <option value="sms" <?php selected($two_factor_settings['method'] ?? 'email', 'sms'); ?>>
                            <?php esc_html('SMS (requires SMS service)', 'attributes-user-access-pro-lite'); ?>
                        </option>
                    </select>
                    <p class="description">
                        <?php esc_html('Select the method for delivering verification codes.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('Excluded Roles', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <?php
                    $all_roles = wp_roles()->get_names();
                    $excluded_roles = $two_factor_settings['excluded_roles'] ?? [];
                    foreach ($all_roles as $role_key => $role_name) {
                        $checked = in_array($role_key, $excluded_roles) ? 'checked' : '';
                    ?>
                        <label style="display: block; margin-bottom: 8px;">
                            <input type="checkbox" name="attrua_pro_2fa_settings[excluded_roles][]" value="<?php echo esc_attr($role_key); ?>" <?php echo $checked; ?> />
                            <?php echo esc_html($role_name); ?>
                        </label>
                    <?php
                    }
                    ?>
                    <p class="description">
                        <?php esc_html('Users with these roles will be exempt from two-factor authentication.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
        </table>

        <h3><?php esc_html('reCAPTCHA Integration', 'attributes-user-access-pro-lite'); ?></h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html('Enable reCAPTCHA', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="attrua_pro_recaptcha_settings[enabled]" value="1" <?php checked(!empty($recaptcha_settings['enabled'])); ?> />
                        <?php esc_html('Enable reCAPTCHA protection', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html('Protect forms against spam and bot attacks.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('reCAPTCHA Version', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <select name="attrua_pro_recaptcha_settings[version]">
                        <option value="v2" <?php selected($recaptcha_settings['version'] ?? 'v2', 'v2'); ?>>
                            <?php esc_html('v2 Checkbox ("I\'m not a robot")', 'attributes-user-access-pro-lite'); ?>
                        </option>
                        <option value="v2_invisible" <?php selected($recaptcha_settings['version'] ?? 'v2', 'v2_invisible'); ?>>
                            <?php esc_html('v2 Invisible', 'attributes-user-access-pro-lite'); ?>
                        </option>
                        <option value="v3" <?php selected($recaptcha_settings['version'] ?? 'v2', 'v3'); ?>>
                            <?php esc_html('v3 (Score-based)', 'attributes-user-access-pro-lite'); ?>
                        </option>
                    </select>
                    <p class="description">
                        <?php esc_html('Select reCAPTCHA version to use across forms.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('Site Key', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <input type="text" name="attrua_pro_recaptcha_settings[site_key]" value="<?php echo esc_attr($recaptcha_settings['site_key'] ?? ''); ?>" class="regular-text" />
                    <p class="description">
                        <?php esc_html('Enter your Google reCAPTCHA site key.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('Secret Key', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <input type="password" name="attrua_pro_recaptcha_settings[secret_key]" value="<?php echo esc_attr($recaptcha_settings['secret_key'] ?? ''); ?>" class="regular-text" />
                    <p class="description">
                        <?php esc_html('Enter your Google reCAPTCHA secret key.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('Forms', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label style="display: block; margin-bottom: 8px;">
                        <input type="checkbox" name="attrua_pro_recaptcha_settings[forms][login]" value="1" <?php checked(!empty($recaptcha_settings['forms']['login'])); ?> />
                        <?php esc_html('Login Form', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <label style="display: block; margin-bottom: 8px;">
                        <input type="checkbox" name="attrua_pro_recaptcha_settings[forms][register]" value="1" <?php checked(!empty($recaptcha_settings['forms']['register'])); ?> />
                        <?php esc_html('Registration Form', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <label style="display: block; margin-bottom: 8px;">
                        <input type="checkbox" name="attrua_pro_recaptcha_settings[forms][lost_password]" value="1" <?php checked(!empty($recaptcha_settings['forms']['lost_password'])); ?> />
                        <?php esc_html('Lost Password Form', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html('Select which forms should include reCAPTCHA verification.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
        </table>

        <h3><?php esc_html('Audit Logging', 'attributes-user-access-pro-lite'); ?></h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html('Enable Logging', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="attrua_pro_security_settings[enable_logging]" value="1" <?php checked(!empty($settings['enable_logging'])); ?> />
                        <?php esc_html('Enable security event logging', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html('Record security events like login attempts, password resets, and user registrations.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('Log Retention', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label>
                        <input type="number" name="attrua_pro_security_settings[log_retention]" value="<?php echo esc_attr($settings['log_retention'] ?? 30); ?>" min="1" max="365" />
                        <?php esc_html('days', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html('Number of days to keep security logs before automatic deletion.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
        </table>

        <?php submit_button(__('Save Security Settings', 'attributes-user-access-pro-lite')); ?>
    </form>
</div>

<script>
    jQuery(document).ready(function($) {
        // Toggle security mode description and custom settings
        $('#attrua_security_mode').on('change', function() {
            var mode = $(this).val();

            // Hide all descriptions
            $('.attrua-security-mode-info > div').hide();

            // Show selected mode description
            $('.attrua-security-mode-' + mode).show();

            // Toggle custom settings container
            if (mode === 'custom') {
                $('#attrua_custom_security_settings').show();
            } else {
                $('#attrua_custom_security_settings').hide();
            }
        });
    });
</script>