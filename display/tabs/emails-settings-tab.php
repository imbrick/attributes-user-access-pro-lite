<?php

/**
 * Email Notifications Settings Tab Template
 *
 * @package Attributes\Pro\Display\Tabs
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Get current settings
$settings = get_option('attrua_pro_email_settings', []);
?>

<div class="attrua-settings-section">
    <div class="attrua-section-header">
        <h2><?php esc_html('Email Notification Settings', 'attributes-user-access-pro-lite'); ?></h2>
        <p class="description">
            <?php esc_html('Configure email templates and notification preferences for user authentication events.', 'attributes-user-access-pro-lite'); ?>
        </p>
    </div>

    <form method="post" action="options.php" id="attrua-email-settings-form">
        <?php settings_fields('attrua_pro_email_settings'); ?>
        <?php wp_nonce_field('attrua_pro_email_settings_nonce', 'attrua_pro_email_settings_nonce'); ?>

        <h3><?php esc_html('General Settings', 'attributes-user-access-pro-lite'); ?></h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html('Email From Name', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <input type="text" name="attrua_pro_email_settings[from_name]" value="<?php echo esc_attr($settings['from_name'] ?? get_bloginfo('name')); ?>" class="regular-text" />
                    <p class="description">
                        <?php esc_html('The name that emails will be sent from. Defaults to your site name.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('Email From Address', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <input type="email" name="attrua_pro_email_settings[from_email]" value="<?php echo esc_attr($settings['from_email'] ?? get_option('admin_email')); ?>" class="regular-text" />
                    <p class="description">
                        <?php esc_html('The email address that emails will be sent from. Defaults to the admin email.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('Email Template', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <select name="attrua_pro_email_settings[template]" id="email-template-selector">
                        <option value="default" <?php selected($settings['template'] ?? 'default', 'default'); ?>>
                            <?php esc_html('Default (Simple)', 'attributes-user-access-pro-lite'); ?>
                        </option>
                        <option value="branded" <?php selected($settings['template'] ?? 'default', 'branded'); ?>>
                            <?php esc_html('Branded', 'attributes-user-access-pro-lite'); ?>
                        </option>
                        <option value="plain" <?php selected($settings['template'] ?? 'default', 'plain'); ?>>
                            <?php esc_html('Plain Text', 'attributes-user-access-pro-lite'); ?>
                        </option>
                    </select>
                    <p class="description">
                        <?php esc_html('Select the template style for emails.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr class="branded-setting" <?php echo ($settings['template'] ?? 'default') !== 'branded' ? 'style="display: none;"' : ''; ?>>
                <th scope="row"><?php esc_html('Header Color', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <input type="text" name="attrua_pro_email_settings[header_color]" value="<?php echo esc_attr($settings['header_color'] ?? '#2271b1'); ?>" class="attrua-color-field" />
                    <p class="description">
                        <?php esc_html('Color for the email header in branded template.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr class="branded-setting" <?php echo ($settings['template'] ?? 'default') !== 'branded' ? 'style="display: none;"' : ''; ?>>
                <th scope="row"><?php esc_html('Logo URL', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <input type="url" name="attrua_pro_email_settings[logo_url]" value="<?php echo esc_url($settings['logo_url'] ?? ''); ?>" class="regular-text" />
                    <button type="button" class="button attrua-media-upload">
                        <?php esc_html('Select Image', 'attributes-user-access-pro-lite'); ?>
                    </button>
                    <p class="description">
                        <?php esc_html('URL to your logo image for branded emails.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
        </table>

        <h3><?php esc_html('User Notifications', 'attributes-user-access-pro-lite'); ?></h3>
        <p class="description">
            <?php esc_html('Configure which email notifications will be sent to users.', 'attributes-user-access-pro-lite'); ?>
        </p>

        <div class="attrua-email-templates-container">
            <!-- Welcome Email -->
            <div class="attrua-email-template-card">
                <div class="attrua-email-template-header">
                    <h4><?php esc_html('Welcome Email', 'attributes-user-access-pro-lite'); ?></h4>
                    <label class="attrua-switch">
                        <input type="checkbox" name="attrua_pro_email_settings[welcome_email][enabled]" value="1" <?php checked(!empty($settings['welcome_email']['enabled'])); ?> class="email-template-toggle" data-target="welcome-email" />
                        <span class="attrua-slider"></span>
                    </label>
                </div>
                <div class="attrua-email-template-body" id="welcome-email" <?php echo empty($settings['welcome_email']['enabled']) ? 'style="display: none;"' : ''; ?>>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><?php esc_html('Subject', 'attributes-user-access-pro-lite'); ?></th>
                            <td>
                                <input type="text" name="attrua_pro_email_settings[welcome_email][subject]"
                                    value="<?php echo esc_attr($settings['welcome_email']['subject'] ?? __('Welcome to {site_name}', 'attributes-user-access-pro-lite')); ?>"
                                    class="large-text" />
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html('Content', 'attributes-user-access-pro-lite'); ?></th>
                            <td>
                                <textarea name="attrua_pro_email_settings[password_expiry][content]" rows="8" class="large-text"><?php
                                                                                                                                    echo esc_textarea($settings['password_expiry']['content'] ?? __("Hello {user_display_name},\n\nYour password for {site_name} will expire in {days_remaining} days.\n\nPlease visit {password_change_url} to update your password before it expires.\n\nRegards,\n{site_name} Team", 'attributes-user-access-pro-lite'));
                                                                                                                                    ?></textarea>
                                <p class="description">
                                    <?php esc_html('Available variables: {site_name}, {site_url}, {days_remaining}, {password_change_url}, {user_login}, {user_display_name}, {user_email}', 'attributes-user-access-pro-lite'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <h3><?php esc_html('Admin Notifications', 'attributes-user-access-pro-lite'); ?></h3>
        <p class="description">
            <?php esc_html('Configure which notification emails will be sent to administrators.', 'attributes-user-access-pro-lite'); ?>
        </p>

        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html('Notification Recipients', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <input type="text" name="attrua_pro_email_settings[admin_recipients]"
                        value="<?php echo esc_attr($settings['admin_recipients'] ?? get_option('admin_email')); ?>"
                        class="regular-text" />
                    <p class="description">
                        <?php esc_html('Email addresses to receive admin notifications. Use commas to separate multiple emails.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('New User Registration', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="attrua_pro_email_settings[admin_new_user]" value="1" <?php checked(!empty($settings['admin_new_user'])); ?> />
                        <?php esc_html('Notify admin when a new user registers', 'attributes-user-access-pro-lite'); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('Failed Login Attempts', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="attrua_pro_email_settings[admin_failed_login]" value="1" <?php checked(!empty($settings['admin_failed_login'])); ?> />
                        <?php esc_html('Notify admin after multiple failed login attempts', 'attributes-user-access-pro-lite'); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('User Locked Out', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="attrua_pro_email_settings[admin_lockout]" value="1" <?php checked(!empty($settings['admin_lockout'])); ?> />
                        <?php esc_html('Notify admin when a user is locked out', 'attributes-user-access-pro-lite'); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html('Blocked IP', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="attrua_pro_email_settings[admin_blocked_ip]" value="1" <?php checked(!empty($settings['admin_blocked_ip'])); ?> />
                        <?php esc_html('Notify admin when an IP is blocked', 'attributes-user-access-pro-lite'); ?>
                    </label>
                </td>
            </tr>
        </table>

        <?php submit_button(__('Save Email Settings', 'attributes-user-access-pro-lite')); ?>
    </form>
</div>
<script>
    jQuery(document).ready(function($) {
        // Toggle template settings
        $('#email-template-selector').on('change', function() {
            if ($(this).val() === 'branded') {
                $('.branded-setting').show();
            } else {
                $('.branded-setting').hide();
            }
        });

        // Toggle email template sections
        $('.email-template-toggle').on('change', function() {
            const targetId = $(this).data('target');
            if ($(this).is(':checked')) {
                $('#' + targetId).slideDown();
            } else {
                $('#' + targetId).slideUp();
            }
        });

        // Media uploader for logo
        $('.attrua-media-upload').on('click', function(e) {
            e.preventDefault();

            const button = $(this);
            const urlField = button.prev('input');

            // Create a media frame
            const frame = wp.media({
                title: '<?php esc_html('Select or Upload Logo', 'attributes-user-access-pro-lite'); ?>',
                button: {
                    text: '<?php esc_html('Use this image', 'attributes-user-access-pro-lite'); ?>'
                },
                multiple: false
            });

            // When an image is selected, run a callback
            frame.on('select', function() {
                const attachment = frame.state().get('selection').first().toJSON();
                urlField.val(attachment.url);
            });

            // Open the media library frame
            frame.open();
        });

        // Initialize color picker
        if ($.fn.wpColorPicker) {
            $('.attrua-color-field').wpColorPicker();
        }
    });
</script>

<style>
    .attrua-email-templates-container {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
        gap: 20px;
        margin-bottom: 30px;
    }

    .attrua-email-template-card {
        border: 1px solid #ccd0d4;
        border-radius: 4px;
        overflow: hidden;
        background: #fff;
    }

    .attrua-email-template-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 15px;
        background: #f9f9f9;
        border-bottom: 1px solid #ccd0d4;
    }

    .attrua-email-template-header h4 {
        margin: 0;
    }

    .attrua-email-template-body {
        padding: 15px;
    }

    .attrua-email-template-body .form-table th {
        width: 120px;
        padding: 15px 10px 15px 0;
    }

    .attrua-switch {
        position: relative;
        display: inline-block;
        width: 40px;
        height: 24px;
    }

    .attrua-switch input {
        opacity: 0;
        width: 0;
        height: 0;
    }

    .attrua-slider {
        position: absolute;
        cursor: pointer;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: #ccc;
        transition: .4s;
        border-radius: 24px;
    }

    .attrua-slider:before {
        position: absolute;
        content: "";
        height: 16px;
        width: 16px;
        left: 4px;
        bottom: 4px;
        background-color: white;
        transition: .4s;
        border-radius: 50%;
    }

    input:checked+.attrua-slider {
        background-color: #2196F3;
    }

    input:checked+.attrua-slider:before {
        transform: translateX(16px);
    }
</style>