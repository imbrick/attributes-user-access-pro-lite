<?php

/**
 * License Activation Form Template
 *
 * Renders the license activation form for users to enter and submit
 * their license key. Implements security best practices including
 * nonce verification and input sanitization.
 *
 * @package Attributes\License\Admin
 * @since 1.0.0
 */

// Prevent direct file access
if (!defined('ABSPATH')) {
    exit;
}

// Define default values
$license_key = isset($license_key) ? $license_key : '';
$form_action = isset($form_action) ? $form_action : admin_url('admin-post.php');
$ajax_enabled = isset($ajax_enabled) ? (bool)$ajax_enabled : true;
?>

<div class="attrua-license-activation-container">
    <?php if (!empty($intro_text)): ?>
        <div class="attrua-activation-intro">
            <p><?php echo wp_kses_post($intro_text); ?></p>
        </div>
    <?php endif; ?>

    <form method="post" action="<?php echo esc_url($form_action); ?>"
        id="attrua-license-activation-form"
        class="<?php echo $ajax_enabled ? 'attrua-ajax-form' : ''; ?>">

        <?php if (!$ajax_enabled): ?>
            <input type="hidden" name="action" value="attrua_activate_license">
            <?php wp_nonce_field('attrua_license_action', 'attrua_license_nonce'); ?>
        <?php else: ?>
            <input type="hidden" name="nonce" value="<?php echo esc_attr(wp_create_nonce('attrua_license_ajax_nonce')); ?>">
        <?php endif; ?>

        <table class="form-table" role="presentation">
            <tr>
                <th scope="row">
                    <label for="attrua_license_key"><?php esc_html('License Key', 'attributes-user-access-pro-lite'); ?></label>
                </th>
                <td>
                    <div class="attrua-license-key-field">
                        <input type="text"
                            id="attrua_license_key"
                            name="license_key"
                            class="regular-text"
                            value="<?php echo esc_attr($license_key); ?>"
                            placeholder="<?php esc_attr_e('Enter your license key', 'attributes-user-access-pro-lite'); ?>"
                            autocomplete="off"
                            aria-required="true">

                        <button type="submit" class="button button-primary attrua-activate-button">
                            <span class="dashicons dashicons-yes-alt"></span>
                            <?php esc_html('Activate License', 'attributes-user-access-pro-lite'); ?>
                        </button>
                    </div>

                    <p class="description">
                        <?php esc_html('Enter your license key to activate premium features. You can find your license key in your purchase receipt email or your account dashboard.', 'attributes-user-access-pro-lite'); ?>
                    </p>

                    <div class="attrua-license-feedback"></div>
                </td>
            </tr>
        </table>
    </form>

    <div class="attrua-license-purchase-options">
        <h3><?php esc_html('Don\'t have a license yet?', 'attributes-user-access-pro-lite'); ?></h3>

        <div class="attrua-pricing-summary">
            <div class="attrua-pricing-options">
                <?php if (!empty($pricing_options) && is_array($pricing_options)): ?>
                    <?php foreach ($pricing_options as $option): ?>
                        <div class="attrua-pricing-option">
                            <h4><?php echo esc_html($option['name']); ?></h4>
                            <div class="attrua-price">
                                <?php echo esc_html($option['price']); ?>
                            </div>
                            <div class="attrua-license-sites">
                                <?php
                                echo esc_html(sprintf(
                                    /* translators: %d: number of sites */
                                    _n('For %d site', 'For %d sites', $option['sites'], 'attributes-user-access-pro-lite'),
                                    $option['sites']
                                ));
                                ?>
                            </div>
                            <div class="attrua-license-features">
                                <ul>
                                    <?php foreach ($option['features'] as $feature): ?>
                                        <li><?php echo esc_html($feature); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                            <a href="<?php echo esc_url($option['url']); ?>"
                                class="button button-secondary"
                                target="_blank">
                                <?php esc_html('Purchase License', 'attributes-user-access-pro-lite'); ?>
                            </a>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <div class="attrua-pricing-cta">
                        <p><?php esc_html('Purchase a license to unlock all premium features.', 'attributes-user-access-pro-lite'); ?></p>
                        <a href="<?php echo esc_url('https://attributeswp.com/pro'); ?>"
                            class="button button-primary"
                            target="_blank">
                            <?php esc_html('View Pricing Options', 'attributes-user-access-pro-lite'); ?>
                        </a>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <?php if ($ajax_enabled): ?>
        <script type="text/javascript">
            jQuery(document).ready(function($) {
                const $form = $('#attrua-license-activation-form');
                const $feedback = $('.attrua-license-feedback');
                const $activateButton = $('.attrua-activate-button');

                $form.on('submit', function(e) {
                    e.preventDefault();

                    const licenseKey = $('#attrua_license_key').val();

                    if (!licenseKey) {
                        $feedback.html('<div class="notice notice-error inline"><p><?php echo esc_js(__('Please enter a license key.', 'attributes-user-access-pro-lite')); ?></p></div>');
                        return;
                    }

                    // Clear previous feedback
                    $feedback.empty();

                    // Disable button and show loading state
                    $activateButton.addClass('attrua-loading').prop('disabled', true);

                    // Make AJAX request
                    $.ajax({
                        url: ajaxurl,
                        type: 'POST',
                        data: {
                            action: 'attrua_license_activate',
                            license_key: licenseKey,
                            nonce: $form.find('input[name="nonce"]').val()
                        },
                        success: function(response) {
                            if (response.success) {
                                $feedback.html('<div class="notice notice-success inline"><p>' + response.data.message + '</p></div>');

                                // Reload page after short delay to show updated license status
                                setTimeout(function() {
                                    location.reload();
                                }, 1500);
                            } else {
                                $feedback.html('<div class="notice notice-error inline"><p>' + response.data.message + '</p></div>');
                                $activateButton.removeClass('attrua-loading').prop('disabled', false);
                            }
                        },
                        error: function() {
                            $feedback.html('<div class="notice notice-error inline"><p><?php echo esc_js(__('Connection error. Please try again.', 'attributes-user-access-pro-lite')); ?></p></div>');
                            $activateButton.removeClass('attrua-loading').prop('disabled', false);
                        }
                    });
                });
            });
        </script>
    <?php endif; ?>
</div>