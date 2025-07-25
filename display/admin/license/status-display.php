<?php

/**
 * License Status Display Template
 *
 * Renders the active license information including status, expiration,
 * site activation counts, and customer details with appropriate data
 * sanitization and internationalization.
 *
 * @package Attributes\License\Admin
 * @since 1.0.0
 */

// Prevent direct file access
if (!defined('ABSPATH')) {
    exit;
}

// Ensure required data is available
if (!isset($license_data) || !is_object($license_data)) {
    return;
}
?>
<div class="attrua-license-info-container">
    <div class="attrua-license-status-header">
        <span class="attrua-license-status attrua-license-<?php echo esc_attr($license_data->get_status()); ?>">
            <span class="dashicons dashicons-yes-alt"></span>
            <span class="attrua-status-text"><?php echo esc_html($license_data->get_status_label()); ?></span>
        </span>
    </div>

    <table class="form-table" role="presentation">
        <tr>
            <th><?php esc_html('License Key', 'attributes-user-access-pro-lite'); ?></th>
            <td>
                <code><?php echo esc_html($masked_license_key); ?></code>
                <?php if ($show_key_toggle): ?>
                    <button type="button" class="button button-small attrua-toggle-license-key"
                        data-show-text="<?php esc_attr_e('Show', 'attributes-user-access-pro-lite'); ?>"
                        data-hide-text="<?php esc_attr_e('Hide', 'attributes-user-access-pro-lite'); ?>">
                        <?php esc_html('Show', 'attributes-user-access-pro-lite'); ?>
                    </button>
                    <span class="hidden attrua-actual-license-key"><?php echo esc_html($license_key); ?></span>
                <?php endif; ?>
            </td>
        </tr>

        <?php if ($license_data->get_plan_name()): ?>
            <tr>
                <th><?php esc_html('Plan', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <?php echo esc_html($license_data->get_plan_name()); ?>
                    <?php if ($license_data->get_customer_name()): ?>
                        <span class="attrua-license-customer">
                            (<?php echo esc_html($license_data->get_customer_name()); ?>)
                        </span>
                    <?php endif; ?>
                </td>
            </tr>
        <?php endif; ?>

        <tr>
            <th><?php esc_html('Expires', 'attributes-user-access-pro-lite'); ?></th>
            <td>
                <?php if ($license_data->get_expires() === __('Lifetime', 'attributes-user-access-pro-lite')): ?>
                    <span class="attrua-license-lifetime">
                        <?php echo esc_html($license_data->get_expires()); ?>
                    </span>
                <?php else: ?>
                    <?php
                    $expiry_class = '';
                    if (isset($license_data->get_raw_data()['expires_at'])) {
                        $validator = new \Attributes\License\Validator();
                        $expiry_timestamp = strtotime($license_data->get_raw_data()['expires_at']);

                        if ($validator->is_expired($license_data->get_raw_data()['expires_at'])) {
                            $expiry_class = 'attrua-license-expired';
                        } elseif ($validator->is_expiring_soon($license_data->get_raw_data()['expires_at'], 30)) {
                            $expiry_class = 'attrua-license-expiring';
                        }
                    }
                    ?>
                    <span class="<?php echo esc_attr($expiry_class); ?>">
                        <?php echo esc_html($license_data->get_expires()); ?>
                    </span>

                    <?php if (!empty($expiry_class) && $expiry_class === 'attrua-license-expiring'): ?>
                        <a href="<?php echo esc_url('https://attributeswp.com/renew/'); ?>"
                            class="button button-small" target="_blank">
                            <?php esc_html('Renew License', 'attributes-user-access-pro-lite'); ?>
                        </a>
                    <?php endif; ?>
                <?php endif; ?>
            </td>
        </tr>

        <?php
        $sites_info = $license_data->get_sites_info();
        if ($sites_info['limit'] > 0):
        ?>
            <tr>
                <th><?php esc_html('Site Activations', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <div class="attrua-activation-count">
                        <span class="attrua-sites-count <?php echo ($sites_info['remaining'] < 1) ? 'attrua-limit-reached' : ''; ?>">
                            <?php
                            echo esc_html(sprintf(
                                /* translators: %1$d: used activations, %2$d: total allowed activations */
                                __('%1$d of %2$d sites activated', 'attributes-user-access-pro-lite'),
                                $sites_info['active'],
                                $sites_info['limit']
                            ));
                            ?>
                        </span>

                        <?php if ($sites_info['remaining'] < 1): ?>
                            <span class="attrua-limit-notice">
                                <?php esc_html('Activation limit reached', 'attributes-user-access-pro-lite'); ?>
                            </span>
                        <?php endif; ?>
                    </div>
                </td>
            </tr>
        <?php endif; ?>

        <tr>
            <th><?php esc_html('Actions', 'attributes-user-access-pro-lite'); ?></th>
            <td>
                <div class="attrua-license-actions">
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="attrua-deactivate-form">
                        <input type="hidden" name="action" value="attrua_deactivate_license">
                        <?php wp_nonce_field('attrua_license_action', 'attrua_license_nonce'); ?>

                        <button type="submit" class="button attrua-deactivate-button"
                            data-confirm="<?php esc_attr_e('Are you sure you want to deactivate this license? Premium features will be disabled.', 'attributes-user-access-pro-lite'); ?>">
                            <span class="dashicons dashicons-no-alt"></span>
                            <?php esc_html('Deactivate License', 'attributes-user-access-pro-lite'); ?>
                        </button>
                    </form>

                    <button type="button" class="button attrua-check-license-button">
                        <span class="dashicons dashicons-update"></span>
                        <?php esc_html('Check License Status', 'attributes-user-access-pro-lite'); ?>
                    </button>
                </div>

                <div class="attrua-license-help">
                    <p>
                        <?php esc_html('Need help with your license?', 'attributes-user-access-pro-lite'); ?>
                        <a href="https://attributeswp.com/support" target="_blank">
                            <?php esc_html('Contact Support', 'attributes-user-access-pro-lite'); ?>
                        </a>
                    </p>
                </div>
            </td>
        </tr>
    </table>
</div>