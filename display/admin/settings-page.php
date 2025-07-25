<?php

/**
 * License Settings Page Template
 *
 * @package Attributes\Pro
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="wrap attrua-license-settings">
    <h1><?php esc_html('License Management', 'attributes-user-access-pro-lite'); ?></h1>

    <p class="description">
        <?php esc_html('Manage your Attributes User Access Pro license.', 'attributes-user-access-pro-lite'); ?>
    </p>

    <div class="attrua-license-status-container">
        <?php if ($is_active): ?>
            <div class="attrua-license-status attrua-license-active">
                <span class="dashicons dashicons-yes-alt"></span>
                <span class="status-text"><?php esc_html('License Active', 'attributes-user-access-pro-lite'); ?></span>
            </div>
        <?php else: ?>
            <div class="attrua-license-status attrua-license-inactive">
                <span class="dashicons dashicons-warning"></span>
                <span class="status-text"><?php esc_html('License Inactive', 'attributes-user-access-pro-lite'); ?></span>
            </div>
        <?php endif; ?>
    </div>

    <?php if ($is_active && $license_data): ?>
        <!-- Active License Information -->
        <div class="attrua-active-license-info">
            <table class="form-table" role="presentation">
                <tr>
                    <th><?php esc_html('License Key', 'attributes-user-access-pro-lite'); ?></th>
                    <td>
                        <code><?php echo esc_html($license_key); ?></code>
                        <div class="attrua-deactivate-container">
                            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                <input type="hidden" name="action" value="attrua_deactivate_license">
                                <?php wp_nonce_field('attrua_license_action', 'attrua_license_nonce'); ?>
                                <button type="submit" class="button button-secondary">
                                    <span class="dashicons dashicons-no-alt" style="margin-top: 3px;"></span>
                                    <?php esc_html('Deactivate License', 'attributes-user-access-pro-lite'); ?>
                                </button>
                            </form>
                        </div>
                    </td>
                </tr>

                <?php if ($license_data->get_customer_name()): ?>
                    <tr>
                        <th><?php esc_html('Customer', 'attributes-user-access-pro-lite'); ?></th>
                        <td><?php echo esc_html($license_data->get_customer_name()); ?></td>
                    </tr>
                <?php endif; ?>

                <?php if ($license_data->get_plan_name()): ?>
                    <tr>
                        <th><?php esc_html('Plan', 'attributes-user-access-pro-lite'); ?></th>
                        <td><?php echo esc_html($license_data->get_plan_name()); ?></td>
                    </tr>
                <?php endif; ?>

                <tr>
                    <th><?php esc_html('Expires', 'attributes-user-access-pro-lite'); ?></th>
                    <td><?php echo esc_html($license_data->get_expires()); ?></td>
                </tr>

                <?php
                $sites_info = $license_data->get_sites_info();
                if ($sites_info['limit'] > 0):
                ?>
                    <tr>
                        <th><?php esc_html('Sites', 'attributes-user-access-pro-lite'); ?></th>
                        <td>
                            <?php
                            echo esc_html(sprintf(
                                __('%1$d of %2$d sites activated', 'attributes-user-access-pro-lite'),
                                $sites_info['active'],
                                $sites_info['limit']
                            ));
                            ?>
                        </td>
                    </tr>
                <?php endif; ?>
            </table>

            <div class="attrua-license-help">
                <p>
                    <?php esc_html('Need help with your license?', 'attributes-user-access-pro-lite'); ?>
                    <a href="https://attributeswp.com/support" target="_blank">
                        <?php esc_html('Contact Support', 'attributes-user-access-pro-lite'); ?>
                    </a>
                </p>
            </div>
        </div>
    <?php else: ?>
        <!-- License Activation Form -->
        <div class="attrua-license-activation-form">
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="attrua_activate_license">
                <?php wp_nonce_field('attrua_license_action', 'attrua_license_nonce'); ?>

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">
                            <label for="license_key"><?php esc_html('License Key', 'attributes-user-access-pro-lite'); ?></label>
                        </th>
                        <td>
                            <input type="text"
                                id="license_key"
                                name="license_key"
                                class="regular-text"
                                placeholder="<?php esc_attr_e('Enter your license key', 'attributes-user-access-pro-lite'); ?>"
                                value="<?php echo esc_attr(get_option('attrua_pro_license_key', '')); ?>"
                                autocomplete="off">
                            <p class="description">
                                <?php esc_html('Enter your license key to activate premium features.', 'attributes-user-access-pro-lite'); ?>
                            </p>
                        </td>
                    </tr>
                </table>

                <p class="submit">
                    <button type="submit" class="button button-primary">
                        <span class="dashicons dashicons-yes-alt" style="margin-top: 3px;"></span>
                        <?php esc_html('Activate License', 'attributes-user-access-pro-lite'); ?>
                    </button>
                </p>
            </form>

            <div class="attrua-purchase-license">
                <p>
                    <?php esc_html('Don\'t have a license yet?', 'attributes-user-access-pro-lite'); ?>
                    <a href="https://attributeswp.com/pro" target="_blank" class="button button-secondary">
                        <?php esc_html('Purchase License', 'attributes-user-access-pro-lite'); ?>
                    </a>
                </p>
            </div>
        </div>
    <?php endif; ?>
</div>

<style>
    /* License settings styles */
    .attrua-license-status {
        display: inline-flex;
        align-items: center;
        padding: 10px 16px;
        border-radius: 4px;
        margin: 15px 0;
    }

    .attrua-license-active {
        background-color: #f0f6e4;
        color: #2c7a2c;
        border: 1px solid #c6e1a5;
    }

    .attrua-license-inactive {
        background-color: #fef2e7;
        color: #c05621;
        border: 1px solid #feecdc;
    }

    .attrua-license-status .dashicons {
        font-size: 20px;
        margin-right: 8px;
    }

    .attrua-active-license-info {
        background-color: #f8f9fa;
        border: 1px solid #e2e4e7;
        border-radius: 4px;
        padding: 15px;
        margin-top: 20px;
    }

    .attrua-license-help {
        margin-top: 15px;
        border-top: 1px solid #e2e4e7;
        padding-top: 15px;
    }

    .attrua-purchase-license {
        margin-top: 30px;
        padding-top: 15px;
        border-top: 1px solid #e2e4e7;
    }
</style>