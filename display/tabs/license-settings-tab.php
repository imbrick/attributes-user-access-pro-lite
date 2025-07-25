<?php

/**
 * SureCart License Settings Tab Template
 *
 * @package Attributes\Pro\Display\Tabs
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

use Attributes\Pro\Core\Constants;
?>

<div class="attrua-settings-section">
    <div class="attrua-section-header">
        <h2><?php esc_html('License Management', Constants::TEXT_DOMAIN); ?></h2>
        <p class="description">
            <?php esc_html('Manage your Attributes User Access Pro license.', Constants::TEXT_DOMAIN); ?>
        </p>
    </div>

    <div class="attrua-license-container">
        <?php if ($is_active): ?>
            <div class="attrua-license-status attrua-license-active">
                <span class="dashicons dashicons-yes-alt"></span>
                <span class="status-text"><?php esc_html('License Active', Constants::TEXT_DOMAIN); ?></span>
            </div>
        <?php else: ?>
            <div class="attrua-license-status attrua-license-inactive">
                <span class="dashicons dashicons-warning"></span>
                <span class="status-text"><?php esc_html('License Inactive', Constants::TEXT_DOMAIN); ?></span>
            </div>
        <?php endif; ?>

        <div class="attrua-license-notices"></div>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" id="attrua-license-form">
            <input type="hidden" name="action" value="attrua_pro_license_action" />
            <?php wp_nonce_field('attrua_pro_license', 'attrua_license_ajax_nonce'); ?>

            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html('License Key', Constants::TEXT_DOMAIN); ?></th>
                    <td>
                        <div class="attrua-license-key-container">
                            <input type="<?php echo $is_active ? 'password' : 'text'; ?>"
                                id="attrua_license_key"
                                name="attrua_pro_license_key"
                                class="regular-text attrua-license-key"
                                value="<?php echo esc_attr($is_active ? '•••••••••••••••••••••' : $license_key); ?>"
                                <?php echo $is_active ? 'disabled' : ''; ?> />

                            <?php if ($is_active): ?>
                                <button type="button" class="attrua-license-toggle">
                                    <span class="dashicons dashicons-visibility"></span>
                                </button>
                            <?php endif; ?>
                        </div>

                        <p class="description">
                            <?php if (!$is_active): ?>
                                <?php esc_html('Enter your license key received from Attributes WP after purchase.', Constants::TEXT_DOMAIN); ?>
                            <?php else: ?>
                                <?php esc_html('Your license key is active and validated with Attributes WP.', Constants::TEXT_DOMAIN); ?>
                            <?php endif; ?>
                        </p>

                        <?php if ($is_active): ?>
                            <input type="hidden" name="attrua_pro_license_action" value="deactivate" />
                            <button type="submit" id="attrua-deactivate-license" class="button button-secondary">
                                <span class="dashicons dashicons-no-alt" style="margin-top: 3px;"></span>
                                <?php esc_html('Deactivate License', Constants::TEXT_DOMAIN); ?>
                            </button>
                        <?php else: ?>
                            <input type="hidden" name="attrua_pro_license_action" value="activate" />
                            <button type="submit" id="attrua-activate-license" class="button button-primary">
                                <span class="dashicons dashicons-yes-alt" style="margin-top: 3px;"></span>
                                <?php esc_html('Activate License', Constants::TEXT_DOMAIN); ?>
                            </button>
                        <?php endif; ?>
                    </td>
                </tr>

                <?php if ($is_active && !empty($license_data)): ?>
                    <tr>
                        <th scope="row"><?php esc_html('License Details', Constants::TEXT_DOMAIN); ?></th>
                        <td>
                            <div class="attrua-license-details">
                                <?php if (!empty($license_data['customer_name'])): ?>
                                    <p>
                                        <span class="label"><?php esc_html('Customer', Constants::TEXT_DOMAIN); ?>:</span>
                                        <?php echo esc_html($license_data['customer_name']); ?>
                                    </p>
                                <?php endif; ?>

                                <?php if (!empty($license_data['plan_name'])): ?>
                                    <p>
                                        <span class="label"><?php esc_html('Plan', Constants::TEXT_DOMAIN); ?>:</span>
                                        <?php echo esc_html($license_data['plan_name']); ?>
                                    </p>
                                <?php endif; ?>

                                <?php if (!empty($license_data['expires'])): ?>
                                    <p>
                                        <span class="label"><?php esc_html('Expires', Constants::TEXT_DOMAIN); ?>:</span>
                                        <?php echo esc_html($license_data['expires']); ?>
                                    </p>
                                <?php endif; ?>

                                <?php if (isset($license_data['sites_active']) && isset($license_data['sites_limit'])): ?>
                                    <p>
                                        <span class="label"><?php esc_html('Sites', Constants::TEXT_DOMAIN); ?>:</span>
                                        <?php
                                        echo esc_html(sprintf(
                                            __('%1$d of %2$d sites activated', Constants::TEXT_DOMAIN),
                                            $license_data['sites_active'],
                                            $license_data['sites_limit']
                                        ));
                                        ?>
                                    </p>
                                <?php endif; ?>
                            </div>

                            <div class="attrua-license-help">
                                <p>
                                    <?php esc_html('Need help with your license?', Constants::TEXT_DOMAIN); ?>
                                    <a href="https://attrubuteswp.com/support" target="_blank">
                                        <?php esc_html('Contact Support', Constants::TEXT_DOMAIN); ?>
                                    </a>
                                </p>
                            </div>
                        </td>
                    </tr>
                <?php endif; ?>
            </table>
        </form>

        <?php if (!$is_active): ?>
            <div class="attrua-purchase-license">
                <p>
                    <?php esc_html('Don\'t have a license yet?', Constants::TEXT_DOMAIN); ?>
                    <a href="https://attributeswp.com/pro" target="_blank" class="button button-secondary">
                        <?php esc_html('Purchase License', Constants::TEXT_DOMAIN); ?>
                    </a>
                </p>
            </div>
        <?php endif; ?>
    </div>
</div>

<style>
    .attrua-content {
        margin-top: 0;
    }

    .attrua-license-container {
        max-width: 800px;
        margin-top: 20px;
        padding: 20px;
    }

    .attrua-license-status {
        display: inline-flex;
        align-items: center;
        padding: 8px 16px;
        border-radius: 4px;
        margin-bottom: 20px;
    }

    .attrua-license-active {
        background-color: #edfaef;
        color: #2a8d3a;
        border: 1px solid #c3e6cb;
    }

    .attrua-license-inactive {
        background-color: #fcf1eb;
        color: #c0582a;
        border: 1px solid #ffebbe;
    }

    .attrua-license-status .dashicons {
        font-size: 20px;
        margin-right: 8px;
    }

    .attrua-license-details {
        background-color: #f8f9fa;
        border: 1px solid #e2e4e7;
        border-radius: 4px;
        padding: 15px;
        margin-bottom: 15px;
    }

    .attrua-license-details p {
        margin: 0 0 10px;
    }

    .attrua-license-details p:last-child {
        margin-bottom: 0;
    }

    .attrua-license-details .label {
        font-weight: 600;
        display: inline-block;
        min-width: 80px;
    }

    .attrua-license-key-container {
        position: relative;
        max-width: 400px;
    }

    .attrua-license-toggle {
        position: absolute;
        right: 10px;
        top: 50%;
        transform: translateY(-50%);
        background: none;
        border: none;
        cursor: pointer;
        color: #007cba;
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

    .attrua-license-notices {
        margin-bottom: 20px;
    }

    /* Button loading state */
    .button.loading {
        position: relative;
        color: transparent !important;
    }

    .button.loading:after {
        content: '';
        position: absolute;
        width: 16px;
        height: 16px;
        top: 50%;
        left: 50%;
        margin: -8px 0 0 -8px;
        border-radius: 50%;
        border: 2px solid rgba(255, 255, 255, 0.3);
        border-top-color: #fff;
        animation: spin 1s infinite linear;
    }

    @keyframes spin {
        from {
            transform: rotate(0deg);
        }

        to {
            transform: rotate(360deg);
        }
    }
</style>