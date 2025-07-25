<?php

/**
 * Integrations Settings Tab Template
 *
 * @package Attributes\Pro\Display\Tabs
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Get current settings
$settings = get_option('attrua_pro_surecart_settings', []);

// Get available roles
$all_roles = wp_roles()->get_names();

// Get SureCart products if available
$products = [];
if (function_exists('SC')) {
    try {
        $products_response = SC()->api->products->list();
        $products = $products_response->data ?? [];
    } catch (\Exception $e) {
        // Handle API error
        $products = [];
    }
}
?>

<div class="attrua-settings-section">
    <div class="attrua-section-header">
        <h2><?php esc_html('SureCart Integration', 'attributes-user-access-pro-lite'); ?></h2>

        <?php if (!$surecart_active): ?>
            <div class="notice notice-warning inline">
                <p>
                    <?php
                    echo wp_kses(
                        sprintf(
                            __('SureCart is not active. Please <a href="%s" target="_blank">install and activate SureCart</a> to use this integration.', 'attributes-user-access-pro-lite'),
                            esc_url(admin_url('plugin-install.php?s=surecart&tab=search&type=term'))
                        ),
                        ['a' => ['href' => [], 'target' => []]]
                    );
                    ?>
                </p>
            </div>
        <?php endif; ?>

        <p class="description">
            <?php esc_html('Integrate Attributes User Access Pro with SureCart for purchase-based access control.', 'attributes-user-access-pro-lite'); ?>
        </p>
    </div>

    <form method="post" action="options.php" id="attrua-surecart-settings-form">
        <?php settings_fields('attrua_pro_integration'); ?>

        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html('Enable Integration', 'attributes-user-access-pro-lite'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="attrua_pro_surecart_settings[enabled]" value="1" <?php checked(!empty($settings['enabled'])); ?> <?php disabled(!$surecart_active); ?> />
                        <?php esc_html('Enable SureCart integration', 'attributes-user-access-pro-lite'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html('Integrate with SureCart to enable purchase-based access control.', 'attributes-user-access-pro-lite'); ?>
                    </p>
                </td>
            </tr>
        </table>

        <!-- Integration Settings Section -->
        <div id="attrua-surecart-settings" style="<?php echo empty($settings['enabled']) ? 'display: none;' : ''; ?>">
            <h3><?php esc_html('User Synchronization', 'attributes-user-access-pro-lite'); ?></h3>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html('Auto-Create Users', 'attributes-user-access-pro-lite'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="attrua_pro_surecart_settings[auto_create_users]" value="1" <?php checked(!empty($settings['auto_create_users'])); ?> />
                            <?php esc_html('Automatically create WordPress users from SureCart customers', 'attributes-user-access-pro-lite'); ?>
                        </label>
                        <p class="description">
                            <?php esc_html('When enabled, new users will be created in WordPress when customers sign up through SureCart.', 'attributes-user-access-pro-lite'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html('Sync WordPress Users', 'attributes-user-access-pro-lite'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="attrua_pro_surecart_settings[sync_users_to_customers]" value="1" <?php checked(!empty($settings['sync_users_to_customers'])); ?> />
                            <?php esc_html('Sync WordPress users to SureCart customers', 'attributes-user-access-pro-lite'); ?>
                        </label>
                        <p class="description">
                            <?php esc_html('When enabled, new WordPress users will be synced to SureCart as customers.', 'attributes-user-access-pro-lite'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html('Default User Role', 'attributes-user-access-pro-lite'); ?></th>
                    <td>
                        <select name="attrua_pro_surecart_settings[default_role]">
                            <?php foreach ($all_roles as $role_key => $role_name): ?>
                                <option value="<?php echo esc_attr($role_key); ?>" <?php selected($settings['default_role'] ?? 'subscriber', $role_key); ?>>
                                    <?php echo esc_html($role_name); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <p class="description">
                            <?php esc_html('Default role for users created from SureCart customers.', 'attributes-user-access-pro-lite'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html('Welcome Email', 'attributes-user-access-pro-lite'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="attrua_pro_surecart_settings[send_welcome_email]" value="1" <?php checked(!empty($settings['send_welcome_email'])); ?> />
                            <?php esc_html('Send welcome email to new users', 'attributes-user-access-pro-lite'); ?>
                        </label>
                        <p class="description">
                            <?php esc_html('Send WordPress welcome email with login credentials to users created from SureCart customers.', 'attributes-user-access-pro-lite'); ?>
                        </p>
                    </td>
                </tr>
            </table>

            <h3><?php esc_html('Product Role Mapping', 'attributes-user-access-pro-lite'); ?></h3>
            <p class="description">
                <?php esc_html('Map SureCart products to WordPress user roles. Users will be granted these roles when they purchase the corresponding products.', 'attributes-user-access-pro-lite'); ?>
            </p>

            <div class="attrua-product-role-mapping">
                <table class="widefat striped">
                    <thead>
                        <tr>
                            <th><?php esc_html('Product', 'attributes-user-access-pro-lite'); ?></th>
                            <th><?php esc_html('Roles', 'attributes-user-access-pro-lite'); ?></th>
                            <th><?php esc_html('Actions', 'attributes-user-access-pro-lite'); ?></th>
                        </tr>
                    </thead>
                    <tbody id="attrua-product-role-mappings">
                        <?php
                        $product_role_mapping = $settings['product_role_mapping'] ?? [];
                        $product_mapping = $settings['product_mapping'] ?? [];

                        foreach ($product_role_mapping as $product_id => $roles):
                            $product_name = $product_mapping[$product_id]['name'] ?? $product_id;
                        ?>
                            <tr class="attrua-product-role-row" data-product-id="<?php echo esc_attr($product_id); ?>">
                                <td>
                                    <input type="hidden" name="attrua_pro_surecart_settings[product_mapping][<?php echo esc_attr($product_id); ?>][name]" value="<?php echo esc_attr($product_name); ?>" />
                                    <?php echo esc_html($product_name); ?>
                                </td>
                                <td>
                                    <select name="attrua_pro_surecart_settings[product_role_mapping][<?php echo esc_attr($product_id); ?>][]" class="attrua-role-select" multiple>
                                        <?php foreach ($all_roles as $role_key => $role_name): ?>
                                            <option value="<?php echo esc_attr($role_key); ?>" <?php selected(in_array($role_key, $roles), true); ?>>
                                                <?php echo esc_html($role_name); ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                </td>
                                <td>
                                    <button type="button" class="button attrua-remove-product-role">
                                        <?php esc_html('Remove', 'attributes-user-access-pro-lite'); ?>
                                    </button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <div class="attrua-add-product-role-mapping">
                    <select id="attrua-product-select">
                        <option value=""><?php esc_html('-- Select Product --', 'attributes-user-access-pro-lite'); ?></option>
                        <?php foreach ($products as $product): ?>
                            <option value="<?php echo esc_attr($product->id); ?>" data-name="<?php echo esc_attr($product->name); ?>">
                                <?php echo esc_html($product->name); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                    <button type="button" class="button" id="attrua-add-product-role">
                        <?php esc_html('Add Product', 'attributes-user-access-pro-lite'); ?>
                    </button>
                </div>
            </div>

            <h3><?php esc_html('Checkout Customization', 'attributes-user-access-pro-lite'); ?></h3>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html('Custom Fields', 'attributes-user-access-pro-lite'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="attrua_pro_surecart_settings[add_custom_fields]" value="1" <?php checked(!empty($settings['add_custom_fields'])); ?> />
                            <?php esc_html('Add custom fields to SureCart checkout', 'attributes-user-access-pro-lite'); ?>
                        </label>
                        <p class="description">
                            <?php esc_html('When enabled, custom fields will be added to the SureCart checkout form.', 'attributes-user-access-pro-lite'); ?>
                        </p>
                    </td>
                </tr>
            </table>

            <div id="attrua-custom-fields-section" style="<?php echo empty($settings['add_custom_fields']) ? 'display: none;' : ''; ?>">
                <div class="attrua-custom-fields">
                    <table class="widefat striped">
                        <thead>
                            <tr>
                                <th><?php esc_html('Field ID', 'attributes-user-access-pro-lite'); ?></th>
                                <th><?php esc_html('Label', 'attributes-user-access-pro-lite'); ?></th>
                                <th><?php esc_html('Type', 'attributes-user-access-pro-lite'); ?></th>
                                <th><?php esc_html('Required', 'attributes-user-access-pro-lite'); ?></th>
                                <th><?php esc_html('Actions', 'attributes-user-access-pro-lite'); ?></th>
                            </tr>
                        </thead>
                        <tbody id="attrua-custom-fields">
                            <?php
                            $custom_fields = $settings['custom_fields'] ?? [];
                            foreach ($custom_fields as $index => $field):
                            ?>
                                <tr class="attrua-custom-field-row">
                                    <td>
                                        <input type="text" name="attrua_pro_surecart_settings[custom_fields][<?php echo esc_attr($index); ?>][id]" value="<?php echo esc_attr($field['id'] ?? ''); ?>" class="regular-text" />
                                    </td>
                                    <td>
                                        <input type="text" name="attrua_pro_surecart_settings[custom_fields][<?php echo esc_attr($index); ?>][label]" value="<?php echo esc_attr($field['label'] ?? ''); ?>" class="regular-text" />
                                    </td>
                                    <td>
                                        <select name="attrua_pro_surecart_settings[custom_fields][<?php echo esc_attr($index); ?>][type]">
                                            <option value="text" <?php selected($field['type'] ?? 'text', 'text'); ?>><?php esc_html('Text', 'attributes-user-access-pro-lite'); ?></option>
                                            <option value="textarea" <?php selected($field['type'] ?? 'text', 'textarea'); ?>><?php esc_html('Textarea', 'attributes-user-access-pro-lite'); ?></option>
                                            <option value="select" <?php selected($field['type'] ?? 'text', 'select'); ?>><?php esc_html('Select', 'attributes-user-access-pro-lite'); ?></option>
                                            <option value="checkbox" <?php selected($field['type'] ?? 'text', 'checkbox'); ?>><?php esc_html('Checkbox', 'attributes-user-access-pro-lite'); ?></option>
                                        </select>
                                    </td>
                                    <td>
                                        <input type="checkbox" name="attrua_pro_surecart_settings[custom_fields][<?php echo esc_attr($index); ?>][required]" value="1" <?php checked(!empty($field['required'])); ?> />
                                    </td>
                                    <td>
                                        <button type="button" class="button attrua-remove-custom-field">
                                            <?php esc_html('Remove', 'attributes-user-access-pro-lite'); ?>
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>

                    <div class="attrua-add-custom-field">
                        <button type="button" class="button" id="attrua-add-custom-field">
                            <?php esc_html('Add Custom Field', 'attributes-user-access-pro-lite'); ?>
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <?php submit_button(__('Save Integration Settings', 'attributes-user-access-pro-lite')); ?>
    </form>
</div>

<script>
    jQuery(document).ready(function($) {
        // Toggle integration settings
        $('input[name="attrua_pro_surecart_settings[enabled]"]').on('change', function() {
            if ($(this).is(':checked')) {
                $('#attrua-surecart-settings').show();
            } else {
                $('#attrua-surecart-settings').hide();
            }
        });

        // Toggle custom fields section
        $('input[name="attrua_pro_surecart_settings[add_custom_fields]"]').on('change', function() {
            if ($(this).is(':checked')) {
                $('#attrua-custom-fields-section').show();
            } else {
                $('#attrua-custom-fields-section').hide();
            }
        });

        // Add product role mapping
        $('#attrua-add-product-role').on('click', function() {
            const productSelect = $('#attrua-product-select');
            const productId = productSelect.val();

            if (!productId) {
                return;
            }

            const productName = productSelect.find('option:selected').data('name');

            // Check if product already exists
            if ($('.attrua-product-role-row[data-product-id="' + productId + '"]').length) {
                alert('This product is already mapped.');
                return;
            }

            // Create new row
            const index = $('.attrua-product-role-row').length;
            const newRow = `
                <tr class="attrua-product-role-row" data-product-id="${productId}">
                    <td>
                        <input type="hidden" name="attrua_pro_surecart_settings[product_mapping][${productId}][name]" value="${productName}" />
                        ${productName}
                    </td>
                    <td>
                        <select name="attrua_pro_surecart_settings[product_role_mapping][${productId}][]" class="attrua-role-select" multiple>
                            <?php foreach ($all_roles as $role_key => $role_name): ?>
                                <option value="<?php echo esc_attr($role_key); ?>"><?php echo esc_html($role_name); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </td>
                    <td>
                        <button type="button" class="button attrua-remove-product-role">
                            <?php esc_html('Remove', 'attributes-user-access-pro-lite'); ?>
                        </button>
                    </td>
                </tr>
            `;

            $('#attrua-product-role-mappings').append(newRow);

            // Reset select
            productSelect.val('');
        });

        // Remove product role mapping
        $(document).on('click', '.attrua-remove-product-role', function() {
            $(this).closest('.attrua-product-role-row').remove();
        });

        // Add custom field
        $('#attrua-add-custom-field').on('click', function() {
            const index = $('.attrua-custom-field-row').length;
            const newRow = `
                <tr class="attrua-custom-field-row">
                    <td>
                        <input type="text" name="attrua_pro_surecart_settings[custom_fields][${index}][id]" class="regular-text" />
                    </td>
                    <td>
                        <input type="text" name="attrua_pro_surecart_settings[custom_fields][${index}][label]" class="regular-text" />
                    </td>
                    <td>
                        <select name="attrua_pro_surecart_settings[custom_fields][${index}][type]">
                            <option value="text"><?php esc_html('Text', 'attributes-user-access-pro-lite'); ?></option>
                            <option value="textarea"><?php esc_html('Textarea', 'attributes-user-access-pro-lite'); ?></option>
                            <option value="select"><?php esc_html('Select', 'attributes-user-access-pro-lite'); ?></option>
                            <option value="checkbox"><?php esc_html('Checkbox', 'attributes-user-access-pro-lite'); ?></option>
                        </select>
                    </td>
                    <td>
                        <input type="checkbox" name="attrua_pro_surecart_settings[custom_fields][${index}][required]" value="1" />
                    </td>
                    <td>
                        <button type="button" class="button attrua-remove-custom-field">
                            <?php esc_html('Remove', 'attributes-user-access-pro-lite'); ?>
                        </button>
                    </td>
                </tr>
            `;

            $('#attrua-custom-fields').append(newRow);
        });

        // Remove custom field
        $(document).on('click', '.attrua-remove-custom-field', function() {
            $(this).closest('.attrua-custom-field-row').remove();
        });
    });
</script>

<style>
    .attrua-product-role-mapping {
        margin: 20px 0;
    }

    .attrua-add-product-role-mapping {
        margin-top: 15px;
        display: flex;
        gap: 10px;
    }

    .attrua-add-product-role-mapping select {
        min-width: 250px;
    }

    .attrua-role-select {
        min-width: 250px;
        min-height: 100px;
    }

    .attrua-custom-fields {
        margin: 20px 0;
    }

    .attrua-add-custom-field {
        margin-top: 15px;
    }

    .attrua-section-header .notice {
        margin: 10px 0;
    }
</style>