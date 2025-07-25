<?php

namespace Attributes\License\Admin;

use Attributes\License\Manager;
use Attributes\License\API\Exception;

/**
 * License Admin UI Controller
 * 
 * Manages all admin interface aspects of license management
 * including settings page, forms, and status displays.
 */
class UI
{
    /**
     * License manager instance
     * 
     * @var Manager
     */
    private Manager $license_manager;

    /**
     * Admin settings page slug
     * 
     * @var string
     */
    private string $page_slug = 'attributes-user-access';

    /**
     * Settings tab
     * 
     * @var string
     */
    private string $tab = 'license';

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->license_manager = Manager::instance();
        $this->init_hooks();
    }

    /**
     * Initialize WordPress hooks
     */
    private function init_hooks(): void
    {
        // Register settings page
        add_action('admin_menu', [$this, 'register_settings_page']);

        // Register settings
        add_action('admin_init', [$this, 'register_settings']);

        // Add settings link to plugins page
        add_filter('plugin_action_links_' . ATTRUA_PRO_BASENAME, [$this, 'add_settings_link']);

        // Render admin notices
        add_action('admin_notices', [$this, 'display_admin_notices']);

        // Handle form submissions
        add_action('admin_post_attrua_activate_license', [$this, 'handle_activate_license']);
        add_action('admin_post_attrua_deactivate_license', [$this, 'handle_deactivate_license']);
    }

    /**
     * Register settings page
     */
    public function register_settings_page(): void
    {
        // License settings are added to the existing settings page
        // No need to register a new page
    }

    /**
     * Register license settings
     */
    public function register_settings(): void
    {
        register_setting(
            'attrua_license_settings',
            'attrua_pro_license_key',
            [
                'type' => 'string',
                'sanitize_callback' => 'sanitize_text_field',
                'default' => ''
            ]
        );
    }

    /**
     * Add settings link to plugins page
     * 
     * @param array $links Existing links
     * @return array Modified links
     */
    public function add_settings_link(array $links): array
    {
        $settings_url = admin_url("admin.php?page={$this->page_slug}&tab={$this->tab}");
        $settings_link = '<a href="' . esc_url($settings_url) . '">' . __('License', 'attributes-user-access-pro-lite') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    /**
     * Display license settings page
     */
    public function display_settings_page(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $license_data = $this->license_manager->get_license_data();
        $is_active = $this->license_manager->is_active();
        $license_key = $this->license_manager->get_sanitized_key();

        include ATTRUA_PRO_PATH . 'templates/admin/license/settings-page.php';
    }

    /**
     * Handle license activation form submission
     */
    public function handle_activate_license(): void
    {
        // Verify permissions
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'attributes-user-access-pro-lite'));
        }

        // Verify nonce
        check_admin_referer('attrua_license_action', 'attrua_license_nonce');

        // Get license key
        $license_key = isset($_POST['license_key']) ? sanitize_text_field($_POST['license_key']) : '';

        if (empty($license_key)) {
            wp_redirect(add_query_arg(
                ['page' => $this->page_slug, 'tab' => $this->tab, 'error' => 'empty_key'],
                admin_url('admin.php')
            ));
            exit;
        }

        try {
            // Activate license
            $this->license_manager->activate($license_key);

            // Redirect with success message
            wp_redirect(add_query_arg(
                ['page' => $this->page_slug, 'tab' => $this->tab, 'activated' => 'true'],
                admin_url('admin.php')
            ));
        } catch (Exception $e) {
            // Redirect with error message
            wp_redirect(add_query_arg(
                [
                    'page' => $this->page_slug,
                    'tab' => $this->tab,
                    'error' => 'activation_failed',
                    'message' => urlencode($e->get_user_message())
                ],
                admin_url('admin.php')
            ));
        }

        exit;
    }

    /**
     * Handle license deactivation form submission
     */
    public function handle_deactivate_license(): void
    {
        // Verify permissions
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'attributes-user-access-pro-lite'));
        }

        // Verify nonce
        check_admin_referer('attrua_license_action', 'attrua_license_nonce');

        try {
            // Deactivate license
            $this->license_manager->deactivate();

            // Redirect with success message
            wp_redirect(add_query_arg(
                ['page' => $this->page_slug, 'tab' => $this->tab, 'deactivated' => 'true'],
                admin_url('admin.php')
            ));
        } catch (Exception $e) {
            // Redirect with error message
            wp_redirect(add_query_arg(
                [
                    'page' => $this->page_slug,
                    'tab' => $this->tab,
                    'error' => 'deactivation_failed',
                    'message' => urlencode($e->get_user_message())
                ],
                admin_url('admin.php')
            ));
        }

        exit;
    }

    /**
     * Display admin notices
     */
    public function display_admin_notices(): void
    {
        $screen = get_current_screen();

        // Only show notices on our settings page
        if (!$screen || $screen->base !== 'attributes_page_' . $this->page_slug) {
            return;
        }

        // Only show notices on our tab
        if (!isset($_GET['tab']) || $_GET['tab'] !== $this->tab) {
            return;
        }

        // Display success notices
        if (isset($_GET['activated']) && $_GET['activated'] === 'true') {
            $this->render_notice(
                'success',
                __('License activated successfully.', 'attributes-user-access-pro-lite')
            );
        }

        if (isset($_GET['deactivated']) && $_GET['deactivated'] === 'true') {
            $this->render_notice(
                'success',
                __('License deactivated successfully.', 'attributes-user-access-pro-lite')
            );
        }

        // Display error notices
        if (isset($_GET['error'])) {
            $error = sanitize_text_field($_GET['error']);
            $message = isset($_GET['message']) ? urldecode($_GET['message']) : '';

            switch ($error) {
                case 'empty_key':
                    $error_message = __('Please enter a license key.', 'attributes-user-access-pro-lite');
                    break;

                case 'activation_failed':
                    $error_message = __('License activation failed.', 'attributes-user-access-pro-lite');
                    break;

                case 'deactivation_failed':
                    $error_message = __('License deactivation failed.', 'attributes-user-access-pro-lite');
                    break;

                default:
                    $error_message = __('An error occurred with your license.', 'attributes-user-access-pro-lite');
            }

            if (!empty($message)) {
                $error_message .= ' ' . $message;
            }

            $this->render_notice('error', $error_message);
        }

        // Display expiration warning if license is active but expiring soon
        $license_data = $this->license_manager->get_license_data();
        if ($license_data && $license_data->is_active()) {
            $validator = new \Attributes\License\Validator();

            if (
                isset($license_data->get_raw_data()['expires_at']) &&
                $validator->is_expiring_soon($license_data->get_raw_data()['expires_at'])
            ) {

                $this->render_notice(
                    'warning',
                    sprintf(
                        __('Your license will expire on %s. Please renew your license to continue receiving updates and support.', 'attributes-user-access-pro-lite'),
                        $license_data->get_expires()
                    )
                );
            }
        }
    }

    /**
     * Render admin notice
     * 
     * @param string $type Notice type (success, error, warning, info)
     * @param string $message Notice message
     */
    private function render_notice(string $type, string $message): void
    {
?>
        <div class="notice notice-<?php echo esc_attr($type); ?> is-dismissible">
            <p><?php echo esc_html($message); ?></p>
        </div>
<?php
    }
}
