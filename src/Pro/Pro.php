<?php

namespace Attributes\Pro;

use Attributes\Pro\Core\Plugin;
use Attributes\Pro\Security\TwoFactor;
use Attributes\Pro\Front\Register;
use Attributes\Pro\Front\Lost;
use Attributes\Pro\Front\Reset;

/**
 * Main Pro plugin class with form handling updates
 */
class Pro
{
    /**
     * Plugin instance
     *
     * @var Pro|null
     */
    private static ?Pro $instance = null;

    /**
     * Plugin instance
     *
     * @var Plugin|null
     */
    private Plugin $plugin;

    /**
     * License Manager instance
     *
     * @var Manager
     */
    private $license;

    /**
     * Components storage
     *
     * @var array
     */
    private array $components = [];

    /**
     * Get plugin instance
     */
    public static function instance(): self
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor
     */
    private function __construct()
    {
        // Initialize the Core Plugin first
        $this->plugin = \Attributes\Pro\Core\Plugin::instance();

        // Now get the license manager which should be initialized
        $this->license = $this->plugin->get_license_manager();

        // Register Assets
        $this->register_assets();

        // Initialize hooks
        $this->attrua_init_hooks();
    }

    /**
     * Register plugin assets
     */
    private function register_assets()
    {
        require_once ATTRUA_PRO_PATH . 'src/Pro/Core/Assets.php';
    }

    /**
     * Initialize hooks
     */
    private function attrua_init_hooks(): void
    {
        // Register admin tabs
        add_action('attrua_admin_tabs', [$this, 'render_admin_tabs']);

        // Filter to indicate premium features are available
        add_filter('attributes_has_premium_features', '__return_true');
        add_filter('attrua_is_premium', [$this, 'is_premium']);

        // Initialize components based on license status
        add_action('init', [$this, 'initialize_components'], 20);

        // Register tab content handlers
        add_action('attrua_tab_content_license', [$this, 'render_license_tab'], 10, 1);
        add_action('attrua_tab_content_security', [$this, 'render_security_tab'], 10, 1);
        add_action('attrua_tab_content_passwords', [$this, 'render_password_policy_tab'], 10, 1);
        add_action('attrua_tab_content_emails', [$this, 'render_emails_tab'], 10, 1);
        add_action('attrua_tab_content_integration', [$this, 'render_integration_tab'], 10, 1);

        // Load textdomain
        add_action('plugins_loaded', [$this, 'attrua_load_textdomain']);
    }

    /**
     * Load textdomain
     */
    public function attrua_load_textdomain(): void
    {
        load_plugin_textdomain(
            'attributes-user-access-pro-lite',
            false,
            dirname(plugin_basename(ATTRUA_PRO_FILE)) . '/languages'
        );
    }

    /**
     * Initialize components
     */
    public function initialize_components(): void
    {
        // Get the License Manager from the Plugin instance
        $license_manager = $this->license;

        // Always initialize license manager
        $this->components['license'] = $license_manager;

        // Initialize premium components only if license is active
        if ($license_manager->is_active()) {
            // Initialize security components
            $this->components['two_factor'] = TwoFactor::instance();

            // Initialize form handling components
            $this->components['register'] = new Register();
            $this->components['lost'] = new Lost();
            $this->components['reset'] = new Reset();

            // Allow extensions to register components
            do_action('attrua_pro_components', $this);
        }
    }

    /**
     * Register admin tabs
     * 
     * Add Pro tabs to the admin interface.
     *
     * @param string $active_tab Currently active tab
     */
    public function render_admin_tabs(string $active_tab): void
    {
        // License tab is always available
        $this->render_tab('license', __('License', 'attributes-user-access-pro-lite'), $active_tab);

        // Only show these tabs if license is active
        if ($this->license->is_active()) {
            $this->render_tab('security', __('Security', 'attributes-user-access-pro-lite'), $active_tab);
            $this->render_tab('passwords', __('Password Policy', 'attributes-user-access-pro-lite'), $active_tab);
            $this->render_tab('emails', __('Notifications', 'attributes-user-access-pro-lite'), $active_tab);
            $this->render_tab('integration', __('Integration', 'attributes-user-access-pro-lite'), $active_tab);
        }
    }

    /**
     * Render individual tab
     * 
     * Create a tab link with active state handling.
     *
     * @param string $tab_id Tab identifier
     * @param string $tab_name Tab display name
     * @param string $active_tab Currently active tab
     */
    private function render_tab(string $tab_id, string $tab_name, string $active_tab): void
    {
        $active_class = $active_tab === $tab_id ? 'nav-tab-active' : '';
        echo '<a href="?page=attributes-user-access&tab=' . esc_attr($tab_id) . '" class="nav-tab ' . esc_attr($active_class) . '">' . esc_html($tab_name) . '</a>';
    }

    /**
     * Check if premium version is active
     *
     * @return bool True if premium features should be enabled
     */
    public function is_premium(): bool
    {
        return $this->license->is_active();
    }

    /**
     * Render tab content
     *
     * @param bool $has_premium_features Whether premium features are active
     */
    public function render_tab_content(bool $has_premium_features): void
    {
        // Only show content for our Pro tabs
        $pro_tabs = ['license', 'security', 'passwords', 'emails', 'integration'];

        if (!in_array($this->active_tab, $pro_tabs)) {
            return;
        }

        // Start our tab content wrapper
        echo '<div class="attrua-pro-tab-content">';

        // Check if license is active, except for license tab
        if (!$has_premium_features && $this->active_tab !== 'license') {
            $this->render_premium_notice();
            echo '</div>'; // Close tab content wrapper
            return;
        }

        // Include the appropriate tab template
        switch ($this->active_tab) {
            case 'license':
                $this->render_license_tab($has_premium_features);
                break;
            case 'security':
                $this->render_security_tab($has_premium_features);
                break;
            case 'passwords':
                $this->render_password_policy_tab($has_premium_features);
                break;
            case 'emails':
                $this->render_emails_tab($has_premium_features);
                break;
            case 'integration':
                $this->render_integration_tab($has_premium_features);
                break;
        }

        // Close tab content wrapper
        echo '</div>';
    }

    /**
     * Render license tab
     *
     * @param bool $has_premium_features Whether premium features are active
     */
    public function render_license_tab(bool $has_premium_features): void
    {
        // Get license data
        $license_data = $this->license->get_license_data();
        $license_key = get_option('attrua_pro_license_key', '');
        $is_active = $this->license->is_active();

        // Include license tab template
        require_once ATTRUA_PRO_PATH . 'display/tabs/license-settings-tab.php';
    }

    /**
     * Render integration tab
     * 
     * Display the integration settings interface.
     *
     * @param bool $has_premium_features Whether premium features are active
     */
    public function render_integration_tab(bool $has_premium_features): void
    {
        // Check if premium features are active
        if (!$has_premium_features) {
            $this->render_premium_notice();
            return;
        }

        // Check if SureCart is active
        $surecart_active = $this->is_surecart_active();

        // Get settings
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

        // Include integration tab template
        require_once ATTRUA_PRO_PATH . 'display/tabs/integration-settings-tab.php';
    }

    /**
     * Render pages tab
     *
     * @param bool $has_premium_features Whether premium features are active
     */
    private function render_pages_tab(bool $has_premium_features): void
    {
        // Include pages tab template
        require_once ATTRUA_PRO_PATH . 'display/tabs/pages-settings-tab.php';
    }

    /**
     * Render security tab
     *
     * @param bool $has_premium_features Whether premium features are active
     */
    private function render_security_tab(bool $has_premium_features): void
    {
        // Get settings
        $settings = get_option('attrua_pro_security_settings', []);
        $two_factor_settings = get_option('attrua_pro_2fa_settings', []);
        $recaptcha_settings = get_option('attrua_pro_recaptcha_settings', []);

        // Include security tab template
        require_once ATTRUA_PRO_PATH . 'display/tabs/security-settings-tab.php';
    }

    /**
     * Render password policy tab
     *
     * @param bool $has_premium_features Whether premium features are active
     */
    private function render_password_policy_tab(bool $has_premium_features): void
    {
        // Get settings
        $settings = get_option('attrua_pro_password_policy', []);

        // Include password policy tab template
        require_once ATTRUA_PRO_PATH . 'display/tabs/password-policy-tab.php';
    }

    /**
     * Render emails tab
     *
     * @param bool $has_premium_features Whether premium features are active
     */
    private function render_emails_tab(bool $has_premium_features): void
    {
        // Get settings
        $settings = get_option('attrua_pro_email_settings', []);

        // Include emails tab template
        require_once ATTRUA_PRO_PATH . 'display/tabs/emails-settings-tab.php';
    }

    /**
     * Render premium features notice
     */
    private function render_premium_notice(): void
    {
?>
        <div class="notice notice-warning">
            <p>
                <strong><?php esc_html('Premium Feature', 'attributes-user-access-pro-lite'); ?></strong>
                <?php esc_html('Please activate your license to access this feature.', 'attributes-user-access-pro-lite'); ?>
                <a href="?page=attributes-user-access&tab=license"><?php esc_html('Activate License', 'attributes-user-access-pro-lite'); ?></a>
            </p>
        </div>
<?php
    }

    /**
     * Get component instance
     *
     * @param string $key Component identifier
     * @return mixed|null Component instance or null if not found
     */
    public function component(string $key)
    {
        return $this->components[$key] ?? null;
    }

    /**
     * Prevent cloning
     */
    private function __clone() {}

    /**
     * Prevent unserializing
     */
    public function __wakeup()
    {
        throw new \RuntimeException('Cannot unserialize singleton');
    }
}
