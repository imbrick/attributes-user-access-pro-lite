<?php

/**
 * Pro Plugin Bootstrap Class
 *
 * Initializes and coordinates all Pro functionality. This class serves as the central
 * orchestration point for Pro features and ensures proper integration with the core plugin.
 * The class follows a modular architecture with dependency injection to maintain clean
 * separation of concerns and enable extensibility.
 *
 * @package Attributes\Pro
 * @since 1.0.0
 */

namespace Attributes\Pro;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Main Attributes Pro Class
 *
 * Bootstraps and coordinates all Pro functionality, ensuring proper initialization order
 * and compatibility with the core plugin. This class implements a facade pattern to
 * provide a clean API for interacting with Pro features.
 */
class Attributes_Pro
{
    /**
     * Singleton instance
     *
     * @var Attributes_Pro|null
     */
    private static ?Attributes_Pro $instance = null;

    /**
     * Components registry
     *
     * Stores instances of initialized feature components for dependency management
     * and service location.
     *
     * @var array<string, object>
     */
    private array $components = [];

    /**
     * Get singleton instance
     *
     * Implements the singleton pattern to ensure only one instance of the Pro functionality
     * exists throughout the application lifecycle.
     *
     * @return self Plugin instance
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
     *
     * Performs initial setup and bootstrapping of Pro functionality. Designed to be
     * called only once through the singleton pattern.
     */
    private function __construct()
    {
        $this->define_constants();
        $this->check_requirements();
        $this->include_dependencies();
        $this->init_hooks();
    }

    /**
     * Define Pro-specific constants
     *
     * Establishes constants used throughout the Pro plugin for consistency and
     * maintainability.
     */
    private function define_constants(): void
    {
        if (!defined('ATTRUA_PRO_VERSION')) {
            define('ATTRUA_PRO_VERSION', '1.0.0');
        }

        if (!defined('ATTRUA_PRO_FILE')) {
            define('ATTRUA_PRO_FILE', ATTRUA_PRO_PATH . 'attributes-user-access-pro-lite.php');
        }

        if (!defined('ATTRUA_PRO_BASENAME')) {
            define('ATTRUA_PRO_BASENAME', plugin_basename(ATTRUA_PRO_FILE));
        }

        if (!defined('ATTRUA_PRO_ASSETS_URL')) {
            define('ATTRUA_PRO_ASSETS_URL', ATTRUA_PRO_URL . 'assets/');
        }
    }

    /**
     * Check plugin requirements
     *
     * Verifies that all dependencies and system requirements are met before
     * initializing Pro functionality.
     */
    private function check_requirements(): void
    {
        // Check if free version is active and compatible
        if (!$this->is_free_version_active()) {
            add_action('admin_notices', [$this, 'display_free_version_notice']);
            return;
        }

        // Check PHP version
        if (version_compare(PHP_VERSION, '7.4', '<')) {
            add_action('admin_notices', [$this, 'display_php_version_notice']);
            return;
        }
    }

    /**
     * Include required files
     *
     * Loads necessary dependency files for Pro functionality using autoloading
     * when possible, with fallbacks for files that need explicit inclusion.
     */
    private function include_dependencies(): void
    {
        // Initialize components
        $this->load_component('license', '\Attributes\Pro\License\License_Manager', 'License_Manager');
    }

    /**
     * Initialize WordPress hooks
     *
     * Sets up all WordPress action and filter hooks for integration with
     * the core plugin and WordPress functionality.
     */
    private function init_hooks(): void
    {
        // Register with core plugin's extension system
        add_action('attrua_register_extensions', [$this, 'register_as_extension']);

        // Initialize Pro when core plugin is loaded
        add_action('attrua_loaded', [$this, 'initialize']);

        // Load textdomain for translations
        add_action('plugins_loaded', [$this, 'load_textdomain']);

        // Plugin activation/deactivation hooks
        register_activation_hook(ATTRUA_PRO_FILE, [$this, 'activate']);
        register_deactivation_hook(ATTRUA_PRO_FILE, [$this, 'deactivate']);
    }

    /**
     * Initialize Pro functionality
     *
     * Called after core plugin is loaded to ensure proper integration.
     * Initializes all Pro components in the correct sequence.
     */
    public function initialize(): void
    {
        // Only proceed if requirements are met
        if (!$this->is_free_version_active()) {
            return;
        }

        // Set up filter to indicate premium features are available
        add_filter('attributes_has_premium_features', '__return_true');

        // Initialize Pro components if license is active
        if ($this->is_license_active()) {
            // Add Pro tabs to admin interface
            add_filter('attrua_admin_tabs', [$this, 'add_admin_tabs']);

            // Load security features
            $this->load_component('two_factor', '\Attributes\Pro\Security\TwoFactor', 'Security/TwoFactor');
            $this->load_component('password_policy', '\Attributes\Pro\Security\Password_Policy', 'Security/Password_Policy');
            $this->load_component('recaptcha', '\Attributes\Pro\Security\Recaptcha', 'Security/Recaptcha');
            $this->load_component('ip_manager', '\Attributes\Pro\Security\IP_Manager', 'Security/IP_Manager');
            $this->load_component('audit_log', '\Attributes\Pro\Security\Audit_Log', 'Security/Audit_Log');

            // Load front-end features
            $this->load_component('register', '\Attributes\Pro\Front\Register', 'Front/Register');
            $this->load_component('lost_password', '\Attributes\Pro\Front\Lost', 'Front/Lost');
            $this->load_component('reset_password', '\Attributes\Pro\Front\Reset', 'Front/Reset');

            // Register custom post types, taxonomies, etc.
            add_action('init', [$this, 'register_custom_types'], 20);
        }

        // Load admin features regardless of license status
        add_action('admin_init', [$this, 'register_pro_settings']);
        add_action('attrua_admin_settings_content', [$this, 'render_license_tab'], 10, 1);
    }

    /**
     * Check if free version is active
     *
     * @return bool True if core plugin is active and compatible
     */
    private function is_free_version_active(): bool
    {
        // Check if core initialization function exists
        if (!function_exists('ATTRUA_init')) {
            return false;
        }

        // Check version compatibility if needed
        // This would check the core plugin version against minimum requirements

        return true;
    }

    /**
     * Check if license is active
     *
     * @return bool Whether Pro license is active
     */
    private function is_license_active(): bool
    {
        if (isset($this->components['license'])) {
            return $this->components['license']->is_active();
        }

        return false;
    }

    /**
     * Register Pro as an extension with the core plugin
     *
     * @param object $extension_manager Extension manager instance
     */
    public function register_as_extension($extension_manager): void
    {
        if (!$extension_manager->attrua_has('pro')) {
            $extension_manager->attrua_register('pro', [
                'name' => 'Attributes User Access Pro',
                'version' => ATTRUA_PRO_VERSION,
                'description' => 'Premium features for enhanced user authentication and security',
                'author' => 'Attributes WP',
                'url' => 'https://attributeswp.com/pro',
                'requires' => [
                    'php' => '7.4',
                    'wp' => '5.8',
                    'core' => '1.0.0'
                ]
            ]);
        }
    }

    /**
     * Add Pro tabs to admin interface
     *
     * @param array $tabs Existing tabs
     * @return array Modified tabs with Pro options
     */
    public function add_admin_tabs(array $tabs): array
    {
        // Add license tab first
        $tabs = array_merge(['license' => __('License', 'attributes-user-access-pro-lite')], $tabs);

        // Add premium tabs
        $tabs['pages'] = __('Pages', 'attributes-user-access-pro-lite');
        $tabs['security'] = __('Security', 'attributes-user-access-pro-lite');
        $tabs['passwords'] = __('Password Policy', 'attributes-user-access-pro-lite');
        $tabs['emails'] = __('Notifications', 'attributes-user-access-pro-lite');

        return $tabs;
    }

    /**
     * Render license tab
     *
     * @param bool $has_premium_features Whether premium features are available
     */
    public function render_license_tab(bool $has_premium_features): void
    {
        // Only render if we're on the license tab
        if (!isset($_GET['tab']) || $_GET['tab'] !== 'license') {
            return;
        }

        // Get license data
        $license_manager = $this->get_component('license');
        if (!$license_manager) {
            return;
        }

        $license_data = $license_manager->get_license_data();
        $license_key = get_option('attrua_pro_license_key', '');
        $is_active = $license_manager->is_active();

        // Include license tab template
        require_once ATTRUA_PRO_PATH . 'display/tabs/license-settings-tab.php';
    }

    /**
     * Load component by key
     *
     * Initializes and stores component instances for service location pattern.
     * 
     * @param string $key Component identifier
     * @param string $class Fully qualified class name
     * @param string $file Optional file path for manual loading
     * @return object|null Component instance or null if initialization failed
     */
    private function load_component(string $key, string $class, string $file = ''): ?object
    {
        // Return existing instance if already loaded
        if (isset($this->components[$key])) {
            return $this->components[$key];
        }

        // If class doesn't exist and file is provided, try to load it
        if (!class_exists($class) && !empty($file)) {
            $file_path = ATTRUA_PRO_PATH . 'src/' . $file . '.php';

            if (file_exists($file_path)) {
                require_once $file_path;
            }
        }

        // Initialize component if class exists
        if (class_exists($class)) {
            // Check for singleton pattern first
            if (method_exists($class, 'instance')) {
                $this->components[$key] = call_user_func([$class, 'instance']);
            } else {
                // Regular instantiation
                $this->components[$key] = new $class();
            }

            return $this->components[$key];
        }

        return null;
    }

    /**
     * Get component instance
     *
     * Retrieves a previously initialized component by key.
     *
     * @param string $key Component identifier
     * @return object|null Component instance or null if not found
     */
    public function get_component(string $key)
    {
        return $this->components[$key] ?? null;
    }

    /**
     * Register custom post types, taxonomies, etc.
     */
    public function register_custom_types(): void
    {
        // Register any Pro-specific custom post types or taxonomies here
        // Example: register_post_type(), register_taxonomy()
    }

    /**
     * Register Pro settings
     */
    public function register_pro_settings(): void
    {
        // Register any Pro-specific settings not handled by components
    }

    /**
     * Load plugin textdomain
     */
    public function load_textdomain(): void
    {
        load_plugin_textdomain(
            'attributes-user-access-pro-lite',
            false,
            dirname(ATTRUA_PRO_BASENAME) . '/languages'
        );
    }

    /**
     * Plugin activation hook
     */
    public function activate(): void
    {
        // Perform activation tasks

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Plugin deactivation hook
     */
    public function deactivate(): void
    {
        // Perform deactivation tasks

        // Flush rewrite rules
        flush_rewrite_rules();

        // Clean up any scheduled events
        wp_clear_scheduled_hook('attrua_pro_daily_tasks');
    }

    /**
     * Display notice when free version is not active
     */
    public function display_free_version_notice(): void
    {
?>
        <div class="notice notice-error">
            <p><?php _e('Attributes User Access Pro requires the free Attributes User Access plugin to be installed and activated.', 'attributes-user-access-pro-lite'); ?></p>
        </div>
    <?php
    }

    /**
     * Display notice when PHP version is insufficient
     */
    public function display_php_version_notice(): void
    {
    ?>
        <div class="notice notice-error">
            <p><?php _e('Attributes User Access Pro requires PHP 7.4 or higher.', 'attributes-user-access-pro-lite'); ?></p>
        </div>
<?php
    }

    /**
     * Prevent cloning
     */
    private function __clone()
    {
        // Prevent cloning of singleton
    }

    /**
     * Prevent unserializing
     */
    public function __wakeup()
    {
        throw new \RuntimeException('Cannot unserialize singleton');
    }
}
