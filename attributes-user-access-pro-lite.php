<?php

/**
 * Plugin Name: Attributes User Access Pro
 * Plugin URI: https://attributeswp.com/pro
 * Description: Premium extension for Attributes User Access adding advanced security, social login, and form customization
 * Version: 1.0.0
 * Author: Attributes WP
 * Author URI: https://attributeswp.com/
 * Text Domain: attributes-user-access-pro-lite
 * Domain Path: /languages
 * Requires PHP: 7.4
 * Requires at least: 5.8
 * License: GPLv3 or later
 */

if (!defined('ABSPATH')) {
    exit;
}

// Define Pro plugin constants
define('ATTRUA_PRO_VERSION', '1.0.0');
define('ATTRUA_PRO_FILE', __FILE__);
define('ATTRUA_PRO_PATH', plugin_dir_path(__FILE__));
define('ATTRUA_PRO_URL', plugin_dir_url(__FILE__));
define('ATTRUA_PRO_BASENAME', plugin_basename(__FILE__));

/**
 * Check if the Lite plugin is active and available
 * 
 * @return bool Whether the lite version is active
 */
function attrua_pro_is_lite_active()
{
    // Check for core initialization function
    if (function_exists('ATTRUA_init')) {
        return true;
    }

    // Check for core plugin class as a fallback
    if (class_exists('\\Attributes\\Core\\Plugin')) {
        return true;
    }

    // Log this check for debugging
    error_log('ATTRUA Lite plugin is NOT detected');

    return false;
}

/**
 * Show admin notice if Lite plugin is not active
 */
function attrua_pro_admin_notice()
{
?>
    <div class="notice notice-error">
        <p><?php _e('Attributes User Access Pro requires the free Attributes User Access plugin to be installed and activated.', 'attributes-user-access-pro-lite'); ?></p>
        <p><a href="<?php echo esc_url(admin_url('plugin-install.php?tab=search&s=attributes-user-access')); ?>" class="button button-primary"><?php _e('Install Lite Version', 'attributes-user-access-pro-lite'); ?></a></p>
    </div>
<?php
}

/**
 * Initialize the Pro plugin
 * 
 * @return \Attributes\Pro\Pro|null Plugin instance or null if requirements not met
 */
function ATTRUA_PRO_init()
{
    static $instance = null;

    // Test debug logging
    error_log('=== ATTRUA DEBUG: ATTRUA_PRO_init() called ===');

    // Return existing instance if already created
    if ($instance !== null) {
        error_log('=== ATTRUA DEBUG: Returning existing instance ===');
        return $instance;
    }

    // Make sure required files exist before trying to load them
    $constants_file = ATTRUA_PRO_PATH . 'src/Pro/Core/Constants.php';
    $pro_class_file = ATTRUA_PRO_PATH . 'src/Pro/Pro.php';
    $core_plugin_file = ATTRUA_PRO_PATH . 'src/Pro/Core/Plugin.php';
    $license_file = ATTRUA_PRO_PATH . 'src/Pro/License/Manager.php';

    if (!file_exists($constants_file) || !file_exists($pro_class_file) || !file_exists($core_plugin_file) || !file_exists($license_file)) {
        error_log('ATTRUA Pro: Required files missing - Constants.php, Pro.php, Core/Plugin.php or Manager.php');
        error_log('ATTRUA Pro: Looking for Constants.php at: ' . $constants_file);
        error_log('ATTRUA Pro: Looking for Pro.php at: ' . $pro_class_file);
        error_log('ATTRUA Pro: Looking for Core/Plugin.php at: ' . $core_plugin_file);
        error_log('ATTRUA Pro: Looking for Manager.php at: ' . $license_file);
        error_log('ATTRUA Pro: Constants.php exists: ' . (file_exists($constants_file) ? 'Yes' : 'No'));
        error_log('ATTRUA Pro: Pro.php exists: ' . (file_exists($pro_class_file) ? 'Yes' : 'No'));
        error_log('ATTRUA Pro: Core/Plugin.php exists: ' . (file_exists($core_plugin_file) ? 'Yes' : 'No'));
        error_log('ATTRUA Pro: Manager.php exists: ' . (file_exists($license_file) ? 'Yes' : 'No'));
        return null;
    }

    // Load required files in correct order
    require_once $constants_file;    // Load Constants first

    // Load License API classes
    require_once ATTRUA_PRO_PATH . 'src/Pro/License/API/Exception.php';
    require_once ATTRUA_PRO_PATH . 'src/Pro/License/API/Client.php';
    require_once ATTRUA_PRO_PATH . 'src/Pro/License/Cache.php';
    require_once ATTRUA_PRO_PATH . 'src/Pro/License/Data.php';
    require_once ATTRUA_PRO_PATH . 'src/Pro/License/Validator.php';
    require_once ATTRUA_PRO_PATH . 'src/Pro/License/Admin/AJAX.php';

    require_once $core_plugin_file;  // Then Core Plugin 
    require_once $license_file;      // Then License Manager
    require_once $pro_class_file;    // Finally Pro class

    // Check if the required class exists
    if (!class_exists('\\Attributes\\Pro\\Pro')) {
        error_log('ATTRUA Pro: Pro class not found after including file');
        return null;
    }

    // Initialize Pro class
    try {
        $instance = \Attributes\Pro\Pro::instance();
        return $instance;
    } catch (\Exception $e) {
        error_log('ATTRUA Pro: Error initializing Pro class - ' . $e->getMessage());
        return null;
    }
}

/**
 * Register Pro as an extension with the core plugin
 * 
 * @param object $extension_manager Extension manager instance
 */
// Add to attributes-user-access-pro-lite.php temporarily
add_action('attrua_register_extensions', function ($extension_manager) {
    // Do the normal registration
    if (!$extension_manager->attrua_has('pro')) {
        $extension_manager->attrua_register('pro', [
            'name' => 'Attributes User Access Pro',
            'version' => ATTRUA_PRO_VERSION,
            'description' => 'Premium extension adding advanced security and customization',
            'author' => 'Attributes WP',
            'url' => 'https://attributeswp.com/pro',
            'requires' => [
                'php' => '7.4',
                'wp' => '5.8',
                'core' => '1.0.0'
            ]
        ]);
    }

    // Add debug output
    error_log('Pro extension registered: ' . ($extension_manager->attrua_has('pro') ? 'Yes' : 'No'));
}, 10);

// Add to attributes-user-access-pro-lite.php
add_action('attrua_loaded', function () {
    error_log('=== ATTRUA DEBUG: attrua_loaded action fired, initializing PRO ===');
    $pro = ATTRUA_PRO_init();
    error_log('=== ATTRUA DEBUG: PRO initialized: ' . ($pro ? 'Yes' : 'No') . ' ===');
});

/**
 * Main plugin initialization on plugins loaded
 */
function attrua_pro_plugin_init()
{
    // Check if lite version is active
    if (!attrua_pro_is_lite_active()) {
        // Show admin notice if not active
        add_action('admin_notices', 'attrua_pro_admin_notice');
        return;
    }

    // Register extension with core plugin
    add_action('attrua_register_extensions', 'attrua_pro_register_extension', 10);

    // Initialize Pro when core plugin is loaded
    add_action('attrua_loaded', function () {
        ATTRUA_PRO_init();
    });
}

// Initialize plugin
add_action('plugins_loaded', 'attrua_pro_plugin_init', 20);

// Enable this for debugging
/*if (defined('WP_DEBUG') && WP_DEBUG) {
    add_action('plugins_loaded', function() {
        error_log('ATTRUA Pro: Debug information - Plugins loaded hook fired');
        error_log('ATTRUA_init function exists: ' . (function_exists('ATTRUA_init') ? 'Yes' : 'No'));
        error_log('\\Attributes\\Core\\Plugin class exists: ' . (class_exists('\\Attributes\\Core\\Plugin') ? 'Yes' : 'No'));
        
        // Get all active plugins
        $active_plugins = get_option('active_plugins');
        error_log('Active plugins: ' . implode(', ', $active_plugins));
    }, 1);
}*/