<?php
namespace Attributes\Pro\Core;

/**
 * Assets Manager for Pro Version
 * 
 * Manages loading of CSS and JavaScript assets for both admin 
 * and frontend contexts with proper dependencies and conditions.
 */
class Assets_pro {
    /**
     * Plugin URL for asset paths
     * 
     * @var string
     */
    private string $plugin_url;
    
    /**
     * Plugin version for cache busting
     * 
     * @var string 
     */
    private string $version;

    /**
     * Constructor
     */
    public function __construct() {
        $this->plugin_url = ATTRUA_PRO_URL;
        $this->version = ATTRUA_PRO_VERSION;
        
        $this->attrua_init_hooks();
    }
    
    /**
     * Initialize WordPress hooks
     */
    private function attrua_init_hooks(): void {
        // Admin assets
        add_action('admin_enqueue_scripts', [$this, 'attrua_register_admin_assets']);
        add_action('admin_enqueue_scripts', [$this, 'attrua_enqueue_admin_assets']);
        
        // Frontend assets
        add_action('wp_enqueue_scripts', [$this, 'attrua_register_frontend_assets']);
        add_action('wp_enqueue_scripts', [$this, 'attrua_enqueue_frontend_assets']);
    }
    
    /**
     * Register admin assets
     */
    public function attrua_register_admin_assets(): void {
        wp_register_style(
            'attrua-admin-pro-css',
            $this->plugin_url . 'assets/css/admin-pro.css',
            ['attrua-admin-css'], // Depends on core plugin admin CSS
            $this->version
        );
        
        wp_register_script(
            'attrua-admin-pro-js',
            $this->plugin_url . 'assets/js/admin-pro.js',
            ['jquery', 'attrua-admin-js'], // Dependencies
            $this->version,
            true // Load in footer
        );
    }
    
    /**
     * Enqueue admin assets
     * 
     * @param string $hook Current admin page hook
     */
    public function attrua_enqueue_admin_assets(string $hook): void {
        // Only load on plugin admin pages
        if (!$this->attrua_is_plugin_admin_page($hook)) {
            return;
        }
        
        wp_enqueue_style('attrua-admin-pro-css');
        wp_enqueue_script('attrua-admin-pro-js');
        
        // Load tab-specific assets
        $this->attrua_load_tab_specific_assets();
    }
    
    /**
     * Register frontend assets
     */
    public function attrua_register_frontend_assets(): void {
        wp_register_style(
            'attrua-front-pro-css',
            $this->plugin_url . 'assets/css/front-pro.css',
            ['attrua-front-css'], // Depends on core plugin frontend CSS
            $this->version
        );
        
        wp_register_script(
            'attrua-front-pro-js',
            $this->plugin_url . 'assets/js/front-pro.js',
            ['jquery', 'attrua-front-js'], // Dependencies
            $this->version,
            true // Load in footer
        );
    }
    
    /**
     * Enqueue frontend assets
     */
    public function attrua_enqueue_frontend_assets(): void {
        // Only load on pages with plugin shortcodes or features
        if (!$this->attrua_should_load_frontend_assets()) {
            return;
        }
        
        wp_enqueue_style('attrua-front-pro-css');
        wp_enqueue_script('attrua-front-pro-js');
    }
    
    /**
     * Load tab-specific admin assets
     */
    private function attrua_load_tab_specific_assets(): void {
        $current_tab = $_GET['tab'] ?? 'general';
        
        // Tab-specific CSS files
        $tab_css_files = [
            'license' => 'license-admin.css',
            'security' => 'security-admin.css',
            'passwords' => 'password-policy-admin.css',
            'emails' => 'email-admin.css',
            'integration' => 'integration-admin.css'
        ];
        
        // Tab-specific JS files
        $tab_js_files = [
            'license' => 'license-admin.js',
            'security' => 'security-admin.js',
            'passwords' => 'password-policy-admin.js',
            'emails' => 'email-admin.js',
            'integration' => 'integration-admin.js'
        ];
        
        // Enqueue tab-specific CSS if it exists
        if (isset($tab_css_files[$current_tab])) {
            $css_file = $tab_css_files[$current_tab];
            $css_path = $this->plugin_url . 'assets/css/' . $css_file;
            
            if (file_exists(ATTRUA_PRO_PATH . 'assets/css/' . $css_file)) {
                wp_enqueue_style(
                    'attrua-' . $current_tab . '-css',
                    $css_path,
                    ['attrua-admin-pro-css'],
                    $this->version
                );
            }
        }
        
        // Enqueue tab-specific JS if it exists
        if (isset($tab_js_files[$current_tab])) {
            $js_file = $tab_js_files[$current_tab];
            $js_path = $this->plugin_url . 'assets/js/' . $js_file;
            
            if (file_exists(ATTRUA_PRO_PATH . 'assets/js/' . $js_file)) {
                wp_enqueue_script(
                    'attrua-' . $current_tab . '-js',
                    $js_path,
                    ['attrua-admin-pro-js'],
                    $this->version,
                    true
                );
            }
        }
    }
    
    /**
     * Check if current page is a plugin admin page
     * 
     * @param string $hook Current admin page hook
     * @return bool Whether current page is a plugin admin page
     */
    private function attrua_is_plugin_admin_page(string $hook): bool {
        $plugin_pages = [
            'settings_page_attributes-user-access',
            'toplevel_page_attributes-user-access',
            'attributes_page_attributes-user-access'
        ];
        
        return in_array($hook, $plugin_pages);
    }
    
    /**
     * Determine if frontend assets should be loaded
     * 
     * @return bool Whether frontend assets should be loaded
     */
    private function attrua_should_load_frontend_assets(): bool {
        // Check if any plugin shortcodes are present in content
        global $post;
        
        if (is_a($post, 'WP_Post')) {
            $shortcodes = [
                'attributes_login_form',
                'attributes_register_form',
                'attributes_reset_form',
                'attributes_account_form'
            ];
            
            foreach ($shortcodes as $shortcode) {
                if (has_shortcode($post->post_content, $shortcode)) {
                    return true;
                }
            }
        }
        
        // Check if on plugin custom pages
        $plugin_pages = get_option('attrua_pro_pages_options', []);
        foreach ($plugin_pages as $page_id) {
            if (is_page($page_id)) {
                return true;
            }
        }
        
        // Allow other components to determine if assets should load
        return apply_filters('attrua_pro_load_frontend_assets', false);
    }
}