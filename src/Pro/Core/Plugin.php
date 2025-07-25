<?php

namespace Attributes\Pro\Core;

use Attributes\Pro\Core\Constants;
use Attributes\Pro\License\API\Client;
use Attributes\Pro\License\Cache;
use Attributes\Pro\License\Validator;
use Attributes\Pro\License\Manager;

/**
 * Main plugin class responsible for initializing all components.
 */
class Plugin
{
    /**
     * Singleton instance
     *
     * @var Plugin|null
     */
    private static ?Plugin $instance = null;

    /**
     * License Manager instance
     *
     * @var Manager
     */
    private Manager $license_manager;
    /**
     * SureCart API auth token
     *
     * @var string
     */
    private string $auth_token;

    /**
     * Plugin slug
     *
     * @var string
     */
    private string $plugin_slug;

    /**
     * Get singleton instance
     *
     * @return Plugin
     */
    public static function instance(): self
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Private constructor to enforce singleton pattern
     */
    private function __construct()
    {
        error_log('ATTRUA Pro: Initializing plugin');

        // Initialize License Manager
        $this->attrua_init_license_manager();
    }

    /**
     * Initialize the License Manager
     */
    private function attrua_init_license_manager(): void
    {
        // Initialize properties
        $this->auth_token = defined('ATTRUA_LICENSE_TOKEN') ? ATTRUA_LICENSE_TOKEN : Constants::LICENSE_TOKEN;
        $this->plugin_slug = 'attributes-user-access-pro-lite';

        // Initialize components
        $api_client = new Client($this->auth_token, $this->plugin_slug);
        $cache = new Cache();
        $validator = new Validator();

        $this->license_manager = new Manager($api_client, $cache, $validator);
    }

    /**
     * Get the License Manager instance
     *
     * @return Manager
     */
    public function get_license_manager(): Manager
    {
        return $this->license_manager;
    }
}
