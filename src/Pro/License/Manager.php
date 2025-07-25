<?php

namespace Attributes\Pro\License;

use Attributes\Pro\Core\Constants;
use Attributes\Pro\License\Admin\AJAX;
use Attributes\Pro\License\API\Client;
use Attributes\Pro\License\API\Exception;


/**
 * License Manager
 * 
 * Implements core business logic for license activation, deactivation,
 * and status verification. Maintains license state and coordinates 
 * between API, cache, and data layers.
 */
class Manager
{
    /**
     * API client instance
     * 
     * @var AJAX
     */
    private ?AJAX $ajax = null;

    /**
     * API client instance
     * 
     * @var Client
     */
    private Client $api_client;

    /**
     * License cache handler
     * 
     * @var Cache
     */
    private Cache $cache;

    /**
     * License validator
     * 
     * @var Validator
     */
    private Validator $validator;

    /**
     * License data object
     * 
     * @var Data|null
     */
    private ?Data $license_data = null;

    /**
     * Constructor
     *
     * @param Client $api_client API client instance
     * @param Cache $cache License cache handler
     * @param Validator $validator License validator
     */
    public function __construct(Client $api_client, Cache $cache, Validator $validator)
    {
        $this->api_client = $api_client;
        $this->cache = $cache;
        $this->validator = $validator;

        // Initialize AJAX handlers
        $this->get_ajax();

        // Load license state
        $this->load_license_state();
    }

    /**
     * Get the AJAX handler instance
     * 
     * @return AJAX
     */
    public function get_ajax(): AJAX
    {
        if ($this->ajax === null) {
            $this->ajax = new AJAX($this);
        }

        return $this->ajax;
    }

    /**
     * Load license state from storage
     */
    private function load_license_state(): void
    {
        // Try to load from cache first
        $cached_data = $this->cache->get_license_data();

        if ($cached_data) {
            $this->license_data = $cached_data;
            return;
        }

        // Fall back to database if cache is empty
        $license_key = get_option('attrua_pro_license_key', '');
        $license_data = get_option('attrua_pro_license_data', []);

        if (!empty($license_data)) {
            // Convert stdClass to array if needed
            if (is_object($license_data)) {
                $license_data = (array) $license_data;
            }

            $this->license_data = new Data($license_data);

            // Refresh cache
            $this->cache->set_license_data($this->license_data);
        }

        // Verify license if we have a key but verification is due
        if (!empty($license_key) && $this->should_verify($license_key)) {
            try {
                $this->verify_license($license_key);
            } catch (Exception $e) {
                // Log error but don't disrupt plugin loading
                error_log('License verification error: ' . $e->getMessage());
            }
        }
    }

    /**
     * Check if license should be verified
     * 
     * @param string $license_key License key
     * @return bool True if verification is due
     */
    private function should_verify(string $license_key): bool
    {
        $last_check = get_option('attrua_pro_license_last_check', 0);
        $check_interval = DAY_IN_SECONDS; // Verify daily

        return (time() - $last_check) > $check_interval;
    }

    /**
     * Check if license is active
     * 
     * @return bool True if license is active and valid
     */
    public function is_active(): bool
    {
        if (!$this->license_data) {
            return false;
        }

        return $this->license_data->is_active();
    }

    /**
     * Get license data
     * 
     * @return Data|null License data or null if not available
     */
    public function get_license_data(): ?Data
    {
        return $this->license_data;
    }

    /**
     * Activate license
     * 
     * @param string $license_key License key to activate
     * @return bool True on successful activation
     * @throws Exception On activation failure
     */
    public function activate(string $license_key): bool
    {
        // Validate license key format
        if (!$this->validator->validate_key_format($license_key)) {
            throw new Exception(
                __('Invalid license key format.', Constants::TEXT_DOMAIN),
                'invalid_license_format'
            );
        }

        // Make API request to activate license
        $response = $this->api_client->activate($license_key);

        // Get full license details
        $license_check = $this->api_client->check($license_key);

        // Create license data object
        $this->license_data = new Data($license_check->get_data());

        // Save license information
        update_option('attrua_pro_license_key', $license_key);
        update_option('attrua_pro_license_data', $this->license_data->to_array());
        update_option('attrua_pro_license_last_check', time());

        // Update cache
        $this->cache->set_license_data($this->license_data);

        return true;
    }

    /**
     * Deactivate license
     * 
     * @return bool True on successful deactivation
     * @throws Exception On deactivation failure
     */
    public function deactivate(): bool
    {
        $license_key = get_option('attrua_pro_license_key', '');

        if (empty($license_key)) {
            throw new Exception(
                __('No active license found.', Constants::TEXT_DOMAIN),
                'no_license'
            );
        }

        // Make API request to deactivate license
        $this->api_client->deactivate($license_key);

        // Clear license data
        delete_option('attrua_pro_license_key');
        delete_option('attrua_pro_license_data');
        delete_option('attrua_pro_license_last_check');

        // Clear cache
        $this->cache->clear();

        // Clear license data object
        $this->license_data = null;

        return true;
    }

    /**
     * Verify license status
     * 
     * @param string|null $license_key License key to verify (uses stored key if null)
     * @return bool True if license is valid
     * @throws Exception On verification failure
     */
    public function verify_license(?string $license_key = null): bool
    {
        $license_key = $license_key ?? get_option('attrua_pro_license_key', '');

        if (empty($license_key)) {
            return false;
        }

        // Check API for license status
        $response = $this->api_client->check($license_key);

        // Create or update license data
        $this->license_data = new Data($response->get_data());

        // Update license data in database
        update_option('attrua_pro_license_data', $this->license_data->to_array());
        update_option('attrua_pro_license_last_check', time());

        // Update cache
        $this->cache->set_license_data($this->license_data);

        return $this->license_data->is_active();
    }

    /**
     * Get sanitized license key for display
     * 
     * @return string Sanitized license key
     */
    public function get_sanitized_key(): string
    {
        $license_key = get_option('attrua_pro_license_key', '');

        if (empty($license_key)) {
            return '';
        }

        // Show first 4 and last 4 characters, mask the rest
        $length = strlen($license_key);
        if ($length <= 8) {
            return str_repeat('•', $length);
        }

        $prefix = substr($license_key, 0, 4);
        $suffix = substr($license_key, -4);
        $mask = str_repeat('•', $length - 8);

        return $prefix . $mask . $suffix;
    }
}
