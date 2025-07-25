<?php
namespace Attributes\Pro\License\Admin;

use Attributes\Pro\Core\Constants;
use Attributes\Pro\License\Manager;
use Attributes\Core\Assets as CoreAssets;

/**
 * License AJAX Handler
 * 
 * Manages asynchronous license operations through WordPress AJAX API.
 * Provides endpoints for activation, deactivation, and license validation
 * with proper security controls and standardized response formatting.
 * 
 * @package Attributes\License\Admin
 * @since 1.0.0
 */
class AJAX {
    /**
     * AJAX action prefix
     * 
     * @var string
     */
    private string $action_prefix = 'attrua_license_';
    
    /**
     * AJAX nonce name
     * 
     * @var string
     */
    private string $nonce_name = 'attrua_license_ajax_nonce';
    
    /**
     * License Manager instance
     *
     * @var Manager
     */
    private Manager $license_manager;

    /**
     * Constructor
     * 
     * Initializes the AJAX handler with license manager dependency
     * and registers WordPress AJAX hooks.
     */
    public function __construct() {
        $this->attrua_register_hooks();
    }
    
    /**
     * Register AJAX hooks
     * 
     * Maps AJAX actions to handler methods and registers them with WordPress.
     * 
     * @return void
     */
    private function attrua_register_hooks(): void {
        // Define AJAX endpoints and their handler methods
        $ajax_actions = [
            'activate' => 'attrua_handle_activate',
            'deactivate' => 'attrua_handle_deactivate',
            'check_status' => 'attrua_handle_check_status',
        ];
        
        // Register each AJAX action
        foreach ($ajax_actions as $action => $method) {
            add_action('wp_ajax_' . $this->action_prefix . $action, [$this, $method]);
        }
        
        // Add script localization for AJAX parameters
        add_action('admin_enqueue_scripts', [$this, 'attrua_localize_script']);
    }
    
    /**
     * Localize AJAX script
     * 
     * Adds required AJAX parameters to JavaScript including URL, nonce,
     * and action prefixes for security and consistency.
     * 
     * @param string $hook Current admin page hook
     * @return void
     */
    public function attrua_localize_script(string $hook): void {
        if (strpos($hook, 'attributes-user-access') === false) {
            error_log('Not a plugin admin page. Skipping script enqueue.');
            return;
        }

        // Debug: Log that the script is being enqueued
        error_log('Enqueuing script for plugin admin page.');
    
        // Enqueue the script
        wp_enqueue_script(
            'attrua-pro-license',
            ATTRUA_PRO_URL . 'assets/js/license-admin.js',
            ['jquery'],
            ATTRUA_PRO_VERSION,
            true
        );
        
        // Localize the script
        wp_localize_script('attrua-pro-license', 'attruaLicense', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce($this->nonce_name),
            'action_prefix' => $this->action_prefix,
            'i18n' => [
                'activating' => __('Activating license...', Constants::TEXT_DOMAIN),
                'deactivating' => __('Deactivating license...', Constants::TEXT_DOMAIN),
                'checking' => __('Checking license status...', Constants::TEXT_DOMAIN),
                'error' => __('Error processing request', Constants::TEXT_DOMAIN),
                'network_error' => __('Network error. Please try again.', Constants::TEXT_DOMAIN),
            ]
        ]);
    
        // Debug: Log that the script has been localized
        error_log('Script localized with attruaLicense data.');
    }
    
    /**
     * Handle license activation
     * 
     * Processes AJAX license activation requests with security validation
     * and standardized response formatting.
     * 
     * @return void
     */
    public function attrua_handle_activate(): void {
        // Check nonce
        if (!isset($_POST['attrua_license_ajax_nonce']) || 
            !wp_verify_nonce($_POST['attrua_license_aja_nonce'], 'attrua_license_action')) {
            wp_die('Security check failed'); // End the script if nonce is invalid
        }
        
        // Sanitize and get the license key from POST
        $license_key = isset($_POST['attrua_pro_license_key']) ? 
            sanitize_text_field(wp_unslash($_POST['attrua_pro_license_key'])) : '';
    
        // If the license key is empty, return an error response
        if (empty($license_key)) {
            wp_send_json_error([
                'message' => __('Please enter a license key.', Constants::TEXT_DOMAIN),
                'error_code' => 'empty_key'
            ]);
        }
    
        try {
            // Attempt to activate the license
            $result = $this->license_manager->activate($license_key);
        
            // Check if the activation was successful (You may need to check the actual result of $result)
            if (!$result) {
                throw new Exception(__('License activation failed.', Constants::TEXT_DOMAIN));
            }
        
            // Get the updated license data
            $license_data = $this->license_manager->get_license_data();
        
            // Check if license data is valid and convert it to an array
            if ($license_data && method_exists($license_data, 'to_array')) {
                $license_data = $license_data->to_array();
            } else {
                $license_data = null;
            }
        
            // Check if the license is active
            $is_active = $this->license_manager->is_active();
            if (!is_bool($is_active)) {
                $is_active = false; // Default to false if not a boolean
            }
        
            // Send success response
            wp_send_json_success([
                'message' => __('License activated successfully.', Constants::TEXT_DOMAIN),
                'license_data' => $license_data,
                'is_active' => $is_active
            ]);
        
        } catch (Exception $e) {
            // Handle known exceptions (e.g., license activation error)
            wp_send_json_error([
                'message' => $e->getMessage(),
                'error_code' => 'activation_failed',
            ]);
        } catch (\Exception $e) {
            // Catch any other errors or unexpected exceptions
            wp_send_json_error([
                'message' => __('An unknown error occurred.', Constants::TEXT_DOMAIN),
                'error_code' => 'unknown_error',
                'details' => $e->getMessage()
            ]);
        }
        
    }
    
    
    /**
     * Handle license deactivation
     * 
     * Processes AJAX license deactivation requests with security validation
     * and standardized response formatting.
     * 
     * @return void
     */
    public function attrua_handle_deactivate(): void {
        $this->attrua_verify_request('deactivate');
        
        try {
            // Attempt to deactivate the license
            $result = $this->license_manager->deactivate();
            
            $this->attrua_send_success_response([
                'message' => __('License deactivated successfully.', Constants::TEXT_DOMAIN)
            ]);
            
        } catch (Exception $e) {
            $this->attrua_send_error_response(
                $e->get_api_error_code(),
                $e->get_user_message(),
                ['context' => $e->get_context()]
            );
        } catch (\Exception $e) {
            $this->attrua_send_error_response(
                'unknown_error',
                $e->getMessage()
            );
        }
    }
    
    /**
     * Handle license status check
     * 
     * Processes AJAX license status verification requests with security validation
     * and standardized response formatting.
     * 
     * @return void
     */
    public function attrua_handle_check_status(): void {
        $this->attrua_verify_request('check_status');
        
        try {
            $license_key = get_option('attrua_pro_license_key', '');
            
            if (empty($license_key)) {
                $this->attrua_send_error_response(
                    'no_license',
                    __('No license key found.', Constants::TEXT_DOMAIN)
                );
            }
            
            // Verify the license status
            $is_valid = $this->license_manager->verify_license($license_key);
            $license_data = $this->license_manager->get_license_data();
            
            $this->attrua_send_success_response([
                'is_active' => $is_valid,
                'license_data' => $license_data ? $license_data->to_array() : null,
                'message' => $is_valid ? 
                    __('License is active and valid.', Constants::TEXT_DOMAIN) : 
                    __('License is inactive or invalid.', Constants::TEXT_DOMAIN)
            ]);
            
        } catch (Exception $e) {
            $this->attrua_send_error_response(
                $e->get_api_error_code(),
                $e->get_user_message(),
                ['context' => $e->get_context()]
            );
        } catch (\Exception $e) {
            $this->attrua_send_error_response(
                'unknown_error',
                $e->getMessage()
            );
        }
    }
    
    /**
     * Verify AJAX request security
     * 
     * Validates nonce, user capabilities, and referrer for AJAX requests
     * to prevent unauthorized access and CSRF attacks.
     * 
     * @param string $action The action being performed
     * @return void
     */
    private function attrua_verify_request(string $action): void {
        // Check nonce
        check_ajax_referer($this->nonce_name, 'nonce');
        
        // Verify user capabilities
        if (!current_user_can('manage_options')) {
            $this->attrua_send_error_response(
                'permission_denied',
                __('You do not have permission to perform this action.', Constants::TEXT_DOMAIN),
                null,
                403
            );
        }
    }
    
    /**
     * Send success response
     * 
     * Formats and outputs a standardized JSON success response
     * with provided data and terminates execution.
     * 
     * @param array|null $data Response data
     * @return void
     */
    private function attrua_send_success_response(?array $data = null): void {
        wp_send_json_success($data);
    }
    
    /**
     * Send error response
     * 
     * Formats and outputs a standardized JSON error response
     * with error code, message, and optional data and HTTP status.
     * 
     * @param string $code Error code
     * @param string $message Error message
     * @param array|null $data Additional error data
     * @param int $status HTTP status code
     * @return void
     */
    private function attrua_send_error_response(
        string $code,
        string $message,
        ?array $data = null,
        int $status = 400
    ): void {
        $response = [
            'code' => $code,
            'message' => $message
        ];
        
        if ($data !== null) {
            $response['data'] = $data;
        }
        
        // Set HTTP status header
        status_header($status);
        
        wp_send_json_error($response);
    }
}