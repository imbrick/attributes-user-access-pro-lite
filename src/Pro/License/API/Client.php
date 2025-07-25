<?php
namespace Attributes\Pro\License\API;

/**
 * SureCart License API Client
 * 
 * Handles all direct communication with the SureCart Licensing API endpoints.
 * Encapsulates API request formatting, authentication, and response handling.
 */
class Client {
    /**
     * Base API endpoint URL for SureCart licenses
     * 
     * @var string
     */
    private string $api_base_url = 'https://api.surecart.com/v1/licenses';
    
    /**
     * Authentication token for SureCart API
     * 
     * @var string
     */
    private string $auth_token;
    
    /**
     * Plugin slug for license identification
     * 
     * @var string
     */
    private string $plugin_slug;
    
    /**
     * Constructor
     * 
     * @param string $auth_token SureCart API authentication token
     * @param string $plugin_slug Plugin identifier for license tracking
     */
    public function __construct(string $auth_token, string $plugin_slug) {
        $this->auth_token = $auth_token;
        $this->plugin_slug = $plugin_slug;
    }
    
    /**
     * Activate a license key for the current site
     * 
     * @param string $license_key License key to activate
     * @return Response API response object
     * @throws Exception When API communication fails
     */
    public function activate(string $license_key): Response {
        return $this->request(
            "{$this->api_base_url}/{$license_key}/activations",
            'POST',
            [
                'domain' => $this->get_site_domain(),
                'name' => $this->get_site_name(),
                'plugin' => $this->plugin_slug,
                'version' => $this->get_plugin_version()
            ]
        );
    }
    
    /**
     * Deactivate a license for the current site
     * 
     * @param string $license_key License key to deactivate
     * @return Response API response object
     * @throws Exception When API communication fails
     */
    public function deactivate(string $license_key): Response {
        return $this->request(
            "{$this->api_base_url}/{$license_key}/activations",
            'DELETE',
            [
                'domain' => $this->get_site_domain()
            ]
        );
    }
    
    /**
     * Check license status
     * 
     * @param string $license_key License key to verify
     * @return Response API response object
     * @throws Exception When API communication fails
     */
    public function check(string $license_key): Response {
        return $this->request(
            "{$this->api_base_url}/{$license_key}",
            'GET',
            [],
            ['X-Domain' => $this->get_site_domain()]
        );
    }
    
    /**
     * Execute HTTP request to SureCart API
     * 
     * @param string $url API endpoint URL
     * @param string $method HTTP method (GET, POST, DELETE)
     * @param array $body Request body data
     * @param array $extra_headers Additional headers
     * @return Response Parsed API response
     * @throws Exception When request fails or returns error
     */
    private function request(string $url, string $method, array $body = [], array $extra_headers = []): Response {
        // Prepare headers with authentication
        $headers = array_merge([
            'Content-Type' => 'application/json',
            'X-Public-Token' => $this->auth_token
        ], $extra_headers);
        
        // Prepare request arguments
        $args = [
            'method' => $method,
            'headers' => $headers,
            'timeout' => 15,
            'sslverify' => true
        ];
        
        // Add body for non-GET requests
        if (!empty($body) && $method !== 'GET') {
            $args['body'] = json_encode($body);
        }
        
        // Execute WordPress HTTP API request
        $raw_response = wp_remote_request($url, $args);
        
        // Handle WordPress HTTP API errors
        if (is_wp_error($raw_response)) {
            throw new Exception(
                $raw_response->get_error_message(),
                'http_request_failed',
                [
                    'url' => $url,
                    'method' => $method,
                    'wp_error' => $raw_response
                ]
            );
        }
        
        // Parse response
        $status_code = wp_remote_retrieve_response_code($raw_response);
        $response_body = json_decode(wp_remote_retrieve_body($raw_response), true);
        
        // Create response object
        $response = new Response($status_code, $response_body, $raw_response);
        
        // Check for API errors
        if (!$response->is_success()) {
            throw new Exception(
                $response->get_error_message(),
                $response->get_error_code(),
                $response->get_data()
            );
        }
        
        return $response;
    }
    
    /**
     * Get normalized site domain
     * 
     * @return string Normalized domain name
     */
    private function get_site_domain(): string {
        $domain = parse_url(home_url(), PHP_URL_HOST);
        
        // Normalize domain by removing www prefix
        if (strpos($domain, 'www.') === 0) {
            $domain = substr($domain, 4);
        }
        
        return $domain;
    }
    
    /**
     * Get site name
     * 
     * @return string Site name
     */
    private function get_site_name(): string {
        return get_bloginfo('name');
    }
    
    /**
     * Get plugin version
     * 
     * @return string Plugin version
     */
    private function get_plugin_version(): string {
        return defined('ATTRUA_PRO_VERSION') ? ATTRUA_PRO_VERSION : '1.0.0';
    }
}