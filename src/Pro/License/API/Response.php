<?php
namespace Attributes\Pro\License\API;

/**
 * SureCart API Response
 * 
 * Standardizes API response handling and provides methods for 
 * accessing response data and error information.
 */
class Response {
    /**
     * HTTP status code from response
     * 
     * @var int
     */
    private int $status_code;
    
    /**
     * Parsed response body
     * 
     * @var array
     */
    private array $data;
    
    /**
     * Raw WordPress HTTP API response
     * 
     * @var array
     */
    private array $raw_response;
    
    /**
     * Constructor
     * 
     * @param int $status_code HTTP status code
     * @param array $data Parsed response data
     * @param array $raw_response WordPress HTTP API response
     */
    public function __construct(int $status_code, array $data, array $raw_response) {
        $this->status_code = $status_code;
        $this->data = $data;
        $this->raw_response = $raw_response;
    }
    
    /**
     * Check if response indicates success
     * 
     * @return bool True if response indicates success
     */
    public function is_success(): bool {
        return $this->status_code >= 200 && $this->status_code < 300;
    }
    
    /**
     * Get HTTP status code
     * 
     * @return int HTTP status code
     */
    public function get_status_code(): int {
        return $this->status_code;
    }
    
    /**
     * Get response data
     * 
     * @return array Response data
     */
    public function get_data(): array {
        return $this->data;
    }
    
    /**
     * Get error message from response
     * 
     * @return string Error message or empty string if no error
     */
    public function get_error_message(): string {
        if ($this->is_success()) {
            return '';
        }
        
        return $this->data['message'] ?? 'Unknown API error';
    }
    
    /**
     * Get error code from response
     * 
     * @return string Error code or empty string if no error
     */
    public function get_error_code(): string {
        if ($this->is_success()) {
            return '';
        }
        
        return $this->data['code'] ?? 'api_error_' . $this->status_code;
    }
    
    /**
     * Get raw response
     * 
     * @return array Raw WordPress HTTP API response
     */
    public function get_raw_response(): array {
        return $this->raw_response;
    }
}