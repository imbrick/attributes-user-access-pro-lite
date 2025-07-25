<?php
namespace Attributes\Pro\License;

/**
 * License Validator
 * 
 * Provides validation functions for license keys and data.
 */
class Validator {
    /**
     * Validate license key format
     * 
     * @param string $license_key License key to validate
     * @return bool Whether format is valid
     */
    public function validate_key_format(string $license_key): bool {
        // Basic validation - adjust pattern based on your actual license key format
        $pattern = '/^[a-zA-Z0-9_-]{8,64}$/';
        return (bool) preg_match($pattern, $license_key);
    }
    
    /**
     * Validate license data structure
     * 
     * @param array $data License data to validate
     * @return bool Whether data structure is valid
     */
    public function validate_data_structure(array $data): bool {
        // Check for required fields
        $required_fields = ['status'];
        
        foreach ($required_fields as $field) {
            if (!array_key_exists($field, $data)) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Check if a license is expired
     * 
     * @param string $expires_at Expiration date string
     * @return bool Whether license is expired
     */
    public function is_expired(string $expires_at): bool {
        if (empty($expires_at)) {
            return false; // Assume lifetime if no date
        }
        
        $expiration_timestamp = strtotime($expires_at);
        return $expiration_timestamp < time();
    }
    
    /**
     * Check if license is nearing expiration
     * 
     * @param string $expires_at Expiration date string
     * @param int $days_threshold Days threshold for warning
     * @return bool Whether license is nearing expiration
     */
    public function is_expiring_soon(string $expires_at, int $days_threshold = 14): bool {
        if (empty($expires_at)) {
            return false; // Assume lifetime if no date
        }
        
        $expiration_timestamp = strtotime($expires_at);
        $warning_timestamp = time() + ($days_threshold * DAY_IN_SECONDS);
        
        return $expiration_timestamp < $warning_timestamp && $expiration_timestamp > time();
    }
}