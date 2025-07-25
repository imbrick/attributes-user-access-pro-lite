<?php
namespace Attributes\Pro\License;

/**
 * License Cache
 * 
 * Manages license data caching for improved performance
 * and reduced API calls.
 */
class Cache {
    /**
     * Cache key prefix
     * 
     * @var string
     */
    private string $cache_prefix = 'attrua_pro_license_';
    
    /**
     * Cache expiration in seconds
     * 
     * @var int
     */
    private int $cache_expiration = 86400; // 24 hours
    
    /**
     * Get license data from cache
     * 
     * @return Data|null License data or null if not cached
     */
    public function get_license_data(): ?Data {
        $cached_data = get_transient($this->cache_prefix . 'data');
        
        if (false === $cached_data) {
            return null;
        }
        
        return new Data($cached_data);
    }
    
    /**
     * Set license data in cache
     * 
     * @param Data $license_data License data object
     * @return bool True on success
     */
    public function set_license_data(Data $license_data): bool {
        return set_transient(
            $this->cache_prefix . 'data',
            $license_data->to_array(),
            $this->cache_expiration
        );
    }
    
    /**
     * Check if license is cached
     * 
     * @return bool Whether license data is cached
     */
    public function has_license_data(): bool {
        return false !== get_transient($this->cache_prefix . 'data');
    }
    
    /**
     * Clear license data cache
     * 
     * @return bool True on success
     */
    public function clear(): bool {
        return delete_transient($this->cache_prefix . 'data');
    }
    
    /**
     * Set license verification timestamp
     * 
     * @return bool True on success
     */
    public function set_verification_timestamp(): bool {
        return set_transient(
            $this->cache_prefix . 'verified',
            time(),
            $this->cache_expiration
        );
    }
    
    /**
     * Get license verification timestamp
     * 
     * @return int|false Timestamp or false if not set
     */
    public function get_verification_timestamp() {
        return get_transient($this->cache_prefix . 'verified');
    }
}