<?php

namespace Attributes\Pro\License;

/**
 * License Data
 * 
 * Provides structured access to license information with
 * data validation and transformation.
 */
class Data
{
    /**
     * License status (active/inactive)
     * 
     * @var string
     */
    private string $status;

    /**
     * License status label
     * 
     * @var string
     */
    private string $status_label;

    /**
     * Whether license is active
     * 
     * @var bool
     */
    private bool $is_active;

    /**
     * License expiration date
     * 
     * @var string
     */
    private string $expires;

    /**
     * Customer name
     * 
     * @var string
     */
    private string $customer_name;

    /**
     * Customer email
     * 
     * @var string
     */
    private string $customer_email;

    /**
     * Plan/product name
     * 
     * @var string
     */
    private string $plan_name;

    /**
     * Number of active sites
     * 
     * @var int
     */
    private int $sites_active;

    /**
     * Maximum number of sites
     * 
     * @var int
     */
    private int $sites_limit;

    /**
     * Timestamp of last verification
     * 
     * @var int
     */
    private int $last_verified;

    /**
     * Raw license data
     * 
     * @var array
     */
    private array $raw_data;

    /**
     * Constructor
     * 
     * @param array $data License data array
     */
    public function __construct(array $data)
    {
        $this->raw_data = $data;
        $this->parse_data($data);
    }

    /**
     * Parse and normalize license data
     * 
     * @param array $data Raw license data
     */
    private function parse_data(array $data): void
    {
        // Handle SureCart API response format
        if (isset($data['status'])) {
            $this->status = $data['status'] === 'enabled' ? 'active' : 'inactive';
            $this->is_active = $data['status'] === 'enabled';

            $this->status_label = $this->is_active ?
                __('Active', 'attributes-user-access-pro-lite') :
                __('Inactive', 'attributes-user-access-pro-lite');

            $this->expires = isset($data['expires_at']) ?
                date_i18n(get_option('date_format'), strtotime($data['expires_at'])) :
                __('Lifetime', 'attributes-user-access-pro-lite');

            $this->customer_name = $data['customer']['name'] ?? '';
            $this->customer_email = $data['customer']['email'] ?? '';

            // Extract product name from line items if available
            if (isset($data['purchase']['line_items'][0]['product']['name'])) {
                $this->plan_name = $data['purchase']['line_items'][0]['product']['name'];
            } else {
                $this->plan_name = '';
            }

            $this->sites_active = $data['activations_count'] ?? 0;
            $this->sites_limit = $data['activations_limit'] ?? 1;

            // Handle our stored data format
        } else {
            $this->status = $data['status'] ?? 'inactive';
            $this->status_label = $data['status_label'] ?? __('Inactive', 'attributes-user-access-pro-lite');
            $this->is_active = $data['is_active'] ?? false;
            $this->expires = $data['expires'] ?? '';
            $this->customer_name = $data['customer_name'] ?? '';
            $this->customer_email = $data['customer_email'] ?? '';
            $this->plan_name = $data['plan_name'] ?? '';
            $this->sites_active = $data['sites_active'] ?? 0;
            $this->sites_limit = $data['sites_limit'] ?? 0;
        }

        $this->last_verified = time();
    }

    /**
     * Check if license is active
     * 
     * @return bool Whether license is active
     */
    public function is_active(): bool
    {
        return $this->is_active;
    }

    /**
     * Get license status
     * 
     * @return string License status
     */
    public function get_status(): string
    {
        return $this->status;
    }

    /**
     * Get license status label
     * 
     * @return string License status label
     */
    public function get_status_label(): string
    {
        return $this->status_label;
    }

    /**
     * Get expiration date
     * 
     * @return string Expiration date
     */
    public function get_expires(): string
    {
        return $this->expires;
    }

    /**
     * Get customer name
     * 
     * @return string Customer name
     */
    public function get_customer_name(): string
    {
        return $this->customer_name;
    }

    /**
     * Get plan name
     * 
     * @return string Plan name
     */
    public function get_plan_name(): string
    {
        return $this->plan_name;
    }

    /**
     * Get sites info
     * 
     * @return array Sites information
     */
    public function get_sites_info(): array
    {
        return [
            'active' => $this->sites_active,
            'limit' => $this->sites_limit,
            'remaining' => max(0, $this->sites_limit - $this->sites_active)
        ];
    }

    /**
     * Convert to array
     * 
     * @return array License data as array
     */
    public function to_array(): array
    {
        return [
            'status' => $this->status,
            'status_label' => $this->status_label,
            'is_active' => $this->is_active,
            'expires' => $this->expires,
            'customer_name' => $this->customer_name,
            'customer_email' => $this->customer_email,
            'plan_name' => $this->plan_name,
            'sites_active' => $this->sites_active,
            'sites_limit' => $this->sites_limit,
            'last_verified' => $this->last_verified
        ];
    }

    /**
     * Get raw data
     * 
     * @return array Raw license data
     */
    public function get_raw_data(): array
    {
        return $this->raw_data;
    }
}
