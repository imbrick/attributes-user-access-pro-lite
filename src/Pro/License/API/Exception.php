<?php

namespace Attributes\Pro\License\API;

/**
 * SureCart API Exception
 * 
 * Specialized exception class for API-related errors with
 * additional context data.
 */
class Exception extends \Exception
{
    /**
     * Error code
     * 
     * @var string
     */
    protected string $api_error_code;

    /**
     * Context data for debugging
     * 
     * @var array
     */
    protected array $context;

    /**
     * Constructor
     * 
     * @param string $message Error message
     * @param string $api_error_code API error code
     * @param array $context Additional context data
     * @param int $code Exception code
     * @param \Throwable|null $previous Previous exception
     */
    public function __construct(
        string $message,
        string $api_error_code = '',
        array $context = [],
        int $code = 0,
        \Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->api_error_code = $api_error_code;
        $this->context = $context;
    }

    /**
     * Get API error code
     * 
     * @return string API error code
     */
    public function get_api_error_code(): string
    {
        return $this->api_error_code;
    }

    /**
     * Get context data
     * 
     * @return array Context data
     */
    public function get_context(): array
    {
        return $this->context;
    }

    /**
     * Get user-friendly error message
     * 
     * Maps API error codes to user-friendly messages.
     * 
     * @return string User-friendly error message
     */
    public function get_user_message(): string
    {
        switch ($this->api_error_code) {
            case 'invalid_license_key':
                return __('The license key is invalid.', 'attributes-user-access-pro-lite');

            case 'license_expired':
                return __('Your license has expired.', 'attributes-user-access-pro-lite');

            case 'license_disabled':
                return __('Your license has been disabled.', 'attributes-user-access-pro-lite');

            case 'no_activations_remaining':
                return __('Your license has reached its activation limit.', 'attributes-user-access-pro-lite');

            case 'domain_already_activated':
                return __('This site is already activated with this license.', 'attributes-user-access-pro-lite');

            case 'http_request_failed':
                return __('Could not connect to the licensing server. Please try again later.', 'attributes-user-access-pro-lite');

            default:
                return $this->getMessage();
        }
    }
}
