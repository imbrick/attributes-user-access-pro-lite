<?php
namespace Attributes\Pro\Security;

use Attributes\Pro\Core\Constants;

/**
 * reCAPTCHA Integration
 * 
 * Implements Google reCAPTCHA integration for form protection
 * against spam and automated attacks.
 * 
 * @package Attributes\Pro\Security
 * @since 1.0.0
 */
class Recaptcha {
    /**
     * Singleton instance
     * 
     * @var Recaptcha|null
     */
    private static ?Recaptcha $instance = null;
    
    /**
     * Settings array
     * 
     * @var array
     */
    private array $settings;
    
    /**
     * Get singleton instance
     * 
     * @return Recaptcha Instance
     */
    public static function instance(): self {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        
        return self::$instance;
    }
    
    /**
     * Constructor
     */
    private function __construct() {
        $this->settings = get_option(Constants::RECAPTCHA_SETTINGS_OPTION, []);
        
        if ($this->is_enabled()) {
            $this->init_hooks();
        }
    }
    
    /**
     * Initialize hooks
     */
    private function init_hooks(): void {
        // Add form fields
        add_action('attrua_login_form_after_fields', [$this, 'add_recaptcha_field']);
        add_action('attrua_register_form_after_fields', [$this, 'add_recaptcha_field']);
        add_action('attrua_lost_form_after_fields', [$this, 'add_recaptcha_field']);
        add_action('attrua_reset_form_after_fields', [$this, 'add_recaptcha_field']);
        
        // Add form validation
        add_filter('attrua_validate_login_form', [$this, 'validate_recaptcha']);
        add_filter('attrua_validate_register_form', [$this, 'validate_recaptcha']);
        add_filter('attrua_validate_lost_form', [$this, 'validate_recaptcha']);
        add_filter('attrua_validate_reset_form', [$this, 'validate_recaptcha']);
        
        // Add settings section
        add_action('attrua_pro_security_settings', [$this, 'render_settings']);
        add_action('attrua_pro_save_security_settings', [$this, 'save_settings']);
        
        // Scripts and styles
        add_action('wp_enqueue_scripts', [$this, 'enqueue_scripts']);
        add_action('login_enqueue_scripts', [$this, 'enqueue_scripts']);
    }
    
    /**
     * Check if reCAPTCHA is enabled
     * 
     * @return bool Whether reCAPTCHA is enabled
     */
    public function is_enabled(): bool {
        return !empty($this->settings['enabled']) && 
               $this->settings['enabled'] === 'yes' && 
               !empty($this->settings['site_key']) && 
               !empty($this->settings['secret_key']);
    }
    
    /**
     * Get reCAPTCHA version
     * 
     * @return string reCAPTCHA version ('v2' or 'v3')
     */
    public function get_version(): string {
        return $this->settings['version'] ?? 'v2';
    }
    
    /**
     * Check if reCAPTCHA is enabled for form
     * 
     * @param string $form_id Form identifier
     * @return bool Whether reCAPTCHA is enabled for form
     */
    public function is_enabled_for_form(string $form_id): bool {
        if (!$this->is_enabled()) {
            return false;
        }
        
        $enabled_forms = $this->settings['forms'] ?? [];
        
        return in_array($form_id, $enabled_forms);
    }
    
    /**
     * Add reCAPTCHA field to form
     * 
     * @param array $form_data Form data including ID
     */
    public function add_recaptcha_field(array $form_data): void {
        $form_id = $form_data['id'] ?? '';
        
        if (!$this->is_enabled_for_form($form_id)) {
            return;
        }
        
        $site_key = $this->settings['site_key'];
        $version = $this->get_version();
        
        if ($version === 'v2') {
            ?>
            <div class="attrua-form-row">
                <div class="g-recaptcha" data-sitekey="<?php echo esc_attr($site_key); ?>"></div>
            </div>
            <?php
        } else {
            // V3 doesn't need a visible element, just add a hidden field
            ?>
            <input type="hidden" name="recaptcha_response" id="attrua-recaptcha-response-<?php echo esc_attr($form_id); ?>" />
            <?php
        }
    }
    
    /**
     * Validate reCAPTCHA response
     * 
     * @param array $errors Current validation errors
     * @return array Updated validation errors
     */
    public function validate_recaptcha(array $errors): array {
        // Get form ID from context
        $form_id = current_filter();
        $form_id = str_replace('attrua_validate_', '', $form_id);
        $form_id = str_replace('_form', '', $form_id);
        
        if (!$this->is_enabled_for_form($form_id)) {
            return $errors;
        }
        
        $version = $this->get_version();
        $secret_key = $this->settings['secret_key'];
        
        // Get response
        if ($version === 'v2') {
            $response = isset($_POST['g-recaptcha-response']) ? sanitize_text_field($_POST['g-recaptcha-response']) : '';
        } else {
            $response = isset($_POST['recaptcha_response']) ? sanitize_text_field($_POST['recaptcha_response']) : '';
        }
        
        if (empty($response)) {
            $errors[] = __('Please complete the reCAPTCHA verification.', Constants::TEXT_DOMAIN);
            return $errors;
        }
        
        // Verify with Google
        $verify = $this->verify_recaptcha($response);
        
        if (!$verify['success']) {
            $errors[] = __('reCAPTCHA verification failed. Please try again.', Constants::TEXT_DOMAIN);
            
            // Log failed verification
            do_action('attrua_pro_security_event', 'recaptcha_failed', 0, [
                'form' => $form_id,
                'ip' => $_SERVER['REMOTE_ADDR'],
                'error_codes' => $verify['error-codes'] ?? []
            ]);
        }
        
        return $errors;
    }
    
    /**
     * Verify reCAPTCHA response with Google API
     * 
     * @param string $response reCAPTCHA response token
     * @return array Verification result
     */
    private function verify_recaptcha(string $response): array {
        $secret_key = $this->settings['secret_key'];
        
        $url = 'https://www.google.com/recaptcha/api/siteverify';
        $data = [
            'secret' => $secret_key,
            'response' => $response,
            'remoteip' => $_SERVER['REMOTE_ADDR']
        ];
        
        $options = [
            'http' => [
                'header' => "Content-type: application/x-www-form-urlencoded\r\n",
                'method' => 'POST',
                'content' => http_build_query($data)
            ]
        ];
        
        $context = stream_context_create($options);
        $result = file_get_contents($url, false, $context);
        
        if ($result === false) {
            return ['success' => false];
        }
        
        $result_json = json_decode($result, true);
        
        // For v3, check score
        if ($this->get_version() === 'v3' && !empty($result_json['success']) && $result_json['success']) {
            $min_score = $this->settings['min_score'] ?? 0.5;
            
            if ($result_json['score'] < $min_score) {
                $result_json['success'] = false;
                $result_json['error-codes'][] = 'score_threshold_not_met';
            }
        }
        
        return $result_json;
    }
    
    /**
     * Enqueue necessary scripts
     */
    public function enqueue_scripts(): void {
        if (!$this->is_enabled()) {
            return;
        }
        
        $version = $this->get_version();
        $site_key = $this->settings['site_key'];
        
        if ($version === 'v2') {
            wp_enqueue_script(
                'google-recaptcha',
                'https://www.google.com/recaptcha/api.js',
                [],
                null,
                true
            );
        } else {
            wp_enqueue_script(
                'google-recaptcha-v3',
                "https://www.google.com/recaptcha/api.js?render={$site_key}",
                [],
                null,
                true
            );
            
            wp_add_inline_script('google-recaptcha-v3', "
                grecaptcha.ready(function() {
                    const forms = document.querySelectorAll('.attrua-form');
                    forms.forEach(function(form) {
                        const formId = form.dataset.formId;
                        const input = document.getElementById('attrua-recaptcha-response-' + formId);
                        
                        if (input) {
                            grecaptcha.execute('{$site_key}', {action: 'attrua_' + formId})
                                .then(function(token) {
                                    input.value = token;
                                });
                        }
                    });
                });
            ");
        }
    }
    
    /**
     * Render settings in admin
     * 
     * @param array $settings Current settings array
     */
    public function render_settings(array $settings): void {
        $recaptcha_settings = $this->settings;
        $enabled = !empty($recaptcha_settings['enabled']) && $recaptcha_settings['enabled'] === 'yes';
        $site_key = $recaptcha_settings['site_key'] ?? '';
        $secret_key = $recaptcha_settings['secret_key'] ?? '';
        $version = $recaptcha_settings['version'] ?? 'v2';
        $min_score = $recaptcha_settings['min_score'] ?? 0.5;
        $enabled_forms = $recaptcha_settings['forms'] ?? [];
        
        $available_forms = [
            'login' => __('Login Form', Constants::TEXT_DOMAIN),
            'register' => __('Registration Form', Constants::TEXT_DOMAIN),
            'lost' => __('Lost Password Form', Constants::TEXT_DOMAIN),
            'reset' => __('Reset Password Form', Constants::TEXT_DOMAIN)
        ];
        
        include ATTRUA_PRO_PATH . 'templates/admin/recaptcha-settings.php';
    }
    
    /**
     * Save settings from admin
     * 
     * @param array $input Form input
     * @return array Sanitized settings
     */
    public function save_settings(array $input): array {
        $settings = [];
        
        // Enabled setting
        $settings['enabled'] = isset($input['recaptcha_enabled']) ? 'yes' : 'no';
        
        // API keys
        $settings['site_key'] = isset($input['recaptcha_site_key']) ? 
            sanitize_text_field($input['recaptcha_site_key']) : '';
            
        $settings['secret_key'] = isset($input['recaptcha_secret_key']) ? 
            sanitize_text_field($input['recaptcha_secret_key']) : '';
        
        // Version
        $settings['version'] = isset($input['recaptcha_version']) && $input['recaptcha_version'] === 'v3' ? 'v3' : 'v2';
        
        // Min score (v3 only)
        if ($settings['version'] === 'v3' && isset($input['recaptcha_min_score'])) {
            $min_score = floatval($input['recaptcha_min_score']);
            $settings['min_score'] = max(0.1, min(1.0, $min_score));
        } else {
            $settings['min_score'] = 0.5;
        }
        
        // Enabled forms
        $settings['forms'] = [];
        $available_forms = ['login', 'register', 'lost', 'reset'];
        
        if (isset($input['recaptcha_forms']) && is_array($input['recaptcha_forms'])) {
            foreach ($input['recaptcha_forms'] as $form) {
                if (in_array($form, $available_forms)) {
                    $settings['forms'][] = $form;
                }
            }
        }
        
        // Update internal settings
        $this->settings = $settings;
        
        // Save to options
        update_option(Constants::RECAPTCHA_SETTINGS_OPTION, $settings);
        
        return $settings;
    }
}