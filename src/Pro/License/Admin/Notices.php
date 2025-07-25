<?php

namespace Attributes\Pro\License\Admin;

use Attributes\Pro\License\Manager;
use Attributes\Pro\License\Validator;

/**
 * License Admin Notices Handler
 * 
 * Manages WordPress admin notifications related to license status,
 * expiration warnings, and error messages. Provides a centralized system
 * for license-related notices with transient-based persistence and
 * conditional display rules.
 * 
 * @package Attributes\License\Admin
 * @since 1.0.0
 */
class Notices
{
    /**
     * License manager instance
     * 
     * @var Manager
     */
    private Manager $license_manager;

    /**
     * License validator
     * 
     * @var Validator
     */
    private Validator $validator;

    /**
     * Notice transient name
     * 
     * @var string
     */
    private string $notice_transient = 'attrua_license_notices';

    /**
     * Notice transient expiration in seconds
     * 
     * @var int
     */
    private int $notice_expiration = 86400; // 24 hours

    /**
     * Collection of notices to display
     * 
     * @var array
     */
    private array $notices = [];

    /**
     * Constructor
     * 
     * Initializes the notices handler with required dependencies
     * and registers WordPress hooks.
     */
    public function __construct()
    {
        $this->license_manager = Manager::instance();
        $this->validator = new Validator();

        $this->register_hooks();
        $this->load_notices();
    }

    /**
     * Register WordPress hooks
     * 
     * Sets up actions for displaying notices, checking license status,
     * and handling admin interface interactions.
     * 
     * @return void
     */
    private function register_hooks(): void
    {
        // Admin notices display
        add_action('attrua_before_admin_settings', [$this, 'display_notices']);

        // License status check triggers
        add_action('admin_init', [$this, 'check_license_status']);

        // Clear specific notices on license actions
        add_action('wp_ajax_attrua_license_activate', [$this, 'clear_license_notices'], 5);
        add_action('wp_ajax_attrua_license_deactivate', [$this, 'clear_license_notices'], 5);

        // Dismiss notice handler
        add_action('wp_ajax_attrua_dismiss_license_notice', [$this, 'handle_notice_dismissal']);
    }

    /**
     * Load persisted notices
     * 
     * Retrieves stored notices from transients for persistence
     * across page loads and request cycles.
     * 
     * @return void
     */
    private function load_notices(): void
    {
        $saved_notices = get_transient($this->notice_transient);

        if ($saved_notices && is_array($saved_notices)) {
            $this->notices = $saved_notices;
        }
    }

    /**
     * Save notices to transient
     * 
     * Persists notice collection to WordPress transients for
     * retrieval on subsequent page loads.
     * 
     * @return void
     */
    private function save_notices(): void
    {
        set_transient($this->notice_transient, $this->notices, $this->notice_expiration);
    }

    /**
     * Add admin notice
     * 
     * Creates a new admin notice with specified parameters and
     * unique identifier for targeted dismissal.
     * 
     * @param string $message Notice message
     * @param string $type Notice type (error, warning, success, info)
     * @param bool $dismissible Whether notice can be dismissed
     * @param string|null $id Unique notice identifier
     * @param array $data Additional notice data
     * @return string The notice ID
     */
    public function add_notice(
        string $message,
        string $type = 'info',
        bool $dismissible = true,
        ?string $id = null,
        array $data = []
    ): string {
        // Generate ID if not provided
        if ($id === null) {
            $id = 'notice_' . md5($message . microtime());
        }

        $this->notices[$id] = [
            'message' => $message,
            'type' => in_array($type, ['error', 'warning', 'success', 'info']) ? $type : 'info',
            'dismissible' => $dismissible,
            'created' => time(),
            'data' => $data
        ];

        $this->save_notices();

        return $id;
    }

    /**
     * Display all registered notices
     * 
     * Renders all active notices in the WordPress admin
     * with appropriate styling and dismissal controls.
     * 
     * @return void
     */
    public function display_notices(): void
    {
        if (empty($this->notices)) {
            return;
        }

        // Get current screen
        $screen = get_current_screen();

        foreach ($this->notices as $id => $notice) {
            // Skip license-specific notices on irrelevant screens
            if (
                isset($notice['data']['license_notice']) &&
                (!$screen || strpos($screen->id, 'attributes') === false)
            ) {
                continue;
            }

            // Skip expired notices
            if (isset($notice['data']['expires']) && $notice['data']['expires'] < time()) {
                unset($this->notices[$id]);
                continue;
            }

            $dismissible_class = $notice['dismissible'] ? 'is-dismissible' : '';
            $notice_class = 'notice notice-' . $notice['type'] . ' ' . $dismissible_class;

            if (isset($notice['data']['class'])) {
                $notice_class .= ' ' . $notice['data']['class'];
            }

?>
            <div class="<?php echo esc_attr($notice_class); ?>"
                data-notice-id="<?php echo esc_attr($id); ?>">
                <p><?php echo wp_kses_post($notice['message']); ?></p>

                <?php if (isset($notice['data']['extra_content'])): ?>
                    <div class="attrua-notice-content">
                        <?php echo wp_kses_post($notice['data']['extra_content']); ?>
                    </div>
                <?php endif; ?>

                <?php if ($notice['dismissible']): ?>
                    <script>
                        jQuery(document).ready(function($) {
                            $(document).on('click', '.notice[data-notice-id="<?php echo esc_js($id); ?>"] .notice-dismiss', function() {
                                $.ajax({
                                    url: ajaxurl,
                                    type: 'POST',
                                    data: {
                                        action: 'attrua_dismiss_license_notice',
                                        notice_id: '<?php echo esc_js($id); ?>',
                                        nonce: '<?php echo esc_js(wp_create_nonce('attrua_dismiss_notice')); ?>'
                                    }
                                });
                            });
                        });
                    </script>
                <?php endif; ?>
            </div>
<?php
        }

        // Clean up displayed non-persistent notices
        $this->cleanup_notices();
    }

    /**
     * Handle AJAX notice dismissal
     * 
     * Processes asynchronous notice dismissal requests with
     * security validation and notice removal.
     * 
     * @return void
     */
    public function handle_notice_dismissal(): void
    {
        // Verify nonce
        check_ajax_referer('attrua_dismiss_notice', 'nonce');

        if (!isset($_POST['notice_id'])) {
            wp_send_json_error('No notice ID provided');
        }

        $notice_id = sanitize_text_field($_POST['notice_id']);

        if (isset($this->notices[$notice_id])) {
            // Remove the notice
            unset($this->notices[$notice_id]);
            $this->save_notices();
            wp_send_json_success();
        } else {
            wp_send_json_error('Notice not found');
        }
    }

    /**
     * Check license status
     * 
     * Performs periodic license validation and generates appropriate
     * notices for expiration, activation issues, and renewal reminders.
     * 
     * @return void
     */
    public function check_license_status(): void
    {
        // Skip on AJAX requests and unauthenticated users
        if (wp_doing_ajax() || !current_user_can('manage_options')) {
            return;
        }

        $license_data = $this->license_manager->get_license_data();

        // If no license data or inactive, show activation notice
        if (!$license_data || !$this->license_manager->is_active()) {
            $this->show_inactive_license_notice();
            return;
        }

        // Check for license expiration
        if (isset($license_data->get_raw_data()['expires_at'])) {
            $expires_at = $license_data->get_raw_data()['expires_at'];

            // Check if license is expired
            if ($this->validator->is_expired($expires_at)) {
                $this->show_expired_license_notice($license_data->get_expires());
                return;
            }

            // Check if license is expiring soon (14 days warning)
            if ($this->validator->is_expiring_soon($expires_at, 14)) {
                $this->show_expiring_license_notice($license_data->get_expires());
                return;
            }
        }
    }

    /**
     * Show inactive license notice
     * 
     * Displays a warning about inactive license and premium
     * features being disabled with call-to-action for activation.
     * 
     * @return void
     */
    private function show_inactive_license_notice(): void
    {
        // Only create if we don't already have an inactive license notice
        foreach ($this->notices as $notice) {
            if (
                isset($notice['data']['notice_type']) &&
                $notice['data']['notice_type'] === 'inactive_license'
            ) {
                return;
            }
        }

        $message = sprintf(
            '%s %s',
            __('Attributes User Access Pro license is not active. Premium features are disabled.', 'attributes-user-access-pro-lite'),
            sprintf(
                '<a href="%s">%s</a>',
                esc_url(admin_url('admin.php?page=attributes-user-access&tab=license')),
                __('Activate your license', 'attributes-user-access-pro-lite')
            )
        );

        $this->add_notice(
            $message,
            'warning',
            true,
            'inactive_license_notice',
            [
                'license_notice' => true,
                'notice_type' => 'inactive_license',
                'persistent' => true
            ]
        );
    }

    /**
     * Show expired license notice
     * 
     * Displays an error about license expiration with information
     * on renewing and steps to restore premium functionality.
     * 
     * @param string $expiry_date Formatted expiration date
     * @return void
     */
    private function show_expired_license_notice(string $expiry_date): void
    {
        // Only create if we don't already have an expired license notice
        foreach ($this->notices as $notice) {
            if (
                isset($notice['data']['notice_type']) &&
                $notice['data']['notice_type'] === 'expired_license'
            ) {
                return;
            }
        }

        $message = sprintf(
            '%s %s',
            sprintf(
                __('Your Attributes User Access Pro license expired on %s.', 'attributes-user-access-pro-lite'),
                '<strong>' . esc_html($expiry_date) . '</strong>'
            ),
            sprintf(
                '<a href="%s" target="_blank">%s</a>',
                'https://attributeswp.com/renew/',
                __('Renew your license', 'attributes-user-access-pro-lite')
            )
        );

        $this->add_notice(
            $message,
            'error',
            true,
            'expired_license_notice',
            [
                'license_notice' => true,
                'notice_type' => 'expired_license',
                'persistent' => true
            ]
        );
    }

    /**
     * Show expiring license notice
     * 
     * Displays a warning about upcoming license expiration
     * with renewal information and timeframe details.
     * 
     * @param string $expiry_date Formatted expiration date
     * @return void
     */
    private function show_expiring_license_notice(string $expiry_date): void
    {
        // Only create if we don't already have an expiring license notice
        foreach ($this->notices as $notice) {
            if (
                isset($notice['data']['notice_type']) &&
                $notice['data']['notice_type'] === 'expiring_license'
            ) {
                return;
            }
        }

        $message = sprintf(
            '%s %s',
            sprintf(
                __('Your Attributes User Access Pro license will expire on %s.', 'attributes-user-access-pro-lite'),
                '<strong>' . esc_html($expiry_date) . '</strong>'
            ),
            sprintf(
                '<a href="%s" target="_blank">%s</a>',
                'https://attributeswp.com/renew/',
                __('Renew your license', 'attributes-user-access-pro-lite')
            )
        );

        $this->add_notice(
            $message,
            'warning',
            true,
            'expiring_license_notice',
            [
                'license_notice' => true,
                'notice_type' => 'expiring_license',
                'persistent' => true,
                'expires' => strtotime($expiry_date) // Auto-remove after expiration
            ]
        );
    }

    /**
     * Clear license-related notices
     * 
     * Removes specific license notices during activation/deactivation
     * to prevent stale or contradictory notifications.
     * 
     * @return void
     */
    public function clear_license_notices(): void
    {
        // Define notice IDs to clear
        $notice_ids = [
            'inactive_license_notice',
            'expired_license_notice',
            'expiring_license_notice'
        ];

        foreach ($notice_ids as $id) {
            if (isset($this->notices[$id])) {
                unset($this->notices[$id]);
            }
        }

        $this->save_notices();
    }

    /**
     * Cleanup non-persistent notices
     * 
     * Removes one-time notices after display to prevent
     * duplication on subsequent page loads.
     * 
     * @return void
     */
    private function cleanup_notices(): void
    {
        $modified = false;

        foreach ($this->notices as $id => $notice) {
            // Keep notices marked as persistent
            if (isset($notice['data']['persistent']) && $notice['data']['persistent']) {
                continue;
            }

            // Remove standard non-persistent notices
            unset($this->notices[$id]);
            $modified = true;
        }

        if ($modified) {
            $this->save_notices();
        }
    }
}
