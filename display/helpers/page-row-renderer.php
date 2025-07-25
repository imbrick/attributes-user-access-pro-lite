<?php

/**
 * Page Row Renderer
 *
 * Handles rendering of page rows in the admin interface for different
 * authentication page types. Supports rendering of login, register,
 * reset password, and account pages with consistent layout and functionality.
 *
 * @package Attributes\Admin\Display
 * @since 1.0.0
 */

namespace Attributes\Admin\Display;

use Attributes\Core\Settings;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Page Row Renderer Class
 */
class Page_Row_Renderer
{

    /**
     * Settings instance
     *
     * @var Settings
     */
    private $settings;

    /**
     * Constructor
     *
     * @param Settings $settings Settings instance
     */
    public function __construct(Settings $settings)
    {
        $this->settings = $settings;
    }

    /**
     * Render page row
     *
     * @param string $page_type Page type identifier (login, register, reset, account)
     * @param array  $options   Options for the page row
     */
    public function render_page_row($page_type, $options = [])
    {
        // Set default options
        $options = wp_parse_args($options, [
            'title' => $this->get_default_title($page_type),
            'slug' => $this->get_default_slug($page_type),
            'shortcode' => $this->get_shortcode($page_type),
            'show_redirect' => true,
            'class' => '',
        ]);

        // Get page ID
        $page_id = $this->settings->attrua_get("pages.{$page_type}");

        // Start row with the required class
        echo '<tr class="attrua-page-row ' . esc_attr($options['class']) . '" data-page-type="' . esc_attr($page_type) . '">';

        // Title column
        $this->render_title_column($page_type, $page_id, $options);

        // Slug column
        $this->render_slug_column($page_type, $page_id, $options);

        // Shortcode column
        $this->render_shortcode_column($page_type, $page_id, $options);

        // Actions column
        $this->render_actions_column($page_type, $page_id, $options);

        // Redirect column
        if ($options['show_redirect']) {
            $this->render_redirect_column($page_type, $page_id, $options);
        } else {
            echo '<td></td>';
        }

        echo '</tr>';
    }

    /**
     * Render title column
     *
     * @param string  $page_type Page type identifier
     * @param int     $page_id   Page ID or null
     * @param array   $options   Options for the page row
     */
    private function render_title_column($page_type, $page_id, $options)
    {
        echo '<th scope="row">';

        if ($page_id) {
            $page = get_post($page_id);
            echo '<strong class="attrua-page-title-display">' . esc_html($page->post_title) . '</strong>';
        } else {
?>
            <input type="text"
                class="attrua-page-title"
                name="attrua_pages_options[<?php echo esc_attr($page_type); ?>_title]"
                value="<?php echo esc_attr($options['title']); ?>"
                placeholder="<?php echo esc_attr($options['title']); ?>" />
        <?php
        }

        echo '</th>';
    }

    /**
     * Render slug column
     *
     * @param string  $page_type Page type identifier
     * @param int     $page_id   Page ID or null
     * @param array   $options   Options for the page row
     */
    private function render_slug_column($page_type, $page_id, $options)
    {
        echo '<td>';

        if ($page_id) {
            $slug = get_post_field('post_name', $page_id);
            echo '<strong class="attrua-page-slug-display"><span class="attrua-page-prefix">/</span>' . esc_html($slug) . '</strong>';
        } else {
        ?>
            <input type="text"
                class="attrua-page-slug"
                name="attrua_pages_options[<?php echo esc_attr($page_type); ?>_slug]"
                value="<?php echo esc_attr($options['slug']); ?>"
                placeholder="<?php echo esc_attr($options['slug']); ?>" />
        <?php
        }

        echo '</td>';
    }

    /**
     * Render shortcode column
     *
     * @param string  $page_type Page type identifier
     * @param int     $page_id   Page ID or null
     * @param array   $options   Options for the page row
     */
    private function render_shortcode_column($page_type, $page_id, $options)
    {
        echo '<td style="width: 200px;">';

        if ($page_id) {
        ?>
            <div class="attrua-page-shortcode">
                <span><?php echo esc_html($options['shortcode']); ?></span>
                <button type="button"
                    class="attrua-copy-shortcode"
                    data-shortcode="<?php echo esc_attr($options['shortcode']); ?>">
                    <i class="ti ti-copy"></i>
                </button>
            </div>
        <?php
        }

        echo '</td>';
    }

    /**
     * Render actions column
     *
     * @param string  $page_type Page type identifier
     * @param int     $page_id   Page ID or null
     * @param array   $options   Options for the page row
     */
    private function render_actions_column($page_type, $page_id, $options)
    {
        echo '<td style="width: 300px;">';
        echo '<div class="attrua-page-control">';

        if ($page_id) {
        ?>
            <div class="attrua-page-actions">
                <a href="<?php echo esc_url(get_edit_post_link($page_id)); ?>" class="button">
                    <i class="ti ti-pencil"></i>&nbsp;<?php esc_html('Edit Page', 'attributes-user-access'); ?>
                </a>
                <a href="<?php echo esc_url(get_permalink($page_id)); ?>" class="button" target="_blank">
                    <i class="ti ti-eye"></i>&nbsp;<?php esc_html('View Page', 'attributes-user-access'); ?>
                </a>
                <button type="button"
                    class="button attrua-delete-page"
                    data-page-id="<?php echo esc_attr($page_id); ?>"
                    data-page-type="<?php echo esc_attr($page_type); ?>">
                    <i class="ti ti-trash"></i>&nbsp;<?php esc_html('Delete', 'attributes-user-access'); ?>
                </button>
            </div>
        <?php
        } else {
        ?>
            <button type="button"
                class="button attrua-create-page"
                data-page-type="<?php echo esc_attr($page_type); ?>"
                data-default-title="<?php echo esc_attr($options['title']); ?>"
                data-default-slug="<?php echo esc_attr($options['slug']); ?>">
                <?php esc_html('Create Page', 'attributes-user-access'); ?>
            </button>
        <?php
        }

        echo '</div>';
        echo '</td>';
    }

    /**
     * Render redirect column
     *
     * @param string  $page_type Page type identifier
     * @param int     $page_id   Page ID or null
     * @param array   $options   Options for the page row
     */
    private function render_redirect_column($page_type, $page_id, $options)
    {
        echo '<td>';

        if ($page_id) {
            $redirect_enabled = $this->settings->attrua_get("redirects.{$page_type}");
            $wp_url = $this->get_wp_url($page_type);
            $custom_url = get_permalink($page_id);

        ?>
            <label class="attrua-redirect-toggle">
                <input type="checkbox"
                    name="attrua_redirect_options[<?php echo esc_attr($page_type); ?>]"
                    value="1"
                    <?php checked($redirect_enabled); ?>
                    data-wp-url="<?php echo esc_url($wp_url); ?>"
                    data-custom-url="<?php echo esc_url($custom_url); ?>">
                <span class="slider"></span>
                <span class="attrua-redirect-url">
                    <small><?php echo esc_url($redirect_enabled ? $custom_url : $wp_url); ?></small>
                </span>
            </label>
<?php
        }

        echo '</td>';
    }

    /**
     * Get default page title
     *
     * @param string $page_type Page type identifier
     * @return string Default title
     */
    private function get_default_title($page_type)
    {
        $titles = [
            'login' => __('Login', 'attributes-user-access'),
            'register' => __('Register', 'attributes-user-access'),
            'reset' => __('Reset Password', 'attributes-user-access'),
            'account' => __('My Account', 'attributes-user-access'),
        ];

        return isset($titles[$page_type]) ? $titles[$page_type] : ucfirst($page_type);
    }

    /**
     * Get default page slug
     *
     * @param string $page_type Page type identifier
     * @return string Default slug
     */
    private function get_default_slug($page_type)
    {
        return $page_type;
    }

    /**
     * Get shortcode for page type
     *
     * @param string $page_type Page type identifier
     * @return string Shortcode
     */
    private function get_shortcode($page_type)
    {
        $shortcodes = [
            'login' => '[attributes_login_form]',
            'register' => '[attributes_register_form]',
            'reset' => '[attributes_reset_form]',
            'account' => '[attributes_account_form]',
        ];

        return isset($shortcodes[$page_type]) ? $shortcodes[$page_type] : '';
    }

    /**
     * Get WordPress URL for page type
     *
     * @param string $page_type Page type identifier
     * @return string WordPress URL
     */
    private function get_wp_url($page_type)
    {
        switch ($page_type) {
            case 'login':
                return wp_login_url();
            case 'register':
                return wp_registration_url();
            case 'reset':
                return wp_lostpassword_url();
            default:
                return home_url('/');
        }
    }
}
