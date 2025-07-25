# Attributes User Access Pro

**Version:** 1.0.0  
**License:** GPLv3 or later  
**License URI:** [https://www.gnu.org/licenses/gpl-3.0.html](https://www.gnu.org/licenses/gpl-3.0.html)  
**Requires at least:** WordPress 5.8  
**Tested up to:** WordPress 6.7  
**Requires PHP:** 7.4

## Description

**Attributes User Access Pro** extends the free plugin with advanced authentication, security, and user management features for WordPress. This premium extension provides enterprise-grade security capabilities while maintaining user experience and performance.

## Key Features

### Enhanced Authentication

- **Two-Factor Authentication**: Secure logins with email, authenticator apps, or recovery codes
- **Password Policies**: Enforce strong password requirements with complexity rules
- **Multiple Login Methods**: Support for email, username, or both authentication methods

### Comprehensive Security

- **reCAPTCHA Integration**: Protect forms against spam and bot attacks (v2 and v3 supported)
- **IP-Based Security**: Country blocking, IP whitelisting/blacklisting, and automated protection
- **Rate Limiting**: Prevent brute force attacks with configurable throttling
- **Security Audit Logs**: Detailed logging of authentication activities and security events

### User Management

- **Custom Registration**: Create beautiful registration forms with custom fields
- **Enhanced Profile Fields**: Extend user profiles with additional information
- **User Verification**: Email verification and approval workflows

### Privacy and Compliance

- **GDPR-Ready Tools**: User data export, anonymization, and erasure capabilities
- **Consent Management**: Built-in consent tracking for legal compliance
- **Data Minimization**: Configure exactly what data to collect and store

### Advanced Customization

- **Email Templating**: Fully customizable HTML emails with branding options
- **Form Styling**: Advanced style controls for all authentication forms
- **Developer API**: Extensive hooks and filters for custom integration

## Installation

### Requirements

- WordPress 5.8 or higher
- PHP 7.4 or higher
- MySQL/MariaDB 5.6 or higher
- Attributes User Access (free plugin) 1.0.0 or higher

### Installation Steps

1. Install and activate the Attributes User Access free plugin
2. Upload the `attributes-user-access-pro-lite` folder to your `/wp-content/plugins/` directory
3. Activate the plugin through the 'Plugins' menu in WordPress
4. Enter your license key in the Settings → User Access → License tab
5. Configure the additional security and authentication options

## Configuration

### Two-Factor Authentication

1. Navigate to Settings → User Access → Security
2. Enable the two-factor authentication option
3. Configure available methods (Email, Authenticator App, Recovery Codes)
4. Set user roles that require 2FA

### Password Policies

1. Navigate to Settings → User Access → Security → Password Policy
2. Configure minimum length, required character types, and expiration
3. Enable common password checking to prevent vulnerable passwords
4. Set custom password requirements message

### reCAPTCHA Integration

1. Create API keys at [Google reCAPTCHA](https://www.google.com/recaptcha/admin)
2. Navigate to Settings → User Access → Security
3. Enter your site key and secret key
4. Configure which forms should use reCAPTCHA protection

### IP Security

1. Navigate to Settings → User Access → Security → IP Management
2. Configure country restrictions, IP whitelisting, and blacklisting
3. Set rate limiting rules for different authentication actions
4. View blocked IP logs and manage manual blocks

## Developer Documentation

### Available Hooks

#### Filters

```php
// Modify password policy requirements
add_filter('attrua_password_requirements', function($requirements) {
    $requirements['min_length'] = 12; // Increase minimum length
    return $requirements;
});

// Customize two-factor authentication methods
add_filter('attrua_available_2fa_methods', function($methods) {
    // Only allow email and authenticator app
    return ['email', 'totp'];
});

// Add custom validation to registration
add_filter('attrua_validate_registration', function($errors, $user_data) {
    // Custom validation logic
    return $errors;
}, 10, 2);
```

#### Actions

```php
// Do something when two-factor is enabled for a user
add_action('attrua_2fa_enabled', function($user_id, $method) {
    // Log or notify about 2FA enablement
}, 10, 2);

// Perform custom action on successful authentication
add_action('attrua_user_authenticated', function($user, $auth_method) {
    // Custom action after successful authentication
}, 10, 2);

// Security audit event hook
add_action('attrua_security_event', function($event_type, $user_id, $details) {
    // Custom security logging or notifications
}, 10, 3);
```

### Custom Templates

You can override any template file by creating a matching structure in your theme:

```
your-theme/
└── attributes/
    └── front/
        └── forms/
            ├── login-form.php
            ├── register-form.php
            └── reset-form.php
```

### JavaScript Events

The plugin triggers various JavaScript events that you can hook into:

```javascript
// Listen for 2FA form initialization
document.addEventListener("attrua_2fa_init", function (e) {
  console.log("2FA form initialized:", e.detail);
});

// React to form submission
document.addEventListener("attrua_form_submit", function (e) {
  console.log("Form being submitted:", e.detail.formId);
});
```

## Frequently Asked Questions

### Is a license required for each site?

Yes, a single site license is valid for one WordPress installation. Multi-site licenses are available for managing multiple websites.

### Can I migrate from other authentication plugins?

Yes, we provide migration tools for several popular authentication plugins. See our documentation for specific migration guides.

### How does two-factor authentication work?

When enabled, users will complete their normal login and then be prompted for a second verification step, either through email codes, an authenticator app (like Google Authenticator or Authy), or recovery codes.

### Can I customize the appearance of the forms?

Yes, all forms can be styled through the customizer, CSS variables, or by overriding the templates in your theme.

### Does this work with WooCommerce?

Yes, the plugin integrates seamlessly with WooCommerce login, registration, and account pages.

### Is this plugin compatible with page builders?

Yes, the plugin works with major page builders including Elementor, Beaver Builder, Divi, and others.

## Support

For premium support, please visit our [support portal](https://attributeswp.com/support) with your license key.

## Changelog

### 1.0.0

- Added: Two-factor authentication with multiple methods
- Added: Advanced password policies with common password detection
- Added: reCAPTCHA integration (v2 and v3)
- Added: IP-based security with country blocking
- Added: Comprehensive security audit logging
- Added: Enhanced registration system with custom fields
- Added: Custom email templates with HTML and plain text options
- Added: Advanced form customization options
- Improved: Performance optimizations for all authentication processes
- Fixed: Various security enhancements and bug fixes

### 1.0.0

- Initial release

## Upgrade Notice

### 1.0.0

Major update with two-factor authentication, advanced security features, and improved user management. Please backup before upgrading.
