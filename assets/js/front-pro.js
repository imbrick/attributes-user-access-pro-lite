/**
 * Attributes User Access Pro - Frontend JavaScript
 *
 * Implements enhanced frontend functionality for the premium extension:
 * - Social login integration
 * - Two-factor authentication
 * - Password strength meter
 * - Login attempt limiting
 * - Enhanced security features
 * - Password reset enhancements
 *
 * @package Attributes\Assets\JS
 * @since 1.0.0
 */

(function($) {
    'use strict';

    /**
     * Frontend Pro Interface Management
     * 
     * Main class for managing the premium plugin's frontend functionality
     */
    class AttributesFrontPro {
        /**
         * Initialize the frontend interface.
         * 
         * @param {Object} config - Configuration options
         */
        constructor(config) {
            // Configuration
            this.config = $.extend({}, AttributesFrontPro.defaults, config);
            
            // Initialize components
            this.socialLogin = new SocialLogin(this.config);
            this.twoFactorAuth = new TwoFactorAuthentication(this.config);
            this.passwordStrength = new PasswordStrengthMeter(this.config);
            this.loginLimiter = new LoginLimiter(this.config);
            this.passwordReset = new PasswordReset(this.config);
            
            // Initialize events
            this.initEvents();
        }

        /**
         * Initialize event listeners
         */
        initEvents() {
            // Global events
            $(document).on('attrua_login_form_loaded', this.enhanceLoginForm.bind(this));
            $(document).on('attrua_register_form_loaded', this.enhanceRegisterForm.bind(this));
            $(document).on('attrua_reset_form_loaded', this.enhanceResetForm.bind(this));
        }

        /**
         * Enhance login form with premium features
         * 
         * @param {Event} e - Custom event
         * @param {Object} data - Event data
         */
        enhanceLoginForm(e, data) {
            const $form = data.$form;
            
            // Apply enhancements only if premium features are active
            if (this.config.premium_active) {
                this.socialLogin.initialize($form);
                this.twoFactorAuth.initialize($form);
                this.loginLimiter.initialize($form);
            }
        }

        /**
         * Enhance register form with premium features
         * 
         * @param {Event} e - Custom event
         * @param {Object} data - Event data
         */
        enhanceRegisterForm(e, data) {
            const $form = data.$form;
            
            // Apply enhancements only if premium features are active
            if (this.config.premium_active) {
                this.passwordStrength.initialize($form);
            }
        }

        /**
         * Enhance password reset form with premium features
         * 
         * @param {Event} e - Custom event
         * @param {Object} data - Event data
         */
        enhanceResetForm(e, data) {
            const $form = data.$form;
            
            // Apply enhancements only if premium features are active
            if (this.config.premium_active) {
                this.passwordReset.initialize($form);
                this.passwordStrength.initialize($form);
            }
        }
    }

    /**
     * Default configuration
     */
    AttributesFrontPro.defaults = {
        ajaxUrl: '',
        nonce: '',
        premium_active: false,
        social_login: {
            enabled: false,
            providers: []
        },
        two_factor: {
            enabled: false,
            methods: []
        },
        password_policy: {
            enabled: false,
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_number: false,
            require_special: false
        },
        login_limiter: {
            enabled: false,
            max_attempts: 5,
            lockout_time: 15
        },
        i18n: {
            error: 'An error occurred. Please try again.',
            password_weak: 'Weak',
            password_medium: 'Medium',
            password_strong: 'Strong',
            password_very_strong: 'Very Strong',
            verification_required: 'Verification code required',
            social_login_error: 'Could not connect to the selected provider. Please try again.',
            login_locked: 'Your account has been temporarily locked due to too many failed login attempts. Please try again later or reset your password.'
        }
    };

    /**
     * Social Login
     * 
     * Manages social login functionality on the frontend
     */
    class SocialLogin {
        /**
         * Initialize social login
         * 
         * @param {Object} config - Configuration options
         */
        constructor(config) {
            this.config = config;
        }

        /**
         * Initialize social login for a specific form
         * 
         * @param {jQuery} $form - Form element
         */
        initialize($form) {
            if (!this.config.social_login.enabled || !this.config.social_login.providers.length) {
                return;
            }

            // Build social login buttons
            const $container = $('<div class="attrua-social-login"></div>');
            const $heading = $('<div class="attrua-social-login-heading">Or login with</div>');
            const $buttons = $('<div class="attrua-social-login-buttons"></div>');

            // Add provider buttons
            $.each(this.config.social_login.providers, (i, provider) => {
                const $button = $(`
                    <button 
                        type="button" 
                        class="attrua-social-login-button attrua-${provider.id}-button"
                        data-provider="${provider.id}">
                        <span class="attrua-provider-icon ${provider.icon}"></span>
                        <span class="attrua-provider-name">${provider.name}</span>
                    </button>
                `);
                
                $buttons.append($button);
            });

            // Add elements to DOM
            $container.append($heading);
            $container.append($buttons);
            $form.find('.attrua-submit-button').after($container);

            // Bind click events
            $container.on('click', '.attrua-social-login-button', this.handleSocialLogin.bind(this));
        }

        /**
         * Handle social login button click
         * 
         * @param {Event} e - Click event
         */
        handleSocialLogin(e) {
            e.preventDefault();
            
            const $button = $(e.currentTarget);
            const provider = $button.data('provider');
            
            // Store original button text
            const originalText = $button.html();
            
            // Show loading state
            $button.prop('disabled', true)
                .html('<span class="attrua-loading"></span>');
            
            // Open the provider's authentication window
            const authWindow = this.openAuthWindow(provider);
            
            // Poll for auth completion
            const checkInterval = setInterval(() => {
                if (authWindow.closed) {
                    clearInterval(checkInterval);
                    
                    // Check authentication status
                    this.checkAuthStatus(provider, (success) => {
                        if (success) {
                            // Redirect to redirect_to parameter or dashboard
                            const redirectTo = this.getRedirectUrl();
                            window.location.href = redirectTo;
                        } else {
                            // Reset button state
                            $button.prop('disabled', false).html(originalText);
                            
                            // Show error
                            this.showError(this.config.i18n.social_login_error);
                        }
                    });
                }
            }, 500);
        }

        /**
         * Open authentication window for the provider
         * 
         * @param {string} provider - Provider ID
         * @returns {Window} Authentication window
         */
        openAuthWindow(provider) {
            const authUrl = `${this.config.ajaxUrl}?action=attrua_social_auth&provider=${provider}&_ajax_nonce=${this.config.nonce}`;
            return window.open(authUrl, 'attrua_social_auth', 'width=600,height=600');
        }

        /**
         * Check authentication status
         * 
         * @param {string} provider - Provider ID
         * @param {Function} callback - Callback function
         */
        checkAuthStatus(provider, callback) {
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_check_social_auth',
                    provider: provider,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    callback(response.success);
                },
                error: () => {
                    callback(false);
                }
            });
        }

        /**
         * Get redirect URL from form or default
         * 
         * @returns {string} Redirect URL
         */
        getRedirectUrl() {
            const $redirectInput = $('input[name="redirect_to"]');
            return $redirectInput.length ? $redirectInput.val() : window.location.href;
        }

        /**
         * Show error message
         * 
         * @param {string} message - Error message
         */
        showError(message) {
            const $errorContainer = $('.attrua-message-container.error');
            
            if ($errorContainer.length) {
                // Update existing error container
                $errorContainer.find('.attrua-message').text(message);
                $errorContainer.show();
            } else {
                // Create new error container
                const $newError = $(`
                    <div class="attrua-message-container error">
                        <div class="attrua-message">${message}</div>
                    </div>
                `);
                
                // Add to form
                $('.attrua-form-wrapper').prepend($newError);
            }
            
            // Scroll to error
            $('html, body').animate({
                scrollTop: $('.attrua-message-container.error').offset().top - 50
            }, 300);
        }
    }

    /**
     * Two-Factor Authentication
     * 
     * Manages two-factor authentication on the frontend
     */
    class TwoFactorAuthentication {
        /**
         * Initialize two-factor authentication
         * 
         * @param {Object} config - Configuration options
         */
        constructor(config) {
            this.config = config;
            this.authInProgress = false;
        }

        /**
         * Initialize two-factor authentication for a specific form
         * 
         * @param {jQuery} $form - Form element
         */
        initialize($form) {
            if (!this.config.two_factor.enabled) {
                return;
            }

            // Add 2FA step to login form
            $form.on('submit', this.handleLoginSubmit.bind(this));
        }

        /**
         * Handle login form submission
         * 
         * @param {Event} e - Submit event
         */
        handleLoginSubmit(e) {
            // Skip if 2FA is already in progress
            if (this.authInProgress) {
                return;
            }
            
            const $form = $(e.currentTarget);
            const username = $form.find('input[name="log"]').val();
            const password = $form.find('input[name="pwd"]').val();
            
            // Check if 2FA is required for this user
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                async: false, // Synchronous request to halt form submission
                data: {
                    action: 'attrua_check_2fa_required',
                    username: username,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success && response.data.required) {
                        // Prevent form submission
                        e.preventDefault();
                        
                        // Store auth in progress state
                        this.authInProgress = true;
                        
                        // Show 2FA form
                        this.show2FAForm($form, username, password, response.data.methods);
                    }
                }
            });
        }

        /**
         * Show two-factor authentication form
         * 
         * @param {jQuery} $form - Original login form
         * @param {string} username - Username
         * @param {string} password - Password
         * @param {Array} methods - Available 2FA methods
         */
        show2FAForm($form, username, password, methods) {
            // Hide form fields
            $form.find('.attrua-form-row').hide();
            
            // Add 2FA form
            const $twoFactorForm = $(`
                <div class="attrua-2fa-form">
                    <h3>Two-Factor Authentication</h3>
                    <p>Please enter the verification code to complete login.</p>
                    <div class="attrua-form-row">
                        <label for="attrua_2fa_code">
                            ${this.config.i18n.verification_required}
                            <span class="required">*</span>
                        </label>
                        <input type="text" 
                               id="attrua_2fa_code" 
                               class="attrua-input attrua-2fa-code" 
                               required 
                               autocomplete="one-time-code"
                               pattern="[0-9]*"
                               inputmode="numeric">
                        <div class="attrua-field-error"></div>
                    </div>
                    <div class="attrua-form-row">
                        <button type="button" class="attrua-submit-button attrua-verify-button">
                            Verify and Login
                        </button>
                    </div>
                    <div class="attrua-form-row">
                        <button type="button" class="attrua-secondary-button attrua-cancel-button">
                            Cancel
                        </button>
                    </div>
                </div>
            `);
            
            // Show available methods if more than one
            if (methods.length > 1) {
                const $methodsRow = $('<div class="attrua-form-row attrua-2fa-methods"></div>');
                const $methodsLabel = $('<label>Authentication Method</label>');
                const $methodsSelect = $('<select class="attrua-input attrua-2fa-method-select"></select>');
                
                // Add method options
                $.each(methods, (i, method) => {
                    $methodsSelect.append(`<option value="${method.id}">${method.name}</option>`);
                });
                
                $methodsRow.append($methodsLabel);
                $methodsRow.append($methodsSelect);
                
                // Insert after heading
                $twoFactorForm.find('p').after($methodsRow);
            }
            
            // Add to form
            $form.prepend($twoFactorForm);
            
            // Focus on code input
            setTimeout(() => {
                $form.find('.attrua-2fa-code').focus();
            }, 100);
            
            // Handle verify button
            $twoFactorForm.on('click', '.attrua-verify-button', () => {
                this.verify2FACode($form, username, password);
            });
            
            // Handle cancel button
            $twoFactorForm.on('click', '.attrua-cancel-button', () => {
                this.cancel2FA($form);
            });
            
            // Handle enter key
            $twoFactorForm.on('keypress', '.attrua-2fa-code', (e) => {
                if (e.which === 13) {
                    e.preventDefault();
                    this.verify2FACode($form, username, password);
                }
            });
        }

        /**
         * Verify two-factor authentication code
         * 
         * @param {jQuery} $form - Form element
         * @param {string} username - Username
         * @param {string} password - Password
         */
        verify2FACode($form, username, password) {
            const code = $form.find('.attrua-2fa-code').val().trim();
            
            if (!code) {
                this.show2FAError('Please enter the verification code.');
                return;
            }
            
            // Get selected method if multiple methods are available
            let method = null;
            const $methodSelect = $form.find('.attrua-2fa-method-select');
            if ($methodSelect.length) {
                method = $methodSelect.val();
            }
            
            // Disable verify button
            const $button = $form.find('.attrua-verify-button');
            const originalText = $button.text();
            $button.prop('disabled', true).text('Verifying...');
            
            // Verify code
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_verify_2fa',
                    username: username,
                    password: password,
                    code: code,
                    method: method,
                    redirect_to: $form.find('input[name="redirect_to"]').val() || '',
                    rememberme: $form.find('input[name="rememberme"]').is(':checked') ? 1 : 0,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        // Redirect to success URL
                        window.location.href = response.data.redirect_to || window.location.href;
                    } else {
                        // Show error
                        this.show2FAError(response.data.message || 'Invalid verification code');
                        
                        // Reset button
                        $button.prop('disabled', false).text(originalText);
                    }
                },
                error: () => {
                    // Show error
                    this.show2FAError('An error occurred. Please try again.');
                    
                    // Reset button
                    $button.prop('disabled', false).text(originalText);
                }
            });
        }

        /**
         * Cancel two-factor authentication
         * 
         * @param {jQuery} $form - Form element
         */
        cancel2FA($form) {
            // Remove 2FA form
            $form.find('.attrua-2fa-form').remove();
            
            // Show original form fields
            $form.find('.attrua-form-row').show();
            
            // Reset auth in progress state
            this.authInProgress = false;
            
            // Focus on username field
            $form.find('input[name="log"]').focus();
        }

        /**
         * Show two-factor authentication error
         * 
         * @param {string} message - Error message
         */
        show2FAError(message) {
            const $errorEl = $('.attrua-2fa-code').siblings('.attrua-field-error');
            $errorEl.text(message);
            
            // Highlight input
            $('.attrua-2fa-code').addClass('error');
            
            // Focus on input
            $('.attrua-2fa-code').focus();
        }
    }

    /**
     * Password Strength Meter
     * 
     * Provides enhanced password strength measurement and feedback
     */
    class PasswordStrengthMeter {
        /**
         * Initialize password strength meter
         * 
         * @param {Object} config - Configuration options
         */
        constructor(config) {
            this.config = config;
            this.strengthLevels = [
                { label: this.config.i18n.password_weak, class: 'weak', score: 0 },
                { label: this.config.i18n.password_medium, class: 'medium', score: 2 },
                { label: this.config.i18n.password_strong, class: 'strong', score: 3 },
                { label: this.config.i18n.password_very_strong, class: 'very-strong', score: 4 }
            ];
        }

        /**
         * Initialize password strength meter for a specific form
         * 
         * @param {jQuery} $form - Form element
         */
        initialize($form) {
            const $passwordField = $form.find('input[type="password"]').first();
            
            if (!$passwordField.length) {
                return;
            }
            
            // Create strength meter UI
            const $meter = $(`
                <div class="attrua-password-strength">
                    <div class="attrua-password-strength-meter">
                        <div class="attrua-password-strength-meter-bar"></div>
                    </div>
                    <div class="attrua-password-strength-text"></div>
                </div>
            `);
            
            // Insert after password field
            $passwordField.parent().after($meter);
            
            // Create requirements list based on policy
            if (this.config.password_policy.enabled) {
                const $requirements = $('<div class="attrua-password-requirements"></div>');
                const $requirementsList = $('<ul></ul>');
                
                // Add requirements based on policy
                if (this.config.password_policy.min_length > 0) {
                    $requirementsList.append(
                        `<li data-requirement="length">At least ${this.config.password_policy.min_length} characters long</li>`
                    );
                }
                
                if (this.config.password_policy.require_uppercase) {
                    $requirementsList.append('<li data-requirement="uppercase">Contains at least one uppercase letter</li>');
                }
                
                if (this.config.password_policy.require_lowercase) {
                    $requirementsList.append('<li data-requirement="lowercase">Contains at least one lowercase letter</li>');
                }
                
                if (this.config.password_policy.require_number) {
                    $requirementsList.append('<li data-requirement="number">Contains at least one number</li>');
                }
                
                if (this.config.password_policy.require_special) {
                    $requirementsList.append('<li data-requirement="special">Contains at least one special character</li>');
                }
                
                // Add requirements to DOM
                $requirements.append($requirementsList);
                $meter.after($requirements);
            }
            
            // Bind input event
            $passwordField.on('input', this.updateStrength.bind(this));
        }

        /**
         * Update password strength
         * 
         * @param {Event} e - Input event
         */
        updateStrength(e) {
            const $input = $(e.currentTarget);
            const password = $input.val();
            
            // Get strength score
            const score = this.calculatePasswordStrength(password);
            
            // Update strength meter
            this.updateStrengthMeter(score, password);
            
            // Update requirement checks if enabled
            if (this.config.password_policy.enabled) {
                this.updateRequirements(password);
            }
        }

        /**
         * Calculate password strength score
         * 
         * @param {string} password - Password to check
         * @returns {number} Strength score (0-4)
         */
        calculatePasswordStrength(password) {
            if (!password) {
                return 0;
            }
            
            let score = 0;
            
            // Length check
            if (password.length >= 12) {
                score += 2;
            } else if (password.length >= 8) {
                score += 1;
            }
            
            // Character variety checks
            const hasLowercase = /[a-z]/.test(password);
            const hasUppercase = /[A-Z]/.test(password);
            const hasNumbers = /\d/.test(password);
            const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
            
            if (hasLowercase) score += 0.5;
            if (hasUppercase) score += 0.5;
            if (hasNumbers) score += 0.5;
            if (hasSpecial) score += 0.5;
            
            // Combination checks
            if (hasLowercase && hasUppercase) score += 0.5;
            if ((hasLowercase || hasUppercase) && hasNumbers) score += 0.5;
            if ((hasLowercase || hasUppercase || hasNumbers) && hasSpecial) score += 0.5;
            
            // Convert to 0-4 scale
            return Math.min(4, Math.floor(score));
        }

        /**
         * Update strength meter UI
         * 
         * @param {number} score - Strength score (0-4)
         * @param {string} password - Password text
         */
        updateStrengthMeter(score, password) {
            const $meter = $('.attrua-password-strength');
            const $bar = $meter.find('.attrua-password-strength-meter-bar');
            const $text = $meter.find('.attrua-password-strength-text');
            
            // Reset classes
            $meter.removeClass('weak medium strong very-strong');
            
            // Empty password
            if (!password) {
                $bar.css('width', '0%');
                $text.text('');
                return;
            }
            
            // Get strength level
            const strengthLevel = this.strengthLevels.find(level => level.score <= score);
            
            // Update UI
            $meter.addClass(strengthLevel.class);
            $bar.css('width', `${(score + 1) * 20}%`);
            $text.text(strengthLevel.label);
        }

        /**
         * Update password requirements
         * 
         * @param {string} password - Password to check
         */
        updateRequirements(password) {
            // Length requirement
            const $lengthReq = $('[data-requirement="length"]');
            const lengthMet = password.length >= this.config.password_policy.min_length;
            this.updateRequirement($lengthReq, lengthMet);
            
            // Uppercase requirement
            const $uppercaseReq = $('[data-requirement="uppercase"]');
            if ($uppercaseReq.length) {
                const uppercaseMet = /[A-Z]/.test(password);
                this.updateRequirement($uppercaseReq, uppercaseMet);
            }
            
            // Lowercase requirement
            const $lowercaseReq = $('[data-requirement="lowercase"]');
            if ($lowercaseReq.length) {
                const lowercaseMet = /[a-z]/.test(password);
                this.updateRequirement($lowercaseReq, lowercaseMet);
            }
            
            // Number requirement
            const $numberReq = $('[data-requirement="number"]');
            if ($numberReq.length) {
                const numberMet = /\d/.test(password);
                this.updateRequirement($numberReq, numberMet);
            }
            
            // Special character requirement
            const $specialReq = $('[data-requirement="special"]');
            if ($specialReq.length) {
                const specialMet = /[!@#$%^&*(),.?":{}|<>]/.test(password);
                this.updateRequirement($specialReq, specialMet);
            }
        }

        /**
         * Update a single requirement
         * 
         * @param {jQuery} $requirement - Requirement element
         * @param {boolean} met - Whether requirement is met
         */
        updateRequirement($requirement, met) {
            if (met) {
                $requirement.addClass('met');
            } else {
                $requirement.removeClass('met');
            }
        }
    }

    /**
     * Login Limiter
     * 
     * Handles login attempt limiting and account lockouts
     */
    class LoginLimiter {
        /**
         * Initialize login limiter
         * 
         * @param {Object} config - Configuration options
         */
        constructor(config) {
            this.config = config;
        }

        /**
         * Initialize login limiter for a specific form
         * 
         * @param {jQuery} $form - Form element
         */
        initialize($form) {
            if (!this.config.login_limiter.enabled) {
                return;
            }

            // Add hidden input to track login attempts
            $form.append('<input type="hidden" name="attrua_login_limiter" value="1">');
            
            // Check if login is currently limited
            const username = $form.find('input[name="log"]').val();
            if (username) {
                this.checkLoginLimits(username, $form);
            }
            
            // Bind username field change to check limits
            $form.find('input[name="log"]').on('blur', (e) => {
                const username = $(e.currentTarget).val().trim();
                if (username) {
                    this.checkLoginLimits(username, $form);
                }
            });
        }

        /**
         * Check login limits for a username
         * 
         * @param {string} username - Username to check
         * @param {jQuery} $form - Login form
         */
        checkLoginLimits(username, $form) {
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_check_login_limits',
                    username: username,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success && response.data.locked) {
                        // Show locked message
                        this.showLockedMessage($form, response.data);
                    }
                }
            });
        }

        /**
         * Show locked account message
         * 
         * @param {jQuery} $form - Login form
         * @param {Object} data - Lock data
         */
        showLockedMessage($form, data) {
            // Disable the form
            $form.find('input, button').prop('disabled', true);
            
            // Show message
            let message = this.config.i18n.login_locked;
            
            // Add unlock time if provided
            if (data.unlock_time) {
                const unlockTime = new Date(data.unlock_time * 1000).toLocaleTimeString();
                message += ` Account will be unlocked at approximately ${unlockTime}.`;
            }
            
            // Add reset password link if provided
            if (data.reset_url) {
                message += ` <a href="${data.reset_url}">Reset your password</a>`;
            }
            
            // Show message
            const $errorContainer = $('<div class="attrua-message-container error"></div>')
                .html(`<div class="attrua-message">${message}</div>`);
            
            // Add to form
            $form.prepend($errorContainer);
        }
    }

    /**
     * Password Reset
     * 
     * Enhances the password reset functionality
     */
    class PasswordReset {
        /**
         * Initialize password reset
         * 
         * @param {Object} config - Configuration options
         */
        constructor(config) {
            this.config = config;
        }

        /**
         * Initialize password reset for a specific form
         * 
         * @param {jQuery} $form - Form element
         */
        initialize($form) {
            // Check if form is a password reset form
            const isResetForm = $form.find('input[name="rp_key"]').length > 0;
            
            if (isResetForm) {
                // This is a reset password form
                this.enhanceResetForm($form);
            } else {
                // This is a request reset form
                this.enhanceRequestForm($form);
            }
        }

        /**
         * Enhance reset password form
         * 
         * @param {jQuery} $form - Form element
         */
        enhanceResetForm($form) {
            // Add password confirmation field if not exists
            if ($form.find('input[name="password_confirm"]').length === 0) {
                const $passwordField = $form.find('input[name="pass1"]');
                const $passwordRow = $passwordField.closest('.attrua-form-row');
                
                // Create confirm password field
                const $confirmRow = $passwordRow.clone();
                $confirmRow.find('label').text('Confirm New Password');
                $confirmRow.find('input').attr({
                    'name': 'password_confirm',
                    'id': 'attrua_password_confirm',
                    'value': '',
                    'autocomplete': 'new-password'
                });
                
                // Insert after password field
                $passwordRow.after($confirmRow);
                
                // Add validation
                $form.on('submit', this.validateConfirmPassword.bind(this));
            }
            
            // Add complexity requirements based on policy
            if (this.config.password_policy.enabled) {
                // Requirements are added by the PasswordStrengthMeter
            }
        }
        
        /**
         * Enhance request password reset form
         * 
         * @param {jQuery} $form - Form element
         */
        enhanceRequestForm($form) {
            // Add an option to recover using email or username
            const $userField = $form.find('input[name="user_login"]');
            const $userRow = $userField.closest('.attrua-form-row');
            
            // Update label to clarify
            $userRow.find('label').text('Username or Email Address');
            
            // Add enhanced recovery options if configured
            if (this.config.enhanced_recovery) {
                // Add security questions recovery option if enabled
                if (this.config.enhanced_recovery.security_questions) {
                    this.addSecurityQuestionsRecovery($form);
                }
                
                // Add SMS recovery option if enabled
                if (this.config.enhanced_recovery.sms) {
                    this.addSMSRecovery($form);
                }
            }
        }
        
        /**
         * Add security questions recovery option
         * 
         * @param {jQuery} $form - Form element
         */
        addSecurityQuestionsRecovery($form) {
            // Add toggle for security question recovery
            const $toggle = $(`
                <div class="attrua-form-row attrua-recovery-toggle">
                    <a href="#" class="attrua-security-questions-toggle">Recover using security questions</a>
                </div>
            `);
            
            // Add security questions form
            const $questionsForm = $(`
                <div class="attrua-security-questions-form" style="display: none;">
                    <div class="attrua-form-row">
                        <label for="attrua_username_sq">Username</label>
                        <input type="text" id="attrua_username_sq" class="attrua-input" required>
                    </div>
                    <div class="attrua-security-questions-container">
                        <!-- Questions will be loaded dynamically -->
                    </div>
                    <div class="attrua-form-row">
                        <button type="button" class="attrua-submit-button attrua-verify-questions-button">
                            Verify Answers
                        </button>
                    </div>
                    <div class="attrua-form-row">
                        <a href="#" class="attrua-back-to-reset">Back to email reset</a>
                    </div>
                </div>
            `);
            
            // Add to form
            $form.find('.attrua-submit-button').parent().after($toggle);
            $form.append($questionsForm);
            
            // Handle toggle click
            $toggle.on('click', '.attrua-security-questions-toggle', (e) => {
                e.preventDefault();
                $form.find('.attrua-form-row').not('.attrua-recovery-toggle').hide();
                $questionsForm.show();
            });
            
            // Handle back click
            $questionsForm.on('click', '.attrua-back-to-reset', (e) => {
                e.preventDefault();
                $questionsForm.hide();
                $form.find('.attrua-form-row').not('.attrua-recovery-toggle, .attrua-security-questions-form').show();
            });
            
            // Handle username input
            $questionsForm.on('blur', '#attrua_username_sq', (e) => {
                const username = $(e.currentTarget).val().trim();
                if (username) {
                    this.loadSecurityQuestions(username);
                }
            });
            
            // Handle verify button
            $questionsForm.on('click', '.attrua-verify-questions-button', () => {
                this.verifySecurityQuestions();
            });
        }
        
        /**
         * Load security questions for a user
         * 
         * @param {string} username - Username
         */
        loadSecurityQuestions(username) {
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_get_security_questions',
                    username: username,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.renderSecurityQuestions(response.data.questions);
                    } else {
                        this.showSecurityQuestionsError(response.data.message || 'User not found or has no security questions.');
                    }
                },
                error: () => {
                    this.showSecurityQuestionsError('An error occurred while loading security questions.');
                }
            });
        }
        
        /**
         * Render security questions
         * 
         * @param {Array} questions - Security questions
         */
        renderSecurityQuestions(questions) {
            const $container = $('.attrua-security-questions-container');
            $container.empty();
            
            if (questions && questions.length > 0) {
                $.each(questions, (i, question) => {
                    $container.append(`
                        <div class="attrua-form-row">
                            <label for="attrua_sq_${i}">${question}</label>
                            <input type="text" id="attrua_sq_${i}" class="attrua-input attrua-security-answer" data-question="${i}" required>
                        </div>
                    `);
                });
            } else {
                $container.append('<p>No security questions available for this user.</p>');
                $('.attrua-verify-questions-button').prop('disabled', true);
            }
        }
        
        /**
         * Verify security questions answers
         */
        verifySecurityQuestions() {
            const username = $('#attrua_username_sq').val().trim();
            const answers = [];
            
            // Collect answers
            $('.attrua-security-answer').each(function() {
                answers.push({
                    question: $(this).data('question'),
                    answer: $(this).val().trim()
                });
            });
            
            // Validate
            if (!username || answers.length === 0) {
                this.showSecurityQuestionsError('Please enter your username and answer all security questions.');
                return;
            }
            
            // Disable button
            const $button = $('.attrua-verify-questions-button');
            const originalText = $button.text();
            $button.prop('disabled', true).text('Verifying...');
            
            // Submit
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_verify_security_questions',
                    username: username,
                    answers: answers,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        // Show password reset form
                        this.showResetPasswordForm(response.data.key, username);
                    } else {
                        // Show error
                        this.showSecurityQuestionsError(response.data.message || 'Incorrect answers. Please try again.');
                        $button.prop('disabled', false).text(originalText);
                    }
                },
                error: () => {
                    this.showSecurityQuestionsError('An error occurred while verifying your answers.');
                    $button.prop('disabled', false).text(originalText);
                }
            });
        }
        
        /**
         * Show security questions error
         * 
         * @param {string} message - Error message
         */
        showSecurityQuestionsError(message) {
            const $container = $('.attrua-security-questions-container');
            
            // Remove existing error
            $container.find('.attrua-error-message').remove();
            
            // Add error message
            $container.prepend(`<div class="attrua-error-message">${message}</div>`);
        }
        
        /**
         * Add SMS recovery option
         * 
         * @param {jQuery} $form - Form element
         */
        addSMSRecovery($form) {
            // Add toggle for SMS recovery
            const $toggle = $(`
                <div class="attrua-form-row attrua-recovery-toggle">
                    <a href="#" class="attrua-sms-toggle">Recover using SMS</a>
                </div>
            `);
            
            // Add SMS form
            const $smsForm = $(`
                <div class="attrua-sms-form" style="display: none;">
                    <div class="attrua-form-row">
                        <label for="attrua_username_sms">Username</label>
                        <input type="text" id="attrua_username_sms" class="attrua-input" required>
                    </div>
                    <div class="attrua-form-row">
                        <button type="button" class="attrua-submit-button attrua-send-sms-button">
                            Send Verification Code
                        </button>
                    </div>
                    <div class="attrua-sms-verification" style="display: none;">
                        <div class="attrua-form-row">
                            <label for="attrua_sms_code">Verification Code</label>
                            <input type="text" id="attrua_sms_code" class="attrua-input" 
                                   pattern="[0-9]*" inputmode="numeric" required>
                        </div>
                        <div class="attrua-form-row">
                            <button type="button" class="attrua-submit-button attrua-verify-sms-button">
                                Verify Code
                            </button>
                        </div>
                    </div>
                    <div class="attrua-form-row">
                        <a href="#" class="attrua-back-to-reset">Back to email reset</a>
                    </div>
                </div>
            `);
            
            // Add to form
            $form.find('.attrua-submit-button').parent().after($toggle);
            $form.append($smsForm);
            
            // Handle toggle click
            $toggle.on('click', '.attrua-sms-toggle', (e) => {
                e.preventDefault();
                $form.find('.attrua-form-row').not('.attrua-recovery-toggle').hide();
                $smsForm.show();
            });
            
            // Handle back click
            $smsForm.on('click', '.attrua-back-to-reset', (e) => {
                e.preventDefault();
                $smsForm.hide();
                $form.find('.attrua-form-row').not('.attrua-recovery-toggle, .attrua-sms-form').show();
            });
            
            // Handle send button
            $smsForm.on('click', '.attrua-send-sms-button', () => {
                const username = $('#attrua_username_sms').val().trim();
                
                if (!username) {
                    return;
                }
                
                // Disable button
                const $button = $('.attrua-send-sms-button');
                const originalText = $button.text();
                $button.prop('disabled', true).text('Sending...');
                
                // Send SMS
                $.ajax({
                    url: this.config.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'attrua_send_recovery_sms',
                        username: username,
                        _ajax_nonce: this.config.nonce
                    },
                    success: (response) => {
                        if (response.success) {
                            // Show verification form
                            $('.attrua-sms-verification').show();
                            $('#attrua_sms_code').focus();
                            
                            // Update button
                            $button.text('Resend Code').prop('disabled', false);
                        } else {
                            // Show error
                            alert(response.data.message || 'Failed to send verification code.');
                            $button.text(originalText).prop('disabled', false);
                        }
                    },
                    error: () => {
                        alert('An error occurred while sending the verification code.');
                        $button.text(originalText).prop('disabled', false);
                    }
                });
            });
            
            // Handle verify button
            $smsForm.on('click', '.attrua-verify-sms-button', () => {
                const username = $('#attrua_username_sms').val().trim();
                const code = $('#attrua_sms_code').val().trim();
                
                if (!username || !code) {
                    return;
                }
                
                // Disable button
                const $button = $('.attrua-verify-sms-button');
                const originalText = $button.text();
                $button.prop('disabled', true).text('Verifying...');
                
                // Verify code
                $.ajax({
                    url: this.config.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'attrua_verify_recovery_sms',
                        username: username,
                        code: code,
                        _ajax_nonce: this.config.nonce
                    },
                    success: (response) => {
                        if (response.success) {
                            // Show password reset form
                            this.showResetPasswordForm(response.data.key, username);
                        } else {
                            // Show error
                            alert(response.data.message || 'Invalid verification code.');
                            $button.text(originalText).prop('disabled', false);
                        }
                    },
                    error: () => {
                        alert('An error occurred while verifying the code.');
                        $button.text(originalText).prop('disabled', false);
                    }
                });
            });
        }
        
        /**
         * Show reset password form
         * 
         * @param {string} key - Reset key
         * @param {string} username - Username
         */
        showResetPasswordForm(key, username) {
            // Create reset form
            const $resetForm = $(`
                <div class="attrua-form-wrapper">
                    <h2>Reset Your Password</h2>
                    <p>Create a new password for your account.</p>
                    <form class="attrua-reset-form">
                        <input type="hidden" name="rp_key" value="${key}">
                        <input type="hidden" name="rp_login" value="${username}">
                        
                        <div class="attrua-form-row">
                            <label for="attrua_new_password">New Password</label>
                            <input type="password" id="attrua_new_password" name="pass1" class="attrua-input" required>
                        </div>
                        
                        <div class="attrua-form-row">
                            <label for="attrua_confirm_password">Confirm New Password</label>
                            <input type="password" id="attrua_confirm_password" name="password_confirm" class="attrua-input" required>
                        </div>
                        
                        <div class="attrua-form-row">
                            <button type="submit" class="attrua-submit-button">Reset Password</button>
                        </div>
                    </form>
                </div>
            `);
            
            // Replace current form with reset form
            $('.attrua-form-wrapper').replaceWith($resetForm);
            
            // Initialize password strength meter
            new PasswordStrengthMeter(this.config).initialize($resetForm.find('form'));
            
            // Add form submission handler
            $resetForm.find('form').on('submit', (e) => {
                e.preventDefault();
                
                // Validate passwords
                const password = $('#attrua_new_password').val();
                const confirmPassword = $('#attrua_confirm_password').val();
                
                if (password !== confirmPassword) {
                    alert('Passwords do not match.');
                    return;
                }
                
                // Submit new password
                $.ajax({
                    url: this.config.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'attrua_reset_password',
                        key: key,
                        login: username,
                        password: password,
                        _ajax_nonce: this.config.nonce
                    },
                    success: (response) => {
                        if (response.success) {
                            // Show success message
                            $resetForm.html(`
                                <div class="attrua-message-container success">
                                    <div class="attrua-message">
                                        <p>Your password has been reset successfully.</p>
                                        <p><a href="${response.data.login_url}">Log in with your new password</a></p>
                                    </div>
                                </div>
                            `);
                        } else {
                            // Show error
                            alert(response.data.message || 'Failed to reset password.');
                        }
                    },
                    error: () => {
                        alert('An error occurred while resetting your password.');
                    }
                });
            });
        }
        
        /**
         * Validate confirm password
         * 
         * @param {Event} e - Submit event
         */
        validateConfirmPassword(e) {
            const $password = $('input[name="pass1"]');
            const $confirm = $('input[name="password_confirm"]');
            
            if ($password.val() !== $confirm.val()) {
                e.preventDefault();
                
                // Show error
                const $error = $confirm.siblings('.attrua-field-error');
                
                if ($error.length) {
                    $error.text('Passwords do not match.');
                } else {
                    $confirm.after('<div class="attrua-field-error">Passwords do not match.</div>');
                }
                
                // Focus on confirm field
                $confirm.focus();
            }
        }
    }

    // Initialize frontend interface on document ready
    $(document).ready(function() {
        // Create event for forms to trigger when they're fully loaded
        $('.attrua-login-form').each(function() {
            $(document).trigger('attrua_login_form_loaded', { $form: $(this) });
        });
        
        $('.attrua-register-form').each(function() {
            $(document).trigger('attrua_register_form_loaded', { $form: $(this) });
        });
        
        $('.attrua-reset-form').each(function() {
            $(document).trigger('attrua_reset_form_loaded', { $form: $(this) });
        });
        
        // Initialize frontend interface
        window.attruaFrontPro = new AttributesFrontPro(window.attruaProConfig || {});
    });

})(jQuery);