/** 
 * Attributes User Access Pro - Admin JavaScript
 *
 * Implements enhanced admin JavaScript functionality for the premium extension:
 * - Security dashboard 
 * - IP management
 * - Audit log interface
 * - Two-factor authentication management
 * - Email template previews
 * - License management
 *
 * @package Attributes\Assets\JS
 * @since 1.0.0
 */

(function($) {
    'use strict';

    /**
     * Admin Pro Interface Management
     * 
     * Main class for managing the premium plugin's admin interface functionality
     */
    class AttributesAdminPro {
        /**
         * Initialize the admin interface.
         * 
         * @param {Object} config - Configuration options
         */
        constructor(config) {
            // Configuration
            this.config = $.extend({}, AttributesAdminPro.defaults, config);
            
            // Initialize components
            this.licenseManager = new LicenseManager(this.config);
            this.securityDashboard = new SecurityDashboard(this.config);
            this.ipManager = new IPManager(this.config);
            this.auditLog = new AuditLog(this.config);
            this.twoFactorManager = new TwoFactorManager(this.config);
            this.emailTemplateManager = new EmailTemplateManager(this.config);
            this.passwordPolicy = new PasswordPolicy(this.config);
            
            // Initialize events
            this.initEvents();
        }

        /**
         * Initialize event listeners
         */
        initEvents() {
            // Tab navigation
            $('.attrua-pro-tabs .nav-tab').on('click', this.handleTabClick.bind(this));
            
            // Initialize the active tab
            this.initActiveTab();
        }

        /**
         * Initialize the active tab based on URL or default
         */
        initActiveTab() {
            // Get tab from URL hash or use default
            const urlParams = new URLSearchParams(window.location.search);
            const activeTab = urlParams.get('tab') || 'dashboard';
            
            // Activate the correct tab
            $(`.attrua-pro-tabs .nav-tab[data-tab="${activeTab}"]`).addClass('nav-tab-active');
            $(`.attrua-tab-content[data-tab="${activeTab}"]`).show();
            
            // Hide other tabs
            $(`.attrua-tab-content:not([data-tab="${activeTab}"])`).hide();
        }

        /**
         * Handle tab click events
         * 
         * @param {Event} e - Click event
         */
        handleTabClick(e) {
            e.preventDefault();
            
            const $tab = $(e.currentTarget);
            const tabId = $tab.data('tab');
            
            // Update URL without reloading
            const url = new URL(window.location);
            url.searchParams.set('tab', tabId);
            window.history.pushState({}, '', url);
            
            // Update active tab
            $('.attrua-pro-tabs .nav-tab').removeClass('nav-tab-active');
            $tab.addClass('nav-tab-active');
            
            // Show selected tab content, hide others
            $('.attrua-tab-content').hide();
            $(`.attrua-tab-content[data-tab="${tabId}"]`).show();
            
            // Trigger tab change event for components to respond
            $(document).trigger('attrua_tab_changed', [tabId]);
        }
    }

    /**
     * Default configuration
     */
    AttributesAdminPro.defaults = {
        ajaxUrl: '',
        nonce: '',
        i18n: {
            confirmDelete: 'Are you sure you want to delete this item?',
            confirmReset: 'Are you sure you want to reset this setting? This action cannot be undone.',
            saveSuccess: 'Settings saved successfully.',
            saveError: 'Error saving settings.',
            testSuccess: 'Test completed successfully.',
            testError: 'Test failed. Please check your settings.'
        }
    };

    /**
     * License Manager
     * 
     * Handles license activation, deactivation, and status checking
     */
    class LicenseManager {
        /**
         * Initialize license manager
         * 
         * @param {Object} config - Configuration options
         */
        constructor(config) {
            this.config = config;
            this.initEvents();
        }

        /**
         * Initialize event listeners
         */
        initEvents() {
            // License key toggle visibility
            $('.attrua-license-toggle').on('click', this.toggleLicenseVisibility.bind(this));
            
            // License activation
            $('#attrua-activate-license').on('click', this.activateLicense.bind(this));
            
            // License deactivation
            $('#attrua-deactivate-license').on('click', this.deactivateLicense.bind(this));
            
            // Check license status on tab change
            $(document).on('attrua_tab_changed', (e, tab) => {
                if (tab === 'license') {
                    this.checkLicenseStatus();
                }
            });
        }

        /**
         * Toggle license key visibility
         * 
         * @param {Event} e - Click event
         */
        toggleLicenseVisibility(e) {
            e.preventDefault();
            
            const $input = $('.attrua-license-key');
            const $button = $(e.currentTarget);
            
            if ($input.attr('type') === 'password') {
                $input.attr('type', 'text');
                $button.html('<span class="dashicons dashicons-hidden"></span>');
            } else {
                $input.attr('type', 'password');
                $button.html('<span class="dashicons dashicons-visibility"></span>');
            }
        }

        /**
         * Activate license
         * 
         * @param {Event} e - Click event
         */
        activateLicense(e) {
            e.preventDefault();
            
            const licenseKey = $('.attrua-license-key').val().trim();
            
            if (!licenseKey) {
                this.showNotice('Please enter a license key.', 'error');
                return;
            }
            
            // Disable the button and show loading state
            const $button = $(e.currentTarget);
            const originalText = $button.text();
            $button.prop('disabled', true).text('Activating...');
            
            // Send activation request
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_activate_license',
                    license_key: licenseKey,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.showNotice('License activated successfully.', 'success');
                        this.updateLicenseStatus(response.data);
                    } else {
                        this.showNotice(response.data.message || 'Failed to activate license.', 'error');
                    }
                },
                error: () => {
                    this.showNotice('Network error occurred. Please try again.', 'error');
                },
                complete: () => {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        }

        /**
         * Deactivate license
         * 
         * @param {Event} e - Click event
         */
        deactivateLicense(e) {
            e.preventDefault();
            
            if (!confirm('Are you sure you want to deactivate this license?')) {
                return;
            }
            
            // Disable the button and show loading state
            const $button = $(e.currentTarget);
            const originalText = $button.text();
            $button.prop('disabled', true).text('Deactivating...');
            
            // Send deactivation request
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_deactivate_license',
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.showNotice('License deactivated successfully.', 'success');
                        this.updateLicenseStatus(response.data);
                    } else {
                        this.showNotice(response.data.message || 'Failed to deactivate license.', 'error');
                    }
                },
                error: () => {
                    this.showNotice('Network error occurred. Please try again.', 'error');
                },
                complete: () => {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        }

        /**
         * Check license status
         */
        checkLicenseStatus() {
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_check_license',
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.updateLicenseStatus(response.data);
                    }
                }
            });
        }

        /**
         * Update license status in the UI
         * 
         * @param {Object} data - License data
         */
        updateLicenseStatus(data) {
            const $status = $('.attrua-license-status');
            const $details = $('.attrua-license-details');
            
            // Update status label and class
            $status.removeClass('active inactive expired').addClass(data.status);
            $status.text(data.status_label);
            
            // Update details
            if (data.is_active) {
                $('#attrua-activate-license').hide();
                $('#attrua-deactivate-license').show();
                
                $details.html(`
                    <p><span class="label">Customer:</span> ${data.customer_name}</p>
                    <p><span class="label">Plan:</span> ${data.plan_name}</p>
                    <p><span class="label">Expires:</span> ${data.expires}</p>
                    <p><span class="label">Sites:</span> ${data.sites_active} / ${data.sites_limit}</p>
                `);
                $details.show();
            } else {
                $('#attrua-activate-license').show();
                $('#attrua-deactivate-license').hide();
                $details.hide();
            }
        }

        /**
         * Show notice message
         * 
         * @param {string} message - Notice message
         * @param {string} type - Notice type (success, error)
         */
        showNotice(message, type) {
            const $notice = $('<div class="notice notice-' + type + ' is-dismissible"><p>' + message + '</p></div>');
            $('.attrua-license-notices').html($notice);
            
            // Add dismiss button
            $notice.append('<button type="button" class="notice-dismiss"><span class="screen-reader-text">Dismiss this notice.</span></button>');
            
            // Handle dismiss
            $notice.find('.notice-dismiss').on('click', function() {
                $(this).parent().fadeOut(300, function() {
                    $(this).remove();
                });
            });
        }
    }

    /**
     * Security Dashboard
     * 
     * Displays security metrics and status information
     */
    class SecurityDashboard {
        /**
         * Initialize security dashboard
         * 
         * @param {Object} config - Configuration options
         */
        constructor(config) {
            this.config = config;
            this.initEvents();
            this.loadDashboardData();
        }

        /**
         * Initialize event listeners
         */
        initEvents() {
            // Refresh dashboard button
            $('#attrua-refresh-security').on('click', this.loadDashboardData.bind(this));
            
            // Reload dashboard on tab change
            $(document).on('attrua_tab_changed', (e, tab) => {
                if (tab === 'dashboard') {
                    this.loadDashboardData();
                }
            });
        }

        /**
         * Load dashboard data
         */
        loadDashboardData() {
            $('.attrua-security-dashboard').addClass('loading');
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_get_security_stats',
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.updateDashboard(response.data);
                    } else {
                        console.error('Failed to load security data');
                    }
                },
                error: () => {
                    console.error('Network error loading security data');
                },
                complete: () => {
                    $('.attrua-security-dashboard').removeClass('loading');
                }
            });
        }

        /**
         * Update dashboard with new data
         * 
         * @param {Object} data - Dashboard data
         */
        updateDashboard(data) {
            // Update security score
            $('#attrua-security-score').text(data.security_score + '%');
            
            // Update feature statuses
            $('.attrua-security-feature').each(function() {
                const feature = $(this).data('feature');
                const status = data.features[feature] || 'inactive';
                
                $(this).find('.status')
                    .removeClass('active inactive warning')
                    .addClass(status);
            });
            
            // Update metrics
            $('#attrua-login-attempts').text(data.login_attempts);
            $('#attrua-blocked-ips').text(data.blocked_ips);
            $('#attrua-active-users').text(data.active_users);
            
            // Update recent events
            const $events = $('#attrua-recent-events');
            $events.empty();
            
            if (data.recent_events && data.recent_events.length > 0) {
                $.each(data.recent_events, function(i, event) {
                    $events.append(`
                        <div class="attrua-event">

                        <div class="event-time">${event.time}</div>
                        <div class="event-type">${event.type}</div>
                        <div class="event-description">${event.description}</div>
                    </div>
                    `);
                });
            } else {
                $events.append('<div class="attrua-no-events">No recent events found.</div>');
            }
        }
    }

    /**
     * IP Manager
     * 
     * Manages IP blocking, whitelisting, and country restrictions
     */
    class IPManager {
        /**
         * Initialize IP manager
         * 
         * @param {Object} config - Configuration options
         */
        constructor(config) {
            this.config = config;
            this.initEvents();
        }

        /**
         * Initialize event listeners
         */
        initEvents() {
            // Add IP to blacklist
            $('#attrua-add-to-blacklist').on('click', this.addToBlacklist.bind(this));
            
            // Add IP to whitelist
            $('#attrua-add-to-whitelist').on('click', this.addToWhitelist.bind(this));
            
            // Remove IP from lists
            $(document).on('click', '.attrua-remove-ip', this.removeIP.bind(this));
            
            // Country selection
            $('.attrua-country-select').on('change', this.handleCountrySelection.bind(this));
            
            // Remove country
            $(document).on('click', '.attrua-country-item .remove', this.removeCountry.bind(this));
            
            // Load data on tab change
            $(document).on('attrua_tab_changed', (e, tab) => {
                if (tab === 'ip_management') {
                    this.loadIPLists();
                }
            });
        }

        /**
         * Add IP to blacklist
         * 
         * @param {Event} e - Click event
         */
        addToBlacklist(e) {
            e.preventDefault();
            
            const ip = $('#attrua-blacklist-ip').val().trim();
            const reason = $('#attrua-blacklist-reason').val().trim();
            
            if (!ip) {
                alert('Please enter an IP address.');
                return;
            }
            
            // Send request to add IP to blacklist
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_add_to_blacklist',
                    ip: ip,
                    reason: reason,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.loadIPLists();
                        $('#attrua-blacklist-ip').val('');
                        $('#attrua-blacklist-reason').val('');
                    } else {
                        alert(response.data.message || 'Failed to add IP to blacklist.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                }
            });
        }

        /**
         * Add IP to whitelist
         * 
         * @param {Event} e - Click event
         */
        addToWhitelist(e) {
            e.preventDefault();
            
            const ip = $('#attrua-whitelist-ip').val().trim();
            
            if (!ip) {
                alert('Please enter an IP address.');
                return;
            }
            
            // Send request to add IP to whitelist
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_add_to_whitelist',
                    ip: ip,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.loadIPLists();
                        $('#attrua-whitelist-ip').val('');
                    } else {
                        alert(response.data.message || 'Failed to add IP to whitelist.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                }
            });
        }

        /**
         * Remove IP from list
         * 
         * @param {Event} e - Click event
         */
        removeIP(e) {
            e.preventDefault();
            
            if (!confirm(this.config.i18n.confirmDelete)) {
                return;
            }
            
            const $entry = $(e.currentTarget).closest('.attrua-ip-entry');
            const ip = $entry.data('ip');
            const list = $entry.closest('.attrua-ip-list').data('list');
            
            // Send request to remove IP
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_remove_from_ip_list',
                    ip: ip,
                    list: list,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        $entry.fadeOut(300, function() {
                            $(this).remove();
                        });
                        
                        // Update count
                        const $count = $entry.closest('.attrua-ip-list').find('.count');
                        $count.text(parseInt($count.text()) - 1);
                    } else {
                        alert(response.data.message || 'Failed to remove IP from list.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                }
            });
        }

        /**
         * Handle country selection
         * 
         * @param {Event} e - Change event
         */
        handleCountrySelection(e) {
            const $select = $(e.currentTarget);
            const country = $select.val();
            const listType = $select.data('list');
            
            if (!country) {
                return;
            }
            
            // Reset select
            $select.val('');
            
            // Send request to add country
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_add_country_to_list',
                    country: country,
                    list: listType,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.loadCountryLists();
                    } else {
                        alert(response.data.message || 'Failed to add country to list.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                }
            });
        }

        /**
         * Remove country from list
         * 
         * @param {Event} e - Click event
         */
        removeCountry(e) {
            e.preventDefault();
            
            if (!confirm(this.config.i18n.confirmDelete)) {
                return;
            }
            
            const $item = $(e.currentTarget).closest('.attrua-country-item');
            const country = $item.data('country');
            const list = $item.closest('.attrua-country-list').data('list');
            
            // Send request to remove country
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_remove_country_from_list',
                    country: country,
                    list: list,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        $item.fadeOut(300, function() {
                            $(this).remove();
                        });
                    } else {
                        alert(response.data.message || 'Failed to remove country from list.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                }
            });
        }

        /**
         * Load IP lists
         */
        loadIPLists() {
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_get_ip_lists',
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.updateIPLists(response.data);
                    } else {
                        console.error('Failed to load IP lists');
                    }
                },
                error: () => {
                    console.error('Network error loading IP lists');
                }
            });
            
            // Also load country lists
            this.loadCountryLists();
        }

        /**
         * Update IP lists in the UI
         * 
         * @param {Object} data - IP list data
         */
        updateIPLists(data) {
            // Update blacklist
            const $blacklist = $('#attrua-blacklist-entries');
            $blacklist.empty();
            
            if (data.blacklist && data.blacklist.length > 0) {
                $.each(data.blacklist, function(i, entry) {
                    $blacklist.append(`
                        <div class="attrua-ip-entry" data-ip="${entry.ip}">
                            <div>
                                <span class="ip">${entry.ip}</span>
                                ${entry.reason ? `<span class="reason">${entry.reason}</span>` : ''}
                            </div>
                            <div class="actions">
                                <button type="button" class="attrua-remove-ip" title="Remove">
                                    <span class="dashicons dashicons-no-alt"></span>
                                </button>
                            </div>
                        </div>
                    `);
                });
                
                // Update count
                $('.attrua-blacklist .count').text(data.blacklist.length);
            } else {
                $blacklist.append('<div class="attrua-no-entries">No blacklisted IPs found.</div>');
                $('.attrua-blacklist .count').text('0');
            }
            
            // Update whitelist
            const $whitelist = $('#attrua-whitelist-entries');
            $whitelist.empty();
            
            if (data.whitelist && data.whitelist.length > 0) {
                $.each(data.whitelist, function(i, entry) {
                    $whitelist.append(`
                        <div class="attrua-ip-entry" data-ip="${entry.ip}">
                            <div>
                                <span class="ip">${entry.ip}</span>
                            </div>
                            <div class="actions">
                                <button type="button" class="attrua-remove-ip" title="Remove">
                                    <span class="dashicons dashicons-no-alt"></span>
                                </button>
                            </div>
                        </div>
                    `);
                });
                
                // Update count
                $('.attrua-whitelist .count').text(data.whitelist.length);
            } else {
                $whitelist.append('<div class="attrua-no-entries">No whitelisted IPs found.</div>');
                $('.attrua-whitelist .count').text('0');
            }
        }

        /**
         * Load country lists
         */
        loadCountryLists() {
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_get_country_lists',
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.updateCountryLists(response.data);
                    } else {
                        console.error('Failed to load country lists');
                    }
                },
                error: () => {
                    console.error('Network error loading country lists');
                }
            });
        }

        /**
         * Update country lists in the UI
         * 
         * @param {Object} data - Country list data
         */
        updateCountryLists(data) {
            // Update whitelist
            const $whitelistBody = $('.attrua-country-whitelist .attrua-country-list-body');
            $whitelistBody.empty();
            
            if (data.whitelist && data.whitelist.length > 0) {
                $.each(data.whitelist, function(i, country) {
                    $whitelistBody.append(`
                        <div class="attrua-country-item" data-country="${country.code}">
                            <div class="flag">${country.flag}</div>
                            <div class="code">${country.code}</div>
                            <div class="name">${country.name}</div>
                            <button type="button" class="remove" title="Remove">×</button>
                        </div>
                    `);
                });
            } else {
                $whitelistBody.append('<div class="attrua-no-countries">No countries added.</div>');
            }
            
            // Update blacklist
            const $blacklistBody = $('.attrua-country-blacklist .attrua-country-list-body');
            $blacklistBody.empty();
            
            if (data.blacklist && data.blacklist.length > 0) {
                $.each(data.blacklist, function(i, country) {
                    $blacklistBody.append(`
                        <div class="attrua-country-item" data-country="${country.code}">
                            <div class="flag">${country.flag}</div>
                            <div class="code">${country.code}</div>
                            <div class="name">${country.name}</div>
                            <button type="button" class="remove" title="Remove">×</button>
                        </div>
                    `);
                });
            } else {
                $blacklistBody.append('<div class="attrua-no-countries">No countries added.</div>');
            }
        }
    }

    /**
     * Audit Log
     * 
     * Manages security audit log viewing and filtering
     */
    class AuditLog {
        /**
         * Initialize audit log manager
         * 
         * @param {Object} config - Configuration options
         */
        constructor(config) {
            this.config = config;
            this.currentPage = 1;
            this.filters = {};
            this.initEvents();
        }

        /**
         * Initialize event listeners
         */
        initEvents() {
            // Apply filters
            $('#attrua-audit-filter-apply').on('click', this.applyFilters.bind(this));
            
            // Reset filters
            $('#attrua-audit-filter-reset').on('click', this.resetFilters.bind(this));
            
            // Pagination
            $(document).on('click', '.attrua-audit-log-pagination button', this.handlePagination.bind(this));
            
            // Export logs
            $('#attrua-export-logs').on('click', this.exportLogs.bind(this));
            
            // Clear logs
            $('#attrua-clear-logs').on('click', this.clearLogs.bind(this));
            
            // Load logs on tab change
            $(document).on('attrua_tab_changed', (e, tab) => {
                if (tab === 'audit_log') {
                    this.loadLogs();
                }
            });
        }

        /**
         * Apply filters to audit log
         * 
         * @param {Event} e - Click event
         */
        applyFilters(e) {
            e.preventDefault();
            
            this.filters = {
                event_type: $('#attrua-filter-event-type').val(),
                user_id: $('#attrua-filter-user').val(),
                ip: $('#attrua-filter-ip').val(),
                date_from: $('#attrua-filter-date-from').val(),
                date_to: $('#attrua-filter-date-to').val()
            };
            
            this.currentPage = 1;
            this.loadLogs();
        }

        /**
         * Reset filters
         * 
         * @param {Event} e - Click event
         */
        resetFilters(e) {
            e.preventDefault();
            
            // Clear filter inputs
            $('#attrua-filter-event-type').val('');
            $('#attrua-filter-user').val('');
            $('#attrua-filter-ip').val('');
            $('#attrua-filter-date-from').val('');
            $('#attrua-filter-date-to').val('');
            
            this.filters = {};
            this.currentPage = 1;
            this.loadLogs();
        }

        /**
         * Handle pagination
         * 
         * @param {Event} e - Click event
         */
        handlePagination(e) {
            e.preventDefault();
            
            const $button = $(e.currentTarget);
            const page = $button.data('page');
            
            if (page === 'prev') {
                this.currentPage = Math.max(1, this.currentPage - 1);
            } else if (page === 'next') {
                this.currentPage += 1;
            } else {
                this.currentPage = parseInt(page);
            }
            
            this.loadLogs();
        }

        /**
         * Export logs
         * 
         * @param {Event} e - Click event
         */
        exportLogs(e) {
            e.preventDefault();
            
            const format = $('#attrua-export-format').val();
            
            // Generate request URL with current filters
            let url = this.config.ajaxUrl + `?action=attrua_export_logs&_ajax_nonce=${this.config.nonce}&format=${format}`;
            
            // Add filters if any
            if (this.filters.event_type) url += `&event_type=${this.filters.event_type}`;
            if (this.filters.user_id) url += `&user_id=${this.filters.user_id}`;
            if (this.filters.ip) url += `&ip=${this.filters.ip}`;
            if (this.filters.date_from) url += `&date_from=${this.filters.date_from}`;
            if (this.filters.date_to) url += `&date_to=${this.filters.date_to}`;
            
            // Trigger download
            window.location.href = url;
        }

        /**
         * Clear logs
         * 
         * @param {Event} e - Click event
         */
        clearLogs(e) {
            e.preventDefault();
            
            if (!confirm('Are you sure you want to clear the audit logs? This action cannot be undone.')) {
                return;
            }
            
            const olderThan = $('#attrua-clear-older-than').val();
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_clear_logs',
                    older_than: olderThan,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        alert(response.data.message || 'Logs cleared successfully.');
                        this.loadLogs();
                    } else {
                        alert(response.data.message || 'Failed to clear logs.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                }
            });
        }

        /**
         * Load audit logs
         */
        loadLogs() {
            const $container = $('.attrua-audit-log-container');
            $container.addClass('loading');
            
            // Prepare data
            const data = {
                action: 'attrua_get_audit_logs',
                _ajax_nonce: this.config.nonce,
                page: this.currentPage,
                per_page: 20,
                ...this.filters
            };
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: data,
                success: (response) => {
                    if (response.success) {
                        this.updateLogTable(response.data);
                    } else {
                        console.error('Failed to load audit logs');
                    }
                },
                error: () => {
                    console.error('Network error loading audit logs');
                },
                complete: () => {
                    $container.removeClass('loading');
                }
            });
        }

        /**
         * Update log table with new data
         * 
         * @param {Object} data - Log data
         */
        updateLogTable(data) {
            const $tbody = $('.attrua-audit-log-table tbody');
            $tbody.empty();
            
            if (data.logs && data.logs.length > 0) {
                $.each(data.logs, function(i, log) {
                    $tbody.append(`
                        <tr>
                            <td class="event-time">${log.time}</td>
                            <td class="event-type">${log.event_type}</td>
                            <td>${log.username || 'N/A'}</td>
                            <td>${log.ip || 'N/A'}</td>
                            <td>${log.country || 'N/A'}</td>
                            <td>${log.data ? '<button type="button" class="attrua-view-details" data-details="' + encodeURIComponent(JSON.stringify(log.data)) + '">View</button>' : 'N/A'}</td>
                        </tr>
                    `);
                });
            } else {
                $tbody.append('<tr><td colspan="6" class="attrua-no-logs">No logs found.</td></tr>');
            }
            
            // Update pagination
            this.updatePagination(data.total, data.pages);
        }

        /**
         * Update pagination controls
         * 
         * @param {number} total - Total number of logs
         * @param {number} pages - Total number of pages
         */
        updatePagination(total, pages) {
            const $pagination = $('.attrua-audit-log-pagination');
            
            // Update info text
            $('.pagination-info').text(`Showing page ${this.currentPage} of ${pages} (${total} logs total)`);
            
            // Clear pagination links
            const $links = $('.pagination-links');
            $links.empty();
            
            // Previous button
            if (this.currentPage > 1) {
                $links.append('<button type="button" data-page="prev">Previous</button>');
            }
            
            // Page numbers
            const startPage = Math.max(1, this.currentPage - 2);
            const endPage = Math.min(pages, startPage + 4);
            
            for (let i = startPage; i <= endPage; i++) {
                $links.append(`<button type="button" data-page="${i}" class="${i === this.currentPage ? 'current' : ''}">${i}</button>`);
            }
            
            // Next button
            if (this.currentPage < pages) {
                $links.append('<button type="button" data-page="next">Next</button>');
            }
        }
    }

    /**
     * Two-Factor Authentication Manager
     * 
     * Manages 2FA methods and settings
     */
    class TwoFactorManager {
        /**
         * Initialize 2FA manager
         * 
         * @param {Object} config - Configuration options
         */
        constructor(config) {
            this.config = config;
            this.initEvents();
        }

        /**
         * Initialize event listeners
         */
        initEvents() {
            // Toggle 2FA methods
            $('.attrua-2fa-method .toggle-switch input').on('change', this.toggle2FAMethod.bind(this));
            
            // Generate QR code
            $('#attrua-generate-qr').on('click', this.generateQRCode.bind(this));
            
            // Verify TOTP
            $('#attrua-verify-totp').on('click', this.verifyTOTP.bind(this));
            
            // Generate recovery codes
            $('#attrua-generate-recovery-codes').on('click', this.generateRecoveryCodes.bind(this));
            
            // Print recovery codes
            $('#attrua-print-recovery-codes').on('click', this.printRecoveryCodes.bind(this));
            
            // Load 2FA settings on tab change
            $(document).on('attrua_tab_changed', (e, tab) => {
                if (tab === 'two_factor') {
                    this.load2FASettings();
                }
            });
        }

        /**
         * Toggle 2FA method
         * 
         * @param {Event} e - Change event
         */
        toggle2FAMethod(e) {
            const $checkbox = $(e.currentTarget);
            const method = $checkbox.data('method');
            const enabled = $checkbox.prop('checked');
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_toggle_2fa_method',
                    method: method,
                    enabled: enabled ? 1 : 0,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        // Update UI based on response
                        if (response.data.reload) {
                            this.load2FASettings();
                        }
                    } else {
                        alert(response.data.message || 'Failed to update 2FA settings.');
                        $checkbox.prop('checked', !enabled);
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                    $checkbox.prop('checked', !enabled);
                }
            });
        }

        /**
         * Generate QR code for TOTP setup
         * 
         * @param {Event} e - Click event
         */
        generateQRCode(e) {
            e.preventDefault();
            
            const $button = $(e.currentTarget);
            const originalText = $button.text();
            $button.prop('disabled', true).text('Generating...');
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_generate_totp_qr',
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        // Update QR code and secret
                        $('#attrua-2fa-qr').html(response.data.qr_code);
                        $('#attrua-2fa-secret').text(response.data.secret);
                        $('.attrua-2fa-verify').show();
                    } else {
                        alert(response.data.message || 'Failed to generate QR code.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                },
                complete: () => {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        }

        /**
         * Verify TOTP code
         * 
         * @param {Event} e - Click event
         */
        verifyTOTP(e) {
            e.preventDefault();
            
            const code = $('#attrua-totp-code').val().trim();
            
            if (!code) {
                alert('Please enter the verification code.');
                return;
            }
            
            const $button = $(e.currentTarget);
            const originalText = $button.text();
            $button.prop('disabled', true).text('Verifying...');
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_verify_totp',
                    code: code,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        alert('TOTP verification successful! Two-factor authentication has been enabled.');
                        this.load2FASettings();
                    } else {
                        alert(response.data.message || 'Invalid verification code. Please try again.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                },
                complete: () => {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        }

        /**
         * Generate recovery codes
         * 
         * @param {Event} e - Click event
         */
        generateRecoveryCodes(e) {
            e.preventDefault();
            
            if (!confirm('This will replace any existing recovery codes. Continue?')) {
                return;
            }
            
            const $button = $(e.currentTarget);
            const originalText = $button.text();
            $button.prop('disabled', true).text('Generating...');
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_generate_recovery_codes',
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        // Update recovery codes
                        const $codesList = $('#attrua-recovery-codes-list');
                        $codesList.empty();
                        
                        $.each(response.data.codes, function(i, code) {
                            $codesList.append(`<li>${code}</li>`);
                        });
                        
                        $('.attrua-recovery-codes').show();
                    } else {
                        alert(response.data.message || 'Failed to generate recovery codes.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                },
                complete: () => {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        }

        /**
         * Print recovery codes
         * 
         * @param {Event} e - Click event
         */
        printRecoveryCodes(e) {
            e.preventDefault();
            
            const content = document.getElementById('attrua-recovery-codes-content');
            const printWindow = window.open('', '_blank');
            
            printWindow.document.write(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Two-Factor Authentication Recovery Codes</title>
                    <style>
                        body { font-family: sans-serif; padding: 20px; }
                        h1 { font-size: 18px; }
                        ul { list-style: none; padding: 0; }
                        li { font-family: monospace; padding: 5px 0; border-bottom: 1px solid #eee; }
                        .note { margin-top: 20px; font-size: 12px; color: #666; }
                    </style>
                </head>
                <body>
                    <h1>Two-Factor Authentication Recovery Codes</h1>
                    <p>Keep these codes in a safe place. Each code can only be used once.</p>
                    ${content.innerHTML}
                    <div class="note">
                        <p>Print date: ${new Date().toLocaleDateString()}</p>
                        <p>These codes can be used to access your account if you lose access to your authentication device.</p>
                    </div>
    </body>
                </html>
            `);
            
            printWindow.document.close();
            printWindow.focus();
            printWindow.print();
            setTimeout(() => printWindow.close(), 500);
        }
        
        /**
         * Load 2FA settings
         */
        load2FASettings() {
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_get_2fa_settings',
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.update2FASettings(response.data);
                    } else {
                        console.error('Failed to load 2FA settings');
                    }
                },
                error: () => {
                    console.error('Network error loading 2FA settings');
                }
            });
        }
        
        /**
         * Update 2FA settings in the UI
         * 
         * @param {Object} data - 2FA settings data
         */
        update2FASettings(data) {
            // Update method toggles
            $('.attrua-2fa-method .toggle-switch input').each(function() {
                const method = $(this).data('method');
                $(this).prop('checked', data.methods[method] || false);
            });
            
            // Show/hide sections based on status
            if (data.totp_enabled) {
                $('.attrua-2fa-setup').hide();
                $('.attrua-2fa-enabled').show();
                $('.attrua-recovery-codes-wrapper').show();
            } else {
                $('.attrua-2fa-setup').show();
                $('.attrua-2fa-enabled').hide();
                $('.attrua-recovery-codes-wrapper').hide();
            }
            
            // Update recovery codes if available
            if (data.has_recovery_codes) {
                $('.attrua-recovery-codes').show();
            } else {
                $('.attrua-recovery-codes').hide();
            }
        }
    }

    /**
     * Email Template Manager
     * 
     * Manages email template previews and settings
     */
    class EmailTemplateManager {
        /**
         * Initialize email template manager
         * 
         * @param {Object} config - Configuration options
         */
        constructor(config) {
            this.config = config;
            this.currentTemplate = null;
            this.initEvents();
        }
        
        /**
         * Initialize event listeners
         */
        initEvents() {
            // Template selection
            $('#attrua-email-template-select').on('change', this.selectTemplate.bind(this));
            
            // Save template settings
            $('#attrua-save-email-template').on('click', this.saveTemplate.bind(this));
            
            // Send test email
            $('#attrua-send-test-email').on('click', this.sendTestEmail.bind(this));
            
            // Reset template to default
            $('#attrua-reset-email-template').on('click', this.resetTemplate.bind(this));
            
            // Preview template
            $('#attrua-preview-email-template').on('click', this.previewTemplate.bind(this));
            
            // Load templates on tab change
            $(document).on('attrua_tab_changed', (e, tab) => {
                if (tab === 'email_templates') {
                    this.loadTemplates();
                }
            });
        }
        
        /**
         * Select a template to edit
         * 
         * @param {Event} e - Change event
         */
        selectTemplate(e) {
            const template = $(e.currentTarget).val();
            
            if (!template) {
                return;
            }
            
            this.currentTemplate = template;
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_get_email_template',
                    template: template,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.updateTemplateForm(response.data);
                    } else {
                        alert(response.data.message || 'Failed to load email template.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                }
            });
        }
        
        /**
         * Save template settings
         * 
         * @param {Event} e - Click event
         */
        saveTemplate(e) {
            e.preventDefault();
            
            if (!this.currentTemplate) {
                alert('Please select a template first.');
                return;
            }
            
            const $form = $('#attrua-email-template-form');
            const $button = $(e.currentTarget);
            const originalText = $button.text();
            
            $button.prop('disabled', true).text('Saving...');
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_save_email_template',
                    template: this.currentTemplate,
                    subject: $('#attrua-email-subject').val(),
                    content: $('#attrua-email-content').val(),
                    from_name: $('#attrua-email-from-name').val(),
                    from_email: $('#attrua-email-from-email').val(),
                    format: $('input[name="attrua-email-format"]:checked').val(),
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        alert('Email template saved successfully.');
                    } else {
                        alert(response.data.message || 'Failed to save email template.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                },
                complete: () => {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        }
        
        /**
         * Send a test email
         * 
         * @param {Event} e - Click event
         */
        sendTestEmail(e) {
            e.preventDefault();
            
            if (!this.currentTemplate) {
                alert('Please select a template first.');
                return;
            }
            
            const email = prompt('Enter the email address to send the test to:', '');
            
            if (!email) {
                return;
            }
            
            const $button = $(e.currentTarget);
            const originalText = $button.text();
            
            $button.prop('disabled', true).text('Sending...');
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_send_test_email',
                    template: this.currentTemplate,
                    email: email,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        alert('Test email sent successfully.');
                    } else {
                        alert(response.data.message || 'Failed to send test email.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                },
                complete: () => {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        }
        
        /**
         * Reset template to default
         * 
         * @param {Event} e - Click event
         */
        resetTemplate(e) {
            e.preventDefault();
            
            if (!this.currentTemplate) {
                alert('Please select a template first.');
                return;
            }
            
            if (!confirm(this.config.i18n.confirmReset)) {
                return;
            }
            
            const $button = $(e.currentTarget);
            const originalText = $button.text();
            
            $button.prop('disabled', true).text('Resetting...');
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_reset_email_template',
                    template: this.currentTemplate,
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        alert('Email template reset successfully.');
                        this.updateTemplateForm(response.data);
                    } else {
                        alert(response.data.message || 'Failed to reset email template.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                },
                complete: () => {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        }
        
        /**
         * Preview the template
         * 
         * @param {Event} e - Click event
         */
        previewTemplate(e) {
            e.preventDefault();
            
            if (!this.currentTemplate) {
                alert('Please select a template first.');
                return;
            }
            
            const previewWindow = window.open('', '_blank');
            
            previewWindow.document.write(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Email Template Preview</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                </head>
                <body style="margin: 0; padding: 20px; font-family: sans-serif; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
                        <h2>Email Template Preview</h2>
                        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                        <h3>${$('#attrua-email-subject').val()}</h3>
                        <div>${$('#attrua-email-content').val()}</div>
                    </div>
                </body>
                </html>
            `);
            
            previewWindow.document.close();
        }
        
        /**
         * Load available templates
         */
        loadTemplates() {
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_get_email_templates',
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.updateTemplateSelect(response.data);
                    } else {
                        console.error('Failed to load email templates');
                    }
                },
                error: () => {
                    console.error('Network error loading email templates');
                }
            });
        }
        
        /**
         * Update template selection dropdown
         * 
         * @param {Object} data - Templates data
         */
        updateTemplateSelect(data) {
            const $select = $('#attrua-email-template-select');
            
            // Save current value
            const currentValue = $select.val();
            
            // Clear options
            $select.empty();
            
            // Add placeholder option
            $select.append('<option value="">Select a template</option>');
            
            // Add template options
            if (data.templates && data.templates.length > 0) {
                $.each(data.templates, function(i, template) {
                    $select.append(`<option value="${template.id}">${template.name}</option>`);
                });
                
                // Restore selection if possible
                if (currentValue && $select.find(`option[value="${currentValue}"]`).length) {
                    $select.val(currentValue);
                    // Trigger change to load the template
                    $select.trigger('change');
                }
            }
        }
        
        /**
         * Update template form with loaded data
         * 
         * @param {Object} data - Template data
         */
        updateTemplateForm(data) {
            $('#attrua-email-subject').val(data.subject);
            $('#attrua-email-content').val(data.content);
            $('#attrua-email-from-name').val(data.from_name);
            $('#attrua-email-from-email').val(data.from_email);
            $(`input[name="attrua-email-format"][value="${data.format}"]`).prop('checked', true);
            
            // Show form
            $('#attrua-email-template-form').show();
            
            // Show available variables
            if (data.variables && data.variables.length > 0) {
                const $variables = $('#attrua-email-variables');
                $variables.empty();
                
                $.each(data.variables, function(i, variable) {
                    $variables.append(`<code>{${variable}}</code>`);
                });
                
                $('.attrua-email-variables-wrapper').show();
            } else {
                $('.attrua-email-variables-wrapper').hide();
            }
        }
    }

    /**
     * Password Policy Manager
     * 
     * Manages password policy settings
     */
    class PasswordPolicy {
        /**
         * Initialize password policy manager
         * 
         * @param {Object} config - Configuration options
         */
        constructor(config) {
            this.config = config;
            this.initEvents();
        }
        
        /**
         * Initialize event listeners
         */
        initEvents() {
            // Enable/disable password policy
            $('#attrua-enable-password-policy').on('change', this.togglePasswordPolicy.bind(this));
            
            // Save password policy
            $('#attrua-save-password-policy').on('click', this.savePasswordPolicy.bind(this));
            
            // Reset password policy
            $('#attrua-reset-password-policy').on('click', this.resetPasswordPolicy.bind(this));
            
            // Load password policy on tab change
            $(document).on('attrua_tab_changed', (e, tab) => {
                if (tab === 'password_policy') {
                    this.loadPasswordPolicy();
                }
            });
        }
        
        /**
         * Toggle password policy
         * 
         * @param {Event} e - Change event
         */
        togglePasswordPolicy(e) {
            const enabled = $(e.currentTarget).prop('checked');
            
            // Enable/disable settings fields
            $('.attrua-password-policy-settings input, .attrua-password-policy-settings select')
                .not('#attrua-enable-password-policy')
                .prop('disabled', !enabled);
        }
        
        /**
         * Save password policy settings
         * 
         * @param {Event} e - Click event
         */
        savePasswordPolicy(e) {
            e.preventDefault();
            
            const $form = $('#attrua-password-policy-form');
            const $button = $(e.currentTarget);
            const originalText = $button.text();
            
            $button.prop('disabled', true).text('Saving...');
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_save_password_policy',
                    enabled: $('#attrua-enable-password-policy').prop('checked') ? 1 : 0,
                    min_length: $('#attrua-password-min-length').val(),
                    require_uppercase: $('#attrua-password-require-uppercase').prop('checked') ? 1 : 0,
                    require_lowercase: $('#attrua-password-require-lowercase').prop('checked') ? 1 : 0,
                    require_number: $('#attrua-password-require-number').prop('checked') ? 1 : 0,
                    require_special: $('#attrua-password-require-special').prop('checked') ? 1 : 0,
                    prevent_common: $('#attrua-password-prevent-common').prop('checked') ? 1 : 0,
                    expiration_days: $('#attrua-password-expiration').val(),
                    history_count: $('#attrua-password-history').val(),
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        alert('Password policy saved successfully.');
                    } else {
                        alert(response.data.message || 'Failed to save password policy.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                },
                complete: () => {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        }
        
        /**
         * Reset password policy to default
         * 
         * @param {Event} e - Click event
         */
        resetPasswordPolicy(e) {
            e.preventDefault();
            
            if (!confirm(this.config.i18n.confirmReset)) {
                return;
            }
            
            const $button = $(e.currentTarget);
            const originalText = $button.text();
            
            $button.prop('disabled', true).text('Resetting...');
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_reset_password_policy',
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        alert('Password policy reset successfully.');
                        this.updatePasswordPolicyForm(response.data);
                    } else {
                        alert(response.data.message || 'Failed to reset password policy.');
                    }
                },
                error: () => {
                    alert('Network error occurred. Please try again.');
                },
                complete: () => {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        }
        
        /**
         * Load password policy settings
         */
        loadPasswordPolicy() {
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'attrua_get_password_policy',
                    _ajax_nonce: this.config.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.updatePasswordPolicyForm(response.data);
                    } else {
                        console.error('Failed to load password policy');
                    }
                },
                error: () => {
                    console.error('Network error loading password policy');
                }
            });
        }
        
        /**
         * Update password policy form with loaded data
         * 
         * @param {Object} data - Password policy data
         */
        updatePasswordPolicyForm(data) {
            $('#attrua-enable-password-policy').prop('checked', data.enabled);
            $('#attrua-password-min-length').val(data.min_length);
            $('#attrua-password-require-uppercase').prop('checked', data.require_uppercase);
            $('#attrua-password-require-lowercase').prop('checked', data.require_lowercase);
            $('#attrua-password-require-number').prop('checked', data.require_number);
            $('#attrua-password-require-special').prop('checked', data.require_special);
            $('#attrua-password-prevent-common').prop('checked', data.prevent_common);
            $('#attrua-password-expiration').val(data.expiration_days);
            $('#attrua-password-history').val(data.history_count);
            
            // Enable/disable fields based on policy status
            this.togglePasswordPolicy({ currentTarget: $('#attrua-enable-password-policy')[0] });
        }
    }

    // Initialize admin interface on document ready
    $(document).ready(function() {
        // Only initialize on plugin admin pages
        if ($('.attrua-pro-admin').length) {
            window.attruaAdminPro = new AttributesAdminPro(window.attruaProConfig || {});
        }
    });

})(jQuery);