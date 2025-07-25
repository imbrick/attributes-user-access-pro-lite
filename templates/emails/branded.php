<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{subject}</title>
    <style type="text/css">
        /* Base styles */
        body {
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333333;
            background-color: #f5f7f9;
            margin: 0;
            padding: 0;
            -webkit-text-size-adjust: none;
            -ms-text-size-adjust: none;
        }
        
        /* Main container */
        .email-container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            padding: 0;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        /* Header */
        .email-header {
            background-color: #2271b1;
            padding: 30px 20px;
            text-align: center;
        }
        
        .email-header h1 {
            margin: 0;
            padding: 0;
            font-size: 28px;
            font-weight: 600;
            color: #ffffff;
        }
        
        .logo {
            max-width: 200px;
            height: auto;
            margin-bottom: 15px;
        }
        
        /* Content */
        .email-content {
            padding: 30px 25px;
            background-color: #ffffff;
        }
        
        h2 {
            color: #2271b1;
            margin-top: 0;
            font-size: 22px;
        }
        
        p {
            margin: 15px 0;
        }
        
        /* Button */
        .button-container {
            text-align: center;
            margin: 30px 0;
        }
        
        .button {
            display: inline-block;
            background-color: #2271b1;
            color: #ffffff !important;
            font-size: 16px;
            font-weight: 600;
            text-align: center;
            text-decoration: none;
            padding: 14px 30px;
            border-radius: 4px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            transition: background-color 0.3s ease;
        }
        
        .button:hover {
            background-color: #135e96;
        }
        
        .link-box {
            word-break: break-all; 
            background-color: #f5f7f9; 
            padding: 15px; 
            border-radius: 4px; 
            font-family: monospace; 
            font-size: 13px;
            border-left: 4px solid #2271b1;
            margin: 20px 0;
        }
        
        /* Footer */
        .email-footer {
            background-color: #f5f7f9;
            padding: 20px;
            border-top: 1px solid #e5e5e5;
            font-size: 13px;
            color: #777777;
            text-align: center;
        }
        
        .divider {
            height: 5px;
            background: linear-gradient(to right, #2271b1, #72aee6);
            margin: 0;
            padding: 0;
        }
        
        .social-links {
            margin: 15px 0;
        }
        
        .social-links a {
            display: inline-block;
            margin: 0 5px;
            color: #2271b1;
            text-decoration: none;
        }
        
        /* Responsive adjustments */
        @media screen and (max-width: 600px) {
            .email-container {
                width: 100% !important;
                border-radius: 0;
            }
            
            .email-content {
                padding: 20px 15px;
            }
            
            .button {
                display: block;
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <table border="0" cellpadding="0" cellspacing="0" width="100%">
        <tr>
            <td align="center" valign="top" style="padding: 30px 10px;">
                <table border="0" cellpadding="0" cellspacing="0" width="600" class="email-container">
                    <!-- Header -->
                    <tr>
                        <td align="center" valign="top" class="email-header">
                            <img class="logo" src="<?php echo ATTRUA_URL; ?>assets/img/logo-white.png" alt="{site_name} Logo">
                            <h1>{site_name}</h1>
                        </td>
                    </tr>
                    
                    <tr>
                        <td height="5" class="divider"></td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td valign="top" class="email-content">
                            <h2>Hello, {username}</h2>
                            
                            <p>We received a request to reset the password for your account. If you made this request, you can reset your password now.</p>
                            
                            <div class="button-container">
                                <a href="{reset_link}" class="button">Reset My Password</a>
                            </div>
                            
                            <p>If the button above doesn't work, copy and paste this link into your browser:</p>
                            
                            <div class="link-box">
                                {reset_link}
                            </div>
                            
                            <p><strong>Please Note:</strong> This password reset link will expire in {expiry_time}.</p>
                            
                            <p>If you didn't request a password reset, you can safely ignore this email. Your account security is important to us, and your password will remain unchanged.</p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td valign="top" class="email-footer">
                            <p>This is an automated message from {site_name}.</p>
                            
                            <div class="social-links">
                                <?php if ($social_twitter = apply_filters('attrua_social_twitter', '')): ?>
                                    <a href="<?php echo esc_url($social_twitter); ?>">Twitter</a> |
                                <?php endif; ?>
                                
                                <?php if ($social_facebook = apply_filters('attrua_social_facebook', '')): ?>
                                    <a href="<?php echo esc_url($social_facebook); ?>">Facebook</a> |
                                <?php endif; ?>
                                
                                <?php if ($social_instagram = apply_filters('attrua_social_instagram', '')): ?>
                                    <a href="<?php echo esc_url($social_instagram); ?>">Instagram</a>
                                <?php endif; ?>
                            </div>
                            
                            <p>&copy; <?php echo date('Y'); ?> {site_name}. All rights reserved.</p>
                            <p>{site_url}</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>