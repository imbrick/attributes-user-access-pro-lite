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
            background-color: #f7f7f7;
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
            padding: 20px;
            border: 1px solid #e5e5e5;
            border-radius: 5px;
        }
        
        /* Header */
        .email-header {
            text-align: center;
            padding-bottom: 20px;
            border-bottom: 1px solid #e5e5e5;
            margin-bottom: 20px;
        }
        
        .email-header h1 {
            margin: 0;
            padding: 0;
            font-size: 24px;
            font-weight: 600;
            color: #333333;
        }
        
        /* Content */
        .email-content {
            padding: 20px 0;
        }
        
        /* Button */
        .button {
            display: inline-block;
            background-color: #2271b1;
            color: #ffffff !important;
            font-size: 16px;
            font-weight: 500;
            line-height: 1.4;
            text-align: center;
            text-decoration: none;
            padding: 12px 24px;
            border-radius: 4px;
            margin: 20px 0;
        }
        
        /* Footer */
        .email-footer {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #e5e5e5;
            font-size: 13px;
            color: #777777;
            text-align: center;
        }
        
        /* Responsive adjustments */
        @media screen and (max-width: 600px) {
            .email-container {
                width: 100% !important;
                padding: 10px !important;
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
            <td align="center" valign="top" style="padding: 20px 10px;">
                <table border="0" cellpadding="0" cellspacing="0" width="600" class="email-container">
                    <!-- Header -->
                    <tr>
                        <td align="center" valign="top" class="email-header">
                            <h1>{site_name}</h1>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td valign="top" class="email-content">
                            <h2>Hello, {username}</h2>
                            
                            <p>Someone has requested a password reset for your account.</p>
                            
                            <p>If this was a mistake, just ignore this email and nothing will happen.</p>
                            
                            <p>To reset your password, click the button below:</p>
                            
                            <p style="text-align: center;">
                                <a href="{reset_link}" class="button">Reset Password</a>
                            </p>
                            
                            <p>Alternatively, you can copy and paste the following URL into your browser:</p>
                            
                            <p style="word-break: break-all; background-color: #f5f5f5; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px;">
                                {reset_link}
                            </p>
                            
                            <p>This password reset link will expire in {expiry_time}.</p>
                            
                            <p>If you didn't request this, please ignore this email.</p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td valign="top" class="email-footer">
                            <p>This email was sent from {site_name} - {site_url}</p>
                            <p>&copy; <?php echo date('Y'); ?> {site_name}. All rights reserved.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>