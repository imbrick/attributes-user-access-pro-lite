<?php
/**
 * Common Passwords List
 * 
 * This file contains a list of commonly used passwords that should be rejected during
 * password creation or reset for security reasons. The passwords in this list are
 * frequently targeted in dictionary attacks and represent significant security risks.
 * 
 * The list is derived from multiple sources including:
 * - Datasets of breached passwords
 * - Security research on password frequency
 * - Common patterns that create vulnerable passwords
 * 
 * @package Attributes\Security
 * @since   1.0.0
 */

// Return array of common passwords
return [
    // Top 25 most common passwords
    '123456',
    'password',
    '12345678',
    'qwerty',
    '123456789',
    '12345',
    '1234',
    '111111',
    '1234567',
    'dragon',
    '123123',
    'baseball',
    'abc123',
    'football',
    'monkey',
    'letmein',
    '696969',
    'shadow',
    'master',
    '666666',
    'qwertyuiop',
    '123321',
    'mustang',
    '1234567890',
    'michael',
    
    // Common patterns
    'password1',
    'password123',
    'admin',
    'admin123',
    'administrator',
    'welcome',
    'welcome1',
    'welcome123',
    'qwerty123',
    'test',
    'test123',
    
    // Names and popular words
    'superman',
    'batman',
    'iloveyou',
    'sunshine',
    'princess',
    'starwars',
    'whatever',
    
    // Years and dates
    '2023',
    '2022',
    '2021',
    '2020',
    '2019',
    'january',
    'february',
    'march',
    'april',
    'summer',
    'winter',
    
    // Sports teams and pop culture
    'liverpool',
    'chelsea',
    'arsenal',
    'yankees',
    'lakers',
    'pokemon',
    'minecraft',
    'fortnite',
    
    // Keyboard patterns
    'qazwsx',
    'asdfgh',
    'zxcvbn',
    'qweasd',
    
    // Simple number patterns
    '11111111',
    '22222222',
    '12121212',
    '55555555',
    '77777777',
    '88888888',
    '99999999',
    
    // Sequential patterns
    'abcdef',
    'abcdefg',
    'abcd1234',
    
    // Simple word + number combinations
    'abc123',
    'test123',
    'hello123',
    'login123',
    
    // Common phrases
    'letmein',
    'trustno1',
    'changeme',
    'secret',
    
    // Technical terms (common for developers)
    'root',
    'admin',
    'user',
    'mysql',
    'oracle',
    'server',
    'computer',
    'internet',
    
    // Single dictionary words
    'monkey',
    'dragon',
    'baseball',
    'football',
    'hockey',
    'soccer',
    'basketball',
    'tennis',
    'golf',
    
    // Common female names
    'jennifer',
    'michelle',
    'jessica',
    'amanda',
    'ashley',
    'sarah',
    'stephanie',
    
    // Common male names
    'michael',
    'christopher',
    'matthew',
    'joshua',
    'david',
    'james',
    'daniel',
    
    // Common last names
    'smith',
    'johnson',
    'williams',
    'brown',
    'jones',
    'miller',
    'davis',
    
    // Company names
    'facebook',
    'twitter',
    'google',
    'microsoft',
    'apple',
    'amazon',
    
    // WordPress-specific
    'wordpress',
    'wppassword',
    'wpadmin',
    'wordpress123',
    
    // Compound words
    'passpass',
    'adminadmin',
    'useradmin',
    
    // Combinations
    'adminuser',
    'adminpass',
    'adminpassword',
    'userpassword',
    
    // Profanity (mild examples only)
    'fuckyou',
    'bullshit',
    
    // Common substitutions
    'p@ssw0rd',
    '@dmin',
    'welc0me',
    
    // Default/example passwords
    'changeme',
    'default',
    'temp',
    'temp123',
    'testtest',
    
    // 4-digit numbers that might be PINs
    '1234',
    '4321',
    '0000',
    '1111',
    '9999',
    '1212',
    '1122',
    
    // Simple letter sequences
    'abcd',
    'wxyz',
    'aaaa',
    'bbbb',
    'cccc',
    
    // Repeating character patterns
    'aaaaaa',
    'bbbbbb',
    'cccccc',
    'aaaaaa',
];