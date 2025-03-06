/**
 * Server-side configuration file for OWASP Training Portal
 * This file should NOT be accessible from the browser
 */

// Admin credentials
const adminCredentials = {
    username: 'admin',
    // In production, this would be properly hashed and salted
    // This is using the same simple hash function as in login.js for consistency
    password: 'hashed_5103e887' // "Yemeraowasppasswordhai29" hashed with the app's hash function
};

// System configuration
const systemConfig = {
    // Security settings
    maxLoginAttempts: 5,
    lockoutTime: 15 * 60 * 1000, // 15 minutes
    sessionTimeout: 60 * 60 * 1000, // 1 hour
    
    // Data storage paths
    userDataPath: './data/users.json',
    statsDataPath: './data/stats.json',
    
    // Feature flags
    enableRegistration: true,
    enablePasswordReset: true
};

module.exports = {
    adminCredentials,
    systemConfig
};