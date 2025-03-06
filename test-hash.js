// Test hash function consistency

function hashPassword(password) {
    // For consistency, we'll use a more deterministic approach
    let hash = 0;
    
    // Add each character code to the hash
    for (let i = 0; i < password.length; i++) {
        // Get the character code
        const char = password.charCodeAt(i);
        // Simple hash algorithm: multiply by 31 and add the character code
        hash = ((hash << 5) - hash) + char;
        // Convert to 32-bit integer
        hash = hash & hash;
    }
    
    // Convert to hex string with fixed prefix
    return 'hashed_' + Math.abs(hash).toString(16);
}

// Test with same password to confirm we get the same hash
const testPassword = "password123";
console.log(`Password: ${testPassword}`);
console.log(`Hash: ${hashPassword(testPassword)}`);

// Test with "testpass" which is what we'll use for testing
const testPass = "testpass";
console.log(`Password: ${testPass}`);
console.log(`Hash: ${hashPassword(testPass)}`);