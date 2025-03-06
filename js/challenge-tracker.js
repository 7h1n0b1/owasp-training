/**
 * Challenge Tracker - Tracks user attempts and success rates for OWASP challenges
 */

// Load existing stats from localStorage (server functionality disabled)
async function loadStats() {
    // Use localStorage directly since we're running client-side only
    const stats = localStorage.getItem('challengeStats');
    return stats ? JSON.parse(stats) : {};
}

// Save stats to localStorage only (server functionality disabled)
async function saveStats(stats) {
    // Save to localStorage only
    localStorage.setItem('challengeStats', JSON.stringify(stats));
}

/**
 * Track a challenge attempt for the current user
 * @param {string} challengeId - The ID of the challenge (e.g., 'a01', 'a02')
 * @param {boolean} isCorrect - Whether the answer was correct
 */
async function trackChallengeAttempt(challengeId, isCorrect) {
    const currentUser = localStorage.getItem('currentUser');
    
    // Only track if a user is logged in
    if (!currentUser) {
        console.warn('Cannot track attempt: No user is logged in');
        return;
    }
    
    // Load existing stats from localStorage
    const allStats = await loadStats();
    
    // Initialize user stats if they don't exist
    if (!allStats[currentUser]) {
        allStats[currentUser] = {
            challenges: {},
            totalAttempts: 0,
            totalCorrect: 0
        };
    }
    
    const userStats = allStats[currentUser];
    
    // Initialize challenge stats if they don't exist
    if (!userStats.challenges[challengeId]) {
        userStats.challenges[challengeId] = {
            attempts: 0,
            correct: 0,
            solved: false, // Marks if challenge was ever solved
            lastAttempt: null
        };
    }
    
    const challengeStats = userStats.challenges[challengeId];
    
    // Update challenge stats
    challengeStats.attempts++;
    if (isCorrect) {
        challengeStats.correct++;
        challengeStats.solved = true;
    }
    challengeStats.lastAttempt = new Date().toISOString();
    
    // Update user totals
    userStats.totalAttempts++;
    if (isCorrect) {
        userStats.totalCorrect++;
    }
    
    // Calculate new accuracy percentage
    userStats.accuracyPercentage = Math.round((userStats.totalCorrect / userStats.totalAttempts) * 100);
    
    // Save updated stats
    await saveStats(allStats);
    
    console.log(`Challenge attempt tracked for ${currentUser}: Challenge ${challengeId}, Correct: ${isCorrect}`);
    return allStats;
}

/**
 * Get stats for the current user
 * @returns {Promise<Object|null>} User's challenge stats or null if no user is logged in
 */
async function getCurrentUserStats() {
    const currentUser = localStorage.getItem('currentUser');
    
    if (!currentUser) {
        return null;
    }
    
    const allStats = await loadStats();
    return allStats[currentUser] || null;
}

/**
 * Get stats for all users
 * @returns {Promise<Object>} All users' challenge stats
 */
async function getAllUserStats() {
    return await loadStats();
}

/**
 * Reset stats for the current user
 * @returns {Promise<void>}
 */
async function resetCurrentUserStats() {
    const currentUser = localStorage.getItem('currentUser');
    
    if (!currentUser) {
        return;
    }
    
    // Reset stats in localStorage
    const allStats = await loadStats();
    
    if (allStats[currentUser]) {
        delete allStats[currentUser];
        await saveStats(allStats);
        console.log(`Stats reset for user: ${currentUser}`);
    }
}