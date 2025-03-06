/**
 * Stats Dashboard - Displays user challenge attempt statistics
 */

document.addEventListener('DOMContentLoaded', () => {
    // Check if user is logged in
    const isLoggedIn = localStorage.getItem('userLoggedIn');
    if (!isLoggedIn) {
        window.location.href = 'login.html';
        return;
    }

    // Get current user
    const currentUser = localStorage.getItem('currentUser');
    if (!currentUser) {
        document.getElementById('stats-container').innerHTML = '<p>No user data available.</p>';
        return;
    }

    // Display welcome message with username
    const welcomeMessageElement = document.getElementById('welcome-message');
    if (welcomeMessageElement) {
        welcomeMessageElement.innerHTML = `<i class="fas fa-user"></i> Welcome, ${currentUser}!`;
    }

    // Load and display user stats
    displayUserStats();
});

/**
 * Load and display user statistics
 */
async function displayUserStats() {
    const statsContainer = document.getElementById('stats-container');
    const userStats = await getCurrentUserStats();
    
    if (!userStats || userStats.totalAttempts === 0) {
        statsContainer.innerHTML = `
            <div class="stats-message">
                <i class="fas fa-info-circle"></i>
                <p>You haven't attempted any challenges yet. Start practicing to see your statistics!</p>
                <a href="index.html" class="btn"><i class="fas fa-tasks"></i> Go to Challenges</a>
            </div>
        `;
        return;
    }

    // Create summary statistics
    const summaryHTML = `
        <div class="stats-summary">
            <h2><i class="fas fa-chart-bar"></i> Your Performance Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">${userStats.totalAttempts}</div>
                    <div class="stat-label">Total Attempts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${userStats.totalCorrect}</div>
                    <div class="stat-label">Correct Solutions</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${userStats.accuracyPercentage}%</div>
                    <div class="stat-label">Accuracy</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${countSolvedChallenges(userStats)}/10</div>
                    <div class="stat-label">Challenges Solved</div>
                </div>
            </div>
        </div>
    `;

    // Create challenge detail section
    let challengeDetailsHTML = `
        <div class="challenge-details">
            <h2><i class="fas fa-list-check"></i> Challenge Details</h2>
            <table class="stats-table">
                <thead>
                    <tr>
                        <th>Challenge</th>
                        <th>Attempts</th>
                        <th>Correct</th>
                        <th>Accuracy</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
    `;

    // Get all vulnerabilities for reference
    const allVulnerabilities = {};
    vulnerabilitiesData.forEach(v => {
        allVulnerabilities[v.id] = v.title;
    });

    // Add rows for each challenge
    for (const challengeId in allVulnerabilities) {
        const challengeStats = userStats.challenges[challengeId] || {
            attempts: 0,
            correct: 0,
            solved: false
        };
        
        const accuracy = challengeStats.attempts > 0 
            ? Math.round((challengeStats.correct / challengeStats.attempts) * 100) 
            : 0;
            
        const status = challengeStats.solved 
            ? '<span class="status-solved"><i class="fas fa-check-circle"></i> Solved</span>' 
            : challengeStats.attempts > 0 
                ? '<span class="status-attempted"><i class="fas fa-clock"></i> Attempted</span>' 
                : '<span class="status-not-attempted"><i class="fas fa-minus-circle"></i> Not Attempted</span>';
                
        challengeDetailsHTML += `
            <tr>
                <td>${allVulnerabilities[challengeId]}</td>
                <td>${challengeStats.attempts}</td>
                <td>${challengeStats.correct}</td>
                <td>${accuracy}%</td>
                <td>${status}</td>
            </tr>
        `;
    }

    challengeDetailsHTML += `
                </tbody>
            </table>
        </div>
    `;

    // Add reset stats button
    const resetButtonHTML = `
        <div class="actions">
            <button id="reset-stats-btn" class="btn danger">
                <i class="fas fa-trash"></i> Reset Statistics
            </button>
            <a href="index.html" class="btn primary">
                <i class="fas fa-tasks"></i> Back to Challenges
            </a>
        </div>
    `;

    // Combine all sections
    statsContainer.innerHTML = summaryHTML + challengeDetailsHTML + resetButtonHTML;

    // Add event listener for reset button
    document.getElementById('reset-stats-btn').addEventListener('click', () => {
        if (confirm('Are you sure you want to reset all your statistics? This cannot be undone.')) {
            resetCurrentUserStats();
            displayUserStats(); // Refresh the display
        }
    });
}

/**
 * Count how many challenges the user has solved
 * @param {Object} userStats - User statistics object
 * @returns {number} Number of solved challenges
 */
function countSolvedChallenges(userStats) {
    let count = 0;
    for (const challengeId in userStats.challenges) {
        if (userStats.challenges[challengeId].solved) {
            count++;
        }
    }
    return count;
}