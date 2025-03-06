document.addEventListener('DOMContentLoaded', () => {
    // Check if user is logged in as admin
    const currentUser = localStorage.getItem('currentUser');
    const isLoggedIn = localStorage.getItem('userLoggedIn');
    const isAdmin = localStorage.getItem('isAdmin') === 'true';
    
    if (!isLoggedIn || !isAdmin) {
        // If not admin, redirect to login page
        window.location.href = 'login.html';
        return;
    }

    // Set welcome message
    const welcomeMessage = document.getElementById('admin-welcome-message');
    welcomeMessage.textContent = `Welcome, Admin`;

    // Sidebar navigation
    const sidebarItems = document.querySelectorAll('.admin-sidebar li');
    const adminSections = document.querySelectorAll('.admin-section');
    
    sidebarItems.forEach(item => {
        item.addEventListener('click', () => {
            const sectionId = item.getAttribute('data-section');
            
            // Update active sidebar item
            sidebarItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            
            // Update active section
            adminSections.forEach(section => {
                section.classList.remove('active');
                if (section.id === sectionId) {
                    section.classList.add('active');
                }
            });
        });
    });

    // Initialize admin dashboard
    initializeDashboard();
    initializeUserManagement();
    initializeAdminSettings();
});

// Dashboard functionality
function initializeDashboard() {
    updateStatsDashboard();
}

async function updateStatsDashboard() {
    // Get all user statistics
    const allStats = await getAllUserStats();
    const usernames = Object.keys(allStats);
    
    // Calculate overall statistics
    const totalUsers = usernames.length;
    let totalAttempts = 0;
    let totalCorrect = 0;
    
    // Aggregate per-challenge statistics
    const challengeStats = {};
    
    // Initialize challenge stats with data from vulnerabilitiesData
    vulnerabilitiesData.forEach(challenge => {
        challengeStats[challenge.id] = {
            id: challenge.id,
            title: challenge.title,
            attempts: 0,
            correct: 0,
            usersCompleted: 0
        };
    });
    
    // Process user statistics
    usernames.forEach(username => {
        const userStats = allStats[username];
        
        // Add to overall totals
        totalAttempts += userStats.totalAttempts || 0;
        totalCorrect += userStats.totalCorrect || 0;
        
        // Process per-challenge statistics
        if (userStats.challenges) {
            Object.keys(userStats.challenges).forEach(challengeId => {
                const challenge = userStats.challenges[challengeId];
                
                // Initialize challenge if not already done
                if (!challengeStats[challengeId]) {
                    challengeStats[challengeId] = {
                        id: challengeId,
                        title: `Challenge ${challengeId}`,
                        attempts: 0,
                        correct: 0,
                        usersCompleted: 0
                    };
                }
                
                // Update challenge stats
                challengeStats[challengeId].attempts += challenge.attempts || 0;
                challengeStats[challengeId].correct += challenge.correct || 0;
                
                // Count users who completed this challenge
                if (challenge.solved) {
                    challengeStats[challengeId].usersCompleted++;
                }
            });
        }
    });
    
    // Calculate overall accuracy
    const overallAccuracy = totalAttempts > 0 ? Math.round((totalCorrect / totalAttempts) * 100) : 0;
    
    // Update dashboard UI
    document.getElementById('total-users-count').textContent = totalUsers;
    document.getElementById('total-attempts-count').textContent = totalAttempts;
    document.getElementById('avg-accuracy-rate').textContent = `${overallAccuracy}%`;
    
    // Update challenge statistics table
    const tableBody = document.querySelector('#challenge-stats-table tbody');
    tableBody.innerHTML = '';
    
    Object.values(challengeStats).forEach(challenge => {
        const accuracy = challenge.attempts > 0 ? Math.round((challenge.correct / challenge.attempts) * 100) : 0;
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${challenge.id}</td>
            <td>${challenge.title}</td>
            <td>${challenge.attempts}</td>
            <td>${challenge.correct}</td>
            <td>${accuracy}%</td>
            <td>${challenge.usersCompleted}</td>
        `;
        
        tableBody.appendChild(row);
    });
}

// User management functionality
async function initializeUserManagement() {
    await updateUserTable();
    
    // Search functionality
    const searchInput = document.getElementById('user-search');
    searchInput.addEventListener('input', () => {
        updateUserTable(searchInput.value.trim().toLowerCase());
    });
    
    // Add user button
    const addUserBtn = document.getElementById('add-user-btn');
    addUserBtn.addEventListener('click', () => {
        openAddUserModal();
    });
    
    // Modal elements
    const modal = document.getElementById('user-modal');
    const closeBtn = document.querySelector('.close-modal');
    const resetForm = document.getElementById('reset-password-form');
    const addUserForm = document.getElementById('add-user-form');
    const modalTitle = document.getElementById('modal-title');
    
    // Close modal functionality
    closeBtn.addEventListener('click', () => {
        modal.style.display = 'none';
        resetForm.reset();
        addUserForm.reset();
        document.getElementById('password-error').textContent = '';
        document.getElementById('add-user-error').textContent = '';
    });
    
    window.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
            resetForm.reset();
            addUserForm.reset();
            document.getElementById('password-error').textContent = '';
            document.getElementById('add-user-error').textContent = '';
        }
    });
    
    // Reset password form submit
    resetForm.addEventListener('submit', (e) => {
        e.preventDefault();
        
        const username = document.getElementById('reset-username').value;
        const newPassword = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        const errorElement = document.getElementById('password-error');
        
        // Validate passwords
        if (newPassword !== confirmPassword) {
            errorElement.textContent = 'Passwords do not match';
            return;
        }
        
        if (newPassword.length < 6) {
            errorElement.textContent = 'Password must be at least 6 characters';
            return;
        }
        
        // Reset password
        resetUserPassword(username, newPassword);
        
        // Clear form and close modal
        resetForm.reset();
        errorElement.textContent = '';
        modal.style.display = 'none';
        
        // Show success message
        alert(`Password for ${username} has been reset successfully`);
    });
    
    // Add user form submit
    addUserForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = document.getElementById('new-username').value;
        const fullname = document.getElementById('new-fullname').value;
        const email = document.getElementById('new-email').value;
        const password = document.getElementById('new-user-password').value;
        const confirmPassword = document.getElementById('new-confirm-password').value;
        const securityQuestion = document.getElementById('new-security-question').value;
        const securityAnswer = document.getElementById('new-security-answer').value;
        const errorElement = document.getElementById('add-user-error');
        
        // Validate input
        if (password !== confirmPassword) {
            errorElement.textContent = 'Passwords do not match';
            return;
        }
        
        if (password.length < 6) {
            errorElement.textContent = 'Password must be at least 6 characters';
            return;
        }
        
        if (!username || !fullname || !email || !securityQuestion || !securityAnswer) {
            errorElement.textContent = 'All fields are required';
            return;
        }
        
        // Create user object
        const userData = {
            username,
            fullname,
            email,
            password: hashPassword(password),
            securityQuestion,
            securityAnswer
        };
        
        // Add the user
        const success = await addNewUser(userData);
        
        if (success) {
            // Clear form and close modal
            addUserForm.reset();
            errorElement.textContent = '';
            modal.style.display = 'none';
            
            // Update the user table
            await updateUserTable();
            
            // Show success message
            alert(`User ${username} has been added successfully`);
        }
    });
}

async function updateUserTable(searchTerm = '') {
    try {
        // Get users from server
        const response = await fetch('/get-users');
        const registeredUsers = await response.json();
        
        // Get stats from server
        const allStats = await getAllUserStats();
        
        const tableBody = document.querySelector('#users-table tbody');
        tableBody.innerHTML = '';
        
        registeredUsers.forEach(user => {
            // Skip if not matching search term
            if (searchTerm && !user.username.toLowerCase().includes(searchTerm) && 
                !user.fullname.toLowerCase().includes(searchTerm) && 
                !user.email.toLowerCase().includes(searchTerm)) {
                return;
            }
            
            // Calculate completed challenges
            let completedChallenges = 0;
            const userStats = allStats[user.username];
            
            if (userStats && userStats.challenges) {
                Object.values(userStats.challenges).forEach(challenge => {
                    if (challenge.solved) {
                        completedChallenges++;
                    }
                });
            }
            
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${user.username}</td>
                <td>${user.fullname}</td>
                <td>${user.email}</td>
                <td>${completedChallenges} / ${vulnerabilitiesData.length}</td>
                <td class="user-actions">
                    <button class="action-btn action-btn-small reset-password-btn" data-username="${user.username}">
                        <i class="fas fa-key"></i> Reset Password
                    </button>
                    <button class="action-btn action-btn-small action-btn-danger delete-user-btn" data-username="${user.username}">
                        <i class="fas fa-trash"></i> Delete
                    </button>
                </td>
            `;
            
            tableBody.appendChild(row);
        });
        
        // Attach event listeners to action buttons
        document.querySelectorAll('.reset-password-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const username = btn.getAttribute('data-username');
                openResetPasswordModal(username);
            });
        });
        
        document.querySelectorAll('.delete-user-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const username = btn.getAttribute('data-username');
                deleteUser(username);
            });
        });
    } catch (error) {
        console.error('Error loading users:', error);
        alert('Failed to load users. Check console for details.');
    }
}

function openResetPasswordModal(username) {
    // Set the modal for password reset mode
    document.getElementById('modal-title').textContent = 'Reset Password';
    document.getElementById('reset-password-form').style.display = 'block';
    document.getElementById('add-user-form').style.display = 'none';
    
    // Set the username
    document.getElementById('reset-username').value = username;
    
    // Show the modal
    document.getElementById('user-modal').style.display = 'block';
}

function openAddUserModal() {
    // Set the modal for add user mode
    document.getElementById('modal-title').textContent = 'Add New User';
    document.getElementById('reset-password-form').style.display = 'none';
    document.getElementById('add-user-form').style.display = 'block';
    
    // Show the modal
    document.getElementById('user-modal').style.display = 'block';
}

async function resetUserPassword(username, newPassword) {
    try {
        // Hash the new password
        const hashedPassword = hashPassword(newPassword);
        
        // Send request to server
        const response = await fetch(`/reset-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username,
                password: hashedPassword
            })
        });
        
        if (response.ok) {
            console.log(`Password reset for user: ${username} via server`);
            return;
        } else {
            console.warn('Server password reset failed, falling back to local reset');
        }
    } catch (error) {
        console.warn('Failed to reset password via server, falling back to local reset:', error);
    }
    
    // Fallback to local storage
    const registeredUsers = JSON.parse(localStorage.getItem('registeredUsers') || '[]');
    
    // Find the user
    const userIndex = registeredUsers.findIndex(user => user.username === username);
    
    if (userIndex !== -1) {
        // Hash the new password
        const hashedPassword = hashPassword(newPassword);
        
        // Update the user's password
        registeredUsers[userIndex].password = hashedPassword;
        
        // Save the updated users
        localStorage.setItem('registeredUsers', JSON.stringify(registeredUsers));
        
        console.log(`Password reset for user: ${username} locally`);
    }
}

async function addNewUser(userData) {
    try {
        // First check if user already exists in local storage
        const registeredUsers = JSON.parse(localStorage.getItem('registeredUsers') || '[]');
        if (registeredUsers.some(user => user.username === userData.username)) {
            document.getElementById('add-user-error').textContent = 'Username already exists';
            return false;
        }
        
        // Try to add user to server
        const response = await fetch('/save-user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData)
        });
        
        if (response.ok) {
            console.log(`User ${userData.username} added successfully via server`);
            return true;
        } else {
            const errorData = await response.json();
            if (errorData.error === 'Username already exists') {
                document.getElementById('add-user-error').textContent = 'Username already exists';
                return false;
            }
            console.warn('Server failed to add user, falling back to local storage');
        }
    } catch (error) {
        console.warn('Failed to add user via server, falling back to local storage:', error);
    }
    
    // Fallback to local storage
    const registeredUsers = JSON.parse(localStorage.getItem('registeredUsers') || '[]');
    
    // Add user to local storage
    registeredUsers.push(userData);
    localStorage.setItem('registeredUsers', JSON.stringify(registeredUsers));
    
    console.log(`User ${userData.username} added successfully to local storage`);
    return true;
}

async function deleteUser(username) {
    // Confirm deletion
    if (!confirm(`Are you sure you want to delete the user "${username}"?`)) {
        return;
    }
    
    try {
        // Delete user from server
        const userResponse = await fetch(`/api/users/${username}`, {
            method: 'DELETE'
        });
        
        // Delete user stats from server
        const statsResponse = await fetch(`/stats/${username}`, {
            method: 'DELETE'
        });
        
        if (userResponse.ok && statsResponse.ok) {
            console.log(`User and stats deleted for: ${username} via server`);
        } else {
            console.warn('Server deletion failed, falling back to local deletion');
        }
    } catch (error) {
        console.warn('Failed to delete user via server, falling back to local deletion:', error);
    }
    
    // Fallback to local storage
    const registeredUsers = JSON.parse(localStorage.getItem('registeredUsers') || '[]');
    
    // Filter out the user to delete
    const updatedUsers = registeredUsers.filter(user => user.username !== username);
    
    // Save the updated users
    localStorage.setItem('registeredUsers', JSON.stringify(updatedUsers));
    
    // Also delete user stats
    const allStats = await getAllUserStats();
    
    if (allStats[username]) {
        delete allStats[username];
        await saveStats(allStats);
    }
    
    // Update the user table
    updateUserTable();
    
    // Update dashboard statistics
    updateStatsDashboard();
    
    console.log(`User deleted: ${username} locally`);
}

// Admin settings functionality
function initializeAdminSettings() {
    const passwordForm = document.getElementById('admin-password-form');
    const clearStatsBtn = document.getElementById('clear-all-stats');
    const exportDataBtn = document.getElementById('export-data');
    
    // Admin password change
    passwordForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const currentPassword = document.getElementById('current-password').value;
        const newPassword = document.getElementById('admin-new-password').value;
        const confirmPassword = document.getElementById('admin-confirm-password').value;
        const errorElement = document.getElementById('admin-password-error');
        
        // Validate passwords match
        if (newPassword !== confirmPassword) {
            errorElement.textContent = 'New passwords do not match';
            return;
        }
        
        if (newPassword.length < 8) {
            errorElement.textContent = 'New password must be at least 8 characters';
            return;
        }
        
        try {
            // Hash the passwords
            const hashedCurrentPassword = hashPassword(currentPassword);
            const hashedNewPassword = hashPassword(newPassword);
            
            // Send request to server
            const response = await fetch('/admin/update-password', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    currentPassword: hashedCurrentPassword,
                    newPassword: hashedNewPassword
                })
            });
            
            if (response.ok) {
                // Clear form and show success
                passwordForm.reset();
                errorElement.textContent = '';
                alert('Admin password has been updated successfully');
            } else {
                const data = await response.json();
                errorElement.textContent = data.error || 'Failed to update password';
            }
        } catch (error) {
            console.error('Error updating admin password:', error);
            errorElement.textContent = 'An error occurred during password update';
        }
    });
    
    // Clear all stats
    clearStatsBtn.addEventListener('click', async () => {
        if (confirm('Are you sure you want to clear all statistics? This action cannot be undone.')) {
            try {
                // Attempt to clear stats from server
                const response = await fetch('/stats', {
                    method: 'DELETE'
                });
                
                if (response.ok) {
                    console.log('All statistics cleared via server');
                } else {
                    console.warn('Failed to clear stats via server, falling back to local clear');
                }
            } catch (error) {
                console.warn('Failed to clear stats via server, falling back to local clear:', error);
            }
            
            // Also clear local stats as fallback
            localStorage.removeItem('challengeStats');
            
            alert('All statistics have been cleared');
            updateStatsDashboard();
        }
    });
    
    // Export data
    exportDataBtn.addEventListener('click', () => {
        exportAllData();
    });
}

async function exportAllData() {
    try {
        // Get users from server
        const usersResponse = await fetch('/get-users');
        const users = await usersResponse.json();
        
        // Get stats from server
        const statsResponse = await fetch('/stats');
        const statistics = await statsResponse.json();
        
        // Combine the data
        const exportData = {
            users,
            statistics
        };
        
        // Create downloadable JSON file
        const dataStr = JSON.stringify(exportData, null, 2);
        const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
        
        // Create and trigger download link
        const exportLink = document.createElement('a');
        exportLink.setAttribute('href', dataUri);
        exportLink.setAttribute('download', 'owasp_portal_data.json');
        document.body.appendChild(exportLink);
        exportLink.click();
        document.body.removeChild(exportLink);
    } catch (error) {
        console.error('Error exporting data:', error);
        alert('Failed to export data. Check console for details.');
    }
}

// Function to hash passwords - same as in login.js and register.js
function hashPassword(password) {
    // This must match exactly the hashing function in login.js and register.js
    let hash = 0;
    
    for (let i = 0; i < password.length; i++) {
        const char = password.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    
    return 'hashed_' + Math.abs(hash).toString(16);
}