// Function to hash passwords - same as in login.js and register.js
function hashPassword(password) {
    // In a real application, you would use a proper hashing library
    // This is a simple hash function for demonstration purposes only
    
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

document.addEventListener('DOMContentLoaded', () => {
    // If already logged in, redirect to index page
    const isLoggedIn = localStorage.getItem('userLoggedIn');
    if (isLoggedIn) {
        window.location.href = 'index.html';
        return;
    }
    
    const resetForm = document.getElementById('password-reset-form');
    const resetMessage = document.getElementById('reset-message');
    const togglePasswordBtn = document.getElementById('toggle-password');
    const passwordField = document.getElementById('new-password');
    const confirmPasswordField = document.getElementById('confirm-password');
    const securityQuestionContainer = document.getElementById('security-question-container');
    const securityQuestionText = document.getElementById('security-question-text');
    const securityAnswer = document.getElementById('security-answer');
    const newPasswordContainer = document.getElementById('new-password-container');
    const confirmPasswordContainer = document.getElementById('confirm-password-container');
    const resetButton = document.getElementById('reset-button');
    
    // Security questions that users can choose from during registration
    const securityQuestionOptions = [
        'What city were you born in?',
        'What was your first pet\'s name?',
        'What is your favorite color?',
        'What is your mother\'s maiden name?',
        'What high school did you attend?'
    ];
    
    let currentStep = 1;
    let currentUser = null;
    
    // Toggle password visibility
    if (togglePasswordBtn) {
        togglePasswordBtn.addEventListener('click', () => {
            const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordField.setAttribute('type', type);
            
            // Toggle eye icon
            const icon = togglePasswordBtn.querySelector('i');
            icon.className = type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
        });
    }
    
    // Handle form submission
    resetForm.addEventListener('submit', (e) => {
        e.preventDefault();
        
        if (currentStep === 1) {
            // Step 1: Find account
            handleFindAccount();
        } else if (currentStep === 2) {
            // Step 2: Verify security question
            handleSecurityQuestion();
        } else if (currentStep === 3) {
            // Step 3: Reset password
            handleResetPassword();
        }
    });
    
    // Handle the find account step
    function handleFindAccount() {
        const identifier = document.getElementById('identifier').value.trim();
        
        if (!identifier) {
            showMessage('Please enter your username or email', 'error');
            return;
        }
        
        // Check both localStorage and server users
        const registeredUsers = JSON.parse(localStorage.getItem('registeredUsers') || '[]');
        
        // Try to find user in localStorage first
        currentUser = registeredUsers.find(user => 
            user.username === identifier || user.email === identifier
        );
        
        // If not found in localStorage, check if the user exists in server/users.json
        // For this demo, we're checking a hardcoded user if not found in localStorage
        if (currentUser) {
            // Show security question for this user
            showMessage('User found!', 'success');
            showSecurityQuestion(currentUser.username);
        } else {
            // Simulate looking up user from server
            showMessage('Searching for user...', 'info');
            
            // For demo, check if it's the user from users.json
            if (identifier === "mayank" || identifier === "mayank@gmail.com") {
                currentUser = {
                    username: "mayank",
                    email: "mayank@gmail.com",
                    securityQuestion: "What was your first pet's name?",
                    securityAnswer: "tree"
                };
                
                setTimeout(() => {
                    showMessage('User found!', 'success');
                    showSecurityQuestion(currentUser.username);
                }, 1000);
            } else {
                setTimeout(() => {
                    showMessage('No account found with that username or email', 'error');
                }, 1000);
            }
        }
    }
    
    // Show security question for the specified user
    function showSecurityQuestion(username) {
        // Check if this is the user from users.json
        if (currentUser && currentUser.username === "mayank") {
            // Use the hardcoded security question for this special user
            document.getElementById('identifier').disabled = true;
            securityQuestionContainer.style.display = 'block';
            securityQuestionText.textContent = currentUser.securityQuestion;
            
            // Hide the main button when showing step buttons
            resetButton.style.display = 'none';
            
            // Update alternative buttons
            findButton.style.display = 'none';
            verifyButton.style.display = 'block';
            
            // Update current step
            currentStep = 2;
            
            showMessage('Please answer the security question', 'info');
            return;
        }
        
        // For regular users, load from localStorage
        const registeredUsers = JSON.parse(localStorage.getItem('registeredUsers') || '[]');
        const userMatch = registeredUsers.find(user => user.username === username);
        
        // Check if user has a security question
        if (userMatch && userMatch.securityQuestion) {
            // Update UI
            document.getElementById('identifier').disabled = true;
            securityQuestionContainer.style.display = 'block';
            securityQuestionText.textContent = userMatch.securityQuestion;
            
            // Hide the main button when showing step buttons
            resetButton.style.display = 'none';
            
            // Update alternative buttons
            findButton.style.display = 'none';
            verifyButton.style.display = 'block';
            
            // Update current step
            currentStep = 2;
            
            showMessage('Please answer the security question', 'info');
        } else {
            // User doesn't have a security question set up
            showMessage('This account doesn\'t have a security question set up. Please contact support.', 'error');
        }
    }
    
    // Handle security question verification
    function handleSecurityQuestion() {
        const answer = securityAnswer.value.trim().toLowerCase();
        
        if (!answer) {
            showMessage('Please enter your answer', 'error');
            return;
        }
        
        // Special case for the user from users.json
        if (currentUser && currentUser.username === "mayank") {
            const storedAnswer = currentUser.securityAnswer.toLowerCase();
            
            if (answer === storedAnswer) {
                // Show password reset fields
                showPasswordReset();
            } else {
                showMessage('Incorrect answer. Please try again.', 'error');
            }
            return;
        }
        
        // For regular users stored in localStorage
        const registeredUsers = JSON.parse(localStorage.getItem('registeredUsers') || '[]');
        const userMatch = registeredUsers.find(user => user.username === currentUser.username);
        
        // Verify user has security question and answer
        if (userMatch && userMatch.securityQuestion && userMatch.securityAnswer) {
            const storedAnswer = userMatch.securityAnswer.toLowerCase();
            
            // For debugging (only in development)
            console.log('User entered answer:', answer);
            console.log('Stored answer:', storedAnswer);
            
            if (answer === storedAnswer) {
                // Show password reset fields
                showPasswordReset();
            } else {
                showMessage('Incorrect answer. Please try again.', 'error');
            }
        } else {
            // Fallback for users without security answers
            showMessage('This account doesn\'t have security answer information. Please contact support.', 'error');
        }
    }
    
    // Show password reset fields
    function showPasswordReset() {
        securityQuestionContainer.style.display = 'none';
        newPasswordContainer.style.display = 'block';
        confirmPasswordContainer.style.display = 'block';
        
        // Keep the main button hidden
        resetButton.style.display = 'none';
        
        // Update alternative buttons
        verifyButton.style.display = 'none';
        resetPassButton.style.display = 'block';
        
        // Update current step
        currentStep = 3;
        
        showMessage('Please enter and confirm your new password', 'info');
    }
    
    // Handle password reset
    function handleResetPassword() {
        const newPassword = passwordField.value;
        const confirmPassword = confirmPasswordField.value;
        
        // Basic validation
        if (!newPassword || !confirmPassword) {
            showMessage('Please enter and confirm your new password', 'error');
            return;
        }
        
        if (newPassword !== confirmPassword) {
            showMessage('Passwords do not match', 'error');
            return;
        }
        
        // Password strength validation (simple check)
        if (newPassword.length < 8) {
            showMessage('Password must be at least 8 characters long', 'error');
            return;
        }
        
        // Hash the new password
        const hashedPassword = hashPassword(newPassword);
        
        // Special case for the mayank user from users.json
        if (currentUser && currentUser.username === "mayank") {
            // Update server copy of user data
            updateUserPassword(currentUser.username, hashedPassword);
            
            // Show success message and redirect
            showMessage('Password reset successful! Redirecting to login...', 'success');
            setTimeout(() => {
                window.location.href = 'login.html';
            }, 2000);
            return;
        }
        
        // For regular users in localStorage
        const registeredUsers = JSON.parse(localStorage.getItem('registeredUsers') || '[]');
        const userIndex = registeredUsers.findIndex(user => user.username === currentUser.username);
        
        if (userIndex !== -1) {
            // Update user's password
            registeredUsers[userIndex].password = hashedPassword;
            localStorage.setItem('registeredUsers', JSON.stringify(registeredUsers));
            
            // Update server copy of user data
            updateUserPassword(currentUser.username, hashedPassword);
            
            // Show success message and redirect
            showMessage('Password reset successful! Redirecting to login...', 'success');
            setTimeout(() => {
                window.location.href = 'login.html';
            }, 2000);
        } else if (currentUser.username === 'admin') {
            // Special case for admin user (would require server-side handling in a real app)
            showMessage('Admin password cannot be reset from this portal', 'error');
        } else {
            showMessage('An error occurred. Please try again later.', 'error');
        }
    }
    
    // Function to update user password on server
    function updateUserPassword(username, hashedPassword) {
        // In a real app, this would send a request to the server
        // For demo purposes, we'll just log it
        console.log(`Password reset for user ${username} to ${hashedPassword}`);
        
        // In a real application, you would make an API call like:
        fetch('/reset-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: hashedPassword
            })
        })
        .catch(error => console.error('Error updating password:', error));
    }
    
    // Show a message in the reset form
    function showMessage(message, type) {
        resetMessage.textContent = message;
        resetMessage.className = `login-message ${type}`;
        resetMessage.style.display = 'block';
    }
    
    // Add animation to make the form more engaging
    function addFormAnimation() {
        const formGroups = document.querySelectorAll('.form-group');
        
        formGroups.forEach((group, index) => {
            if (getComputedStyle(group).display !== 'none') {
                group.style.opacity = '0';
                group.style.transform = 'translateY(20px)';
                group.style.transition = `opacity 0.3s ease-out ${index * 0.1}s, transform 0.3s ease-out ${index * 0.1}s`;
                
                setTimeout(() => {
                    group.style.opacity = '1';
                    group.style.transform = 'translateY(0)';
                }, 100);
            }
        });
    }
    
    // Run the animation when the page loads
    addFormAnimation();
    
    // Set up alternative buttons
    const findButton = document.getElementById('find-button');
    const verifyButton = document.getElementById('verify-button');
    const resetPassButton = document.getElementById('reset-pass-button');
    
    if (findButton) {
        findButton.addEventListener('click', function(e) {
            e.preventDefault();
            handleFindAccount();
        });
    }
    
    if (verifyButton) {
        verifyButton.addEventListener('click', function(e) {
            e.preventDefault();
            handleSecurityQuestion();
        });
    }
    
    if (resetPassButton) {
        resetPassButton.addEventListener('click', function(e) {
            e.preventDefault();
            handleResetPassword();
        });
    }
    
    // No debug needed anymore
});