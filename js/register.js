// Function to hash passwords
function hashPassword(password) {
    // In a real application, you would use a proper hashing library
    // This is a simple hash function for demonstration purposes only
    // IMPORTANT: This hash function must match exactly in both login.js and register.js
    
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
    
    const registerForm = document.getElementById('register-form');
    const registerMessage = document.getElementById('register-message');
    const togglePasswordBtn = document.getElementById('toggle-password');
    const toggleConfirmPasswordBtn = document.getElementById('toggle-confirm-password');
    const passwordField = document.getElementById('password');
    const confirmPasswordField = document.getElementById('confirm-password');
    const termsLink = document.getElementById('terms-link');
    const privacyLink = document.getElementById('privacy-link');
    
    // Toggle password visibility for main password field
    togglePasswordBtn.addEventListener('click', () => {
        const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordField.setAttribute('type', type);
        
        // Toggle eye icon
        const icon = togglePasswordBtn.querySelector('i');
        icon.className = type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
    });
    
    // Toggle password visibility for confirm password field
    toggleConfirmPasswordBtn.addEventListener('click', () => {
        const type = confirmPasswordField.getAttribute('type') === 'password' ? 'text' : 'password';
        confirmPasswordField.setAttribute('type', type);
        
        // Toggle eye icon
        const icon = toggleConfirmPasswordBtn.querySelector('i');
        icon.className = type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
    });
    
    // Add password strength indicator
    let passwordTips;
    
    // Create password strength indicator after password field
    function createPasswordStrengthIndicator() {
        const passwordGroup = passwordField.closest('.form-group');
        
        // Create password strength bar
        const strengthBar = document.createElement('div');
        strengthBar.className = 'password-strength';
        const strengthMeter = document.createElement('div');
        strengthMeter.className = 'password-strength-meter';
        strengthBar.appendChild(strengthMeter);
        
        // Create password strength text
        const strengthText = document.createElement('div');
        strengthText.className = 'password-strength-text';
        strengthText.innerHTML = '<span class="strength-label">Password Strength:</span><span class="strength-value">None</span>';
        
        // Create password tips
        passwordTips = document.createElement('div');
        passwordTips.className = 'password-tips';
        passwordTips.innerHTML = `
            <strong>Your password should:</strong>
            <ul>
                <li id="length-check">Be at least 8 characters long</li>
                <li id="uppercase-check">Contain at least one uppercase letter</li>
                <li id="lowercase-check">Contain at least one lowercase letter</li>
                <li id="number-check">Contain at least one number</li>
                <li id="special-check">Contain at least one special character</li>
            </ul>
        `;
        
        // Insert all elements after password input container
        const inputContainer = passwordGroup.querySelector('.password-input-container');
        inputContainer.insertAdjacentElement('afterend', strengthBar);
        strengthBar.insertAdjacentElement('afterend', strengthText);
        strengthText.insertAdjacentElement('afterend', passwordTips);
        
        return { strengthMeter, strengthText: strengthText.querySelector('.strength-value') };
    }
    
    const { strengthMeter, strengthText } = createPasswordStrengthIndicator();
    
    // Password strength check
    passwordField.addEventListener('input', () => {
        const password = passwordField.value;
        const { score, feedback } = checkPasswordStrength(password);
        
        // Update the strength meter
        let color = '';
        let strengthValue = '';
        
        switch(score) {
            case 0:
                color = '#e53935'; // Red
                strengthValue = 'Very Weak';
                strengthMeter.style.width = '20%';
                break;
            case 1:
                color = '#ef6c00'; // Orange
                strengthValue = 'Weak';
                strengthMeter.style.width = '40%';
                break;
            case 2:
                color = '#fbc02d'; // Yellow
                strengthValue = 'Fair';
                strengthMeter.style.width = '60%';
                break;
            case 3:
                color = '#7cb342'; // Light Green
                strengthValue = 'Good';
                strengthMeter.style.width = '80%';
                break;
            case 4:
                color = '#2e7d32'; // Green
                strengthValue = 'Strong';
                strengthMeter.style.width = '100%';
                break;
            default:
                color = '#e0e0e0';
                strengthValue = 'None';
                strengthMeter.style.width = '0%';
        }
        
        strengthMeter.style.backgroundColor = color;
        strengthText.textContent = strengthValue;
        
        // Update password tips
        updatePasswordTips(password);
    });
    
    // Update password tips based on password strength
    function updatePasswordTips(password) {
        // Check for various password requirements
        const hasLength = password.length >= 8;
        const hasUppercase = /[A-Z]/.test(password);
        const hasLowercase = /[a-z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSpecial = /[^A-Za-z0-9]/.test(password);
        
        // Update the UI for each check
        updateTipStatus('length-check', hasLength);
        updateTipStatus('uppercase-check', hasUppercase);
        updateTipStatus('lowercase-check', hasLowercase);
        updateTipStatus('number-check', hasNumber);
        updateTipStatus('special-check', hasSpecial);
    }
    
    // Update the status of a password tip
    function updateTipStatus(id, isValid) {
        const tipElement = document.getElementById(id);
        if (isValid) {
            tipElement.classList.add('valid');
            tipElement.classList.remove('invalid');
            tipElement.innerHTML = tipElement.innerHTML.replace(/^(Be|Contain)/, '✓ $1');
        } else {
            tipElement.classList.add('invalid');
            tipElement.classList.remove('valid');
            tipElement.innerHTML = tipElement.textContent.replace(/^✓ /, '');
        }
    }
    
    // Check password strength
    function checkPasswordStrength(password) {
        // Simple password strength rules
        let score = 0;
        let feedback = '';
        
        if (!password) {
            return { score: 0, feedback: 'Password is empty' };
        }
        
        // Length check
        if (password.length < 8) {
            feedback = 'Password is too short';
        } else {
            score += 1;
        }
        
        // Complexity checks
        if (/[A-Z]/.test(password)) score += 1;
        if (/[a-z]/.test(password)) score += 1;
        if (/[0-9]/.test(password)) score += 1;
        if (/[^A-Za-z0-9]/.test(password)) score += 1;
        
        // Adjust score based on length
        if (password.length >= 12) score += 1;
        if (password.length >= 16) score += 1;
        
        // Cap the score at 4
        score = Math.min(4, Math.floor(score / 2));
        
        return { score, feedback };
    }
    
    // Handle form submission
    registerForm.addEventListener('submit', (e) => {
        e.preventDefault();
        
        const fullname = document.getElementById('fullname').value.trim();
        const email = document.getElementById('email').value.trim();
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        const securityQuestion = document.getElementById('security-question').value;
        const securityAnswer = document.getElementById('security-answer').value.trim();
        const termsAgreed = document.getElementById('terms').checked;
        
        // Basic validation
        if (!fullname || !email || !username || !password || !securityQuestion || !securityAnswer) {
            showMessage('Please fill out all fields', 'error');
            return;
        }
        
        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            showMessage('Please enter a valid email address', 'error');
            return;
        }
        
        // Password match validation
        if (password !== confirmPassword) {
            showMessage('Passwords do not match', 'error');
            return;
        }
        
        // Password strength validation
        const { score } = checkPasswordStrength(password);
        if (score < 2) {
            showMessage('Please use a stronger password', 'error');
            return;
        }
        
        // Terms agreement validation
        if (!termsAgreed) {
            showMessage('You must agree to the Terms of Service', 'error');
            return;
        }
        
        // For demo purposes, let's simulate a successful registration
        // In a real application, this would be a server request
        showMessage('Registration successful! You can now login.', 'success');
        
        // Hash the password before storing
        const hashedPassword = hashPassword(password);
        
        // Security question and answer were already captured above
        
        // Create user object with hashed password and security info
        const userObj = { 
            fullname, 
            email, 
            username, 
            password: hashedPassword,
            securityQuestion,
            securityAnswer
        };
        
        // Add debugging
        console.log('Saving user with details:', {
            username: username,
            hashedPassword: hashedPassword,
        });
        
        // Save to localStorage
        const registeredUsers = JSON.parse(localStorage.getItem('registeredUsers') || '[]');
        registeredUsers.push(userObj);
        localStorage.setItem('registeredUsers', JSON.stringify(registeredUsers));
        
        // Save to local file using fetch API
        fetch('/save-user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(userObj)
        })
        .catch(error => console.error('Error saving user to file:', error));
        
        // Redirect to login page after successful registration
        setTimeout(() => {
            window.location.href = 'login.html';
        }, 2000);
    });
    
    // Handle terms link click
    termsLink.addEventListener('click', (e) => {
        e.preventDefault();
        showMessage('Terms of Service document coming soon!', 'info');
    });
    
    // Handle privacy link click
    privacyLink.addEventListener('click', (e) => {
        e.preventDefault();
        showMessage('Privacy Policy document coming soon!', 'info');
    });
    
    // Show a message in the registration form
    function showMessage(message, type) {
        registerMessage.textContent = message;
        registerMessage.className = `login-message ${type}`;
        registerMessage.style.display = 'block';
        
        // Scroll to message
        registerMessage.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
});