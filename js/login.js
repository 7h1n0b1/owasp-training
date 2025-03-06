// Function to hash passwords - same as in register.js
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
    
    // Load server-side users for login authentication
    let serverUsers = [];
    fetch('/get-users')
        .then(response => response.json())
        .then(data => {
            serverUsers = data;
            console.log('Server users loaded:', serverUsers);
        })
        .catch(error => {
            console.error('Error loading server users:', error);
        });
    
    const loginForm = document.getElementById('login-form');
    const loginMessage = document.getElementById('login-message');
    const togglePasswordBtn = document.getElementById('toggle-password');
    const passwordField = document.getElementById('password');
    const registerLink = document.getElementById('register-link');
    const forgotPasswordLink = document.getElementById('forgot-password');

    // Toggle password visibility
    togglePasswordBtn.addEventListener('click', () => {
        const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordField.setAttribute('type', type);
        
        // Toggle eye icon
        const icon = togglePasswordBtn.querySelector('i');
        icon.className = type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
    });

    // Handle form submission
    loginForm.addEventListener('submit', (e) => {
        e.preventDefault();
        
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const rememberMe = document.getElementById('remember').checked;
        
        // Basic validation
        if (!username || !password) {
            showMessage('Please enter both username and password', 'error');
            return;
        }
        
        // For demo purposes, let's use a simple authentication
        // In a real application, this would be a server request
        
        // Hash the password for server authentication
        const hashedPassword = hashPassword(password);
        
        // Send authentication request to server
        fetch('/auth', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                username: username, 
                password: hashedPassword 
            }),
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Authentication successful
                console.log('Login successful:', data.user);
                
                // Store authentication state
                localStorage.setItem('userLoggedIn', 'true');
                localStorage.setItem('currentUser', username);
                localStorage.setItem('isAdmin', data.user.isAdmin);
                
                // If "Remember me" is checked, store the username in localStorage
                if (rememberMe) {
                    localStorage.setItem('rememberedUser', username);
                } else {
                    localStorage.removeItem('rememberedUser');
                }
                
                // Show success message and redirect
                showMessage('Login successful! Redirecting...', 'success');
                
                // Redirect based on user type (admin or regular user)
                setTimeout(() => {
                    if (data.user.isAdmin) {
                        window.location.href = 'admin.html';
                    } else {
                        window.location.href = 'index.html';
                    }
                }, 1500);
            } else {
                // Authentication failed
                showMessage(data.message || 'Invalid username or password', 'error');
            }
        })
        .catch(error => {
            console.error('Login error:', error);
            showMessage('An error occurred during login. Please try again.', 'error');
        });
    });
            
    // Rest of the login form event handler code is updated above

    // Register link now points directly to register.html via href

    // Handle forgot password link click
    forgotPasswordLink.addEventListener('click', (e) => {
        e.preventDefault();
        window.location.href = 'forgot-password.html';
    });

    // Show a message in the login form
    function showMessage(message, type) {
        loginMessage.textContent = message;
        loginMessage.className = `login-message ${type}`;
        loginMessage.style.display = 'block';
    }

    // Check if we have a remembered user
    const rememberedUser = localStorage.getItem('rememberedUser');
    if (rememberedUser) {
        document.getElementById('username').value = rememberedUser;
        document.getElementById('remember').checked = true;
    }

    // Add some simple animation to make the form more engaging
    function addFormAnimation() {
        const formGroups = document.querySelectorAll('.form-group');
        
        formGroups.forEach((group, index) => {
            group.style.opacity = '0';
            group.style.transform = 'translateY(20px)';
            group.style.transition = `opacity 0.3s ease-out ${index * 0.1}s, transform 0.3s ease-out ${index * 0.1}s`;
            
            setTimeout(() => {
                group.style.opacity = '1';
                group.style.transform = 'translateY(0)';
            }, 100);
        });
    }
    
    // Run the animation when the page loads
    addFormAnimation();
});