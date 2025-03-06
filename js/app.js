document.addEventListener('DOMContentLoaded', () => {
    const vulnerabilitiesContainer = document.getElementById('vulnerabilities-container');
    
    // Debug - check if vulnerabilitiesData exists
    console.log("Loading vulnerabilities:", typeof vulnerabilitiesData, Array.isArray(vulnerabilitiesData) ? vulnerabilitiesData.length : 'not an array');
    
    // For development - add a fake user if not logged in
    if (!localStorage.getItem('userLoggedIn')) {
        localStorage.setItem('userLoggedIn', 'true');
        localStorage.setItem('currentUser', 'testuser');
    }
    
    // Check if user is logged in
    checkUserAuthentication();
    
    // Display welcome message with username
    displayWelcomeMessage();
    
    // Initialize theme toggle functionality
    initThemeToggle();
    
    // Simulate loading delay for better UX
    setTimeout(() => {
        // Clear loading text
        vulnerabilitiesContainer.innerHTML = '';
        
        // Forcefully load the first vulnerability if the data array exists
        if (Array.isArray(vulnerabilitiesData) && vulnerabilitiesData.length > 0) {
            // Create vulnerability cards
            vulnerabilitiesData.forEach(vulnerability => {
                try {
                    createVulnerabilityCard(vulnerability, vulnerabilitiesContainer);
                } catch (error) {
                    console.error("Error creating vulnerability card:", error, vulnerability);
                    // Create a fallback card if there's an error
                    const errorCard = document.createElement('div');
                    errorCard.className = 'vulnerability-card';
                    errorCard.innerHTML = `<div class="vulnerability-header">
                        <h2><i class="fas fa-exclamation-triangle"></i> ${vulnerability.title || 'Error loading vulnerability'}</h2>
                    </div>`;
                    vulnerabilitiesContainer.appendChild(errorCard);
                }
            });
        } else {
            // Display error message if vulnerabilities don't load
            vulnerabilitiesContainer.innerHTML = `
                <div class="error-message" style="text-align: center; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
                    <h3><i class="fas fa-exclamation-circle"></i> Error Loading Content</h3>
                    <p>Could not load vulnerabilities data. Please check your browser console for errors.</p>
                </div>
            `;
        }
        
        // Check if there's a hash in the URL to open a specific vulnerability
        const hash = window.location.hash;
        if (hash) {
            const targetElement = document.querySelector(hash);
            if (targetElement) {
                setTimeout(() => {
                    targetElement.querySelector('.vulnerability-header').click();
                    targetElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }, 100);
            }
        }
    }, 500);
    
    // Handle logout button click
    const logoutBtn = document.querySelector('.logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            localStorage.removeItem('userLoggedIn');
            window.location.href = 'login.html';
        });
    }
});

// Check if user is authenticated, redirect to login page if not
function checkUserAuthentication() {
    const isLoggedIn = localStorage.getItem('userLoggedIn');
    if (!isLoggedIn && window.location.pathname !== '/login.html') {
        window.location.href = 'login.html';
    }
}

// Display welcome message with the current username
function displayWelcomeMessage() {
    const welcomeMessageElement = document.getElementById('welcome-message');
    if (welcomeMessageElement) {
        const username = localStorage.getItem('currentUser');
        if (username) {
            welcomeMessageElement.innerHTML = `<i class="fas fa-user"></i> Welcome, ${username}!`;
            
            // Add admin link if the user is admin
            if (username === 'admin') {
                const headerActions = document.querySelector('.header-actions');
                const statsBtn = document.querySelector('.stats-btn');
                
                // Create admin link if it doesn't exist yet
                if (!document.querySelector('.admin-btn')) {
                    const adminLink = document.createElement('a');
                    adminLink.href = 'admin.html';
                    adminLink.className = 'admin-btn';
                    adminLink.innerHTML = '<i class="fas fa-user-shield"></i> Admin Panel';
                    
                    // Insert before the stats button
                    headerActions.insertBefore(adminLink, statsBtn);
                }
            }
        }
    }
}

// Get icon for each vulnerability category
function getVulnerabilityIcon(id) {
    const icons = {
        'a01': 'fas fa-user-lock',           // Broken Access Control
        'a02': 'fas fa-key',                 // Cryptographic Failures
        'a03': 'fas fa-code',                // Injection
        'a04': 'fas fa-sitemap',             // Insecure Design
        'a05': 'fas fa-cogs',                // Security Misconfiguration
        'a06': 'fas fa-box-open',            // Vulnerable and Outdated Components
        'a07': 'fas fa-user-shield',         // Identification and Authentication Failures
        'a08': 'fas fa-clipboard-check',     // Software and Data Integrity Failures
        'a09': 'fas fa-search',              // Security Logging and Monitoring Failures
        'a10': 'fas fa-exchange-alt'         // Server-Side Request Forgery
    };
    
    return icons[id] || 'fas fa-shield-alt';
}

// Get icon for each section
function getSectionIcon(title) {
    const icons = {
        'Description': 'fas fa-info-circle',
        'Scenario': 'fas fa-project-diagram',
        'Vulnerable Code': 'fas fa-bug',
        'Challenge': 'fas fa-tasks',
        'Hint': 'fas fa-lightbulb',
        'Common Mitigation Strategies': 'fas fa-shield-alt'
    };
    
    return icons[title] || 'fas fa-angle-right';
}

function createVulnerabilityCard(vulnerability, container) {
    try {
        console.log("Creating card for vulnerability:", vulnerability.id);
        
        const card = document.createElement('div');
        card.className = 'vulnerability-card';
        card.id = vulnerability.id;
        
        // Create header
        const header = document.createElement('div');
        header.className = 'vulnerability-header';
        header.innerHTML = `
            <h2><i class="${getVulnerabilityIcon(vulnerability.id)}"></i> ${vulnerability.title}</h2>
            <span class="toggle-icon"><i class="fas fa-chevron-down"></i></span>
        `;
        
        // Toggle card expansion
        header.addEventListener('click', () => {
            const content = card.querySelector('.vulnerability-content');
            content.classList.toggle('expanded');
            const toggleIcon = header.querySelector('.toggle-icon i');
            toggleIcon.className = content.classList.contains('expanded') ? 'fas fa-chevron-up' : 'fas fa-chevron-down';
            
            // Update URL hash
            if (content.classList.contains('expanded')) {
                history.replaceState(null, null, `#${vulnerability.id}`);
            } else if (window.location.hash === `#${vulnerability.id}`) {
                history.replaceState(null, null, window.location.pathname);
            }
        });
        
        // Create content
        const content = document.createElement('div');
        content.className = 'vulnerability-content';
        
        // Description section
        if (vulnerability.description) {
            const descriptionSection = createSection('Description', vulnerability.description);
            content.appendChild(descriptionSection);
        }
        
        // Scenario section (if exists)
        if (vulnerability.scenario) {
            const scenarioSection = createSection('Scenario', vulnerability.scenario);
            content.appendChild(scenarioSection);
        }
    
        // Vulnerable Code section
        if (vulnerability.vulnerableCode) {
            const vulnerableCodeSection = createCollapsibleSection('Vulnerable Code', `
                <div class="code-block">${highlightCode(vulnerability.vulnerableCode)}</div>
            `);
            content.appendChild(vulnerableCodeSection);
        }
        
        // Challenge section
        if (vulnerability.challenge) {
            const challengeSection = createCollapsibleSection('Challenge', `
                <p>${vulnerability.challenge}</p>
                <div class="interactive-section">
                    <textarea class="user-input" placeholder="Enter your solution here..."></textarea>
                    <div class="button-group">
                        <button class="submit-btn" data-id="${vulnerability.id}"><i class="fas fa-check-circle"></i> Submit</button>
                        <button class="hint-btn" data-id="${vulnerability.id}"><i class="fas fa-lightbulb"></i> Show Hint</button>
                    </div>
                    <div class="result-message" style="display: none;"></div>
                    <div class="mitigation">
                        <h4><i class="fas fa-shield-alt"></i> Mitigation Example:</h4>
                        <div class="code-block">${highlightCode(vulnerability.mitigation || '')}</div>
                    </div>
                </div>
            `);
            content.appendChild(challengeSection);
        }
        
        // Hint section
        if (vulnerability.hint) {
            const hintSection = createCollapsibleSection('Hint', `<p>${vulnerability.hint}</p>`);
            content.appendChild(hintSection);
        }
        
        // Mitigation Strategies section
        if (vulnerability.mitigationStrategies && Array.isArray(vulnerability.mitigationStrategies)) {
            const mitigationStrategiesSection = createCollapsibleSection('Common Mitigation Strategies', `
                <ul>
                    ${vulnerability.mitigationStrategies.map(strategy => `<li>${strategy}</li>`).join('')}
                </ul>
            `);
            content.appendChild(mitigationStrategiesSection);
        }
        
        // Append header and content to card
        card.appendChild(header);
        card.appendChild(content);
        
        // Append card to container
        container.appendChild(card);
        
        // Add event listeners for the challenge
        const submitBtn = card.querySelector('.submit-btn');
        const hintBtn = card.querySelector('.hint-btn');
        const userInput = card.querySelector('.user-input');
        const resultMessage = card.querySelector('.result-message');
        const mitigation = card.querySelector('.mitigation');
        
        if (submitBtn && hintBtn && userInput && resultMessage && mitigation) {
            // Handle solution submission
            submitBtn.addEventListener('click', () => {
                const userSolution = userInput.value.trim();
                const correctSolution = vulnerability.solution;
                const isCorrect = isCorrectSolution(userSolution, correctSolution);
                
                // Track this attempt if tracking function is available
                if (typeof trackChallengeAttempt === 'function') {
                    trackChallengeAttempt(vulnerability.id, isCorrect);
                }
                
                if (isCorrect) {
                    resultMessage.innerHTML = '<i class="fas fa-check-circle"></i> Correct! Well done.';
                    resultMessage.className = 'result-message success';
                    mitigation.classList.add('visible');
                    
                    // Add confetti effect for correct answer
                    addConfetti();
                } else {
                    resultMessage.innerHTML = '<i class="fas fa-times-circle"></i> Incorrect. Try again or use the hint.';
                    resultMessage.className = 'result-message error';
                }
                
                resultMessage.style.display = 'block';
            });
            
            // Handle hint button click
            hintBtn.addEventListener('click', () => {
                // Find the Hint section by title instead of position, as position might vary
                const sections = card.querySelectorAll('.section');
                let hintSection = null;
                
                sections.forEach(section => {
                    const title = section.querySelector('h3').textContent.trim();
                    if (title.includes('Hint')) {
                        hintSection = section;
                    }
                });
                
                if (hintSection) {
                    const hintSectionContent = hintSection.querySelector('.section-content');
                    hintSectionContent.classList.add('expanded');
                    const toggleIcon = hintSection.querySelector('h3 .toggle-icon i');
                    if (toggleIcon) {
                        toggleIcon.className = 'fas fa-chevron-up';
                    }
                }
            });
            
            // Allow pressing Enter to submit
            userInput.addEventListener('keydown', (event) => {
                if (event.key === 'Enter' && !event.shiftKey) {
                    event.preventDefault();
                    submitBtn.click();
                }
            });
        }
    } catch (error) {
        console.error("Error in createVulnerabilityCard:", error, vulnerability);
        // Create a simple error card
        const errorCard = document.createElement('div');
        errorCard.className = 'vulnerability-card';
        errorCard.innerHTML = `
            <div class="vulnerability-header">
                <h2><i class="fas fa-exclamation-triangle"></i> Error Loading ${vulnerability.title || 'Vulnerability'}</h2>
            </div>
            <div class="vulnerability-content expanded" style="padding: 1rem;">
                <p>An error occurred while loading this vulnerability. Check the console for details.</p>
            </div>
        `;
        container.appendChild(errorCard);
    }
}

function createSection(title, content) {
    const section = document.createElement('div');
    section.className = 'section';
    
    // Process content to properly handle newlines in descriptions and scenarios
    // Replace \n with <br> for proper line breaks
    const formattedContent = content.replace(/\n/g, '<br>');
    
    section.innerHTML = `
        <h3><i class="${getSectionIcon(title)}"></i> ${title}</h3>
        <div class="section-content expanded">
            <p>${formattedContent}</p>
        </div>
    `;
    return section;
}

function createCollapsibleSection(title, content) {
    const section = document.createElement('div');
    section.className = 'section';
    section.innerHTML = `
        <h3>
            <i class="${getSectionIcon(title)}"></i> ${title}
            <span class="toggle-icon"><i class="fas fa-chevron-down"></i></span>
        </h3>
        <div class="section-content">
            ${content}
        </div>
    `;
    
    const sectionHeader = section.querySelector('h3');
    sectionHeader.addEventListener('click', () => {
        const sectionContent = section.querySelector('.section-content');
        sectionContent.classList.toggle('expanded');
        const toggleIcon = sectionHeader.querySelector('.toggle-icon i');
        toggleIcon.className = sectionContent.classList.contains('expanded') ? 'fas fa-chevron-up' : 'fas fa-chevron-down';
    });
    
    return section;
}

function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function highlightCode(code) {
    // Escape HTML first
    const escapedCode = escapeHtml(code);
    
    // Apply basic syntax highlighting with Java and Spring Boot keywords added
    return escapedCode
        .replace(/\/\/(.*)/g, '<span class="comment">//$1</span>')
        .replace(/\/\*([\s\S]*?)\*\//g, '<span class="comment">/*$1*/</span>')
        // Add Java and Spring Boot keywords
        .replace(/\b(const|let|var|function|if|else|return|await|async|try|catch|for|while|class|import|export|from|require|public|private|protected|static|void|String|int|boolean|throws|throw|new|extends|implements|interface|abstract|final|package|this|super|null|instanceof|enum|long|double|System|out|println|ResponseEntity|RequestMapping|RestController|Autowired|GetMapping|PostMapping|PathVariable|RequestParam)\b/g, '<span class="keyword">$1</span>')
        .replace(/\b(true|false|null|undefined)\b/g, '<span class="keyword">$1</span>')
        .replace(/"(.*?)"/g, '<span class="string">"$1"</span>')
        .replace(/'(.*?)'/g, '<span class="string">\'$1\'</span>')
        .replace(/`([\s\S]*?)`/g, '<span class="string">`$1`</span>')
        .replace(/\b(\d+)\b/g, '<span class="number">$1</span>')
        // Add annotation highlighting
        .replace(/(@\w+)/g, '<span class="annotation">$1</span>');
}

function isCorrectSolution(userSolution, correctSolution) {
    // Special case for A05 Security Misconfiguration challenge
    if (correctSolution === '/user/100' || correctSolution === 'Content-Security-Policy') {
        // Check if the user's solution matches the pattern /user/NUMBER where NUMBER > 99
        const a05Pattern = /^\/user\/(\d+)$/i;
        const match = userSolution.match(a05Pattern);
        if (match && parseInt(match[1]) > 99) {
            return true;
        }
        
        // For Content-Security-Policy
        if (userSolution.toLowerCase() === 'content-security-policy') {
            return true;
        }
    }
    
    // For A03 SQL Injection solution
    if (correctSolution === "' OR '1'='1") {
        // Various forms of SQL injection
        const sqlInjectionPatterns = [
            /' OR '1'='1/i,
            /' OR 1=1/i,
            /OR 1=1/i,
            /' --/i
        ];
        
        for (const pattern of sqlInjectionPatterns) {
            if (pattern.test(userSolution)) {
                return true;
            }
        }
    }
    
    // Case-insensitive comparison for simpler answers
    return userSolution.toLowerCase() === correctSolution.toLowerCase() ||
           // Allow partial matching for more complex solutions
           (correctSolution.length > 10 && userSolution.toLowerCase().includes(correctSolution.toLowerCase()));
}

// Simple confetti effect for correct answers
function addConfetti() {
    const confettiContainer = document.createElement('div');
    confettiContainer.className = 'confetti-container';
    document.body.appendChild(confettiContainer);
    
    const colors = ['#f44336', '#2196f3', '#ffeb3b', '#4caf50', '#9c27b0'];
    
    for (let i = 0; i < 100; i++) {
        const confetti = document.createElement('div');
        confetti.className = 'confetti';
        confetti.style.backgroundColor = colors[Math.floor(Math.random() * colors.length)];
        confetti.style.left = Math.random() * 100 + 'vw';
        confetti.style.animationDuration = (Math.random() * 3 + 2) + 's';
        confetti.style.animationDelay = Math.random() * 5 + 's';
        confettiContainer.appendChild(confetti);
    }
    
    setTimeout(() => {
        confettiContainer.remove();
    }, 5000);
}

// Theme toggle functionality
function initThemeToggle() {
    const themeToggleBtn = document.getElementById('theme-toggle');
    if (!themeToggleBtn) return;
    
    // Apply saved theme on page load
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
    
    // Toggle between light and dark mode
    themeToggleBtn.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? '' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
    });
}