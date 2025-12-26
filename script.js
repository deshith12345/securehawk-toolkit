/**
 * SecureHawk - Password Security Tool Suite
 * 
 * This application provides three main security tools:
 * 1. Password Strength Checker - Analyzes password strength and provides detailed feedback
 * 2. Breach Checker - Checks if passwords have been compromised in data breaches (using HIBP API)
 * 3. Password Generator - Creates cryptographically secure random passwords
 * 
 * @version 3.5
 */

// ============================================================================
// PASSWORD STRENGTH CHECKER
// ============================================================================

// DOM Elements for password strength checker
const passwordCheckInput = document.getElementById('password-check');
const strengthBar = document.getElementById('strength-bar');
const strengthText = document.getElementById('strength-text');
const analysisResults = document.getElementById('analysis-results');
const analysisList = document.getElementById('analysis-list');

console.log('SecureHawk Logic v3.5 Loaded'); // Cache Confirmation

/**
 * Common weak passwords database
 * These passwords are frequently used and easily cracked
 */
const commonPasswords = [
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
    'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
    'ashley', 'bailey', 'passw0rd', 'shadow', '123123', '654321', 'superman',
    'qazwsx', 'michael', 'football'
];

/**
 * Common keyboard patterns that indicate weak passwords
 * Sequential keys on a QWERTY keyboard
 */
const keyboardPatterns = [
    'qwerty', 'asdfgh', 'zxcvbn', '1qaz2wsx', 'qwertyuiop', 'asdfghjkl'
];

// Event listener for real-time password strength checking
if (passwordCheckInput) {
    passwordCheckInput.addEventListener('input', function () {
        const password = this.value;
        if (password.length === 0) {
            resetStrengthChecker();
            return;
        }
        analyzePassword(password);
    });
}

/**
 * Analyze password and display strength metrics
 * Performs comprehensive analysis including character variety, patterns, and entropy
 * 
 * @param {string} password - The password to analyze
 */
function analyzePassword(password) {
    const analysis = {
        length: password.length,
        hasUppercase: /[A-Z]/.test(password),
        hasLowercase: /[a-z]/.test(password),
        hasNumbers: /[0-9]/.test(password),
        hasSymbols: /[^a-zA-Z0-9]/.test(password),
        hasSequential: hasSequentialChars(password),
        hasKeyboardPattern: hasKeyboardPattern(password),
        isCommon: isCommonPassword(password),
        hasRepeatingChars: hasRepeatingChars(password)
    };

    const strength = calculateStrength(password, analysis);
    const entropy = calculateEntropy(password);
    const crackTime = estimateCrackTime(entropy);

    updateStrengthMeter(strength);
    displayAnalysis(password, analysis, entropy, crackTime);
}

/**
 * Calculate password strength score based on various criteria
 * 
 * @param {string} password - The password to evaluate
 * @param {Object} analysis - Analysis object with password characteristics
 * @returns {string} Strength level: 'very-weak', 'weak', 'fair', 'good', or 'strong'
 */
function calculateStrength(password, analysis) {
    let score = 0;

    // Length scoring - longer passwords are stronger
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;
    if (password >= 20) score += 1;

    // Character variety - diverse character types increase strength
    if (analysis.hasUppercase) score += 1;
    if (analysis.hasLowercase) score += 1;
    if (analysis.hasNumbers) score += 1;
    if (analysis.hasSymbols) score += 1;

    // Penalties for weak patterns
    if (analysis.isCommon) score -= 3;           // Common passwords are very weak
    if (analysis.hasSequential) score -= 1;       // Sequential characters are predictable
    if (analysis.hasKeyboardPattern) score -= 1;  // Keyboard patterns are easily guessed
    if (analysis.hasRepeatingChars) score -= 1;   // Repeating characters reduce complexity

    // Map score to strength level
    if (score <= 2) return 'very-weak';
    if (score <= 4) return 'weak';
    if (score <= 5) return 'fair';
    if (score <= 6) return 'good';
    return 'strong';
}

/**
 * Calculate password entropy (randomness) in bits
 * Higher entropy means more possible combinations and stronger password
 * 
 * @param {string} password - The password to analyze
 * @returns {number} Entropy value in bits
 */
function calculateEntropy(password) {
    let poolSize = 0;

    // Calculate character pool size based on character types used
    if (/[a-z]/.test(password)) poolSize += 26;  // Lowercase letters
    if (/[A-Z]/.test(password)) poolSize += 26;  // Uppercase letters
    if (/[0-9]/.test(password)) poolSize += 10;  // Digits
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;  // Symbols

    // Entropy = log2(poolSize^length)
    return Math.log2(Math.pow(poolSize, password.length));
}

/**
 * Estimate time to crack password using brute force
 * Assumes 1 billion guesses per second (modern GPU capability)
 * 
 * @param {number} entropy - Password entropy in bits
 * @returns {string} Human-readable crack time estimate
 */
function estimateCrackTime(entropy) {
    const guessesPerSecond = 1e9; // 1 billion guesses per second (GPU)
    const totalGuesses = Math.pow(2, entropy);
    const seconds = totalGuesses / guessesPerSecond / 2; // Divide by 2 for average case

    // Convert to human-readable time
    if (seconds < 1) return 'Instant';
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 3153600000) return `${Math.round(seconds / 31536000)} years`;
    return 'Centuries';
}

/**
 * Check if password contains sequential characters (e.g., "abc", "123")
 * 
 * @param {string} password - Password to check
 * @returns {boolean} True if sequential characters found
 */
function hasSequentialChars(password) {
    const sequential = ['0123456789', 'abcdefghijklmnopqrstuvwxyz'];
    const lowerPass = password.toLowerCase();

    for (let seq of sequential) {
        // Check for any 3-character sequence
        for (let i = 0; i < seq.length - 2; i++) {
            if (lowerPass.includes(seq.substring(i, i + 3))) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Check if password contains keyboard patterns
 * 
 * @param {string} password - Password to check
 * @returns {boolean} True if keyboard pattern found
 */
function hasKeyboardPattern(password) {
    const lowerPass = password.toLowerCase();
    return keyboardPatterns.some(pattern => lowerPass.includes(pattern));
}

/**
 * Check if password is in the common passwords list
 * 
 * @param {string} password - Password to check
 * @returns {boolean} True if password is common
 */
function isCommonPassword(password) {
    return commonPasswords.includes(password.toLowerCase());
}

/**
 * Check if password has repeating characters (e.g., "aaa", "111")
 * 
 * @param {string} password - Password to check
 * @returns {boolean} True if 3+ repeating characters found
 */
function hasRepeatingChars(password) {
    return /(.)\\1{2,}/.test(password);
}

/**
 * Update the visual strength meter display
 * 
 * @param {string} strength - Strength level ('very-weak' to 'strong')
 */
function updateStrengthMeter(strength) {
    // Color scheme using Apple design system colors
    const styles = {
        'very-weak': { width: '20%', color: '#FF3B30' },  // Apple Red
        'weak': { width: '40%', color: '#FF9F0A' },       // Apple Orange
        'fair': { width: '60%', color: '#FFD60A' },       // Apple Yellow
        'good': { width: '80%', color: '#34C759' },       // Apple Green
        'strong': { width: '100%', color: '#30D158' }     // Apple Bright Green
    };

    const config = styles[strength];

    // Apply inline styles to ensure visual consistency
    strengthBar.className = 'strength-fill';
    strengthBar.style.width = config.width;
    strengthBar.style.backgroundColor = config.color;
    strengthBar.style.boxShadow = `0 0 10px ${config.color}`; // Glow effect

    const strengthLabels = {
        'very-weak': 'Very Weak',
        'weak': 'Weak',
        'fair': 'Fair',
        'good': 'Good',
        'strong': 'Strong'
    };

    strengthText.textContent = strengthLabels[strength];
}

/**
 * Display detailed password analysis feedback
 * Shows what requirements are met and what's missing
 * 
 * @param {string} password - The analyzed password
 * @param {Object} analysis - Analysis results
 * @param {number} entropy - Calculated entropy
 * @param {string} crackTime - Estimated crack time
 */
function displayAnalysis(password, analysis, entropy, crackTime) {
    analysisResults.style.display = 'block';
    analysisList.innerHTML = '';

    const feedback = [];

    // Positive feedback for met requirements
    if (analysis.length >= 12) {
        feedback.push({ type: 'valid', text: `Length: ${analysis.length} chars` });
    } else {
        feedback.push({ type: 'invalid', text: `Too short (<12 chars)` });
    }

    if (analysis.hasUppercase) feedback.push({ type: 'valid', text: 'Uppercase' });
    else feedback.push({ type: 'invalid', text: 'Missing Uppercase' });

    if (analysis.hasLowercase) feedback.push({ type: 'valid', text: 'Lowercase' });
    else feedback.push({ type: 'invalid', text: 'Missing Lowercase' });

    if (analysis.hasNumbers) feedback.push({ type: 'valid', text: 'Numbers' });
    else feedback.push({ type: 'invalid', text: 'Missing Numbers' });

    if (analysis.hasSymbols) feedback.push({ type: 'valid', text: 'Symbols' });
    else feedback.push({ type: 'invalid', text: 'Missing Symbols' });

    // Negative patterns that weaken the password
    if (analysis.isCommon) feedback.push({ type: 'invalid', text: 'Common Password' });
    if (analysis.hasSequential) feedback.push({ type: 'invalid', text: 'Sequential Chars' });
    if (analysis.hasKeyboardPattern) feedback.push({ type: 'invalid', text: 'Keyboard Pattern' });
    if (analysis.hasRepeatingChars) feedback.push({ type: 'invalid', text: 'Repeating Chars' });

    // Render feedback items
    feedback.forEach(item => {
        const li = document.createElement('li');
        li.className = 'analysis-item ' + item.type;
        li.innerHTML = item.type === 'valid'
            ? `<i class="fas fa-check"></i> ${item.text}`
            : `<i class="fas fa-times"></i> ${item.text}`;
        analysisList.appendChild(li);
    });

    // Update statistics display
    document.getElementById('stat-length').textContent = analysis.length;
    document.getElementById('stat-entropy').textContent = entropy.toFixed(0);
    document.getElementById('stat-crack').textContent = crackTime;
}

/**
 * Reset the strength checker to initial state
 */
function resetStrengthChecker() {
    strengthBar.className = 'strength-fill';
    strengthBar.style.width = '0%';
    strengthBar.style.backgroundColor = 'transparent';
    strengthText.textContent = 'Enter a password to check';
    analysisResults.style.display = 'none';

    document.getElementById('stat-length').textContent = '0';
    document.getElementById('stat-entropy').textContent = '0';
    document.getElementById('stat-crack').textContent = '-';
}

// ============================================================================
// PASSWORD BREACH CHECKER
// ============================================================================

/**
 * Check if password has been compromised in data breaches
 * Uses the Have I Been Pwned (HIBP) API with k-Anonymity model
 * Only sends first 5 characters of hash to protect privacy
 */
async function checkBreach() {
    const passwordInput = document.getElementById('password-breach');
    const resultsDiv = document.getElementById('breach-results');
    const password = passwordInput.value;

    if (!password) {
        resultsDiv.style.display = 'block';
        resultsDiv.className = 'breach-alert danger';
        resultsDiv.innerHTML = '<i class="fas fa-exclamation-circle"></i> Please enter a password to check.';
        return;
    }

    // Show loading state
    resultsDiv.style.display = 'block';
    resultsDiv.className = 'breach-alert';
    resultsDiv.style.backgroundColor = '#f1f5f9';
    resultsDiv.style.color = '#64748b';
    resultsDiv.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking database...';

    try {
        // Hash the password using SHA-1 (required by HIBP API)
        const hash = await sha1(password);
        const prefix = hash.substring(0, 5);  // Send only first 5 chars for privacy
        const suffix = hash.substring(5);

        // Query HIBP API with k-Anonymity model
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        const data = await response.text();

        // Parse response to find matching hash
        const hashes = data.split('\r\n');
        let found = false;
        let count = 0;

        for (let line of hashes) {
            const [hashSuffix, frequency] = line.split(':');
            if (hashSuffix.toLowerCase() === suffix.toLowerCase()) {
                found = true;
                count = parseInt(frequency);
                break;
            }
        }

        // Display results
        if (found) {
            resultsDiv.className = 'breach-alert danger';
            resultsDiv.style.backgroundColor = '';
            resultsDiv.style.color = '';
            resultsDiv.innerHTML = `
                <div style="font-weight: bold; margin-bottom: 0.5rem; font-size: 1.1em;">
                    <i class="fas fa-triangle-exclamation"></i> Compromised!
                </div>
                <div>
                    This password appears <strong>${count.toLocaleString()}</strong> times in data breaches.
                    <br>Do not use this password on any account.
                </div>
            `;
        } else {
            resultsDiv.className = 'breach-alert safe';
            resultsDiv.style.backgroundColor = '';
            resultsDiv.style.color = '';
            resultsDiv.innerHTML = `
                <div style="font-weight: bold; margin-bottom: 0.5rem; font-size: 1.1em;">
                    <i class="fas fa-check-shield"></i> Safe
                </div>
                <div>
                    This password was not found in the breach database.
                </div>
            `;
        }
    } catch (error) {
        resultsDiv.className = 'breach-alert danger';
        resultsDiv.innerHTML = `
            <i class="fas fa-times-circle"></i> Unable to check password. Network error?
        `;
        console.error('Breach check error:', error);
    }
}

/**
 * SHA-1 hashing function using Web Crypto API
 * 
 * @param {string} str - String to hash
 * @returns {Promise<string>} Uppercase hexadecimal hash
 */
async function sha1(str) {
    const buffer = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// ============================================================================
// PASSWORD GENERATOR
// ============================================================================

/**
 * Update the displayed length value as slider moves
 * 
 * @param {number} value - Current slider value
 */
function updateLengthValue(value) {
    document.getElementById('length-value').textContent = value;
}

/**
 * Generate a secure random password based on user preferences
 */
function generatePassword() {
    const length = parseInt(document.getElementById('password-length').value);
    const includeUppercase = document.getElementById('include-uppercase').checked;
    const includeLowercase = document.getElementById('include-lowercase').checked;
    const includeNumbers = document.getElementById('include-numbers').checked;
    const includeSymbols = document.getElementById('include-symbols').checked;


    // Validate that at least one character type is selected
    if (!includeUppercase && !includeLowercase && !includeNumbers && !includeSymbols) {
        alert('Please select at least one character type!');
        return;
    }

    const options = {
        length,
        includeUppercase,
        includeLowercase,
        includeNumbers,
        includeSymbols,

    };

    const password = createPassword(options);
    displayGeneratedPassword(password);
}

/**
 * Create a cryptographically secure random password
 * Uses Web Crypto API for true randomness
 * 
 * @param {Object} options - Password generation options
 * @returns {string} Generated password
 */
function createPassword(options) {
    let charset = '';

    // Build character set based on options
    if (options.includeUppercase) {
        charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    }

    if (options.includeLowercase) {
        charset += 'abcdefghijklmnopqrstuvwxyz';
    }

    if (options.includeNumbers) {
        charset += '0123456789';
    }

    if (options.includeSymbols) {
        charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    }

    let password = '';
    const chars = new Array(options.length);

    /**
     * Get cryptographically secure random index
     * Uses Web Crypto API instead of Math.random()
     */
    const getRandomIndex = (max) => {
        const array = new Uint32Array(1);
        crypto.getRandomValues(array);
        return array[0] % max;
    };

    // Generate random password
    for (let i = 0; i < options.length; i++) {
        chars[i] = charset[getRandomIndex(charset.length)];
    }

    password = chars.join('');

    // Ensure at least one character from each selected type
    if (options.includeUppercase && !/[A-Z]/.test(password)) {
        const upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        chars[0] = upperChars[getRandomIndex(upperChars.length)];
    }

    if (options.includeLowercase && !/[a-z]/.test(password)) {
        const lowerChars = 'abcdefghijklmnopqrstuvwxyz';
        chars[1] = lowerChars[getRandomIndex(lowerChars.length)];
    }

    if (options.includeNumbers && !/[0-9]/.test(password)) {
        const numChars = '0123456789';
        chars[2] = numChars[getRandomIndex(numChars.length)];
    }

    if (options.includeSymbols && !/[^a-zA-Z0-9]/.test(password)) {
        const symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        chars[3] = symbolChars[getRandomIndex(symbolChars.length)];
    }

    // Shuffle using Fisher-Yates algorithm with crypto randomness
    for (let i = chars.length - 1; i > 0; i--) {
        const j = getRandomIndex(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }

    return chars.join('');
}

/**
 * Display the generated password in the UI
 * 
 * @param {string} password - The generated password
 */
function displayGeneratedPassword(password) {
    const container = document.getElementById('generated-password-container');
    const display = document.getElementById('generated-password');

    display.textContent = password;
    container.style.display = 'block';

    // Store password in dataset for copying
    container.dataset.password = password;
}

/**
 * Copy generated password to clipboard
 */
function copyPassword() {
    const container = document.getElementById('generated-password-container');
    const password = container.dataset.password;
    const feedback = document.getElementById('copy-feedback');

    navigator.clipboard.writeText(password).then(() => {
        // Show success feedback
        feedback.style.display = 'block';
        setTimeout(() => {
            feedback.style.display = 'none';
        }, 2000);
    }).catch(err => {
        alert('Failed to copy password');
        console.error('Copy error:', err);
    });
}

// ============================================================================
// UI UTILITIES
// ============================================================================

/**
 * Toggle password visibility (show/hide)
 * 
 * @param {string} inputId - ID of the password input element
 */
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const button = input.nextElementSibling;
    const icon = button.querySelector('i');

    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

/**
 * Tab Navigation System
 * Handles switching between different tool sections
 */
/**
 * Tab Navigation System & Mobile Menu
 * Handles switching between different tool sections and mobile drawer
 */
document.addEventListener('DOMContentLoaded', function () {
    const navItems = document.querySelectorAll('.nav-item');
    const toolSections = document.querySelectorAll('.tool-section');

    // Mobile Navigation Logic
    const mobileToggle = document.getElementById('mobile-nav-toggle');
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.getElementById('sidebar-overlay');

    function toggleMenu() {
        sidebar.classList.toggle('open');
        overlay.classList.toggle('active');
    }

    function closeMenu() {
        sidebar.classList.remove('open');
        overlay.classList.remove('active');
    }

    if (mobileToggle) {
        mobileToggle.addEventListener('click', toggleMenu);
    }

    if (overlay) {
        overlay.addEventListener('click', closeMenu);
    }

    navItems.forEach(item => {
        item.addEventListener('click', function () {
            const targetTab = this.getAttribute('data-tab');

            // Remove active class from all tabs and sections
            navItems.forEach(t => t.classList.remove('active'));
            toolSections.forEach(section => section.classList.remove('active'));

            // Activate clicked tab and corresponding section
            this.classList.add('active');
            const targetContent = document.getElementById(targetTab);
            if (targetContent) {
                targetContent.classList.add('active');
            }

            // Close mobile menu on selection
            if (window.innerWidth <= 768) {
                closeMenu();
            }
        });
    });
});