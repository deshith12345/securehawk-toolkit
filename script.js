// Password Strength Checker
const passwordCheckInput = document.getElementById('password-check');
const strengthBar = document.getElementById('strength-bar');
const strengthText = document.getElementById('strength-text');
const analysisResults = document.getElementById('analysis-results');
const analysisList = document.getElementById('analysis-list');

console.log('SecureHawk Logic v3.5 Loaded'); // Cache Confirmation


// Common weak password patterns
const commonPasswords = [
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
    'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
    'ashley', 'bailey', 'passw0rd', 'shadow', '123123', '654321', 'superman',
    'qazwsx', 'michael', 'football'
];

const keyboardPatterns = [
    'qwerty', 'asdfgh', 'zxcvbn', '1qaz2wsx', 'qwertyuiop', 'asdfghjkl'
];

// Event listener for password strength checking
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

function analyzePassword(password) {
    const analysis = {
        length: password.length,
        hasUppercase: /[A-Z]/.test(password),
        hasLowercase: /[a-z]/.test(password),
        hasNumbers: /[0-9]/.test(password),
        hasSymbols: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
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

function calculateStrength(password, analysis) {
    let score = 0;

    // Length scoring
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;
    if (password.length >= 20) score += 1;

    // Character variety
    if (analysis.hasUppercase) score += 1;
    if (analysis.hasLowercase) score += 1;
    if (analysis.hasNumbers) score += 1;
    if (analysis.hasSymbols) score += 1;

    // Penalties
    if (analysis.isCommon) score -= 3;
    if (analysis.hasSequential) score -= 1;
    if (analysis.hasKeyboardPattern) score -= 1;
    if (analysis.hasRepeatingChars) score -= 1;

    // Determine strength level
    if (score <= 2) return 'very-weak';
    if (score <= 4) return 'weak';
    if (score <= 5) return 'fair';
    if (score <= 6) return 'good';
    return 'strong';
}

function calculateEntropy(password) {
    let poolSize = 0;

    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;

    return Math.log2(Math.pow(poolSize, password.length));
}

function estimateCrackTime(entropy) {
    const guessesPerSecond = 1e9; // 1 billion guesses per second
    const totalGuesses = Math.pow(2, entropy);
    const seconds = totalGuesses / guessesPerSecond / 2; // Divide by 2 for average

    if (seconds < 1) return 'Instant';
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 3153600000) return `${Math.round(seconds / 31536000)} years`;
    return 'Centuries';
}

function hasSequentialChars(password) {
    const sequential = ['0123456789', 'abcdefghijklmnopqrstuvwxyz'];
    const lowerPass = password.toLowerCase();

    for (let seq of sequential) {
        for (let i = 0; i < seq.length - 2; i++) {
            if (lowerPass.includes(seq.substring(i, i + 3))) {
                return true;
            }
        }
    }
    return false;
}

function hasKeyboardPattern(password) {
    const lowerPass = password.toLowerCase();
    return keyboardPatterns.some(pattern => lowerPass.includes(pattern));
}

function isCommonPassword(password) {
    return commonPasswords.includes(password.toLowerCase());
}

function hasRepeatingChars(password) {
    return /(.)\1{2,}/.test(password);
}

function updateStrengthMeter(strength) {
    // Explicitly control aesthetics via JS to ensure reliability
    const styles = {
        'very-weak': { width: '20%', color: '#FF3B30' }, // Apple Red
        'weak': { width: '40%', color: '#FF9F0A' }, // Apple Orange
        'fair': { width: '60%', color: '#FFD60A' }, // Apple Yellow
        'good': { width: '80%', color: '#34C759' }, // Apple Green
        'strong': { width: '100%', color: '#30D158' } // Apple Bright Green
    };

    const config = styles[strength];

    // Force inline styles to override any CSS specificity issues
    strengthBar.className = 'strength-fill'; // Reset base class
    strengthBar.style.width = config.width;
    strengthBar.style.backgroundColor = config.color;
    strengthBar.style.boxShadow = `0 0 10px ${config.color}`; // Add glow directly

    const strengthLabels = {
        'very-weak': 'Very Weak',
        'weak': 'Weak',
        'fair': 'Fair',
        'good': 'Good',
        'strong': 'Strong'
    };

    strengthText.textContent = strengthLabels[strength];
}

function displayAnalysis(password, analysis, entropy, crackTime) {
    analysisResults.style.display = 'block';
    analysisList.innerHTML = '';

    const feedback = [];

    // Positive feedback
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

    // Negative patterns
    if (analysis.isCommon) feedback.push({ type: 'invalid', text: 'Common Password' });
    if (analysis.hasSequential) feedback.push({ type: 'invalid', text: 'Sequential Chars' });
    if (analysis.hasKeyboardPattern) feedback.push({ type: 'invalid', text: 'Keyboard Pattern' });
    if (analysis.hasRepeatingChars) feedback.push({ type: 'invalid', text: 'Repeating Chars' });

    feedback.forEach(item => {
        const li = document.createElement('li');
        li.className = 'analysis-item ' + item.type;
        li.innerHTML = item.type === 'valid'
            ? `<i class="fas fa-check"></i> ${item.text}`
            : `<i class="fas fa-times"></i> ${item.text}`;
        analysisList.appendChild(li);
    });

    // Update stats
    document.getElementById('stat-length').textContent = analysis.length;
    document.getElementById('stat-entropy').textContent = entropy.toFixed(0);
    document.getElementById('stat-crack').textContent = crackTime;
}

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

// Password Breach Checker
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

    resultsDiv.style.display = 'block';
    resultsDiv.className = 'breach-alert';
    resultsDiv.style.backgroundColor = '#f1f5f9'; // Neutral loading
    resultsDiv.style.color = '#64748b';
    resultsDiv.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking database...';

    try {
        // Hash the password using SHA-1
        const hash = await sha1(password);
        const prefix = hash.substring(0, 5);
        const suffix = hash.substring(5);

        // Query HIBP API with k-Anonymity
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        const data = await response.text();

        // Parse the response
        const hashes = data.split('\n');
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

        if (found) {
            resultsDiv.className = 'breach-alert danger';
            resultsDiv.style.backgroundColor = ''; // Use class styles
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

// SHA-1 hashing function
async function sha1(str) {
    const buffer = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// Password Generator
function updateLengthValue(value) {
    document.getElementById('length-value').textContent = value;
}

function generatePassword() {
    const length = parseInt(document.getElementById('password-length').value);
    const includeUppercase = document.getElementById('include-uppercase').checked;
    const includeLowercase = document.getElementById('include-lowercase').checked;
    const includeNumbers = document.getElementById('include-numbers').checked;
    const includeSymbols = document.getElementById('include-symbols').checked;
    const excludeAmbiguous = document.getElementById('exclude-ambiguous').checked;

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
        excludeAmbiguous
    };

    const password = createPassword(options);
    displayGeneratedPassword(password);
}

function createPassword(options) {
    let charset = '';

    if (options.includeUppercase) {
        charset += options.excludeAmbiguous ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    }

    if (options.includeLowercase) {
        charset += options.excludeAmbiguous ? 'abcdefghijkmnopqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
    }

    if (options.includeNumbers) {
        charset += options.excludeAmbiguous ? '23456789' : '0123456789';
    }

    if (options.includeSymbols) {
        charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    }

    let password = '';
    const chars = new Array(options.length);

    // Use crypto for secure randomness
    const getRandomIndex = (max) => {
        const array = new Uint32Array(1);
        crypto.getRandomValues(array);
        return array[0] % max;
    };

    for (let i = 0; i < options.length; i++) {
        chars[i] = charset[getRandomIndex(charset.length)];
    }

    password = chars.join('');

    // Ensure at least one character from each selected type
    if (options.includeUppercase && !/[A-Z]/.test(password)) {
        const upperChars = options.excludeAmbiguous ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        chars[0] = upperChars[getRandomIndex(upperChars.length)];
    }

    if (options.includeLowercase && !/[a-z]/.test(password)) {
        const lowerChars = options.excludeAmbiguous ? 'abcdefghijkmnopqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
        chars[1] = lowerChars[getRandomIndex(lowerChars.length)];
    }

    if (options.includeNumbers && !/[0-9]/.test(password)) {
        const numChars = options.excludeAmbiguous ? '23456789' : '0123456789';
        chars[2] = numChars[getRandomIndex(numChars.length)];
    }

    if (options.includeSymbols && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        const symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        chars[3] = symbolChars[getRandomIndex(symbolChars.length)];
    }

    // Shuffle using Fisher-Yates with crypto randomness
    for (let i = chars.length - 1; i > 0; i--) {
        const j = getRandomIndex(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }

    return chars.join('');
}

function displayGeneratedPassword(password) {
    const container = document.getElementById('generated-password-container');
    const display = document.getElementById('generated-password');

    display.textContent = password;
    container.style.display = 'block';

    // Store password for copying
    container.dataset.password = password;
}

function copyPassword() {
    const container = document.getElementById('generated-password-container');
    const password = container.dataset.password;
    const feedback = document.getElementById('copy-feedback');

    navigator.clipboard.writeText(password).then(() => {
        feedback.style.display = 'block';
        setTimeout(() => {
            feedback.style.display = 'none';
        }, 2000);
    }).catch(err => {
        alert('Failed to copy password');
        console.error('Copy error:', err);
    });
}

// Toggle password visibility
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

// Tab Navigation System (Updated for Sidebar)
document.addEventListener('DOMContentLoaded', function () {
    const navItems = document.querySelectorAll('.nav-item');
    const toolSections = document.querySelectorAll('.tool-section');

    navItems.forEach(item => {
        item.addEventListener('click', function () {
            const targetTab = this.getAttribute('data-tab');

            // Remove active class from all tabs and contents
            navItems.forEach(t => t.classList.remove('active'));
            toolSections.forEach(section => section.classList.remove('active'));

            // Add active class to clicked tab and corresponding content
            this.classList.add('active');
            const targetContent = document.getElementById(targetTab);
            if (targetContent) {
                targetContent.classList.add('active');
            }
        });
    });
});