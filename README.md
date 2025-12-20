#  SecureHawk - Password Security Toolkit

**A comprehensive web-based tool for password security education and analysis**

## 📖 About The Project

SecureHawk is an interactive password security toolkit designed to educate users about password security best practices. This project demonstrates practical cybersecurity concepts including real-time password strength analysis, breach checking using the Have I Been Pwned API, and cryptographically secure password generation.



### Project Purpose

- Demonstrate practical understanding of web security principles
- Show proficiency in API integration and client-side cryptography
- Provide an educational tool for password security awareness
- Serve as a portfolio project showcasing cybersecurity skills

---

## Features

### 1. Password Strength Checker
Analyze password security in real-time with comprehensive feedback:

- **Visual Strength Meter** - Color-coded strength indicator
- **Entropy Calculation** - Measure password randomness in bits
- **Crack Time Estimation** - Estimate time to crack with modern hardware
- **Pattern Detection**:
  - Sequential characters (123, abc)
  - Keyboard patterns (qwerty, asdf, 1qaz2wsx)
  - Common passwords from breach databases
  - Repeating characters (aaa, 111)
- **Character Analysis** - Uppercase, lowercase, numbers, symbols
- **Detailed Recommendations** - Actionable tips to improve password strength

### 2. Breach Checker
Check if your password has appeared in known data breaches:

- **Have I Been Pwned Integration** - Access 600+ million breached passwords
- **k-Anonymity Privacy Protection** - Your password never leaves your browser
- **SHA-1 Hashing** - Secure local hashing before API query
- **Breach Count Display** - See how many times password was compromised
- **Privacy-First Design** - Only partial hash (5 characters) sent to API

### 3. Secure Password Generator
Generate cryptographically strong passwords:

- **Customizable Length** - 8 to 64 characters
- **Character Set Options**:
  - ✓ Uppercase letters (A-Z)
  - ✓ Lowercase letters (a-z)
  - ✓ Numbers (0-9)
  - ✓ Special symbols (!@#$%^&*)
- **Exclude Ambiguous Characters** - Optional removal of 0, O, l, 1, etc.
- **Crypto-Secure Random** - Uses Web Crypto API for true randomness
- **One-Click Copy** - Instant clipboard copy functionality

### 4. Educational Content
Built-in security education:

- Common weak password patterns explained
- Attack method descriptions (brute force, dictionary, rainbow tables)
- Password best practices guide
- Understanding entropy and complexity
- Time-to-crack calculations by password length

---

## Technologies Used

- **HTML5** - Semantic markup and structure
- **CSS3** - Modern styling with:
  - CSS Grid & Flexbox for responsive layouts
  - Custom properties (CSS variables) for theming
  - Smooth animations and transitions
  - Glassmorphism effects
  - Mobile-first responsive design
- **JavaScript (ES6+)** - Client-side logic featuring:
  - Async/await for API calls
  - Web Crypto API for secure hashing
  - Regular expressions for pattern detection
  - Event-driven architecture
- **Have I Been Pwned API** - Breach database integration
- **Font Awesome** - Professional iconography

---

### Quick Start (No Installation Required)

Live Demo : securehawk.vercel.app

---

## 🔒 Security & Privacy

### Privacy-First Design

**Your passwords NEVER leave your device.** Here's how we ensure privacy:

1. **Local Processing** - All password analysis happens in your browser
2. **No Server Storage** - No passwords are logged, stored, or transmitted
3. **k-Anonymity Method** - For breach checking:
   - Password is hashed locally using SHA-1
   - Only first 5 characters of hash sent to API
   - API returns all matching hashes
   - Final comparison done locally in browser
   - Your actual password never transmitted

### Security Implementation

- **Web Crypto API** - Browser's native cryptographic functions
- **Client-Side Hashing** - SHA-1 implementation for HIBP API
- **Secure Random Generation** - Cryptographically strong password generation
- **No Dependencies** - Pure vanilla JavaScript (no vulnerable libraries)
- **HTTPS Recommended** - For API calls to Have I Been Pwned

---

## 🔗 Resources & References

### APIs & Services
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3) - Password breach database
- [Web Crypto API Documentation](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) - Browser cryptography

### Security Guidelines
- [OWASP Password Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Troy Hunt's Blog](https://www.troyhunt.com/) - Security research and insights



