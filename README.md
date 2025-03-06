# OWASP Top 10 Training Portal

This is a simple interactive web application that helps you learn about the OWASP Top 10 web application security risks. The portal includes detailed information, code examples, interactive challenges, and mitigation strategies for each vulnerability.

## Features

- Detailed explanations of each OWASP Top 10 vulnerability
- Vulnerable code examples showing common mistakes
- Interactive challenges to test your understanding
- Solution hints to guide you in the right direction
- Mitigation code examples to show proper implementation
- Common mitigation strategies for each vulnerability
- User registration with hashed password storage
- Login system with password protection
- Password recovery functionality via security questions
- User data stored in localStorage and server file (when using server mode)

## Setup

### Client-only mode
1. Open the `index.html` file in your web browser
2. Register an account or use the default credentials (admin/password123)

### With server (for persistent user storage)
1. Install Node.js and npm
2. Install dependencies:
   ```
   npm install express body-parser
   ```
3. Start the server:
   ```
   node server/server.js
   ```
4. Access the application at http://localhost:3000

## Usage
1. Log in to access the OWASP Top 10 vulnerabilities
2. Click on any vulnerability to expand its content
3. Read the description and explore the vulnerable code
4. Try to solve the challenge for each vulnerability
5. Use the hint if you get stuck
6. Submit your answer to see if it's correct
7. When you get the correct answer, you'll see the proper mitigation code

## OWASP Top 10 (2021)

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)

## Educational Purpose

This training portal is designed for educational purposes only. The vulnerable code examples should never be used in production environments. Always follow security best practices in your applications.

## License

This project is available for anyone to use and modify for educational purposes.