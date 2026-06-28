window.vulnerabilities = [
  {
    id: "API1",
    title: "API1:2023 Broken Object Level Authorization (BOLA)",
    severity: "High",
    description: "Occurs when an API does not perform appropriate authorization checks when accessing individual objects via IDs, exposing internal objects to unauthorized requests.",
    concept: "APIs commonly expose endpoints that handle object identifiers (e.g., `/api/v1/trips/{trip_id}`). An attacker alters the ID parameter to point to a resource they do not own, and the lack of validation on the backend allows them to retrieve or modify data belonging to other users.",
    remediation: [
      "Implement a robust authorization mechanism that validates if the logged-in user owns or has access rights to the specific object ID requested.",
      "Avoid relying on client-supplied keys/IDs without verification on the server-side.",
      "Use random, unguessable UUIDv4 values as object identifiers instead of sequential integers.",
      "Write comprehensive authorization tests for all endpoints that access identifiers."
    ],
    vulnerableCode: `// Express.js Vulnerable Code
app.get('/api/users/profile', async (req, res) => {
  // Vulnerability: Reads user ID directly from query/parameter or body,
  // without validating if the current session owner matches this ID.
  const userId = req.query.userId;
  
  const user = await db.findUserById(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  res.json(user); // Returns arbitrary profile without checking authorization
});`,
    secureCode: `// Express.js Secure Code (Mitigated)
app.get('/api/users/profile', authenticateToken, async (req, res) => {
  // Mitigation 1: Retrieve user identity from verified session token (JWT/Session)
  const currentUserId = req.user.id; 
  const requestedUserId = req.query.userId;

  // Mitigation 2: Explicitly validate the session user matches the requested resource
  if (currentUserId !== requestedUserId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: You do not own this resource' });
  }

  const user = await db.findUserById(requestedUserId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json(user);
});`,
    simulation: {
      title: "Authorization Validation Loop",
      steps: [
        {
          label: "Client Request",
          description: "Attacker (User 102) sends a request targeting User 101's account: GET /api/user/profile?userId=101",
          vulnerableStatus: "Processing request directly...",
          secureStatus: "Authenticating token first..."
        },
        {
          label: "Authentication Check",
          description: "The backend verifies JWT. The sender is verified as User 102.",
          vulnerableStatus: "Auth Valid: User 102. (Proceeding to database query)",
          secureStatus: "Auth Valid: User 102. (Checking Object Permissions...)"
        },
        {
          label: "Authorization Enforcement",
          description: "Comparing User 102 permissions against target ID 101.",
          vulnerableStatus: "Bypassed: No check comparing Session User (102) with Parameter User (101).",
          secureStatus: "Validation: Requested ID (101) != Authenticated User (102). Access Denied!"
        },
        {
          label: "Final Result",
          description: "Action outcome returned to user.",
          vulnerableStatus: "SUCCESS: User 101 data leaked to User 102!",
          secureStatus: "BLOCKED: 403 Forbidden Response sent."
        }
      ]
    }
  },
  {
    id: "API2",
    title: "API2:2023 Broken Authentication",
    severity: "High",
    description: "Occurs when authentication mechanisms are poorly implemented, allowing attackers to compromise authentication tokens or exploit implementation flaws to assume identities.",
    concept: "Authentication flows (such as login, password reset, or API key usage) are highly targeted. Common issues include lack of rate-limiting on login endpoints, exposing JWTs in URLs, using weak signature keys, or failing to validate token expiration.",
    remediation: [
      "Use established authentication standards (OAuth 2.0, OpenID Connect, standard JWT libraries).",
      "Always enforce rate limiting on password reset, verification code, and login endpoints.",
      "Implement robust password complexity controls and support multi-factor authentication (MFA).",
      "Never put sensitive auth identifiers (tokens, session IDs) in query strings or URL paths."
    ],
    vulnerableCode: `// Express.js Vulnerable Login Endpoint
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Vulnerability 1: Lack of rate limiting allows brute force attacks.
  // Vulnerability 2: Poor credential check or insecure token expiration.
  const user = await db.findUserByUsername(username);
  if (user && user.password === password) { // plaintext password check
    const token = jwt.sign({ id: user.id }, 'weak_secret_key'); // weak secret key
    return res.json({ token });
  }
  
  res.status(401).json({ error: 'Invalid credentials' });
});`,
    secureCode: `// Express.js Secure Login Endpoint
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');

// Mitigation 1: Enforce strict rate-limiting on authentication routes
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per window
  message: 'Too many login attempts, please try again later'
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  
  const user = await db.findUserByUsername(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  // Mitigation 2: Securely verify cryptographic hashes, not plaintext
  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

  // Mitigation 3: Sign tokens with strong system secrets and explicit expiration
  const token = jwt.sign(
    { id: user.id }, 
    process.env.JWT_STRONG_SECRET, 
    { expiresIn: '1h', algorithm: 'HS256' }
  );

  res.json({ token });
});`,
    simulation: {
      title: "Credential Guessing & Rate Limiting Simulation",
      steps: [
        {
          label: "Multiple Attempts",
          description: "An automated script sends 10 sequential authentication guesses to the database.",
          vulnerableStatus: "Processes all 10 login queries consecutively.",
          secureStatus: "Receives attempts; tracking IP request count."
        },
        {
          label: "Threshold Reached",
          description: "Count hits safety limit (5 requests within window).",
          vulnerableStatus: "Continues checking passwords (high CPU / brute-force risk).",
          secureStatus: "Triggers lockout block for caller's IP address."
        },
        {
          label: "Result",
          description: "System response to subsequent requests.",
          vulnerableStatus: "Will eventually leak profile once script hits the right combination.",
          secureStatus: "Responds instantly with HTTP 429 Too Many Requests (Blocked)."
        }
      ]
    }
  },
  {
    id: "API3",
    title: "API3:2023 Broken Object Property Level Authorization (BOPLA)",
    severity: "Medium",
    description: "Occurs when endpoints expose too much internal object property data (Excessive Data Exposure) or accept modification of unauthorized internal properties (Mass Assignment).",
    concept: "BOPLA combines two classic issues: Excessive Data Exposure (where the server returns more properties of an object than necessary, assuming the frontend will filter it) and Mass Assignment (where clients send property updates to fields they shouldn't edit, like `isAdmin = true`).",
    remediation: [
      "Avoid returning full database model serialization directly. Define Data Transfer Objects (DTOs) or explicitly select returned fields.",
      "Avoid blindly binding client-supplied requests directly to internal objects (`req.body`).",
      "Whitelist permitted properties that can be modified by the client."
    ],
    vulnerableCode: `// Express.js BOPLA Vulnerabilities
// 1. Excessive Data Exposure (GET)
app.get('/api/users/:id', async (req, res) => {
  const user = await db.findUser(req.params.id);
  res.json(user); // Vulnerability: returns user.passwordHash, resetToken, role, etc.
});

// 2. Mass Assignment (PUT)
app.put('/api/users/:id', async (req, res) => {
  const user = await db.findUser(req.params.id);
  // Vulnerability: Blindly copies req.body parameters onto the database entity.
  // Attackers can pass {"role": "admin"} or {"balance": 99999}.
  Object.assign(user, req.body);
  await db.save(user);
  res.json(user);
});`,
    secureCode: `// Express.js BOPLA Mitigations
// 1. Safe Projection (GET)
app.get('/api/users/:id', async (req, res) => {
  const user = await db.findUser(req.params.id);
  
  // Mitigation: Return only safe public properties (DTO pattern)
  const safeProfile = {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl
  };
  res.json(safeProfile);
});

// 2. Strict Whitelisting (PUT)
app.put('/api/users/:id', authenticateToken, async (req, res) => {
  const user = await db.findUser(req.params.id);
  
  // Mitigation: Explicitly destructure only allowed properties
  const { displayName, avatarUrl } = req.body;
  
  // Only apply properties client is authorized to modify
  if (displayName) user.displayName = displayName;
  if (avatarUrl) user.avatarUrl = avatarUrl;
  
  await db.save(user);
  res.json({ message: 'Profile updated successfully' });
});`,
    simulation: {
      title: "Property Scope Filter Simulation",
      steps: [
        {
          label: "Request Dispatch",
          description: "User submits profile update request with extra property: { \"displayName\": \"Bob\", \"role\": \"admin\" }",
          vulnerableStatus: "Unpacking body properties...",
          secureStatus: "Unpacking body properties..."
        },
        {
          label: "Model Mapping",
          description: "System maps JSON keys to target database object.",
          vulnerableStatus: "Updates local record fields: Object.assign(user, body) mappings apply both keys.",
          secureStatus: "Applies whitelist check. Extracted fields: displayName. Property 'role' is discarded."
        },
        {
          label: "Result",
          description: "Database modification output.",
          vulnerableStatus: "Record updated: Role updated to 'admin'. (Escalation Succeeded)",
          secureStatus: "Record updated: Only displayName changed. 'role' remains unchanged."
        }
      ]
    }
  },
  {
    id: "API4",
    title: "API4:2023 Unrestricted Resource Consumption",
    severity: "Medium",
    description: "Occurs when API endpoints are not protected against excessive volume requests, file uploads, payload sizes, or intensive processing, causing Denial of Service (DoS) or increased cloud bills.",
    concept: "APIs must limit client consumption of system resources. Without limits, an attacker can spam heavy SQL queries, upload multi-gigabyte files, cause memory exhaustion, or consume premium downstream API services, resulting in high resource consumption and outages.",
    remediation: [
      "Enforce maximum execution timeouts, upload limits, and request payload size limits.",
      "Implement pagination with hard ceilings (e.g., maximum page size of 50).",
      "Apply API rate limiting (throttling) globally and on resource-heavy routes.",
      "Limit CPU/Memory footprints on third-party operations (like image rendering)."
    ],
    vulnerableCode: `// Express.js Vulnerable Server
// Vulnerability 1: Lack of global rate limiting or payload limits
app.post('/api/image/resize', async (req, res) => {
  // Vulnerability 2: Reading unlimited page size from client request
  const pageSize = req.query.limit || 1000000;
  
  const records = await db.fetchRecords(pageSize);
  res.json(records); // Heavy SQL load + memory exhaustion
});`,
    secureCode: `// Express.js Secured Config
const express = require('express');
const app = express();

// Mitigation 1: Define explicit JSON payload size limit globally
app.use(express.json({ limit: '10kb' })); 

// Mitigation 2: Enforce query bounds in API logic
app.get('/api/records', async (req, res) => {
  let limit = parseInt(req.query.limit, 10) || 20;
  
  // Hard ceiling: Client cannot request more than 100 items at a time
  if (limit > 100) {
    limit = 100;
  }
  
  const page = parseInt(req.query.page, 10) || 1;
  const offset = (page - 1) * limit;

  const records = await db.fetchRecords(limit, offset);
  res.json({ data: records, page, limit });
});`,
    simulation: {
      title: "Query Limit Filter Simulation",
      steps: [
        {
          label: "Request Received",
          description: "Client submits database lookup requesting 1,000,000 records: GET /api/records?limit=1000000",
          vulnerableStatus: "Queries db with LIMIT 1000000.",
          secureStatus: "Normalizing parameter limit = 1000000."
        },
        {
          label: "Memory & Resource Evaluation",
          description: "System processes limit bounds before database invocation.",
          vulnerableStatus: "Database retrieves millions of rows, allocating substantial heap memory.",
          secureStatus: "Limit is constrained: 1000000 reduced to hard max ceiling of 100."
        },
        {
          label: "Result",
          description: "System execution status and response size.",
          vulnerableStatus: "Crash or high latency: Node process runs out of memory (OOM) / database bottlenecks.",
          secureStatus: "SUCCESS: Responds with exactly 100 entries. Latency remains low (50ms)."
        }
      ]
    }
  },
  {
    id: "API5",
    title: "API5:2023 Broken Function Level Authorization (BFLA)",
    severity: "High",
    description: "Occurs when authentication and access control policies do not validate authorization based on hierarchies or functional access levels (e.g. general user calling administrative routes).",
    concept: "BFLA happens when administrative or specialized endpoints are exposed without verifying the role of the caller. Attackers search for administration functions (e.g. changing `/api/v1/user/details` to `/api/v1/admin/delete_user`) and call them directly by guessing the path structure.",
    remediation: [
      "Implement a centralized access control middleware to map routes to roles (RBAC/ABAC).",
      "By default, deny all access; explicitly authorize roles for sensitive API administrative endpoints.",
      "Perform thorough testing to ensure normal users cannot invoke administrative actions."
    ],
    vulnerableCode: `// Express.js BFLA Vulnerability
// Regular user actions are checked, but administrative functions are not restricted
app.post('/api/admin/users/:id/delete', async (req, res) => {
  // Vulnerability: Only verifies authentication token exists,
  // but fails to verify if user's role is 'admin'.
  const user = req.user; 
  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  await db.deleteUser(req.params.id);
  res.json({ message: 'User deleted' });
});`,
    secureCode: `// Express.js BFLA Mitigations
// Helper RBAC middleware to enforce roles
const requireRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ 
        error: 'Forbidden: You do not have permissions for this action' 
      });
    }
    next();
  };
};

// Administrative function explicitly restricts access to authorized roles
app.post(
  '/api/admin/users/:id/delete', 
  authenticateToken, 
  requireRole(['admin']), // Mitigation: Explicit authorization check
  async (req, res) => {
    await db.deleteUser(req.params.id);
    res.json({ message: 'User deleted successfully' });
  }
);`,
    simulation: {
      title: "Role Hierarchy Validation Simulation",
      steps: [
        {
          label: "Request Received",
          description: "Authenticated non-admin user (role = 'member') calls POST /api/admin/users/99/delete",
          vulnerableStatus: "Authentication passed. Processing user deletion.",
          secureStatus: "Authentication passed. Verifying user roles..."
        },
        {
          label: "Role Mapping Verification",
          description: "Validating user role matches route permissions.",
          vulnerableStatus: "Bypassed: Role attribute not evaluated on route.",
          secureStatus: "Denied: Member role does not match permitted roles (admin)."
        },
        {
          label: "Result",
          description: "Target action execution status.",
          vulnerableStatus: "Account deleted. (Privilege escalation succeeded)",
          secureStatus: "Action Blocked: Returns 403 Forbidden. Account remains safe."
        }
      ]
    }
  },
  {
    id: "API6",
    title: "API6:2023 Unrestricted Access to Sensitive Business Flows",
    severity: "Medium",
    description: "Occurs when an API exposes sensitive business workflows without adequate safeguards, allowing malicious actors to automate and abuse logic (e.g. buying out ticket stocks, spamming SMS, index scraping).",
    concept: "Unlike technical bugs, this targets logic. If an API handles operations like buying items, reserving reservations, or sending SMS OTPs without transaction tracking or bot detection, an attacker can automate these processes, draining business resources or causing financial damage.",
    remediation: [
      "Identify sensitive flows (e.g., signups, checkouts, OTP requests) and implement specialized rate limits.",
      "Use CAPTCHAs, bot-detection tools, and behavioral analysis to block automated scripts.",
      "Implement step-up authentication (re-entering credentials, MFA validation) before critical actions."
    ],
    vulnerableCode: `// Express.js Vulnerable Business Flow
app.post('/api/reminders/sms', async (req, res) => {
  const { phoneNumber, message } = req.body;
  
  // Vulnerability: Anyone can call this endpoint repeatedly,
  // triggering expensive third-party SMS Gateway APIs.
  // No rate limits or phone verification.
  await smsGateway.send(phoneNumber, message);
  res.json({ success: true });
});`,
    secureCode: `// Express.js Protected Business Flow
const RateLimit = require('express-rate-limit');

// Mitigation 1: Enforce strict rate limits on OTP/SMS endpoints
const smsLimiter = RateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 3, // Limit each IP or user to 3 SMS requests per hour
  message: 'SMS limit reached. Please wait before trying again.'
});

app.post('/api/reminders/sms', authenticateToken, smsLimiter, async (req, res) => {
  const { phoneNumber, message } = req.body;
  
  // Mitigation 2: Additional validation for sensitive business rules
  if (!phoneNumber.startsWith('+1')) {
    return res.status(400).json({ error: 'International SMS not allowed' });
  }

  // Mitigation 3: Enforce captchas or tokens for non-interactive requests
  if (!req.body.captchaToken) {
    return res.status(400).json({ error: 'Missing security verification' });
  }

  const isHuman = await verifyCaptcha(req.body.captchaToken);
  if (!isHuman) {
    return res.status(403).json({ error: 'Bot signature detected' });
  }

  await smsGateway.send(phoneNumber, message);
  res.json({ success: true });
});`,
    simulation: {
      title: "Flow Automation Defense Simulation",
      steps: [
        {
          label: "Automated Loop",
          description: "Script launches loops targeting /api/reminders/sms to send 100 identical notifications.",
          vulnerableStatus: "Processes each request, invoking the paid SMS gateway API.",
          secureStatus: "Processes request 1, 2, and 3 successfully."
        },
        {
          label: "Threshold Counter Triggered",
          description: "Evaluating limit context for the current IP/User.",
          vulnerableStatus: "Continues processing loop. SMS gateway charge mounts ($10.00).",
          secureStatus: "Limiter intercepts request 4. Threshold limit (3) exceeded."
        },
        {
          label: "Result",
          description: "System response to subsequent automated request loops.",
          vulnerableStatus: "All 100 messages sent. Significant resource/monetary loss.",
          secureStatus: "Blocked: 429 Too Many Requests. Stops script execution, preserving balance."
        }
      ]
    }
  },
  {
    id: "API7",
    title: "API7:2023 Server Side Request Forgery (SSRF)",
    severity: "High",
    description: "Occurs when an API fetches a remote resource based on a client-provided URI without validating the destination, allowing attackers to force the application to send requests to internal resources.",
    concept: "Server Side Request Forgery occurs when the server acts as a proxy to fetch a URL provided by the user. If the user provides a local IP (e.g. `http://127.0.0.1:8500`) or metadata addresses (like AWS IMDS `http://169.254.169.254`), the server might fetch it, leaking internal configuration data.",
    remediation: [
      "Validate and restrict client-provided URLs to an explicit whitelist of allowed domains.",
      "Block requests pointing to internal subnets, localhost, and non-routable ranges (RFC 1918).",
      "Do not forward raw HTTP responses or metadata from remote lookups directly to the client."
    ],
    vulnerableCode: `// Express.js SSRF Vulnerability
const axios = require('axios');

app.post('/api/preview-image', async (req, res) => {
  const { imageUrl } = req.body;
  
  try {
    // Vulnerability: Axios requests the remote site directly.
    // An attacker can pass 'http://169.254.169.254/latest/meta-data/'
    // or 'http://localhost:8080/admin/dashboard'.
    const response = await axios.get(imageUrl);
    res.send(response.data);
  } catch (err) {
    res.status(500).send(err.message);
  }
});`,
    secureCode: `// Express.js SSRF Mitigation
const axios = require('axios');
const ip = require('ip');
const { URL } = require('url');

app.post('/api/preview-image', async (req, res) => {
  const { imageUrl } = req.body;

  try {
    const parsedUrl = new URL(imageUrl);
    
    // Mitigation 1: Enforce HTTPS scheme only
    if (parsedUrl.protocol !== 'https:') {
      return res.status(400).json({ error: 'Only HTTPS protocol is supported' });
    }

    // Mitigation 2: Restrict allowed domains if possible
    const allowedDomains = ['images.unsplash.com', 'res.cloudinary.com'];
    if (!allowedDomains.includes(parsedUrl.hostname)) {
      return res.status(400).json({ error: 'Domain is not whitelisted' });
    }

    // Mitigation 3: Resolve IP and block private/non-routable/internal networks
    const dns = require('dns').promises;
    const lookup = await dns.lookup(parsedUrl.hostname);
    const destinationIp = lookup.address;

    if (ip.isPrivate(destinationIp) || ip.isLoopback(destinationIp)) {
      return res.status(403).json({ error: 'Access to internal IP address is forbidden' });
    }

    const response = await axios.get(imageUrl, { timeout: 3000 });
    res.send(response.data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch image preview' });
  }
});`,
    simulation: {
      title: "URL Target Sanitization Loop",
      steps: [
        {
          label: "Receive Remote URI",
          description: "User submits URI for profile picture import: http://169.254.169.254/latest/meta-data/",
          vulnerableStatus: "Initializing remote GET to target...",
          secureStatus: "Parsing URL structures..."
        },
        {
          label: "Domain and Schema Validation",
          description: "Analyzing remote address features.",
          vulnerableStatus: "Bypassed: No structure validation.",
          secureStatus: "Validation: Scheme http != https. Rejected. Domain validation: Address '169.254.169.254' is not in whitelist. Rejected."
        },
        {
          label: "IP Range Resolution",
          description: "Checking system routing safety parameters.",
          vulnerableStatus: "Outgoing network request dispatched.",
          secureStatus: "Validation: Host resolves to AWS IMDS metadata IP (Non-routable block). Access denied."
        },
        {
          label: "Result",
          description: "Server HTTP response state.",
          vulnerableStatus: "Exposes raw AWS metadata keys (credentials, account info) to attacker.",
          secureStatus: "Blocked: Returns 400 Bad Request error. Safe."
        }
      ]
    }
  },
  {
    id: "API8",
    title: "API8:2023 Security Misconfiguration",
    severity: "Medium",
    description: "Occurs when APIs have unhardened configurations, enable verbose debugging, leave test routes exposed, support insecure HTTP methods, or use permissive CORS headers.",
    concept: "Security misconfigurations cover issues outside application code. Common cases include exposing debug consoles, enabling overly broad CORS policies (`Access-Control-Allow-Origin: *` with credentials), displaying verbose stack traces in production, or leaving default credentials active.",
    remediation: [
      "Disable debugging features and verbose error trace displays in production.",
      "Restrict CORS permissions to trusted domains rather than using wildcard values.",
      "Use automated scanners to audit infrastructure settings and HTTP headers (e.g. Helmet.js).",
      "Remove unused endpoints, API versions, and default accounts before deployment."
    ],
    vulnerableCode: `// Express.js Insecure Settings
const cors = require('cors');

// Vulnerability 1: Permissive CORS exposing internal responses to any site
app.use(cors({ origin: '*' }));

// Vulnerability 2: Verbose stack traces leaked to client
app.use((err, req, res, next) => {
  res.status(500).json({
    message: err.message,
    stack: err.stack // Vulnerability: leaks folder paths, SQL queries, variables
  });
});`,
    secureCode: `// Express.js Secured Settings
const cors = require('cors');
const helmet = require('helmet');

// Mitigation 1: Add default secure HTTP headers using Helmet middleware
app.use(helmet());

// Mitigation 2: Configure CORS with explicit domains
const allowedOrigins = ['https://dashboard.company.com'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Blocked by CORS policy'));
    }
  }
}));

// Mitigation 3: Secure Error Handler
app.use((err, req, res, next) => {
  // Log full trace internally for devs, but hide from users
  console.error(err.stack);
  
  res.status(500).json({
    message: 'An internal server error occurred. Please contact support.'
    // Mitigation: stack property omitted
  });
});`,
    simulation: {
      title: "Error Reporting Configuration Simulation",
      steps: [
        {
          label: "Exception Occurs",
          description: "Database throws error: 'Table users does not have field user_pass_temp'.",
          vulnerableStatus: "Generating custom error response.",
          secureStatus: "Generating custom error response."
        },
        {
          label: "Output Formatting",
          description: "Compiling JSON attributes for the response body.",
          vulnerableStatus: "Attaches message and full error stack: '/var/www/src/db.js:124 SQL...' to response.",
          secureStatus: "Logs detailed stack trace to server logs. Formats client response with generic message."
        },
        {
          label: "Result",
          description: "Information visible to client.",
          vulnerableStatus: "Client receives detailed system paths and database queries, facilitating further attacks.",
          secureStatus: "Client receives generic 500 error. No internal data is exposed."
        }
      ]
    }
  },
  {
    id: "API9",
    title: "API9:2023 Improper Inventory Management",
    severity: "Low",
    description: "Occurs when old, deprecated, or unpatched API versions are kept running and exposed alongside current versions, increasing the overall attack surface.",
    concept: "Developers release new API versions (e.g. `/v2/`) but leave legacy versions (e.g. `/v1/`) running on the same server to avoid breaking old clients. These deprecated endpoints often lack security patches, rate limiting, and robust input validation, making them targets for attackers.",
    remediation: [
      "Retire and decommission old API endpoints and versions once deprecated.",
      "Adopt automated inventory discovery tools to map active routes and endpoints.",
      "Apply security controls (like authentication and rate limits) uniformly across all active API versions."
    ],
    vulnerableCode: `// Express.js Routing (Incomplete Inventory)
// Active route (/v2/) contains robust authorization
app.get('/api/v2/user/profile', authenticateToken, checkBOLA, async (req, res) => {
  const profile = await db.getUserProfile(req.user.id);
  res.json(profile);
});

// Legacy route (/v1/) left active for backwards compatibility
// Vulnerability: Lacks BOLA validation middleware
app.get('/api/v1/user/profile', authenticateToken, async (req, res) => {
  const targetId = req.query.id;
  const profile = await db.getUserProfile(targetId); // BOLA present here
  res.json(profile);
});`,
    secureCode: `// Express.js Routing (Remediated Inventory)
// Mitigation 1: Explicitly decommission legacy routes
app.use('/api/v1/*', (req, res) => {
  res.status(410).json({
    error: 'API Version 1 is deprecated and no longer supported. Please upgrade to /api/v2/'
  });
});

// Mitigation 2: Ensure uniform security controls if legacy routes must run
// Map both versions through the same authorization middleware
app.get('/api/v2/user/profile', authenticateToken, checkBOLA, async (req, res) => {
  const profile = await db.getUserProfile(req.user.id);
  res.json(profile);
});`,
    simulation: {
      title: "API Deprecation Validation Loop",
      steps: [
        {
          label: "Legacy Access Attempt",
          description: "Attacker attempts to access legacy endpoint: GET /api/v1/user/profile?id=99",
          vulnerableStatus: "Routing to legacy function handler.",
          secureStatus: "Routing to legacy middleware controller."
        },
        {
          label: "Decommission Check",
          description: "Checking route deprecation database status.",
          vulnerableStatus: "Bypassed: Legacy handler executes directly.",
          secureStatus: "Validation: Path matches /api/v1/ prefix which is marked as deprecated (HTTP 410)."
        },
        {
          label: "Result",
          description: "System outcome response.",
          vulnerableStatus: "Legacy code executes, allowing BOLA vulnerability to succeed.",
          secureStatus: "Blocked: Response '410 Gone' returned. Request terminates safely."
        }
      ]
    }
  },
  {
    id: "API10",
    title: "API10:2023 Unsafe Consumption of APIs",
    severity: "Medium",
    description: "Occurs when an API trusts data received from third-party APIs without proper validation, sanitation, or validation of transport security.",
    concept: "APIs frequently integrate with third-party microservices (e.g. payment processors, geocoders, social logins). If the server trusts these services blindly and processes their data without validation, it can be vulnerable to SQL injection, XSS, or buffer overflows if the third-party service is compromised.",
    remediation: [
      "Sanitize and validate all data received from external third-party API services before processing it.",
      "Enforce transport encryption (HTTPS) and verify certificates when connecting to external APIs.",
      "Implement proper timeouts, retry limits, and circuit breakers for external integrations."
    ],
    vulnerableCode: `// Express.js Vulnerable Integration
const axios = require('axios');

app.post('/api/weather/report', async (req, res) => {
  // Fetch details from third-party integration
  const response = await axios.get('https://api.external-weather.com/today');
  const forecast = response.data.summary;
  
  // Vulnerability: Concatenates third-party data directly into database query
  // or embeds it in a webpage without escaping, leading to SQLi or XSS.
  const query = "INSERT INTO reports (info) VALUES ('" + forecast + "')";
  await db.executeRaw(query);
  
  res.json({ status: 'Report recorded' });
});`,
    secureCode: `// Express.js Secure Integration
const axios = require('axios');
const validator = require('validator');

app.post('/api/weather/report', async (req, res) => {
  try {
    const response = await axios.get('https://api.external-weather.com/today', {
      timeout: 5000 // Mitigation 1: Enforce strict connection timeout
    });

    const rawForecast = response.data.summary;

    // Mitigation 2: Sanitize and validate external input before processing
    if (typeof rawForecast !== 'string' || !validator.isAlphanumeric(rawForecast.replace(/\\s/g, ''))) {
      return res.status(422).json({ error: 'Invalid response signature from external provider' });
    }

    // Mitigation 3: Use parameterized database queries to prevent SQL injection
    const query = "INSERT INTO reports (info) VALUES ($1)";
    await db.query(query, [rawForecast]);

    res.json({ status: 'Report recorded successfully' });
  } catch (err) {
    res.status(502).json({ error: 'Bad Gateway: External service error or timeout' });
  }
});`,
    simulation: {
      title: "Third-Party Data Verification Loop",
      steps: [
        {
          label: "Fetch External Data",
          description: "App requests data from third-party service, which returns a malicious payload: { \"summary\": \"' OR 1=1 --\" }",
          vulnerableStatus: "Reading payload property value.",
          secureStatus: "Reading payload property value."
        },
        {
          label: "Sanitization & Parsing",
          description: "Checking input safety before database insertion.",
          vulnerableStatus: "Bypassed: Directly concatenating payload into SQL query string.",
          secureStatus: "Validation: Regex check identifies SQL characters. Request rejected."
        },
        {
          label: "Result",
          description: "Database execution status.",
          vulnerableStatus: "SQL injection executed on the internal database. Data leak risk.",
          secureStatus: "Error handled: Execution aborted before reaching database. Safe."
        }
      ]
    }
  }
];
