const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const crypto = require('crypto-js');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
const PORT = 3000;

// VULNERABILITY: Hardcoded JWT secret
const JWT_SECRET = 'null_mystery_secret_2024';

// VULNERABILITY: Hardcoded API keys in backend (also exposed in frontend)
const API_KEYS = {
    stripe: 'sk_live_51ABC123DEF456GHI789JKL',
    crypto: 'crypto_api_key_0xDEADBEEF',
    internal: 'internal_api_key_supersecret'
};

// Initialize SQLite database
const db = new sqlite3.Database(':memory:');

// Helper function to run queries with promises
function dbRun(query, params = []) {
    return new Promise((resolve, reject) => {
        db.run(query, params, function(err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
}

function dbGet(query, params = []) {
    return new Promise((resolve, reject) => {
        db.get(query, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function dbAll(query, params = []) {
    return new Promise((resolve, reject) => {
        db.all(query, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

// Create tables with plaintext passwords (VULNERABILITY)
db.serialize(() => {
    db.run(`
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'agent',
            isSubscribed INTEGER DEFAULT 0,
            donationTotal REAL DEFAULT 0,
            createdAt TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    db.run(`
        CREATE TABLE cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            caseNumber TEXT,
            title TEXT,
            description TEXT,
            classification TEXT,
            submittedBy INTEGER,
            content TEXT,
            isRedacted INTEGER DEFAULT 0
        )
    `);
    
    db.run(`
        CREATE TABLE donations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId INTEGER,
            amount REAL,
            cryptoAddress TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    db.run(`
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            caseId INTEGER,
            userId INTEGER,
            content TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    db.run(`
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId INTEGER,
            token TEXT,
            createdAt TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    db.run(`
        CREATE TABLE coupons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            discount REAL,
            used INTEGER DEFAULT 0
        )
    `);
    
    db.run(`
        CREATE TABLE password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId INTEGER,
            token TEXT,
            email TEXT,
            createdAt TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Seed data
    db.run(`INSERT INTO users (username, email, password, role, isSubscribed) VALUES (?, ?, ?, ?, ?)`,
        ['admin', 'admin@null.org', 's3cr3t_p4ss!', 'admin', 1]);
    db.run(`INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)`,
        ['shadowkeeper', 'shadow@null.org', 'password123', 'moderator']);
    db.run(`INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)`,
        ['agent_x', 'agentx@null.org', '123456', 'agent']);
    db.run(`INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)`,
        ['deepthroat', 'deep@null.org', 'admin', 'agent']);

    const cases = [
        ['NULL-001', 'The Philadelphia Experiment', 'Naval invisibility project gone wrong. 1943.', 'TOP SECRET', 'In October 1943, the USS Eldridge allegedly became invisible and teleported. Survivors reported horrific side effects. Navy denies everything.', 0],
        ['NULL-002', 'Area 51 Whistleblower', 'Former contractor testimony. Location: [REDACTED]', 'CLASSIFIED', 'Robert "Bob" Lazar claimed to have worked on reverse-engineering extraterrestrial technology at S-4 near Area 51. Government discredited him.', 0],
        ['NULL-003', 'MKUltra Subject 24', 'Mind control experiments. CIA involvement confirmed.', 'TOP SECRET - EYES ONLY', 'Documents reveal extensive human experimentation. Most files destroyed in 1973. Surviving subjects report ongoing surveillance.', 0],
        ['NULL-004', 'The Montauk Project', 'Psychological warfare research. Long Island, NY.', 'CLASSIFIED', 'Allegedly conducted at Camp Hero. Time travel, mind control, contact with extraterrestrials. All officially denied.', 0],
        ['NULL-005', 'Operation Mockingbird', 'Media manipulation program. Active since 1950s.', 'SECRET', 'CIA program to influence domestic and foreign media. Journalists on payroll. Still operational according to sources.', 1],
        ['NULL-006', 'D.B. Cooper - True Identity', 'Skyjacker identity known to FBI. Case closed internally.', 'RESTRICTED', 'FBI knows the identity but case remains "unsolved." Connected to larger intelligence operation.', 1],
        ['NULL-007', 'The Dyatlov Pass Incident', 'Soviet cover-up. True cause classified.', 'TOP SECRET', 'Nine hikers died under mysterious circumstances. Soviet investigation sealed. Radiation detected on clothing. Military involvement suspected.', 1],
        ['NULL-008', 'Project Blue Book - Hidden Files', 'Unexplained cases removed from public record.', 'CLASSIFIED', '701 cases remained "unidentified." True number is higher. Best evidence sequestered to separate archive.', 1]
    ];

    cases.forEach((c) => {
        db.run(`INSERT INTO cases (caseNumber, title, description, classification, content, submittedBy, isRedacted) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [c[0], c[1], c[2], c[3], c[4], 1, c[5]]);
    });

    db.run(`INSERT INTO coupons (code, discount) VALUES (?, ?)`, ['TRUTHSEEKER', 20]);
    db.run(`INSERT INTO coupons (code, discount) VALUES (?, ?)`, ['INNERCIRCLE50', 50]);
    db.run(`INSERT INTO coupons (code, discount) VALUES (?, ?)`, ['ONEUSE99', 99]);
});

// VULNERABILITY: Overly permissive CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', '*');
    res.header('Access-Control-Allow-Headers', '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});

// VULNERABILITY: Cookie without HttpOnly or Secure flags
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// VULNERABILITY: Verbose error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: err.message,
        stack: err.stack,
        query: req.query,
        body: req.body,
        database: 'SQLite3 in-memory',
        tables: ['users', 'cases', 'donations', 'comments', 'sessions', 'coupons']
    });
});

// File upload configuration - VULNERABILITY: No validation
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'public', 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
});
const upload = multer({ storage: storage });

// ============ AUTHENTICATION ROUTES ============

// VULNERABILITY: SQL Injection in login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    
    const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
    
    try {
        const user = await dbGet(query);
        
        if (user) {
            const existingSession = await dbGet('SELECT token FROM sessions WHERE userId = ?', [user.id]);
            let token;
            
            if (existingSession) {
                token = existingSession.token;
            } else {
                token = jwt.sign(
                    { id: user.id, email: user.email, role: user.role, isSubscribed: user.isSubscribed },
                    JWT_SECRET,
                    { algorithm: 'HS256' }
                );
                await dbRun('INSERT INTO sessions (userId, token) VALUES (?, ?)', [user.id, token]);
            }
            
            res.cookie('session', token, { httpOnly: false, secure: false });
            res.cookie('userId', user.id, { httpOnly: false, secure: false });
            
            res.json({
                success: true,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    isSubscribed: user.isSubscribed
                },
                token: token
            });
        } else {
            const userExists = await dbGet(`SELECT id FROM users WHERE email = '${email}'`);
            if (userExists) {
                res.status(401).json({ error: 'Invalid password for this account' });
            } else {
                res.status(401).json({ error: 'No account found with this email' });
            }
        }
    } catch (err) {
        res.status(500).json({ 
            error: 'Database error', 
            details: err.message,
            query: query 
        });
    }
});

app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    try {
        await dbRun('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, password]);
        res.json({ success: true, message: 'Agent registered. Welcome to the shadows.' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
    
    if (user) {
        const resetToken = crypto.MD5(email + Date.now()).toString();
        await dbRun('INSERT INTO password_resets (userId, token, email) VALUES (?, ?, ?)', [user.id, resetToken, email]);
        
        res.json({ 
            success: true, 
            message: 'Reset link sent',
            debug: { token: resetToken, resetLink: `/reset-password?token=${resetToken}&email=${email}` }
        });
    } else {
        res.status(404).json({ error: 'Email not found in our records' });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    const { token, email, newPassword } = req.body;
    
    const reset = await dbGet('SELECT * FROM password_resets WHERE token = ? AND email = ?', [token, email]);
    
    if (reset) {
        await dbRun('UPDATE users SET password = ? WHERE email = ?', [newPassword, email]);
        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'Invalid reset token' });
    }
});

// ============ USER ROUTES ============

app.get('/api/user/:id', async (req, res) => {
    const user = await dbGet('SELECT id, username, email, role, isSubscribed, donationTotal, password FROM users WHERE id = ?', [req.params.id]);
    if (user) {
        res.json(user);
    } else {
        res.status(404).json({ error: 'User not found' });
    }
});

app.put('/api/user/:id', async (req, res) => {
    const { username, email, role, isSubscribed, donationTotal } = req.body;
    
    try {
        if (role) {
            await dbRun('UPDATE users SET role = ? WHERE id = ?', [role, req.params.id]);
        }
        if (isSubscribed !== undefined) {
            await dbRun('UPDATE users SET isSubscribed = ? WHERE id = ?', [isSubscribed, req.params.id]);
        }
        if (donationTotal !== undefined) {
            await dbRun('UPDATE users SET donationTotal = ? WHERE id = ?', [donationTotal, req.params.id]);
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ CASES ROUTES ============

app.get('/api/cases/search', async (req, res) => {
    const { q } = req.query;
    const query = `SELECT * FROM cases WHERE title LIKE '%${q}%' OR description LIKE '%${q}%' OR caseNumber LIKE '%${q}%'`;
    
    try {
        const cases = await dbAll(query);
        res.json(cases);
    } catch (err) {
        res.status(500).json({ error: err.message, query: query });
    }
});

app.get('/api/cases/:id', async (req, res) => {
    const caseData = await dbGet('SELECT * FROM cases WHERE id = ?', [req.params.id]);
    if (caseData) {
        res.json(caseData);
    } else {
        res.status(404).json({ error: 'Case not found' });
    }
});

app.get('/api/cases', async (req, res) => {
    const cases = await dbAll('SELECT id, caseNumber, title, description, classification, isRedacted FROM cases');
    res.json(cases);
});

app.post('/api/cases/:id/notes', async (req, res) => {
    const { content } = req.body;
    const caseId = req.params.id;
    
    const ejs = require('ejs');
    try {
        const rendered = ejs.render(content, { 
            caseId: caseId,
            secret: 'CLASSIFIED_INTEL_2024',
            dbPath: ':memory:',
            apiKeys: API_KEYS
        });
        
        await dbRun('INSERT INTO comments (caseId, userId, content) VALUES (?, ?, ?)', [caseId, 1, rendered]);
        res.json({ success: true, rendered: rendered });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ COMMENTS - STORED XSS ============

app.get('/api/cases/:id/comments', async (req, res) => {
    const comments = await dbAll('SELECT * FROM comments WHERE caseId = ?', [req.params.id]);
    res.json(comments);
});

app.post('/api/comments', async (req, res) => {
    const { caseId, content } = req.body;
    await dbRun('INSERT INTO comments (caseId, userId, content) VALUES (?, ?, ?)', [caseId, 1, content]);
    res.json({ success: true });
});

// ============ DONATIONS ============

app.post('/api/donate', async (req, res) => {
    let { userId, amount, cryptoAddress } = req.body;
    
    amount = parseFloat(amount);
    
    await dbRun('INSERT INTO donations (userId, amount, cryptoAddress) VALUES (?, ?, ?)', [userId, amount, cryptoAddress]);
    await dbRun('UPDATE users SET donationTotal = donationTotal + ? WHERE id = ?', [amount, userId]);
    
    const user = await dbGet('SELECT donationTotal FROM users WHERE id = ?', [userId]);
    
    res.json({ 
        success: true, 
        message: `Thank you for your ${amount >= 0 ? 'donation' : 'withdrawal'} of $${amount}`,
        newTotal: user?.donationTotal
    });
});

app.get('/api/donations/:userId', async (req, res) => {
    const donations = await dbAll('SELECT * FROM donations WHERE userId = ?', [req.params.userId]);
    res.json(donations);
});

// ============ SUBSCRIPTION ============

app.post('/api/subscribe', async (req, res) => {
    const { userId, plan, paymentToken, isSubscribed } = req.body;
    
    if (isSubscribed === true || isSubscribed === 'true' || isSubscribed === 1) {
        await dbRun('UPDATE users SET isSubscribed = 1 WHERE id = ?', [userId]);
        res.json({ success: true, message: 'Welcome to the Inner Circle' });
    } else {
        if (paymentToken) {
            await dbRun('UPDATE users SET isSubscribed = 1 WHERE id = ?', [userId]);
            res.json({ success: true, message: 'Payment processed. Welcome to the Inner Circle' });
        } else {
            res.status(400).json({ error: 'Payment required' });
        }
    }
});

// ============ COUPONS ============

app.post('/api/coupon/apply', async (req, res) => {
    const { code, userId } = req.body;
    
    const coupon = await dbGet('SELECT * FROM coupons WHERE code = ?', [code]);
    
    if (coupon) {
        res.json({ 
            success: true, 
            discount: coupon.discount,
            message: `Coupon applied! ${coupon.discount}% off`
        });
    } else {
        res.status(404).json({ error: 'Invalid coupon code' });
    }
});

// ============ REPORT CASE - COMMAND INJECTION ============

app.post('/api/report', (req, res) => {
    const { title, description, contactEmail } = req.body;
    
    const logCommand = process.platform === 'win32' 
        ? `echo Report: ${title} >> reports.log`
        : `echo "Report: ${title}" >> reports.log`;
    
    exec(logCommand, (error, stdout, stderr) => {
        if (error) {
            res.json({ success: true, message: 'Report logged', debug: error.message });
        } else {
            res.json({ success: true, message: 'Report submitted to the Archive' });
        }
    });
});

// ============ FILE UPLOAD ============

app.post('/api/upload', upload.single('evidence'), (req, res) => {
    if (req.file) {
        res.json({ 
            success: true, 
            filename: req.file.originalname,
            path: `/uploads/${req.file.originalname}`
        });
    } else {
        res.status(400).json({ error: 'No file uploaded' });
    }
});

app.get('/api/files/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'public', 'uploads', filename);
    
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.status(404).json({ error: 'File not found' });
    }
});

// ============ ADMIN ROUTES ============

app.get('/secret-admin-console', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/api/admin/users', async (req, res) => {
    const users = await dbAll('SELECT * FROM users');
    res.json(users);
});

app.get('/api/admin/logs', (req, res) => {
    res.json({
        logs: [
            { timestamp: '2024-01-15 03:42:11', action: 'LOGIN', user: 'admin@null.org', ip: '192.168.1.1' },
            { timestamp: '2024-01-15 03:45:22', action: 'FILE_ACCESS', user: 'admin@null.org', file: '/secrets/classified.pdf' },
            { timestamp: '2024-01-15 04:12:33', action: 'DATABASE_BACKUP', user: 'system', details: 'Backup saved to /backup.zip' }
        ],
        dbCredentials: {
            host: 'localhost',
            database: 'null_mystery',
            username: 'root',
            password: 'r00t_p4ss!'
        }
    });
});

// ============ BACKUP FILE ============

app.get('/backup.zip', async (req, res) => {
    const users = await dbAll('SELECT * FROM users');
    const cases = await dbAll('SELECT * FROM cases');
    const donations = await dbAll('SELECT * FROM donations');
    
    const backupContent = JSON.stringify({
        users,
        cases,
        donations,
        api_keys: API_KEYS,
        jwt_secret: JWT_SECRET
    }, null, 2);
    
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename=backup.zip');
    res.send(backupContent);
});

// ============ OPEN REDIRECT ============

app.get('/redirect', (req, res) => {
    const { url } = req.query;
    res.redirect(url);
});

// ============ REFLECTED XSS ============

app.get('/error', (req, res) => {
    const { message } = req.query;
    res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Error - Null Mystery</title></head>
        <body style="background: #0a0a0a; color: #ff0040; font-family: monospace; padding: 50px;">
            <h1>⚠ SYSTEM ERROR</h1>
            <p>${message}</p>
            <a href="/" style="color: #00ff88;">Return to Archive</a>
        </body>
        </html>
    `);
});

// ============ WEB CACHE POISONING ============

app.get('/api/config', (req, res) => {
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    res.json({
        baseUrl: `http://${host}`,
        apiUrl: `http://${host}/api`,
        cdnUrl: `http://${host}/static`
    });
});

// ============ JWT VULNERABILITIES ============

app.post('/api/auth/verify-token', (req, res) => {
    const { token } = req.body;
    
    try {
        const decoded = jwt.decode(token);
        
        if (decoded) {
            res.json({ valid: true, payload: decoded });
        } else {
            res.status(401).json({ valid: false });
        }
    } catch (err) {
        res.status(401).json({ valid: false, error: err.message });
    }
});

// ============ BLIND SQL INJECTION ============

app.get('/api/cases/exists/:id', async (req, res) => {
    const { id } = req.params;
    const start = Date.now();
    
    try {
        const query = `SELECT * FROM cases WHERE id = ${id}`;
        const result = await dbGet(query);
        
        const elapsed = Date.now() - start;
        
        if (result) {
            res.json({ exists: true, queryTime: elapsed });
        } else {
            res.json({ exists: false, queryTime: elapsed });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ WHISTLEBLOWER XXE VULNERABILITY ============

const xml2js = require('xml2js');
const https = require('https');
const http = require('http');

app.post('/api/whistleblower/submit', upload.array('evidence'), async (req, res) => {
    try {
        const { xmlData } = req.body;
        
        if (xmlData) {
            // XXE VULNERABILITY: Parser configured to allow external entities
            const parser = new xml2js.Parser({
                explicitRoot: false,
                explicitArray: false,
                // DANGEROUS: Allows XXE attacks
                xmlns: true,
                xmldecl: true
            });
            
            parser.parseString(xmlData, async (err, result) => {
                if (err) {
                    res.status(400).json({ error: 'XML parsing error', details: err.message });
                } else {
                    // Store report
                    const reportId = 'WB-' + Date.now();
                    res.json({ 
                        success: true, 
                        reportId: reportId,
                        parsed: result,
                        files: req.files ? req.files.map(f => f.filename) : []
                    });
                }
            });
        } else {
            res.status(400).json({ error: 'No XML data provided' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============ SSRF VULNERABILITY ============

app.post('/api/download', async (req, res) => {
    const { url } = req.body;
    
    if (!url) {
        return res.status(400).json({ error: 'URL required' });
    }
    
    try {
        // SSRF VULNERABILITY: No URL validation
        const protocol = url.startsWith('https') ? https : http;
        
        protocol.get(url, (response) => {
            let data = '';
            
            response.on('data', (chunk) => {
                data += chunk;
            });
            
            response.on('end', () => {
                res.json({ 
                    success: true, 
                    filename: url.split('/').pop(),
                    content: data.substring(0, 1000), // Truncate for display
                    statusCode: response.statusCode
                });
            });
        }).on('error', (err) => {
            res.json({ success: false, error: err.message });
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============ DESERIALIZATION VULNERABILITY ============

app.post('/api/import-config', (req, res) => {
    const { config } = req.body;
    
    try {
        // VULNERABILITY: eval() on user input
        const parsed = eval('(' + config + ')');
        res.json({ success: true, imported: parsed });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============ LDAP INJECTION (Simulated) ============

app.post('/api/ldap/search', async (req, res) => {
    const { username } = req.body;
    
    // Simulated LDAP query with injection vulnerability
    const ldapQuery = `(uid=${username})`;
    
    // VULNERABILITY: No input sanitization
    const users = await dbAll(`SELECT * FROM users WHERE username LIKE '%${username}%'`);
    
    res.json({
        ldapQuery: ldapQuery,
        results: users,
        hint: 'Try: *)(uid=*) to bypass filters'
    });
});

// ============ CSV INJECTION ============

app.get('/api/export/users', async (req, res) => {
    const users = await dbAll('SELECT username, email, role, donationTotal FROM users');
    
    // VULNERABILITY: No sanitization of cell values
    let csv = 'Username,Email,Role,Donation Total\n';
    users.forEach(user => {
        csv += `${user.username},${user.email},${user.role},${user.donationTotal}\n`;
    });
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=users.csv');
    res.send(csv);
});

// ============ HOST HEADER INJECTION ============

app.get('/api/reset-link', async (req, res) => {
    const { email } = req.query;
    const host = req.headers.host; // VULNERABILITY: Trusts Host header
    
    const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
    
    if (user) {
        const token = crypto.MD5(email + Date.now()).toString();
        await dbRun('INSERT INTO password_resets (userId, token, email) VALUES (?, ?, ?)', 
                   [user.id, token, email]);
        
        const resetUrl = `http://${host}/reset-password?token=${token}&email=${email}`;
        
        res.json({
            success: true,
            message: 'Reset link generated',
            resetUrl: resetUrl,
            warning: 'Host header can be manipulated for phishing'
        });
    } else {
        res.status(404).json({ error: 'User not found' });
    }
});

// ============ HTTP PARAMETER POLLUTION ============

app.get('/api/search-users', async (req, res) => {
    // VULNERABILITY: Takes last value if parameter appears multiple times
    const role = Array.isArray(req.query.role) ? req.query.role[req.query.role.length - 1] : req.query.role;
    
    const users = await dbAll(`SELECT username, email, role FROM users WHERE role = '${role}'`);
    
    res.json({
        searchedRole: role,
        users: users,
        hint: 'Try: ?role=agent&role=admin to cause confusion'
    });
});

// ============ NOSQL INJECTION (Simulated with SQL) ============

app.post('/api/nosql/login', async (req, res) => {
    const { email, password } = req.body;
    
    // Simulating NoSQL-style query but using SQL
    // VULNERABILITY: Object injection patterns
    let query;
    if (typeof email === 'object' || typeof password === 'object') {
        // NoSQL injection attempt detected but still processed
        query = `SELECT * FROM users WHERE email = 'admin@null.org' OR '1'='1'`;
    } else {
        query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
    }
    
    const user = await dbGet(query);
    
    if (user) {
        res.json({ success: true, user: user, query: query });
    } else {
        res.status(401).json({ error: 'Invalid credentials', triedQuery: query });
    }
});

// ============ XML BOMB (Billion Laughs) ============

app.post('/api/parse-xml', (req, res) => {
    const { xml } = req.body;
    
    // VULNERABILITY: No protection against XML bombs
    const parser = new xml2js.Parser();
    
    parser.parseString(xml, (err, result) => {
        if (err) {
            res.status(400).json({ error: err.message });
        } else {
            res.json({ parsed: result });
        }
    });
});

// ============ PATH TRAVERSAL ============

app.get('/api/read-file', (req, res) => {
    const { filename } = req.query;
    
    // VULNERABILITY: No path sanitization
    const filePath = path.join(__dirname, 'public', 'uploads', filename);
    
    if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf8');
        res.json({ content: content });
    } else {
        res.status(404).json({ 
            error: 'File not found', 
            tried: filePath,
            hint: 'Try: ../../../package.json or ..\\..\\..\\package.json' 
        });
    }
});

// ============ REGEX DOS (ReDoS) ============

app.post('/api/validate-email', (req, res) => {
    const { email } = req.body;
    
    // VULNERABILITY: Catastrophic backtracking regex
    const regex = /^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$/;
    
    const start = Date.now();
    const isValid = regex.test(email);
    const elapsed = Date.now() - start;
    
    res.json({
        valid: isValid,
        email: email,
        processingTime: elapsed + 'ms',
        hint: 'Try: aaaaaaaaaaaaaaaaaaaaaaaa@aaaaaaaaaaaaaa for ReDoS'
    });
});

// ============ INFORMATION DISCLOSURE ============

app.get('/.env', (req, res) => {
    // VULNERABILITY: Exposing environment file
    res.send(`
DATABASE_URL=sqlite:///null_mystery.db
JWT_SECRET=null_mystery_secret_2024
API_KEY_STRIPE=sk_live_51ABC123DEF456GHI789JKL
API_KEY_CRYPTO=crypto_api_key_0xDEADBEEF
ADMIN_PASSWORD=s3cr3t_p4ss!
SESSION_SECRET=supersecret123
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    `);
});

app.get('/.git/config', (req, res) => {
    // VULNERABILITY: Exposed git config
    res.send(`
[core]
    repositoryformatversion = 0
    filemode = false
[remote "origin"]
    url = https://github.com/nullmystery/archive.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[user]
    name = Admin
    email = admin@null.org
[credential]
    helper = store
    `);
});

// ============ MORE VULNERABILITIES (100+ total) ============

// VULNERABILITY: Session fixation
app.get('/api/set-session', (req, res) => {
    const { sessionId } = req.query;
    res.cookie('sessionId', sessionId || 'session_' + Date.now(), { httpOnly: false });
    res.json({ success: true, sessionId: sessionId });
});

// VULNERABILITY: Insecure direct object reference (files)
app.get('/api/documents/:docId', (req, res) => {
    const { docId } = req.params;
    res.json({ 
        id: docId,
        content: `Classified document ${docId} content`,
        author: 'admin@null.org',
        hint: 'Try different docId values: 1, 2, 3, admin, secret'
    });
});

// VULNERABILITY: XML External Entity (XXE) in API
app.post('/api/xml-import', (req, res) => {
    const xmlData = req.body.xml;
    parseString(xmlData, { strict: false }, (err, result) => {
        if (err) return res.status(400).json({ error: err.message });
        res.json({ parsed: result, hint: 'XXE vulnerable endpoint' });
    });
});

// VULNERABILITY: Deserialization attack
app.post('/api/deserialize', (req, res) => {
    try {
        const userData = JSON.parse(req.body.data);
        if (userData.eval) {
            const result = eval(userData.eval); // CRITICAL: Remote Code Execution
            res.json({ result, warning: 'eval() executed' });
        } else {
            res.json({ data: userData });
        }
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// VULNERABILITY: Timing attack on authentication
app.post('/api/auth/timing-attack', async (req, res) => {
    const { username, password } = req.body;
    const user = await dbGet('SELECT * FROM users WHERE email = ?', [username]);
    
    if (user) {
        // Vulnerable: Character-by-character comparison reveals password length
        for (let i = 0; i < password.length; i++) {
            if (password[i] !== user.password[i]) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            // Simulated processing delay
            await new Promise(resolve => setTimeout(resolve, 10));
        }
        if (password.length === user.password.length) {
            return res.json({ success: true, token: generateToken(user) });
        }
    }
    res.status(401).json({ error: 'Invalid credentials' });
});

// VULNERABILITY: HTTP Parameter Pollution
app.get('/api/users/filter', async (req, res) => {
    const { role, status } = req.query;
    // HPP: ?role=admin&role=user picks first or last depending on server
    const query = `SELECT * FROM users WHERE role = '${Array.isArray(role) ? role[0] : role}' AND status = '${status}'`;
    const users = await dbAll(query);
    res.json({ users, hint: 'Try ?role=admin&role=user' });
});

// VULNERABILITY: Cache poisoning
app.get('/api/cached-content', (req, res) => {
    const host = req.headers.host;
    res.set('Cache-Control', 'public, max-age=3600');
    res.send(`<html><body><h1>Cached for: ${host}</h1><script src="https://${host}/assets/app.js"></script></body></html>`);
});

// VULNERABILITY: JWT algorithm confusion
app.post('/api/auth/jwt-verify', (req, res) => {
    try {
        const token = req.body.token;
        // CRITICAL: Doesn't verify algorithm, allows "none"
        const decoded = jwt.decode(token, { complete: true });
        res.json({ decoded, hint: 'Try algorithm: "none"' });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// VULNERABILITY: Mass assignment
app.put('/api/profile/update', async (req, res) => {
    const userId = req.query.userId || 1;
    const updates = req.body; // No filtering!
    
    // Build update query from ALL body params
    const fields = Object.keys(updates).map(key => `${key} = ?`).join(', ');
    const values = [...Object.values(updates), userId];
    
    await dbRun(`UPDATE users SET ${fields} WHERE id = ?`, values);
    res.json({ success: true, hint: 'Try adding "role": "admin" to your update' });
});

// VULNERABILITY: Server-Side Template Injection (SSTI)
app.get('/api/render-template', (req, res) => {
    const template = req.query.template || 'Hello <%= name %>';
    const data = { name: req.query.name || 'User' };
    
    try {
        const rendered = ejs.render(template, data);
        res.send(rendered);
    } catch (e) {
        res.status(400).send(e.message);
    }
});

// VULNERABILITY: Insecure randomness
app.get('/api/generate-token', (req, res) => {
    const token = Math.random().toString(36).substr(2, 9);
    res.json({ token, hint: 'Predictable Math.random()' });
});

// VULNERABILITY: Business logic flaw - negative numbers
app.post('/api/transfer-funds', async (req, res) => {
    const { fromUserId, toUserId, amount } = req.body;
    
    // No validation for negative amounts!
    await dbRun('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, fromUserId]);
    await dbRun('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, toUserId]);
    
    res.json({ success: true, amount, hint: 'Try negative amounts' });
});

// VULNERABILITY: Race condition
let globalCounter = 0;
app.post('/api/increment-counter', async (req, res) => {
    const current = globalCounter;
    // Simulate async operation
    await new Promise(resolve => setTimeout(resolve, 100));
    globalCounter = current + 1;
    res.json({ counter: globalCounter, hint: 'Send multiple requests simultaneously' });
});

// VULNERABILITY: GraphQL-style introspection
app.get('/api/schema', (req, res) => {
    res.json({
        tables: ['users', 'cases', 'donations', 'subscriptions', 'sessions'],
        users: { id: 'int', email: 'string', password: 'string', role: 'string', balance: 'float' },
        hint: 'Full database schema exposed'
    });
});

// VULNERABILITY: Weak cryptography
app.post('/api/encrypt-data', (req, res) => {
    const { data } = req.body;
    const encrypted = CryptoJS.MD5(data).toString(); // Weak hash as encryption!
    res.json({ encrypted, hint: 'MD5 is not encryption' });
});

// VULNERABILITY: Unvalidated redirects
app.get('/api/external-redirect', (req, res) => {
    const { target } = req.query;
    res.redirect(target); // No validation!
});

// VULNERABILITY: Information disclosure via error messages
app.get('/api/user-lookup', async (req, res) => {
    try {
        const { email } = req.query;
        const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
        if (user) {
            res.json({ exists: true, userId: user.id });
        } else {
            res.status(404).json({ error: 'User not found', email });
        }
    } catch (e) {
        res.status(500).json({ error: e.message, stack: e.stack }); // Stack trace!
    }
});

// VULNERABILITY: Clickjacking - no X-Frame-Options
app.get('/api/frame-test', (req, res) => {
    res.send('<h1>This page can be framed</h1><p>Clickjacking vulnerable</p>');
});

// VULNERABILITY: CORS misconfiguration
app.options('/api/sensitive-data', (req, res) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin); // Reflects any origin!
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.send();
});

app.get('/api/sensitive-data', (req, res) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.json({ secret: 'API_KEY_123456', users: ['admin@null.org'] });
});

// VULNERABILITY: File inclusion
app.get('/api/load-template', (req, res) => {
    const { file } = req.query;
    const fs = require('fs');
    try {
        const content = fs.readFileSync(file, 'utf8'); // LFI!
        res.send(content);
    } catch (e) {
        res.status(404).send('File not found');
    }
});

// VULNERABILITY: Type confusion
app.post('/api/is-admin', (req, res) => {
    const { userId } = req.body;
    if (userId == 0) { // == instead of ===
        res.json({ isAdmin: true, hint: 'Type coercion: try "0", false, null' });
    } else {
        res.json({ isAdmin: false });
    }
});

// VULNERABILITY: Prototype pollution
app.post('/api/merge-config', (req, res) => {
    const defaultConfig = { theme: 'dark', lang: 'en' };
    const userConfig = req.body;
    
    function merge(target, source) {
        for (let key in source) {
            if (typeof source[key] === 'object') {
                target[key] = merge(target[key] || {}, source[key]);
            } else {
                target[key] = source[key];
            }
        }
        return target;
    }
    
    const config = merge(defaultConfig, userConfig);
    res.json({ config, hint: 'Try {"__proto__": {"isAdmin": true}}' });
});

// VULNERABILITY: NoSQL injection simulation
app.get('/api/nosql-query', async (req, res) => {
    const { username, password } = req.query;
    // Simulating MongoDB-style query
    const query = { email: username, password: password };
    
    if (typeof password === 'object') {
        // NoSQL injection: ?password[$ne]=null
        const users = await dbAll('SELECT * FROM users');
        return res.json({ users, hint: 'NoSQL injection worked!' });
    }
    
    const user = await dbGet('SELECT * FROM users WHERE email = ? AND password = ?', [username, password]);
    res.json({ user: user || null });
});

// VULNERABILITY: DNS rebinding
app.get('/api/internal-network', (req, res) => {
    const host = req.headers.host;
    res.json({ 
        host,
        internal_services: ['http://localhost:3306/phpmyadmin', 'http://192.168.1.1/admin'],
        hint: 'DNS rebinding attack vector'
    });
});

// VULNERABILITY: Weak session management
app.get('/api/create-session', (req, res) => {
    const sessionId = Date.now().toString(); // Predictable!
    res.cookie('session', sessionId, { httpOnly: false, secure: false });
    res.json({ sessionId, hint: 'Predictable session IDs' });
});

// VULNERABILITY: API rate limiting - NONE
app.post('/api/brute-force-endpoint', async (req, res) => {
    const { pin } = req.body;
    if (pin === '1234') {
        res.json({ success: true, message: 'Correct PIN!' });
    } else {
        res.json({ success: false, hint: 'No rate limiting - brute force away!' });
    }
});

// ============ SERVE STATIC PAGES ============

// Homepage
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Public pages
app.get('/cases', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'cases.html'));
});

app.get('/donate', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'donate.html'));
});

app.get('/subscribe', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'subscribe.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/archives', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'archives.html'));
});

// VULNERABILITY: Hidden Inner Circle page
app.get('/inner-circle-secret-archives', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'inner-circle.html'));
});

// Alternative route names
app.get('/all-cases', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'cases.html'));
});

// SECRET PAGES (Find these through hacking!)
app.get('/classified-submissions', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'whistleblower.html'));
});

app.get('/evidence-room-beta', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'vault.html'));
});

app.get('/hacker-guide', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'hacker-guide.html'));
});

// ============ 50+ MORE VULNERABILITIES ============

// VULN #51: HTML Injection
app.get('/api/html-inject', (req, res) => {
    const { name } = req.query;
    res.send(`<html><body><h1>Welcome ${name}!</h1></body></html>`);
});

// VULN #52: CSS Injection
app.get('/api/style', (req, res) => {
    const { bg } = req.query;
    res.send(`<style>body { background: ${bg}; }</style>`);
});

// VULN #53: JWT None Algorithm
app.post('/api/jwt-none', (req, res) => {
    const token = req.body.token;
    const decoded = jwt.decode(token, { complete: true });
    res.json({ decoded, user: decoded?.payload });
});

// VULN #54: Authorization bypass via headers
app.get('/api/admin-only', (req, res) => {
    if (req.headers['x-admin'] === 'true') {
        res.json({ secret: 'Admin data', users: ['all@data.com'] });
    } else {
        res.status(403).json({ error: 'Forbidden' });
    }
});

// VULN #55: Subdomain takeover simulation
app.get('/api/subdomain-check', (req, res) => {
    const { domain } = req.query;
    res.json({ 
        domain,
        cname: 'old-service-12345.herokuapp.com',
        status: 'UNCLAIMED',
        hint: 'Subdomain takeover possible'
    });
});

// VULN #56: Memory leak
const leakyArray = [];
app.get('/api/memory-leak', (req, res) => {
    leakyArray.push(new Array(10000).fill('leak'));
    res.json({ leaks: leakyArray.length });
});

// VULN #57: Unsafe regex
app.get('/api/regex-dos', (req, res) => {
    const { input } = req.query;
    const unsafeRegex = /^(a+)+$/;
    const start = Date.now();
    const match = unsafeRegex.test(input);
    res.json({ match, time: Date.now() - start });
});

// VULN #58: Server-side includes
app.get('/api/ssi', (req, res) => {
    const { include } = req.query;
    res.send(`<!--#include file="${include}" -->`);
});

// VULN #59: XSLT injection
app.post('/api/xslt', (req, res) => {
    const { xml, xsl } = req.body;
    res.json({ xml, xsl, hint: 'XSLT injection point' });
});

// VULN #60: WebSocket hijacking
app.get('/api/ws-token', (req, res) => {
    const wsToken = Math.random().toString(36);
    res.json({ wsToken, hint: 'Predictable WebSocket tokens' });
});

// VULN #61: SMTP header injection
app.post('/api/send-email', (req, res) => {
    const { to, subject, body } = req.body;
    const email = `To: ${to}\nSubject: ${subject}\n\n${body}`;
    res.json({ sent: true, email });
});

// VULN #62: LDAP injection variant
app.get('/api/ldap-auth', (req, res) => {
    const { user } = req.query;
    const ldapQuery = `(uid=${user})`;
    res.json({ query: ldapQuery, hint: 'Try user=*)(uid=*)' });
});

// VULN #63: Expression language injection
app.get('/api/eval-expr', (req, res) => {
    const { expr } = req.query;
    try {
        const result = eval(expr);
        res.json({ result });
    } catch (e) {
        res.json({ error: e.message });
    }
});

// VULN #64: Insecure deserialization (Node)
app.post('/api/unserialize', (req, res) => {
    const { data } = req.body;
    const obj = JSON.parse(data);
    if (obj.constructor) {
        res.json({ danger: 'Constructor manipulation possible' });
    }
    res.json({ obj });
});

// VULN #65: Format string
app.get('/api/format', (req, res) => {
    const { format } = req.query;
    res.send(format.replace(/%s/g, 'data'));
});

// VULN #66: Integer overflow
app.post('/api/calculate', (req, res) => {
    const { a, b } = req.body;
    const result = parseInt(a) + parseInt(b);
    res.json({ result, overflow: result < 0 });
});

// VULN #67: Null byte injection
app.get('/api/file-read', (req, res) => {
    const { path: filePath } = req.query;
    res.json({ path: filePath, hint: 'Try null bytes: %00' });
});

// VULN #68: Unicode normalization
app.get('/api/normalize', (req, res) => {
    const { input } = req.query;
    res.json({ input, normalized: input.normalize() });
});

// VULN #69: Timing side-channel
app.post('/api/compare-secret', async (req, res) => {
    const secret = 'FLAG{secret123}';
    const { guess } = req.body;
    for (let i = 0; i < Math.min(guess.length, secret.length); i++) {
        if (guess[i] !== secret[i]) {
            return res.json({ correct: false });
        }
        await new Promise(r => setTimeout(r, 50));
    }
    res.json({ correct: guess === secret });
});

// VULN #70: Zip slip
app.post('/api/extract-zip', (req, res) => {
    const { filename } = req.body;
    res.json({ extractTo: `/uploads/${filename}`, hint: 'Try ../../../etc/passwd' });
});

// VULN #71: XXE via SVG
app.post('/api/upload-svg', (req, res) => {
    const { svg } = req.body;
    res.send(`<img src="data:image/svg+xml,${svg}" />`);
});

// VULN #72: Billion laughs attack
app.post('/api/xml-parse', (req, res) => {
    const { xml } = req.body;
    res.json({ xml, hint: 'Billion laughs DoS' });
});

// VULN #73: Insecure randomness (crypto)
app.get('/api/reset-token', (req, res) => {
    const token = Math.floor(Math.random() * 1000000);
    res.json({ token });
});

// VULN #74: Path confusion
app.get('/api/assets/*', (req, res) => {
    const asset = req.params[0];
    res.sendFile(path.join(__dirname, 'public', asset));
});

// VULN #75: HTTP request smuggling hint
app.post('/api/smuggle', (req, res) => {
    res.json({ 
        contentLength: req.headers['content-length'],
        transferEncoding: req.headers['transfer-encoding']
    });
});

// VULN #76: Host header poisoning
app.get('/api/reset-link', (req, res) => {
    const host = req.headers.host;
    res.json({ resetLink: `https://${host}/reset?token=abc123` });
});

// VULN #77: Cookie tossing
app.get('/api/set-cookie-multiple', (req, res) => {
    res.cookie('auth', 'user', { domain: '.null.org' });
    res.cookie('auth', 'admin', { domain: 'admin.null.org' });
    res.json({ hint: 'Cookie tossing' });
});

// VULN #78: DOM clobbering
app.get('/api/dom-test', (req, res) => {
    const { id } = req.query;
    res.send(`<html><div id="${id}">Test</div></html>`);
});

// VULN #79: PostMessage XSS
app.get('/api/postmessage', (req, res) => {
    res.send(`<script>window.addEventListener('message', e => eval(e.data))</script>`);
});

// VULN #80: WebRTC leak
app.get('/api/webrtc-config', (req, res) => {
    res.json({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
});

// VULN #81: CRLF injection
app.get('/api/header-inject', (req, res) => {
    const { value } = req.query;
    res.set('X-Custom', value);
    res.send('OK');
});

// VULN #82: Template injection (Handlebars)
app.get('/api/template', (req, res) => {
    const { tpl } = req.query;
    res.send(tpl);
});

// VULN #83: Prototype pollution via merge
app.post('/api/deep-merge', (req, res) => {
    const target = {};
    function merge(dst, src) {
        for (let key in src) {
            if (typeof src[key] === 'object') {
                dst[key] = merge(dst[key] || {}, src[key]);
            } else {
                dst[key] = src[key];
            }
        }
        return dst;
    }
    merge(target, req.body);
    res.json({ target });
});

// VULN #84: GraphQL introspection
app.get('/api/graphql-schema', (req, res) => {
    res.json({
        __schema: {
            types: ['User', 'Case', 'Donation'],
            queries: ['user', 'users', 'case', 'cases']
        }
    });
});

// VULN #85: Blind XXE
app.post('/api/xml-blind', (req, res) => {
    const { xml } = req.body;
    // Process XML but don't return result
    res.json({ processed: true });
});

// VULN #86: SSRF via redirect
app.get('/api/follow-redirect', (req, res) => {
    const { url } = req.query;
    res.redirect(url);
});

// VULN #87: Authentication bypass via parameter
app.get('/api/secure-data', (req, res) => {
    if (req.query.debug === 'true') {
        return res.json({ allData: 'exposed' });
    }
    res.status(401).json({ error: 'Unauthorized' });
});

// VULN #88: Session puzzling
app.get('/api/multi-session', (req, res) => {
    const session1 = req.cookies.session;
    const session2 = req.query.session;
    res.json({ session1, session2, hint: 'Session puzzling' });
});

// VULN #89: API key in URL
app.get('/api/data', (req, res) => {
    const { apiKey } = req.query;
    if (apiKey) {
        res.json({ data: 'sensitive', key: apiKey });
    } else {
        res.status(401).json({ error: 'No API key' });
    }
});

// VULN #90: Verb tampering
app.all('/api/admin-delete', (req, res) => {
    if (req.method === 'DELETE') {
        res.json({ deleted: true });
    } else if (req.method === 'GET') {
        res.json({ deleted: true, hint: 'Verb tampering works!' });
    } else {
        res.status(405).json({ error: 'Method not allowed' });
    }
});

// VULN #91: CSV formula injection
app.get('/api/export-csv', async (req, res) => {
    const users = await dbAll('SELECT username, email FROM users');
    let csv = 'Username,Email\n';
    users.forEach(u => csv += `${u.username},${u.email}\n`);
    res.set('Content-Type', 'text/csv');
    res.send(csv);
});

// VULN #92: PDF XSS
app.get('/api/generate-pdf', (req, res) => {
    const { content } = req.query;
    res.json({ pdf: `<html>${content}</html>`, format: 'pdf' });
});

// VULN #93: Tabnabbing
app.get('/api/external-link', (req, res) => {
    const { url } = req.query;
    res.send(`<a href="${url}" target="_blank">Click</a>`);
});

// VULN #94: Reverse tabnabbing
app.get('/api/opener', (req, res) => {
    res.send(`<a href="http://evil.com" target="_blank">Link</a>`);
});

// VULN #95: Dangling markup
app.get('/api/markup', (req, res) => {
    const { input } = req.query;
    res.send(`<input value="${input}">`);
});

// VULN #96: MIME sniffing
app.get('/api/download', (req, res) => {
    res.set('Content-Type', 'text/plain');
    res.send('<script>alert(1)</script>');
});

// VULN #97: Content spoofing
app.get('/api/spoof', (req, res) => {
    const { msg } = req.query;
    res.send(`<h1>${msg}</h1>`);
});

// VULN #98: Information disclosure via headers
app.get('/api/headers', (req, res) => {
    res.json({
        headers: req.headers,
        server: 'Express/4.18.2',
        node: process.version
    });
});

// VULN #99: Source code disclosure
app.get('/api/source', (req, res) => {
    res.set('Content-Type', 'text/plain');
    res.send(fs.readFileSync(__filename, 'utf8'));
});

// VULN #100: Backup file exposure
app.get('/server.js.bak', (req, res) => {
    res.set('Content-Type', 'text/plain');
    res.send(fs.readFileSync(__filename, 'utf8'));
});

// VULN #101: Git folder exposure
app.get('/.git/HEAD', (req, res) => {
    res.send('ref: refs/heads/master');
});

// VULN #102: Environment disclosure
app.get('/api/env', (req, res) => {
    res.json({ env: process.env });
});

// VULN #103: Stack trace in production
app.get('/api/error', (req, res) => {
    throw new Error('Intentional error with full stack trace');
});

// VULN #104: Weak password policy
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    // No password validation!
    await dbRun('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, password]);
    res.json({ success: true });
});

// VULN #105: Account enumeration
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await dbGet('SELECT id FROM users WHERE email = ?', [email]);
    if (user) {
        res.json({ message: 'Reset link sent to ' + email });
    } else {
        res.json({ message: 'Email not found in our system' });
    }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ███╗   ██╗██╗   ██╗██╗     ██╗                             ║
    ║   ████╗  ██║██║   ██║██║     ██║                             ║
    ║   ██╔██╗ ██║██║   ██║██║     ██║                             ║
    ║   ██║╚██╗██║██║   ██║██║     ██║                             ║
    ║   ██║ ╚████║╚██████╔╝███████╗███████╗                        ║
    ║   ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝                        ║
    ║                                                               ║
    ║   M Y S T E R Y   O R G A N I S A T I O N                    ║
    ║                                                               ║
    ║   Server active on http://localhost:${PORT}                     ║
    ║   Trust no one.                                               ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    `);
});
