const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'login_system',
    port: process.env.DB_PORT || 3306
});

// Connect to database
db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
        // For demo purposes, we'll continue without database
        console.log('Running in demo mode (no database)');
    } else {
        console.log('Connected to MySQL database');
        createTables();
    }
});

// Create users table if it doesn't exist
function createTables() {
    const createTableQuery = `
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            name VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP NULL
        )
    `;
    
    db.query(createTableQuery, (err) => {
        if (err) {
            console.error('Error creating table:', err);
        } else {
            console.log('Users table ready');
            // Insert a demo user if table is empty
            insertDemoUser();
        }
    });
}

// Insert a demo user for testing
function insertDemoUser() {
    const checkUserQuery = 'SELECT COUNT(*) as count FROM users';
    db.query(checkUserQuery, (err, results) => {
        if (err) return;
        
        if (results[0].count === 0) {
            const hashedPassword = bcrypt.hashSync('password123', 10);
            const insertQuery = 'INSERT INTO users (email, password, name) VALUES (?, ?, ?)';
            db.query(insertQuery, ['demo@example.com', hashedPassword, 'Demo User'], (err) => {
                if (err) {
                    console.error('Error inserting demo user:', err);
                } else {
                    console.log('Demo user created: demo@example.com / password123');
                }
            });
        }
    });
}

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Routes

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        message: 'Login API is running',
        timestamp: new Date().toISOString()
    });
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password, remember } = req.body;
        
        // Input validation
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email and password are required' 
            });
        }
        
        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid email format' 
            });
        }
        
        // Check if database is connected
        if (db.state === 'disconnected') {
            // Demo mode - simulate login without database
            return handleDemoLogin(email, password, remember, res);
        }
        
        // Find user in database
        const query = 'SELECT * FROM users WHERE email = ?';
        db.query(query, [email], async (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Database error' 
                });
            }
            
            if (results.length === 0) {
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid email or password' 
                });
            }
            
            const user = results[0];
            
            // Verify password
            const isPasswordValid = await bcrypt.compare(password, user.password);
            
            if (!isPasswordValid) {
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid email or password' 
                });
            }
            
            // Update last login
            const updateQuery = 'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?';
            db.query(updateQuery, [user.id]);
            
            // Create JWT token
            const token = jwt.sign(
                { 
                    userId: user.id, 
                    email: user.email,
                    name: user.name 
                },
                JWT_SECRET,
                { expiresIn: remember ? '7d' : '1d' }
            );
            
            // Return success response
            res.json({
                success: true,
                message: 'Login successful',
                token: token,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name
                },
                redirectUrl: '/dashboard.html'
            });
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Demo login handler (when database is not connected)
function handleDemoLogin(email, password, remember, res) {
    // Demo credentials
    const demoEmail = 'demo@example.com';
    const demoPassword = 'password123';
    
    if (email === demoEmail && password === demoPassword) {
        // Create a mock token
        const mockToken = jwt.sign(
            { 
                userId: 1, 
                email: demoEmail,
                name: 'Demo User',
                demo: true 
            },
            JWT_SECRET,
            { expiresIn: remember ? '7d' : '1d' }
        );
        
        return res.json({
            success: true,
            message: 'Login successful (demo mode)',
            token: mockToken,
            user: {
                id: 1,
                email: demoEmail,
                name: 'Demo User'
            },
            redirectUrl: '/dashboard.html',
            demo: true
        });
    } else {
        return res.status(401).json({ 
            success: false, 
            message: 'Invalid email or password' 
        });
    }
}

// Registration endpoint
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        
        // Input validation
        if (!email || !password || !name) {
            return res.status(400).json({ 
                success: false, 
                message: 'All fields are required' 
            });
        }
        
        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid email format' 
            });
        }
        
        // Password validation
        if (password.length < 6) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password must be at least 6 characters' 
            });
        }
        
        // Check if database is connected
        if (db.state === 'disconnected') {
            return res.status(503).json({ 
                success: false, 
                message: 'Registration unavailable in demo mode' 
            });
        }
        
        // Check if user already exists
        const checkQuery = 'SELECT id FROM users WHERE email = ?';
        db.query(checkQuery, [email], async (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Database error' 
                });
            }
            
            if (results.length > 0) {
                return res.status(409).json({ 
                    success: false, 
                    message: 'Email already registered' 
                });
            }
            
            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);
            
            // Insert new user
            const insertQuery = 'INSERT INTO users (email, password, name) VALUES (?, ?, ?)';
            db.query(insertQuery, [email, hashedPassword, name], (err, result) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'Registration failed' 
                    });
                }
                
                // Create JWT token
                const token = jwt.sign(
                    { 
                        userId: result.insertId, 
                        email: email,
                        name: name 
                    },
                    JWT_SECRET,
                    { expiresIn: '1d' }
                );
                
                res.status(201).json({
                    success: true,
                    message: 'Registration successful',
                    token: token,
                    user: {
                        id: result.insertId,
                        email: email,
                        name: name
                    }
                });
            });
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Protected route example
app.get('/api/profile', authenticateToken, (req, res) => {
    res.json({
        success: true,
        user: req.user
    });
});

// Token authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'Access token required' 
        });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                message: 'Invalid or expired token' 
            });
        }
        req.user = user;
        next();
    });
}

// Forgot password endpoint
app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ 
            success: false, 
            message: 'Email is required' 
        });
    }
    
    // In a real application, you would:
    // 1. Check if email exists in database
    // 2. Generate a password reset token
    // 3. Send reset email with link
    // 4. Store token in database with expiration
    
    res.json({
        success: true,
        message: 'If this email exists in our system, you will receive a password reset link',
        demoNote: 'This is a demo endpoint. In production, an email would be sent.'
    });
});

// Serve static files (for frontend)
app.use(express.static('public'));

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Frontend: http://localhost:${PORT}/login.html`);
    console.log(`API Health: http://localhost:${PORT}/api/health`);
});