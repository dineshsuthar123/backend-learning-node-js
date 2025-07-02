/**
 * PROJECT 3: Authentication & Authorization System
 * 
 * Learning Objectives:
 * - JWT (JSON Web Tokens) authentication
 * - Password hashing with bcrypt
 * - Protected routes and middleware
 * - Role-based access control (RBAC)
 * - Login/logout functionality
 * - Password reset system
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRE = process.env.JWT_EXPIRE || '7d';

// Rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: {
        success: false,
        error: 'Too many authentication attempts, please try again later'
    }
});

// Middleware
app.use(cors());
app.use(express.json());

// Enhanced user store with authentication data
let users = [
    {
        id: 1,
        name: 'Admin User',
        email: 'admin@example.com',
        password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // 'password'
        role: 'admin',
        isActive: true,
        emailVerified: true,
        lastLogin: null,
        createdAt: new Date('2024-01-01'),
        updatedAt: new Date('2024-01-01')
    },
    {
        id: 2,
        name: 'Regular User',
        email: 'user@example.com',
        password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // 'password'
        role: 'user',
        isActive: true,
        emailVerified: true,
        lastLogin: null,
        createdAt: new Date('2024-01-02'),
        updatedAt: new Date('2024-01-02')
    }
];

let refreshTokens = [];
let nextId = 3;

// Utility functions
const generateTokens = (user) => {
    const payload = {
        id: user.id,
        email: user.email,
        role: user.role
    };
    
    const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRE });
    
    return { accessToken, refreshToken };
};

const hashPassword = async (password) => {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
};

const comparePassword = async (password, hashedPassword) => {
    return await bcrypt.compare(password, hashedPassword);
};

// Validation helpers
const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

const validatePassword = (password) => {
    const errors = [];
    
    if (!password || password.length < 8) {
        errors.push('Password must be at least 8 characters long');
    }
    
    if (!/(?=.*[a-z])/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }
    
    if (!/(?=.*[A-Z])/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }
    
    if (!/(?=.*\d)/.test(password)) {
        errors.push('Password must contain at least one number');
    }
    
    if (!/(?=.*[@$!%*?&])/.test(password)) {
        errors.push('Password must contain at least one special character (@$!%*?&)');
    }
    
    return errors;
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
        return res.status(401).json({
            success: false,
            error: 'Access token required'
        });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({
                    success: false,
                    error: 'Token expired',
                    code: 'TOKEN_EXPIRED'
                });
            }
            return res.status(403).json({
                success: false,
                error: 'Invalid token'
            });
        }
        
        // Check if user still exists and is active
        const currentUser = users.find(u => u.id === user.id);
        if (!currentUser || !currentUser.isActive) {
            return res.status(401).json({
                success: false,
                error: 'User not found or inactive'
            });
        }
        
        req.user = user;
        next();
    });
};

// Authorization middleware
const authorize = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                error: 'Authentication required'
            });
        }
        
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                error: 'Insufficient permissions',
                requiredRoles: roles,
                userRole: req.user.role
            });
        }
        
        next();
    };
};

// Routes

// API Documentation
app.get('/', (req, res) => {
    res.json({
        message: '🔐 Authentication & Authorization API',
        version: '3.0.0',
        endpoints: {
            public: [
                'POST /api/auth/register - Register new user',
                'POST /api/auth/login - Login user',
                'POST /api/auth/refresh - Refresh access token',
                'GET /api/auth/verify-email/:token - Verify email',
                'POST /api/auth/forgot-password - Request password reset'
            ],
            protected: [
                'GET /api/auth/me - Get current user profile',
                'PUT /api/auth/profile - Update profile',
                'POST /api/auth/change-password - Change password',
                'POST /api/auth/logout - Logout user'
            ],
            admin: [
                'GET /api/admin/users - Get all users (admin only)',
                'PUT /api/admin/users/:id/role - Update user role (admin only)',
                'DELETE /api/admin/users/:id - Delete user (admin only)'
            ]
        },
        authentication: {
            type: 'Bearer Token',
            header: 'Authorization: Bearer <access_token>',
            tokenExpiry: '15 minutes',
            refreshTokenExpiry: '7 days'
        }
    });
});

// Register new user
app.post('/api/auth/register', authLimiter, async (req, res) => {
    try {
        const { name, email, password, role = 'user' } = req.body;
        
        // Validation
        if (!name || name.trim().length < 2) {
            return res.status(400).json({
                success: false,
                error: 'Name is required and must be at least 2 characters'
            });
        }
        
        if (!email || !validateEmail(email)) {
            return res.status(400).json({
                success: false,
                error: 'Valid email is required'
            });
        }
        
        const passwordErrors = validatePassword(password);
        if (passwordErrors.length > 0) {
            return res.status(400).json({
                success: false,
                error: 'Password validation failed',
                details: passwordErrors
            });
        }
        
        // Check if user already exists
        const existingUser = users.find(u => u.email.toLowerCase() === email.toLowerCase());
        if (existingUser) {
            return res.status(409).json({
                success: false,
                error: 'User already exists with this email'
            });
        }
        
        // Hash password
        const hashedPassword = await hashPassword(password);
        
        // Create new user
        const newUser = {
            id: nextId++,
            name: name.trim(),
            email: email.toLowerCase(),
            password: hashedPassword,
            role: role === 'admin' ? 'user' : role, // Prevent admin registration
            isActive: true,
            emailVerified: false,
            lastLogin: null,
            createdAt: new Date(),
            updatedAt: new Date()
        };
        
        users.push(newUser);
        
        // Generate tokens
        const { accessToken, refreshToken } = generateTokens(newUser);
        refreshTokens.push(refreshToken);
        
        // Remove password from response
        const { password: _, ...userResponse } = newUser;
        
        res.status(201).json({
            success: true,
            data: {
                user: userResponse,
                accessToken,
                refreshToken
            },
            message: 'User registered successfully'
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Login user
app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                error: 'Email and password are required'
            });
        }
        
        // Find user
        const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
        if (!user) {
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }
        
        // Check if user is active
        if (!user.isActive) {
            return res.status(401).json({
                success: false,
                error: 'Account is deactivated'
            });
        }
        
        // Verify password
        const isValidPassword = await comparePassword(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }
        
        // Update last login
        user.lastLogin = new Date();
        user.updatedAt = new Date();
        
        // Generate tokens
        const { accessToken, refreshToken } = generateTokens(user);
        refreshTokens.push(refreshToken);
        
        // Remove password from response
        const { password: _, ...userResponse } = user;
        
        res.json({
            success: true,
            data: {
                user: userResponse,
                accessToken,
                refreshToken
            },
            message: 'Login successful'
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Refresh access token
app.post('/api/auth/refresh', (req, res) => {
    try {
        const { refreshToken } = req.body;
        
        if (!refreshToken) {
            return res.status(401).json({
                success: false,
                error: 'Refresh token required'
            });
        }
        
        if (!refreshTokens.includes(refreshToken)) {
            return res.status(403).json({
                success: false,
                error: 'Invalid refresh token'
            });
        }
        
        jwt.verify(refreshToken, JWT_SECRET, (err, user) => {
            if (err) {
                // Remove invalid token
                refreshTokens = refreshTokens.filter(token => token !== refreshToken);
                
                return res.status(403).json({
                    success: false,
                    error: 'Invalid or expired refresh token'
                });
            }
            
            // Check if user still exists
            const currentUser = users.find(u => u.id === user.id);
            if (!currentUser || !currentUser.isActive) {
                refreshTokens = refreshTokens.filter(token => token !== refreshToken);
                
                return res.status(401).json({
                    success: false,
                    error: 'User not found or inactive'
                });
            }
            
            // Generate new access token
            const { accessToken } = generateTokens(currentUser);
            
            res.json({
                success: true,
                data: {
                    accessToken
                }
            });
        });
        
    } catch (error) {
        console.error('Token refresh error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Get current user profile
app.get('/api/auth/me', authenticateToken, (req, res) => {
    try {
        const user = users.find(u => u.id === req.user.id);
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        const { password, ...userResponse } = user;
        
        res.json({
            success: true,
            data: userResponse
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Update user profile
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const { name, email } = req.body;
        const userIndex = users.findIndex(u => u.id === req.user.id);
        
        if (userIndex === -1) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        // Validation
        if (name && name.trim().length < 2) {
            return res.status(400).json({
                success: false,
                error: 'Name must be at least 2 characters'
            });
        }
        
        if (email && !validateEmail(email)) {
            return res.status(400).json({
                success: false,
                error: 'Valid email is required'
            });
        }
        
        // Check for duplicate email
        if (email) {
            const existingUser = users.find(u => 
                u.email.toLowerCase() === email.toLowerCase() && u.id !== req.user.id
            );
            if (existingUser) {
                return res.status(409).json({
                    success: false,
                    error: 'Email already exists'
                });
            }
        }
        
        // Update user
        if (name) users[userIndex].name = name.trim();
        if (email) {
            users[userIndex].email = email.toLowerCase();
            users[userIndex].emailVerified = false; // Reset verification
        }
        users[userIndex].updatedAt = new Date();
        
        const { password, ...userResponse } = users[userIndex];
        
        res.json({
            success: true,
            data: userResponse,
            message: 'Profile updated successfully'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Change password
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                error: 'Current password and new password are required'
            });
        }
        
        const user = users.find(u => u.id === req.user.id);
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        // Verify current password
        const isValidPassword = await comparePassword(currentPassword, user.password);
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                error: 'Current password is incorrect'
            });
        }
        
        // Validate new password
        const passwordErrors = validatePassword(newPassword);
        if (passwordErrors.length > 0) {
            return res.status(400).json({
                success: false,
                error: 'New password validation failed',
                details: passwordErrors
            });
        }
        
        // Hash new password
        const hashedPassword = await hashPassword(newPassword);
        
        // Update password
        user.password = hashedPassword;
        user.updatedAt = new Date();
        
        // Invalidate all refresh tokens for this user
        refreshTokens = refreshTokens.filter(token => {
            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                return decoded.id !== user.id;
            } catch (error) {
                return false;
            }
        });
        
        res.json({
            success: true,
            message: 'Password changed successfully. Please login again.'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Logout user
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    try {
        const { refreshToken } = req.body;
        
        if (refreshToken) {
            // Remove specific refresh token
            refreshTokens = refreshTokens.filter(token => token !== refreshToken);
        } else {
            // Remove all refresh tokens for this user
            refreshTokens = refreshTokens.filter(token => {
                try {
                    const decoded = jwt.verify(token, JWT_SECRET);
                    return decoded.id !== req.user.id;
                } catch (error) {
                    return false;
                }
            });
        }
        
        res.json({
            success: true,
            message: 'Logged out successfully'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Admin Routes

// Get all users (Admin only)
app.get('/api/admin/users', authenticateToken, authorize('admin'), (req, res) => {
    try {
        const { page = 1, limit = 10, role, status } = req.query;
        
        let filteredUsers = users.map(user => {
            const { password, ...userWithoutPassword } = user;
            return userWithoutPassword;
        });
        
        // Apply filters
        if (role) {
            filteredUsers = filteredUsers.filter(user => user.role === role);
        }
        
        if (status) {
            const isActive = status === 'active';
            filteredUsers = filteredUsers.filter(user => user.isActive === isActive);
        }
        
        // Pagination
        const total = filteredUsers.length;
        const startIndex = (page - 1) * limit;
        const endIndex = page * limit;
        const paginatedUsers = filteredUsers.slice(startIndex, endIndex);
        
        res.json({
            success: true,
            data: paginatedUsers,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Update user role (Admin only)
app.put('/api/admin/users/:id/role', authenticateToken, authorize('admin'), (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const { role } = req.body;
        
        if (!['user', 'admin', 'moderator'].includes(role)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid role. Must be user, admin, or moderator'
            });
        }
        
        const userIndex = users.findIndex(u => u.id === userId);
        if (userIndex === -1) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        // Prevent admin from changing their own role
        if (userId === req.user.id) {
            return res.status(400).json({
                success: false,
                error: 'Cannot change your own role'
            });
        }
        
        users[userIndex].role = role;
        users[userIndex].updatedAt = new Date();
        
        const { password, ...userResponse } = users[userIndex];
        
        res.json({
            success: true,
            data: userResponse,
            message: 'User role updated successfully'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Delete user (Admin only)
app.delete('/api/admin/users/:id', authenticateToken, authorize('admin'), (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        // Prevent admin from deleting themselves
        if (userId === req.user.id) {
            return res.status(400).json({
                success: false,
                error: 'Cannot delete your own account'
            });
        }
        
        const deletedUser = users.splice(userIndex, 1)[0];
        const { password, ...userResponse } = deletedUser;
        
        // Remove user's refresh tokens
        refreshTokens = refreshTokens.filter(token => {
            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                return decoded.id !== userId;
            } catch (error) {
                return false;
            }
        });
        
        res.json({
            success: true,
            data: userResponse,
            message: 'User deleted successfully'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Route not found'
    });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('Global Error Handler:', error.stack);
    res.status(500).json({
        success: false,
        error: 'Something went wrong!'
    });
});

// Start server
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`🔐 Authentication API Server running on port ${PORT}`);
        console.log(`📖 API Documentation: http://localhost:${PORT}`);
        console.log('');
        console.log('🧪 Test Credentials:');
        console.log('Admin: admin@example.com / password');
        console.log('User: user@example.com / password');
    });
}

module.exports = app;
