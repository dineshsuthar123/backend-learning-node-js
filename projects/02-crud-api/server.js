/**
 * PROJECT 2: Enhanced CRUD API with Validation
 * 
 * Learning Objectives:
 * - Environment variables with dotenv
 * - Input validation
 * - Better error handling
 * - API documentation
 * - Modular code structure
 */

const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Custom middleware
const requestLogger = (req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip}`);
    next();
};

app.use(requestLogger);

// Data validation helpers
const validateUser = (userData) => {
    const errors = [];
    const { name, email, age, role } = userData;
    
    if (!name || name.trim().length < 2) {
        errors.push('Name is required and must be at least 2 characters');
    }
    
    if (!email || !isValidEmail(email)) {
        errors.push('Valid email is required');
    }
    
    if (age !== undefined && (age < 0 || age > 150)) {
        errors.push('Age must be between 0 and 150');
    }
    
    if (role && !['user', 'admin', 'moderator'].includes(role)) {
        errors.push('Role must be user, admin, or moderator');
    }
    
    return errors;
};

const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

// Enhanced data store with metadata
let users = [
    { 
        id: 1, 
        name: 'John Doe', 
        email: 'john@example.com', 
        age: 30, 
        role: 'user',
        createdAt: new Date('2024-01-01'),
        updatedAt: new Date('2024-01-01')
    },
    { 
        id: 2, 
        name: 'Jane Smith', 
        email: 'jane@example.com', 
        age: 25, 
        role: 'admin',
        createdAt: new Date('2024-01-02'),
        updatedAt: new Date('2024-01-02')
    },
    { 
        id: 3, 
        name: 'Bob Johnson', 
        email: 'bob@example.com', 
        age: 35, 
        role: 'moderator',
        createdAt: new Date('2024-01-03'),
        updatedAt: new Date('2024-01-03')
    }
];

let nextId = 4;

// API Documentation endpoint
app.get('/', (req, res) => {
    res.json({
        message: '📚 Enhanced CRUD API with Validation',
        version: '2.0.0',
        documentation: {
            endpoints: {
                'GET /': 'API documentation',
                'GET /api/users': 'Get all users with optional filtering',
                'GET /api/users/:id': 'Get user by ID',
                'POST /api/users': 'Create new user',
                'PUT /api/users/:id': 'Update user (full replacement)',
                'PATCH /api/users/:id': 'Update user (partial)',
                'DELETE /api/users/:id': 'Delete user',
                'GET /api/stats': 'Get user statistics'
            },
            queryParameters: {
                'role': 'Filter by role (user, admin, moderator)',
                'age_min': 'Filter by minimum age',
                'age_max': 'Filter by maximum age',
                'search': 'Search in name and email',
                'limit': 'Limit results (default: 10)',
                'offset': 'Offset for pagination (default: 0)',
                'sort': 'Sort by field (name, email, age, createdAt)',
                'order': 'Sort order (asc, desc)'
            }
        },
        examples: {
            createUser: {
                method: 'POST',
                url: '/api/users',
                body: {
                    name: 'Alice Brown',
                    email: 'alice@example.com',
                    age: 28,
                    role: 'user'
                }
            }
        }
    });
});

// GET all users with advanced filtering
app.get('/api/users', (req, res) => {
    try {
        let filteredUsers = [...users];
        const { role, age_min, age_max, search, limit = 10, offset = 0, sort = 'id', order = 'asc' } = req.query;
        
        // Apply filters
        if (role) {
            filteredUsers = filteredUsers.filter(user => user.role === role);
        }
        
        if (age_min) {
            filteredUsers = filteredUsers.filter(user => user.age >= parseInt(age_min));
        }
        
        if (age_max) {
            filteredUsers = filteredUsers.filter(user => user.age <= parseInt(age_max));
        }
        
        if (search) {
            const searchLower = search.toLowerCase();
            filteredUsers = filteredUsers.filter(user => 
                user.name.toLowerCase().includes(searchLower) || 
                user.email.toLowerCase().includes(searchLower)
            );
        }
        
        // Sort
        filteredUsers.sort((a, b) => {
            let aVal = a[sort];
            let bVal = b[sort];
            
            if (sort === 'createdAt' || sort === 'updatedAt') {
                aVal = new Date(aVal);
                bVal = new Date(bVal);
            }
            
            if (order === 'desc') {
                return bVal > aVal ? 1 : -1;
            }
            return aVal > bVal ? 1 : -1;
        });
        
        // Pagination
        const total = filteredUsers.length;
        const paginatedUsers = filteredUsers.slice(
            parseInt(offset), 
            parseInt(offset) + parseInt(limit)
        );
        
        res.json({
            success: true,
            data: paginatedUsers,
            pagination: {
                total,
                count: paginatedUsers.length,
                limit: parseInt(limit),
                offset: parseInt(offset),
                hasNext: parseInt(offset) + parseInt(limit) < total,
                hasPrev: parseInt(offset) > 0
            },
            filters: { role, age_min, age_max, search, sort, order }
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error',
            details: error.message
        });
    }
});

// GET single user by ID
app.get('/api/users/:id', (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        
        if (isNaN(userId)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid user ID format'
            });
        }
        
        const user = users.find(u => u.id === userId);
        
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        res.json({
            success: true,
            data: user
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// POST create new user
app.post('/api/users', (req, res) => {
    try {
        const { name, email, age, role = 'user' } = req.body;
        
        // Validation
        const validationErrors = validateUser({ name, email, age, role });
        if (validationErrors.length > 0) {
            return res.status(400).json({
                success: false,
                error: 'Validation failed',
                details: validationErrors
            });
        }
        
        // Check for duplicate email
        const existingUser = users.find(u => u.email.toLowerCase() === email.toLowerCase());
        if (existingUser) {
            return res.status(409).json({
                success: false,
                error: 'Email already exists'
            });
        }
        
        const newUser = {
            id: nextId++,
            name: name.trim(),
            email: email.toLowerCase(),
            age: age || null,
            role,
            createdAt: new Date(),
            updatedAt: new Date()
        };
        
        users.push(newUser);
        
        res.status(201).json({
            success: true,
            data: newUser,
            message: 'User created successfully'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// PUT update user (full replacement)
app.put('/api/users/:id', (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        const { name, email, age, role = 'user' } = req.body;
        
        // Validation
        const validationErrors = validateUser({ name, email, age, role });
        if (validationErrors.length > 0) {
            return res.status(400).json({
                success: false,
                error: 'Validation failed',
                details: validationErrors
            });
        }
        
        // Check for duplicate email (excluding current user)
        const existingUser = users.find(u => 
            u.email.toLowerCase() === email.toLowerCase() && u.id !== userId
        );
        if (existingUser) {
            return res.status(409).json({
                success: false,
                error: 'Email already exists'
            });
        }
        
        // Full replacement
        users[userIndex] = {
            ...users[userIndex],
            name: name.trim(),
            email: email.toLowerCase(),
            age: age || null,
            role,
            updatedAt: new Date()
        };
        
        res.json({
            success: true,
            data: users[userIndex],
            message: 'User updated successfully'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// PATCH update user (partial)
app.patch('/api/users/:id', (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        const updates = req.body;
        const allowedUpdates = ['name', 'email', 'age', 'role'];
        const actualUpdates = Object.keys(updates).filter(key => allowedUpdates.includes(key));
        
        if (actualUpdates.length === 0) {
            return res.status(400).json({
                success: false,
                error: 'No valid fields to update',
                allowedFields: allowedUpdates
            });
        }
        
        // Validation for provided fields only
        const validationErrors = validateUser(updates);
        if (validationErrors.length > 0) {
            return res.status(400).json({
                success: false,
                error: 'Validation failed',
                details: validationErrors
            });
        }
        
        // Check for duplicate email if email is being updated
        if (updates.email) {
            const existingUser = users.find(u => 
                u.email.toLowerCase() === updates.email.toLowerCase() && u.id !== userId
            );
            if (existingUser) {
                return res.status(409).json({
                    success: false,
                    error: 'Email already exists'
                });
            }
        }
        
        // Apply partial updates
        actualUpdates.forEach(key => {
            if (key === 'email' && updates[key]) {
                users[userIndex][key] = updates[key].toLowerCase();
            } else if (key === 'name' && updates[key]) {
                users[userIndex][key] = updates[key].trim();
            } else {
                users[userIndex][key] = updates[key];
            }
        });
        
        users[userIndex].updatedAt = new Date();
        
        res.json({
            success: true,
            data: users[userIndex],
            message: 'User updated successfully',
            updatedFields: actualUpdates
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// DELETE user
app.delete('/api/users/:id', (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        const deletedUser = users.splice(userIndex, 1)[0];
        
        res.json({
            success: true,
            data: deletedUser,
            message: 'User deleted successfully'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// GET user statistics
app.get('/api/stats', (req, res) => {
    try {
        const stats = {
            totalUsers: users.length,
            usersByRole: {
                user: users.filter(u => u.role === 'user').length,
                admin: users.filter(u => u.role === 'admin').length,
                moderator: users.filter(u => u.role === 'moderator').length
            },
            averageAge: users.length > 0 ? 
                Math.round(users.reduce((sum, u) => sum + (u.age || 0), 0) / users.length) : 0,
            ageDistribution: {
                '0-18': users.filter(u => u.age >= 0 && u.age <= 18).length,
                '19-30': users.filter(u => u.age >= 19 && u.age <= 30).length,
                '31-50': users.filter(u => u.age >= 31 && u.age <= 50).length,
                '51+': users.filter(u => u.age >= 51).length
            },
            recentActivity: {
                usersCreatedToday: users.filter(u => 
                    new Date(u.createdAt).toDateString() === new Date().toDateString()
                ).length,
                usersUpdatedToday: users.filter(u => 
                    new Date(u.updatedAt).toDateString() === new Date().toDateString()
                ).length
            }
        };
        
        res.json({
            success: true,
            data: stats
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Route not found',
        availableRoutes: [
            'GET /',
            'GET /api/users',
            'GET /api/users/:id',
            'POST /api/users',
            'PUT /api/users/:id',
            'PATCH /api/users/:id',
            'DELETE /api/users/:id',
            'GET /api/stats',
            'GET /api/health'
        ]
    });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('Global Error Handler:', error.stack);
    
    // Handle specific error types
    if (error.type === 'entity.parse.failed') {
        return res.status(400).json({
            success: false,
            error: 'Invalid JSON format'
        });
    }
    
    res.status(500).json({
        success: false,
        error: 'Something went wrong!',
        message: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
});

// Start server
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`🚀 Enhanced CRUD API Server running on port ${PORT}`);
        console.log(`📖 API Documentation: http://localhost:${PORT}`);
        console.log(`🔍 Health Check: http://localhost:${PORT}/api/health`);
        console.log(`📊 Statistics: http://localhost:${PORT}/api/stats`);
    });
}

module.exports = app;
