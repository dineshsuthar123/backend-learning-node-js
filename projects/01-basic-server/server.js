/**
 * PROJECT 1: Basic Express Server
 * 
 * Learning Objectives:
 * - Set up Express.js server
 * - Create basic routes (GET, POST, PUT, DELETE)
 * - Use middleware
 * - Handle JSON requests/responses
 * - Basic error handling
 */

const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json()); // Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies

// Custom middleware example
const logger = (req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
};

app.use(logger);

// Root route
app.get('/', (req, res) => {
    res.json({
        message: '🚀 Welcome to Backend Development Course!',
        project: 'Basic Express Server',
        endpoints: [
            'GET /',
            'GET /api/users',
            'POST /api/users',
            'PUT /api/users/:id',
            'DELETE /api/users/:id'
        ]
    });
});

// In-memory data store (for learning purposes)
let users = [
    { id: 1, name: 'John Doe', email: 'john@example.com', age: 30 },
    { id: 2, name: 'Jane Smith', email: 'jane@example.com', age: 25 },
    { id: 3, name: 'Bob Johnson', email: 'bob@example.com', age: 35 }
];

// GET all users
app.get('/api/users', (req, res) => {
    res.json({
        success: true,
        count: users.length,
        data: users
    });
});

// GET single user by ID
app.get('/api/users/:id', (req, res) => {
    const userId = parseInt(req.params.id);
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
});

// POST create new user
app.post('/api/users', (req, res) => {
    const { name, email, age } = req.body;
    
    // Basic validation
    if (!name || !email) {
        return res.status(400).json({
            success: false,
            error: 'Name and email are required'
        });
    }
    
    const newUser = {
        id: users.length + 1,
        name,
        email,
        age: age || null
    };
    
    users.push(newUser);
    
    res.status(201).json({
        success: true,
        data: newUser
    });
});

// PUT update user
app.put('/api/users/:id', (req, res) => {
    const userId = parseInt(req.params.id);
    const userIndex = users.findIndex(u => u.id === userId);
    
    if (userIndex === -1) {
        return res.status(404).json({
            success: false,
            error: 'User not found'
        });
    }
    
    const { name, email, age } = req.body;
    
    // Update user
    users[userIndex] = {
        ...users[userIndex],
        name: name || users[userIndex].name,
        email: email || users[userIndex].email,
        age: age !== undefined ? age : users[userIndex].age
    };
    
    res.json({
        success: true,
        data: users[userIndex]
    });
});

// DELETE user
app.delete('/api/users/:id', (req, res) => {
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
    console.error(error.stack);
    res.status(500).json({
        success: false,
        error: 'Something went wrong!'
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📖 Visit http://localhost:${PORT} to get started`);
});

module.exports = app;
