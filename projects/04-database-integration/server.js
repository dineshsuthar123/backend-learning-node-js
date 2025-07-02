/**
 * PROJECT 4: Database Integration with MongoDB
 * 
 * Learning Objectives:
 * - MongoDB connection and configuration
 * - Mongoose ODM (Object Document Mapping)
 * - Schema design and validation
 * - Database operations (CRUD)
 * - Relationships and population
 * - Indexes and performance optimization
 */

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/backend_course';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Database connection
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true,
        minlength: [2, 'Name must be at least 2 characters'],
        maxlength: [50, 'Name cannot exceed 50 characters']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please enter a valid email']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [8, 'Password must be at least 8 characters'],
        select: false // Don't include password in queries by default
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'moderator'],
        default: 'user'
    },
    profile: {
        avatar: String,
        bio: {
            type: String,
            maxlength: [500, 'Bio cannot exceed 500 characters']
        },
        dateOfBirth: Date,
        phone: String,
        location: {
            city: String,
            country: String,
            coordinates: {
                lat: Number,
                lng: Number
            }
        }
    },
    preferences: {
        newsletter: { type: Boolean, default: true },
        notifications: { type: Boolean, default: true },
        theme: { type: String, enum: ['light', 'dark'], default: 'light' }
    },
    isActive: {
        type: Boolean,
        default: true
    },
    emailVerified: {
        type: Boolean,
        default: false
    },
    lastLogin: Date,
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: Date
}, {
    timestamps: true, // Adds createdAt and updatedAt
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Virtual for full name
userSchema.virtual('fullName').get(function() {
    return this.name;
});

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
    return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
    // Only hash the password if it has been modified (or is new)
    if (!this.isModified('password')) return next();
    
    try {
        // Hash password with cost of 12
        const hashedPassword = await bcrypt.hash(this.password, 12);
        this.password = hashedPassword;
        next();
    } catch (error) {
        next(error);
    }
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        return await bcrypt.compare(candidatePassword, this.password);
    } catch (error) {
        throw error;
    }
};

// Method to generate JWT token
userSchema.methods.generateAuthToken = function() {
    const payload = {
        id: this._id,
        email: this.email,
        role: this.role
    };
    
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
};

// Static method to find by email
userSchema.statics.findByEmail = function(email) {
    return this.findOne({ email: email.toLowerCase() });
};

// Index for better performance
userSchema.index({ email: 1 });
userSchema.index({ role: 1 });
userSchema.index({ createdAt: -1 });

const User = mongoose.model('User', userSchema);

// Post Schema
const postSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Title is required'],
        trim: true,
        maxlength: [200, 'Title cannot exceed 200 characters']
    },
    content: {
        type: String,
        required: [true, 'Content is required'],
        maxlength: [10000, 'Content cannot exceed 10000 characters']
    },
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    tags: [{
        type: String,
        trim: true,
        lowercase: true
    }],
    category: {
        type: String,
        required: true,
        enum: ['technology', 'health', 'travel', 'food', 'lifestyle', 'business', 'education']
    },
    status: {
        type: String,
        enum: ['draft', 'published', 'archived'],
        default: 'draft'
    },
    featured: {
        type: Boolean,
        default: false
    },
    viewCount: {
        type: Number,
        default: 0
    },
    likes: [{
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        createdAt: {
            type: Date,
            default: Date.now
        }
    }],
    comments: [{
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        content: {
            type: String,
            required: true,
            maxlength: [1000, 'Comment cannot exceed 1000 characters']
        },
        createdAt: {
            type: Date,
            default: Date.now
        }
    }],
    publishedAt: Date
}, {
    timestamps: true
});

// Virtual for like count
postSchema.virtual('likeCount').get(function() {
    return this.likes.length;
});

// Virtual for comment count
postSchema.virtual('commentCount').get(function() {
    return this.comments.length;
});

// Pre-save middleware to set publishedAt
postSchema.pre('save', function(next) {
    if (this.isModified('status') && this.status === 'published' && !this.publishedAt) {
        this.publishedAt = new Date();
    }
    next();
});

// Indexes for better performance
postSchema.index({ author: 1, createdAt: -1 });
postSchema.index({ status: 1, publishedAt: -1 });
postSchema.index({ tags: 1 });
postSchema.index({ category: 1 });
postSchema.index({ title: 'text', content: 'text' }); // Text search

const Post = mongoose.model('Post', postSchema);

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({
                success: false,
                error: 'Access token required'
            });
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);
        
        if (!user || !user.isActive) {
            return res.status(401).json({
                success: false,
                error: 'User not found or inactive'
            });
        }
        
        req.user = user;
        next();
        
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                error: 'Token expired'
            });
        }
        
        return res.status(403).json({
            success: false,
            error: 'Invalid token'
        });
    }
};

// Authorization middleware
const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                error: 'Insufficient permissions'
            });
        }
        next();
    };
};

// Routes

// API Documentation
app.get('/', (req, res) => {
    res.json({
        message: '🗄️  Database Integration API with MongoDB',
        version: '4.0.0',
        database: 'MongoDB with Mongoose ODM',
        features: [
            'User authentication with MongoDB',
            'Blog post management',
            'Advanced querying and filtering',
            'Data relationships and population',
            'Full-text search',
            'Aggregation pipelines'
        ],
        endpoints: {
            auth: [
                'POST /api/auth/register',
                'POST /api/auth/login',
                'GET /api/auth/me',
                'PUT /api/auth/profile'
            ],
            posts: [
                'GET /api/posts',
                'GET /api/posts/:id',
                'POST /api/posts',
                'PUT /api/posts/:id',
                'DELETE /api/posts/:id',
                'POST /api/posts/:id/like',
                'POST /api/posts/:id/comment'
            ]
        }
    });
});

// Auth Routes

// Register user
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, role = 'user' } = req.body;
        
        // Check if user already exists
        const existingUser = await User.findByEmail(email);
        if (existingUser) {
            return res.status(409).json({
                success: false,
                error: 'User already exists with this email'
            });
        }
        
        // Create new user
        const user = new User({
            name,
            email,
            password,
            role: role === 'admin' ? 'user' : role // Prevent admin registration
        });
        
        await user.save();
        
        // Generate token
        const token = user.generateAuthToken();
        
        // Remove password from response
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.status(201).json({
            success: true,
            data: {
                user: userResponse,
                token
            },
            message: 'User registered successfully'
        });
        
    } catch (error) {
        // Handle validation errors
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                error: 'Validation failed',
                details: errors
            });
        }
        
        // Handle duplicate key error
        if (error.code === 11000) {
            return res.status(409).json({
                success: false,
                error: 'Email already exists'
            });
        }
        
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Login user
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                error: 'Email and password are required'
            });
        }
        
        // Find user and include password for comparison
        const user = await User.findByEmail(email).select('+password');
        if (!user) {
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }
        
        // Check if account is locked
        if (user.isLocked) {
            return res.status(423).json({
                success: false,
                error: 'Account is temporarily locked due to too many failed login attempts'
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
        const isValidPassword = await user.comparePassword(password);
        if (!isValidPassword) {
            // Increment login attempts
            user.loginAttempts += 1;
            
            // Lock account after 5 failed attempts
            if (user.loginAttempts >= 5) {
                user.lockUntil = Date.now() + 30 * 60 * 1000; // 30 minutes
            }
            
            await user.save();
            
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }
        
        // Reset login attempts on successful login
        user.loginAttempts = 0;
        user.lockUntil = undefined;
        user.lastLogin = new Date();
        await user.save();
        
        // Generate token
        const token = user.generateAuthToken();
        
        // Remove password from response
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.json({
            success: true,
            data: {
                user: userResponse,
                token
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

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        
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

// Update user profile
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const allowedUpdates = ['name', 'profile', 'preferences'];
        const updates = {};
        
        // Filter allowed updates
        Object.keys(req.body).forEach(key => {
            if (allowedUpdates.includes(key)) {
                updates[key] = req.body[key];
            }
        });
        
        if (Object.keys(updates).length === 0) {
            return res.status(400).json({
                success: false,
                error: 'No valid fields to update'
            });
        }
        
        const user = await User.findByIdAndUpdate(
            req.user._id,
            updates,
            { new: true, runValidators: true }
        );
        
        res.json({
            success: true,
            data: user,
            message: 'Profile updated successfully'
        });
        
    } catch (error) {
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                error: 'Validation failed',
                details: errors
            });
        }
        
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Post Routes

// Get all posts with advanced filtering
app.get('/api/posts', async (req, res) => {
    try {
        const {
            page = 1,
            limit = 10,
            status = 'published',
            category,
            author,
            tags,
            search,
            sort = '-publishedAt',
            featured
        } = req.query;
        
        // Build query
        const query = {};
        
        if (status) query.status = status;
        if (category) query.category = category;
        if (author) query.author = author;
        if (featured !== undefined) query.featured = featured === 'true';
        if (tags) {
            const tagArray = tags.split(',').map(tag => tag.trim());
            query.tags = { $in: tagArray };
        }
        if (search) {
            query.$text = { $search: search };
        }
        
        // Execute query with pagination
        const posts = await Post.find(query)
            .populate('author', 'name email profile.avatar')
            .populate('comments.user', 'name profile.avatar')
            .sort(sort)
            .limit(parseInt(limit))
            .skip((parseInt(page) - 1) * parseInt(limit));
        
        // Get total count for pagination
        const total = await Post.countDocuments(query);
        
        res.json({
            success: true,
            data: posts,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / parseInt(limit))
            }
        });
        
    } catch (error) {
        console.error('Get posts error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Get single post
app.get('/api/posts/:id', async (req, res) => {
    try {
        const post = await Post.findById(req.params.id)
            .populate('author', 'name email profile.avatar profile.bio')
            .populate('comments.user', 'name profile.avatar');
        
        if (!post) {
            return res.status(404).json({
                success: false,
                error: 'Post not found'
            });
        }
        
        // Increment view count
        post.viewCount += 1;
        await post.save();
        
        res.json({
            success: true,
            data: post
        });
        
    } catch (error) {
        if (error.name === 'CastError') {
            return res.status(400).json({
                success: false,
                error: 'Invalid post ID'
            });
        }
        
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Create new post
app.post('/api/posts', authenticateToken, async (req, res) => {
    try {
        const postData = {
            ...req.body,
            author: req.user._id
        };
        
        const post = new Post(postData);
        await post.save();
        
        // Populate author information
        await post.populate('author', 'name email profile.avatar');
        
        res.status(201).json({
            success: true,
            data: post,
            message: 'Post created successfully'
        });
        
    } catch (error) {
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                error: 'Validation failed',
                details: errors
            });
        }
        
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Update post
app.put('/api/posts/:id', authenticateToken, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        
        if (!post) {
            return res.status(404).json({
                success: false,
                error: 'Post not found'
            });
        }
        
        // Check ownership or admin role
        if (post.author.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'Not authorized to update this post'
            });
        }
        
        // Update post
        const allowedUpdates = ['title', 'content', 'tags', 'category', 'status', 'featured'];
        const updates = {};
        
        Object.keys(req.body).forEach(key => {
            if (allowedUpdates.includes(key)) {
                updates[key] = req.body[key];
            }
        });
        
        const updatedPost = await Post.findByIdAndUpdate(
            req.params.id,
            updates,
            { new: true, runValidators: true }
        ).populate('author', 'name email profile.avatar');
        
        res.json({
            success: true,
            data: updatedPost,
            message: 'Post updated successfully'
        });
        
    } catch (error) {
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                error: 'Validation failed',
                details: errors
            });
        }
        
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Delete post
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        
        if (!post) {
            return res.status(404).json({
                success: false,
                error: 'Post not found'
            });
        }
        
        // Check ownership or admin role
        if (post.author.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'Not authorized to delete this post'
            });
        }
        
        await Post.findByIdAndDelete(req.params.id);
        
        res.json({
            success: true,
            message: 'Post deleted successfully'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Like/unlike post
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        
        if (!post) {
            return res.status(404).json({
                success: false,
                error: 'Post not found'
            });
        }
        
        // Check if user already liked the post
        const existingLike = post.likes.find(like => 
            like.user.toString() === req.user._id.toString()
        );
        
        if (existingLike) {
            // Unlike post
            post.likes = post.likes.filter(like => 
                like.user.toString() !== req.user._id.toString()
            );
            await post.save();
            
            res.json({
                success: true,
                message: 'Post unliked successfully',
                likeCount: post.likeCount
            });
        } else {
            // Like post
            post.likes.push({ user: req.user._id });
            await post.save();
            
            res.json({
                success: true,
                message: 'Post liked successfully',
                likeCount: post.likeCount
            });
        }
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Add comment to post
app.post('/api/posts/:id/comment', authenticateToken, async (req, res) => {
    try {
        const { content } = req.body;
        
        if (!content || content.trim().length === 0) {
            return res.status(400).json({
                success: false,
                error: 'Comment content is required'
            });
        }
        
        const post = await Post.findById(req.params.id);
        
        if (!post) {
            return res.status(404).json({
                success: false,
                error: 'Post not found'
            });
        }
        
        const comment = {
            user: req.user._id,
            content: content.trim()
        };
        
        post.comments.push(comment);
        await post.save();
        
        // Populate the new comment
        await post.populate('comments.user', 'name profile.avatar');
        
        // Get the newly added comment
        const newComment = post.comments[post.comments.length - 1];
        
        res.status(201).json({
            success: true,
            data: newComment,
            message: 'Comment added successfully'
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Analytics endpoint
app.get('/api/analytics', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        // User statistics
        const userStats = await User.aggregate([
            {
                $group: {
                    _id: null,
                    totalUsers: { $sum: 1 },
                    activeUsers: {
                        $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] }
                    },
                    verifiedUsers: {
                        $sum: { $cond: [{ $eq: ['$emailVerified', true] }, 1, 0] }
                    }
                }
            }
        ]);
        
        // Post statistics
        const postStats = await Post.aggregate([
            {
                $group: {
                    _id: '$status',
                    count: { $sum: 1 },
                    totalViews: { $sum: '$viewCount' },
                    totalLikes: { $sum: { $size: '$likes' } },
                    totalComments: { $sum: { $size: '$comments' } }
                }
            }
        ]);
        
        // Popular categories
        const categoryStats = await Post.aggregate([
            { $match: { status: 'published' } },
            {
                $group: {
                    _id: '$category',
                    count: { $sum: 1 },
                    totalViews: { $sum: '$viewCount' }
                }
            },
            { $sort: { count: -1 } }
        ]);
        
        res.json({
            success: true,
            data: {
                users: userStats[0] || { totalUsers: 0, activeUsers: 0, verifiedUsers: 0 },
                posts: postStats,
                categories: categoryStats
            }
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Database health check
app.get('/api/health', async (req, res) => {
    try {
        // Check database connection
        const dbState = mongoose.connection.readyState;
        const dbStatus = dbState === 1 ? 'connected' : 'disconnected';
        
        // Get database stats
        const stats = await mongoose.connection.db.stats();
        
        res.json({
            success: true,
            status: 'healthy',
            database: {
                status: dbStatus,
                name: mongoose.connection.name,
                collections: stats.collections,
                dataSize: `${(stats.dataSize / 1024 / 1024).toFixed(2)} MB`,
                indexSize: `${(stats.indexSize / 1024 / 1024).toFixed(2)} MB`
            },
            server: {
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                timestamp: new Date().toISOString()
            }
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Health check failed'
        });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Global Error Handler:', error);
    
    // MongoDB connection error
    if (error.name === 'MongoNetworkError') {
        return res.status(503).json({
            success: false,
            error: 'Database connection error'
        });
    }
    
    res.status(500).json({
        success: false,
        error: 'Something went wrong!'
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Route not found'
    });
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n🛑 Received SIGINT. Shutting down gracefully...');
    
    try {
        await mongoose.connection.close();
        console.log('✅ MongoDB connection closed');
        process.exit(0);
    } catch (error) {
        console.error('❌ Error during shutdown:', error);
        process.exit(1);
    }
});

// Start server
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`🗄️  Database Integration API running on port ${PORT}`);
        console.log(`📖 API Documentation: http://localhost:${PORT}`);
        console.log(`🏥 Health Check: http://localhost:${PORT}/api/health`);
        console.log(`📊 Analytics: http://localhost:${PORT}/api/analytics`);
    });
}

module.exports = app;
