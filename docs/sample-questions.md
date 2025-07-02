# 🎯 Comprehensive Backend Development Sample Questions

## 🧪 Practical Coding Challenges

### Challenge 1: Build a Simple API Rate Limiter
```javascript
/**
 * Implement a rate limiter that allows only N requests per minute per IP
 * Requirements:
 * - Track requests per IP address
 * - Reset counter every minute
 * - Return 429 status when limit exceeded
 * - Should work with multiple server instances
 */

class RateLimiter {
    constructor(maxRequests = 60, windowMs = 60000) {
        // TODO: Implement your solution
    }
    
    middleware() {
        return (req, res, next) => {
            // TODO: Implement rate limiting logic
        };
    }
}

// Usage
const limiter = new RateLimiter(10, 60000); // 10 requests per minute
app.use(limiter.middleware());
```

### Challenge 2: Design a Caching System
```javascript
/**
 * Create a caching middleware that:
 * - Caches API responses for specified duration
 * - Supports cache invalidation
 * - Works with different cache strategies (LRU, TTL)
 * - Handles cache misses gracefully
 */

class APICache {
    constructor(options = {}) {
        // TODO: Initialize cache with options
        // - maxSize: maximum cache entries
        // - defaultTTL: default time to live
        // - strategy: 'LRU' or 'TTL'
    }
    
    middleware(duration) {
        return async (req, res, next) => {
            // TODO: Implement caching logic
            // 1. Generate cache key from request
            // 2. Check if cached response exists
            // 3. Return cached response or continue to next middleware
            // 4. Cache the response before sending
        };
    }
    
    invalidate(pattern) {
        // TODO: Implement cache invalidation
    }
}
```

### Challenge 3: Build Authentication Middleware
```javascript
/**
 * Create a complete authentication system with:
 * - User registration with email verification
 * - Login with rate limiting
 * - JWT token management (access + refresh tokens)
 * - Password reset functionality
 * - Role-based authorization
 */

class AuthSystem {
    constructor(options = {}) {
        this.jwtSecret = options.jwtSecret;
        this.tokenExpiry = options.tokenExpiry || '15m';
        this.refreshTokenExpiry = options.refreshTokenExpiry || '7d';
    }
    
    // TODO: Implement all authentication methods
    async register(userData) { }
    async login(credentials) { }
    async refreshToken(refreshToken) { }
    async resetPassword(email) { }
    async verifyEmail(token) { }
    
    // Middleware functions
    authenticate() {
        return async (req, res, next) => {
            // TODO: Verify JWT token
        };
    }
    
    authorize(...roles) {
        return (req, res, next) => {
            // TODO: Check user roles
        };
    }
}
```

---

## 📊 Database Design Questions

### Question 1: E-commerce Database Schema
Design a MongoDB schema for an e-commerce platform with:
- Users (customers and sellers)
- Products with variants (size, color)
- Orders with multiple items
- Reviews and ratings
- Shopping cart functionality

```javascript
// TODO: Design schemas for:
// 1. User schema with profile information
// 2. Product schema with variants and inventory
// 3. Order schema with items and status tracking
// 4. Review schema with ratings
// 5. Cart schema for shopping cart

const userSchema = new mongoose.Schema({
    // TODO: Define user fields
});

const productSchema = new mongoose.Schema({
    // TODO: Define product fields with variants
});

// Continue with other schemas...
```

### Question 2: Social Media Platform
Design schemas for a social media platform:
- User profiles with followers/following
- Posts with images and videos
- Comments and nested replies
- Like and share functionality
- Real-time messaging

### Question 3: Learning Management System
Create database design for:
- Courses with lessons and modules
- Student enrollment and progress tracking
- Quizzes and assignments with grades
- Discussion forums
- Certificate generation

---

## 🔄 API Design Challenges

### Challenge 4: RESTful API Design
Design a complete REST API for a blog platform:

```javascript
/**
 * Design endpoints for:
 * - User management (CRUD)
 * - Blog posts (CRUD with search and filtering)
 * - Comments (nested comments support)
 * - Categories and tags
 * - File uploads for images
 * - Analytics and reporting
 */

// TODO: Define all routes with proper HTTP methods
// Example structure:

// User routes
app.post('/api/users/register', userController.register);
app.post('/api/users/login', userController.login);
app.get('/api/users/profile', auth, userController.getProfile);
// ... continue with all endpoints

// Define request/response formats
// Define error handling
// Define validation rules
```

### Challenge 5: GraphQL vs REST
Compare and implement the same functionality using both GraphQL and REST:

```javascript
// REST Implementation
app.get('/api/posts', async (req, res) => {
    // TODO: Implement with pagination, filtering, sorting
});

app.get('/api/posts/:id', async (req, res) => {
    // TODO: Get single post with comments and author
});

// GraphQL Implementation
const typeDefs = `
    type Post {
        # TODO: Define GraphQL schema
    }
    
    type Query {
        # TODO: Define queries
    }
    
    type Mutation {
        # TODO: Define mutations
    }
`;

const resolvers = {
    Query: {
        // TODO: Implement resolvers
    }
};
```

---

## 🧪 Testing Scenarios

### Challenge 6: Write Comprehensive Tests
```javascript
/**
 * Write tests for a user authentication API:
 * - Unit tests for individual functions
 * - Integration tests for API endpoints
 * - End-to-end tests for user workflows
 * - Performance tests for load handling
 */

describe('User Authentication API', () => {
    // TODO: Setup and teardown
    beforeEach(async () => {
        // TODO: Setup test database
    });
    
    afterEach(async () => {
        // TODO: Cleanup test data
    });
    
    describe('POST /api/auth/register', () => {
        it('should register a new user with valid data', async () => {
            // TODO: Test successful registration
        });
        
        it('should reject registration with invalid email', async () => {
            // TODO: Test validation
        });
        
        it('should reject duplicate email registration', async () => {
            // TODO: Test duplicate handling
        });
        
        // TODO: Add more test cases
    });
    
    describe('POST /api/auth/login', () => {
        // TODO: Test login scenarios
    });
    
    // TODO: Add more endpoint tests
});
```

### Challenge 7: Mock External Services
```javascript
/**
 * Test an application that depends on external services:
 * - Email service
 * - Payment gateway
 * - Third-party APIs
 * - File storage service
 */

// TODO: Create mocks for external services
const mockEmailService = {
    sendEmail: jest.fn().mockResolvedValue({ success: true })
};

const mockPaymentGateway = {
    processPayment: jest.fn()
};

// TODO: Write tests using mocks
```

---

## 🚀 Performance & Scalability

### Challenge 8: Optimize Database Queries
```javascript
/**
 * Optimize these slow database operations:
 * 1. Find all posts by a user with their comments
 * 2. Get trending posts from last week
 * 3. Search posts by title and content
 * 4. Get user statistics and post counts
 */

// Slow query example
const getUserPosts = async (userId) => {
    const posts = await Post.find({ author: userId });
    
    for (let post of posts) {
        post.comments = await Comment.find({ postId: post._id });
        post.author = await User.findById(post.author);
    }
    
    return posts;
};

// TODO: Optimize this query using:
// - Population
// - Aggregation pipelines
// - Indexing
// - Caching

const optimizedGetUserPosts = async (userId) => {
    // TODO: Write optimized version
};
```

### Challenge 9: Handle High Traffic
```javascript
/**
 * Design solutions for handling 10,000+ concurrent users:
 * - Load balancing strategy
 * - Database connection pooling
 * - Caching layers
 * - Session management
 * - File upload optimization
 */

// TODO: Implement solutions for:

// 1. Connection pooling
const mongoose = require('mongoose');
// TODO: Configure proper connection settings

// 2. Caching strategy
const redis = require('redis');
// TODO: Implement multi-layer caching

// 3. Load balancing
// TODO: Design load balancer configuration

// 4. Database sharding
// TODO: Implement data partitioning strategy
```

---

## 🔐 Security Challenges

### Challenge 10: Security Audit
```javascript
/**
 * Identify and fix security vulnerabilities in this code:
 */

app.post('/api/users/:id/update', (req, res) => {
    const userId = req.params.id;
    const updateData = req.body;
    
    // VULNERABILITY 1: No authentication check
    // VULNERABILITY 2: No authorization check
    // VULNERABILITY 3: No input validation
    // VULNERABILITY 4: Direct object modification
    
    User.findByIdAndUpdate(userId, updateData, (err, user) => {
        if (err) {
            // VULNERABILITY 5: Information leakage
            res.status(500).json({ error: err.message });
        } else {
            res.json(user);
        }
    });
});

// TODO: Fix all security issues
app.post('/api/users/:id/update', 
    authenticate,
    authorize('admin', 'self'),
    validateInput,
    async (req, res) => {
        // TODO: Implement secure version
    }
);
```

### Challenge 11: Input Validation & Sanitization
```javascript
/**
 * Create a comprehensive input validation system:
 */

class InputValidator {
    static email(email) {
        // TODO: Validate email format
        // TODO: Check for malicious patterns
        // TODO: Normalize email
    }
    
    static password(password) {
        // TODO: Check password strength
        // TODO: Prevent common passwords
        // TODO: Check for injection attempts
    }
    
    static sanitizeHtml(html) {
        // TODO: Remove malicious HTML
        // TODO: Allow only safe tags
    }
    
    static validateObjectId(id) {
        // TODO: Validate MongoDB ObjectId
    }
}
```

---

## 📈 Real-World Scenarios

### Scenario 1: System Migration
"You need to migrate a legacy system with 1 million users to a new Node.js backend. How do you ensure zero downtime and data integrity?"

**TODO: Design migration strategy covering:**
- Data migration plan
- API versioning
- Gradual rollout
- Rollback strategy
- Monitoring and alerts

### Scenario 2: Performance Crisis
"Your API response time suddenly increased from 200ms to 5 seconds. How do you debug and fix this?"

**TODO: Create debugging approach:**
- Performance monitoring
- Database query analysis
- Memory leak detection
- Network bottleneck identification

### Scenario 3: Security Breach
"You discovered unauthorized access to user data. What's your incident response plan?"

**TODO: Design incident response:**
- Immediate containment
- Impact assessment
- User notification
- System hardening
- Legal compliance

---

## 🎯 Mini Project Challenges

### Project A: Real-time Chat Application
Build a complete chat system with:
- User authentication
- Real-time messaging (Socket.io)
- Group chats and private messages
- File sharing
- Message history and search
- Online status tracking

### Project B: API Gateway
Create an API gateway that:
- Routes requests to microservices
- Handles authentication and authorization
- Implements rate limiting
- Provides request/response transformation
- Includes monitoring and analytics

### Project C: Content Management System
Develop a CMS with:
- Multi-user content creation
- Version control for content
- Media management
- SEO optimization
- Performance caching
- Admin dashboard

---

## 📋 Evaluation Criteria

### Code Quality (30%)
- Clean, readable code
- Proper error handling
- Input validation
- Security considerations
- Performance optimization

### Architecture (25%)
- Proper separation of concerns
- Scalable design
- Database design
- API design principles

### Problem Solving (25%)
- Understanding requirements
- Breaking down complex problems
- Creative solutions
- Edge case handling

### Best Practices (20%)
- Security best practices
- Testing strategies
- Documentation
- Git workflow

---

## 🎓 Study Resources

### Books
- "Node.js Design Patterns" by Mario Casciaro
- "Building Microservices" by Sam Newman
- "Designing Data-Intensive Applications" by Martin Kleppmann

### Online Courses
- Node.js courses on Udemy/Coursera
- FreeCodeCamp backend certification
- MongoDB University courses

### Practice Platforms
- LeetCode (system design questions)
- HackerRank (coding challenges)
- GitHub (open source contributions)

---

Ready to tackle these challenges? Start with the ones matching your skill level and gradually progress to more advanced topics! 🚀
