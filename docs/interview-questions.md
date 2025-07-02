# 🎯 Backend Development Interview Questions & Answers

## 📚 Node.js Fundamentals

### Q1: What is Node.js and how does it work?
**Answer:** Node.js is a JavaScript runtime built on Chrome's V8 JavaScript engine. It uses an event-driven, non-blocking I/O model that makes it lightweight and efficient.

**Key features:**
- Single-threaded event loop
- Non-blocking I/O operations
- NPM package ecosystem
- Cross-platform

### Q2: Explain the Event Loop in Node.js
**Answer:** The Event Loop is what allows Node.js to perform non-blocking I/O operations. It has several phases:
1. **Timer phase** - executes setTimeout() and setInterval()
2. **Pending callbacks** - executes I/O callbacks
3. **Poll phase** - fetches new I/O events
4. **Check phase** - executes setImmediate() callbacks
5. **Close callbacks** - executes close event callbacks

### Q3: What's the difference between `require()` and `import`?
**Answer:**
- `require()` - CommonJS module system, synchronous, dynamic
- `import` - ES6 modules, static, supports tree shaking

```javascript
// CommonJS
const express = require('express');

// ES6 Modules
import express from 'express';
```

---

## 🌐 Express.js & Web APIs

### Q4: What is middleware in Express.js?
**Answer:** Middleware functions are functions that have access to the request object (req), response object (res), and the next middleware function in the application's request-response cycle.

```javascript
// Custom middleware
const logger = (req, res, next) => {
    console.log(`${req.method} ${req.path}`);
    next(); // Must call next() to continue
};

app.use(logger);
```

### Q5: Explain RESTful API principles
**Answer:** REST (Representational State Transfer) principles:
1. **Stateless** - Each request contains all necessary information
2. **Client-Server** - Separation of concerns
3. **Cacheable** - Responses can be cached
4. **Uniform Interface** - Standard HTTP methods
5. **Layered System** - Architecture can have multiple layers

### Q6: What are HTTP status codes? Provide examples.
**Answer:**
- **2xx Success**: 200 (OK), 201 (Created), 204 (No Content)
- **4xx Client Error**: 400 (Bad Request), 401 (Unauthorized), 404 (Not Found)
- **5xx Server Error**: 500 (Internal Server Error), 503 (Service Unavailable)

---

## 🔐 Authentication & Security

### Q7: What is JWT and how does it work?
**Answer:** JWT (JSON Web Token) is a compact, URL-safe token format for securely transmitting information between parties.

**Structure:** `header.payload.signature`

```javascript
// Creating JWT
const token = jwt.sign(
    { userId: user.id, role: user.role },
    'secret',
    { expiresIn: '24h' }
);

// Verifying JWT
const decoded = jwt.verify(token, 'secret');
```

### Q8: How do you implement password security?
**Answer:**
```javascript
const bcrypt = require('bcryptjs');

// Hash password
const hashPassword = async (password) => {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
};

// Compare password
const comparePassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
};
```

### Q9: What's the difference between authentication and authorization?
**Answer:**
- **Authentication** - Verifying who the user is (login)
- **Authorization** - Verifying what the user can do (permissions)

---

## 🗄️ Database & Data Management

### Q10: Explain the difference between SQL and NoSQL databases
**Answer:**

| SQL | NoSQL |
|-----|-------|
| Structured data | Flexible schema |
| ACID compliance | Eventual consistency |
| Vertical scaling | Horizontal scaling |
| Examples: MySQL, PostgreSQL | Examples: MongoDB, Redis |

### Q11: What is Mongoose and why use it?
**Answer:** Mongoose is an ODM (Object Document Mapping) library for MongoDB and Node.js. It provides:
- Schema validation
- Query building
- Middleware (hooks)
- Population (joins)
- Built-in type casting

```javascript
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, unique: true, required: true }
});

const User = mongoose.model('User', userSchema);
```

### Q12: How do you handle database relationships in MongoDB?
**Answer:**
```javascript
// Embedding (One-to-Few)
const userSchema = new mongoose.Schema({
    name: String,
    addresses: [{
        street: String,
        city: String
    }]
});

// Referencing (One-to-Many)
const postSchema = new mongoose.Schema({
    title: String,
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

// Population
const posts = await Post.find().populate('author');
```

---

## ⚡ Performance & Optimization

### Q13: How do you handle errors in Node.js?
**Answer:**
```javascript
// Try-catch for async/await
try {
    const result = await someAsyncFunction();
} catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
}

// Global error handler
app.use((error, req, res, next) => {
    console.error(error.stack);
    res.status(500).json({ error: 'Internal Server Error' });
});

// Unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});
```

### Q14: How do you implement rate limiting?
**Answer:**
```javascript
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP'
});

app.use('/api/', limiter);
```

### Q15: What are some Node.js performance best practices?
**Answer:**
1. **Use async/await** instead of callbacks
2. **Implement caching** (Redis, in-memory)
3. **Use connection pooling** for databases
4. **Enable gzip compression**
5. **Use clustering** for multi-core systems
6. **Monitor memory usage** and prevent leaks

---

## 🧪 Testing & Development

### Q16: How do you test APIs in Node.js?
**Answer:**
```javascript
const request = require('supertest');
const app = require('../app');

describe('GET /api/users', () => {
    test('should return list of users', async () => {
        const response = await request(app)
            .get('/api/users')
            .expect(200);
            
        expect(response.body.success).toBe(true);
        expect(response.body.data).toBeInstanceOf(Array);
    });
});
```

### Q17: What's the difference between unit and integration tests?
**Answer:**
- **Unit tests** - Test individual functions/modules in isolation
- **Integration tests** - Test how different parts work together
- **End-to-end tests** - Test complete user workflows

---

## 🔄 Async Programming

### Q18: Explain Promises vs async/await
**Answer:**
```javascript
// Promises
function fetchUser(id) {
    return User.findById(id)
        .then(user => {
            return user;
        })
        .catch(error => {
            throw error;
        });
}

// Async/Await
async function fetchUser(id) {
    try {
        const user = await User.findById(id);
        return user;
    } catch (error) {
        throw error;
    }
}
```

### Q19: How do you handle multiple async operations?
**Answer:**
```javascript
// Sequential (one after another)
const user = await User.findById(id);
const posts = await Post.find({ author: user._id });

// Parallel (simultaneously)
const [user, posts] = await Promise.all([
    User.findById(id),
    Post.find({ author: id })
]);

// With error handling
const results = await Promise.allSettled([
    User.findById(id),
    Post.find({ author: id })
]);
```

---

## 🏗️ Architecture & Design Patterns

### Q20: What is MVC architecture?
**Answer:** MVC (Model-View-Controller) separates application logic:
- **Model** - Data and business logic
- **View** - User interface (not applicable in APIs)
- **Controller** - Handles requests and responses

```javascript
// Model
const User = mongoose.model('User', userSchema);

// Controller
const userController = {
    async getUsers(req, res) {
        const users = await User.find();
        res.json({ success: true, data: users });
    }
};

// Routes
app.get('/api/users', userController.getUsers);
```

### Q21: What are microservices?
**Answer:** Microservices architecture breaks down a large application into smaller, independent services that communicate over well-defined APIs.

**Benefits:**
- Independent deployment
- Technology diversity
- Fault isolation
- Scalability

**Challenges:**
- Increased complexity
- Network communication overhead
- Data consistency

---

## 🚀 Advanced Topics

### Q22: How do you implement caching?
**Answer:**
```javascript
const redis = require('redis');
const client = redis.createClient();

// Caching middleware
const cache = (duration) => {
    return async (req, res, next) => {
        const key = req.originalUrl;
        const cached = await client.get(key);
        
        if (cached) {
            return res.json(JSON.parse(cached));
        }
        
        // Store original res.json
        const originalJson = res.json;
        res.json = function(data) {
            // Cache the response
            client.setex(key, duration, JSON.stringify(data));
            originalJson.call(this, data);
        };
        
        next();
    };
};

app.get('/api/users', cache(300), userController.getUsers);
```

### Q23: How do you handle file uploads?
**Answer:**
```javascript
const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const extname = allowedTypes.test(
            path.extname(file.originalname).toLowerCase()
        );
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Invalid file type'));
        }
    }
});

app.post('/api/upload', upload.single('image'), (req, res) => {
    res.json({ filename: req.file.filename });
});
```

---

## 🎯 System Design Questions

### Q24: How would you design a URL shortener like bit.ly?
**Answer:**
**Components:**
1. **URL encoding service** - Generate short URLs
2. **Database** - Store URL mappings
3. **Cache** - Frequently accessed URLs
4. **Analytics service** - Track clicks

**Database schema:**
```javascript
const urlSchema = {
    shortUrl: String,      // abc123
    originalUrl: String,   // https://example.com/very/long/url
    userId: ObjectId,      // Creator
    createdAt: Date,
    expiresAt: Date,
    clickCount: Number
};
```

### Q25: How would you handle high traffic in a Node.js application?
**Answer:**
1. **Horizontal scaling** - Multiple server instances
2. **Load balancing** - Distribute requests
3. **Caching** - Redis for session storage
4. **Database optimization** - Indexes, connection pooling
5. **CDN** - Static asset delivery
6. **Monitoring** - Track performance metrics

---

## 💡 Practical Coding Questions

### Q26: Implement a middleware to log request duration
```javascript
const requestTimer = (req, res, next) => {
    const start = Date.now();
    
    // Override res.end to calculate duration
    const originalEnd = res.end;
    res.end = function(...args) {
        const duration = Date.now() - start;
        console.log(`${req.method} ${req.path} - ${duration}ms`);
        originalEnd.apply(this, args);
    };
    
    next();
};

app.use(requestTimer);
```

### Q27: Create a function to validate email format
```javascript
const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

// Usage in middleware
const validateUserInput = (req, res, next) => {
    const { email } = req.body;
    
    if (!email || !validateEmail(email)) {
        return res.status(400).json({
            success: false,
            error: 'Valid email is required'
        });
    }
    
    next();
};
```

### Q28: Implement pagination helper
```javascript
const paginate = (model) => {
    return async (req, res, next) => {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        
        try {
            const total = await model.countDocuments();
            const results = await model.find()
                .skip(skip)
                .limit(limit);
            
            req.pagination = {
                data: results,
                pagination: {
                    page,
                    limit,
                    total,
                    pages: Math.ceil(total / limit),
                    hasNext: page * limit < total,
                    hasPrev: page > 1
                }
            };
            
            next();
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    };
};

// Usage
app.get('/api/users', paginate(User), (req, res) => {
    res.json({
        success: true,
        ...req.pagination
    });
});
```

---

## 🎯 Difficulty Levels

### 🟢 Beginner (0-1 years)
- Questions 1-10
- Focus on basics: HTTP, Express, basic CRUD

### 🟡 Intermediate (1-3 years)
- Questions 11-20
- Focus on: Authentication, databases, error handling

### 🔴 Advanced (3+ years)
- Questions 21-28
- Focus on: Architecture, performance, system design

---

## 📚 Recommended Study Plan

### Week 1-2: Fundamentals
- Node.js basics and Event Loop
- Express.js and middleware
- HTTP methods and status codes

### Week 3-4: Database & Authentication
- MongoDB and Mongoose
- JWT authentication
- Password security

### Week 5-6: Advanced Topics
- Caching and performance
- Testing strategies
- Error handling patterns

### Week 7-8: System Design
- Microservices architecture
- Scalability patterns
- Real-world applications

---

## 🎯 Practice Tips

1. **Build projects** - Apply concepts practically
2. **Read documentation** - Stay updated with latest features
3. **Code daily** - Consistency is key
4. **Join communities** - Stack Overflow, Discord, Reddit
5. **Contribute to open source** - Learn from others' code

Good luck with your interviews! 🚀
