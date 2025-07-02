# 🎯 Backend Development Exercises & Interview Questions

## 📚 Project 1: Basic Express Server

### 🧪 Practical Exercises

#### Exercise 1.1: Add Input Validation
```javascript
// Add validation middleware for user creation
const validateUserInput = (req, res, next) => {
    const { name, email, age } = req.body;
    const errors = [];
    
    // TODO: Implement validation logic
    // - Name: required, min 2 characters, max 50
    // - Email: required, valid email format
    // - Age: optional, number between 0-120
    
    if (errors.length > 0) {
        return res.status(400).json({ success: false, errors });
    }
    next();
};
```

#### Exercise 1.2: Add Pagination
```javascript
// Add pagination to GET /api/users
app.get('/api/users', (req, res) => {
    const { page = 1, limit = 5 } = req.query;
    // TODO: Implement pagination logic
    // Return: data, currentPage, totalPages, totalUsers
});
```

#### Exercise 1.3: Add Search and Filter
```javascript
// Add search and filter functionality
app.get('/api/users', (req, res) => {
    const { search, minAge, maxAge, sortBy = 'name' } = req.query;
    // TODO: Implement search and filter
    // Search by name or email
    // Filter by age range
    // Sort by name, email, or age
});
```

### 🤔 Interview Questions

#### Beginner Level
1. **What is Express.js and why is it popular?**
   - Answer: Express.js is a minimal web framework for Node.js that provides robust features for web and mobile applications.

2. **Explain the difference between GET, POST, PUT, and DELETE HTTP methods.**
   - GET: Retrieve data
   - POST: Create new resource
   - PUT: Update entire resource
   - DELETE: Remove resource

3. **What is middleware in Express?**
   - Functions that execute during request-response cycle
   - Can modify req/res objects or end the request

#### Intermediate Level
4. **How do you handle errors in Express applications?**
5. **What are route parameters vs query parameters?**
6. **Explain the concept of RESTful APIs.**

#### Advanced Level
7. **How would you implement rate limiting?**
8. **What are the best practices for API design?**
9. **How do you handle file uploads in Express?**

---

## 📚 Project 2: Enhanced CRUD API

### 🧪 Practical Exercises

#### Exercise 2.1: Advanced Filtering
```javascript
// Implement complex filtering
app.get('/api/users', (req, res) => {
    const { 
        role, 
        age_min, 
        age_max, 
        created_after, 
        created_before,
        search,
        sort_by = 'createdAt',
        sort_order = 'desc'
    } = req.query;
    
    // TODO: Implement all filters
    // - Filter by role
    // - Age range filtering
    // - Date range filtering
    // - Text search in name/email
    // - Sorting by any field
});
```

#### Exercise 2.2: Batch Operations
```javascript
// Implement batch operations
app.post('/api/users/batch', (req, res) => {
    const { users } = req.body; // Array of user objects
    // TODO: Create multiple users at once
    // Validate all users before creating any
    // Return created users and any errors
});

app.delete('/api/users/batch', (req, res) => {
    const { userIds } = req.body; // Array of user IDs
    // TODO: Delete multiple users
    // Return success/failure for each user
});
```

#### Exercise 2.3: Data Export
```javascript
// Add data export functionality
app.get('/api/users/export', (req, res) => {
    const { format = 'json' } = req.query; // json, csv, xml
    // TODO: Export users in different formats
    // Support filtering before export
    // Set appropriate headers for download
});
```

### 🤔 Interview Questions

#### Beginner Level
10. **What is input validation and why is it important?**
11. **How do you handle pagination in APIs?**
12. **What are HTTP status codes? Name 5 common ones.**

#### Intermediate Level
13. **How would you implement search functionality?**
14. **What is the difference between PUT and PATCH?**
15. **How do you handle concurrent requests?**

#### Advanced Level
16. **How would you implement API versioning?**
17. **What are the best practices for error handling in APIs?**
18. **How do you handle large datasets efficiently?**

---

## 📚 Project 3: Authentication & Authorization

### 🧪 Practical Exercises

#### Exercise 3.1: Password Reset System
```javascript
// Implement password reset functionality
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    // TODO: 
    // 1. Find user by email
    // 2. Generate reset token
    // 3. Store token with expiration
    // 4. Send email with reset link
});

app.post('/api/auth/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    // TODO:
    // 1. Verify reset token
    // 2. Check token expiration
    // 3. Hash new password
    // 4. Update user password
    // 5. Invalidate reset token
});
```

#### Exercise 3.2: Email Verification
```javascript
// Implement email verification
app.post('/api/auth/send-verification', authenticateToken, async (req, res) => {
    // TODO: Send verification email to user
});

app.get('/api/auth/verify-email/:token', async (req, res) => {
    const { token } = req.params;
    // TODO: Verify email with token
});
```

#### Exercise 3.3: Two-Factor Authentication
```javascript
// Implement 2FA
app.post('/api/auth/enable-2fa', authenticateToken, async (req, res) => {
    // TODO: Generate TOTP secret and QR code
});

app.post('/api/auth/verify-2fa', async (req, res) => {
    const { email, password, token } = req.body;
    // TODO: Verify password and TOTP token
});
```

### 🤔 Interview Questions

#### Beginner Level
19. **What is JWT and how does it work?**
20. **Why do we hash passwords?**
21. **What is the difference between authentication and authorization?**

#### Intermediate Level
22. **How do you implement logout functionality with JWTs?**
23. **What are refresh tokens and why use them?**
24. **How do you implement role-based access control?**

#### Advanced Level
25. **How do you handle token security?**
26. **What are the security considerations for authentication?**
27. **How would you implement SSO (Single Sign-On)?**

---

## 🎯 Coding Challenges

### Challenge 1: Rate Limiting Implementation
```javascript
// Implement a custom rate limiter
class RateLimiter {
    constructor(maxRequests, windowMs) {
        // TODO: Implement rate limiting logic
        // Track requests per IP
        // Reset window after time expires
    }
    
    middleware() {
        return (req, res, next) => {
            // TODO: Check if request should be allowed
            // Return 429 Too Many Requests if limit exceeded
        };
    }
}
```

### Challenge 2: API Key Authentication
```javascript
// Implement API key authentication system
app.post('/api/api-keys', authenticateToken, authorize('admin'), (req, res) => {
    // TODO: Generate API key for user
    // Store with permissions and rate limits
});

const apiKeyAuth = (req, res, next) => {
    // TODO: Validate API key from header
    // Check permissions and rate limits
};
```

### Challenge 3: Audit Logging
```javascript
// Implement audit logging for all user actions
const auditLogger = (action) => {
    return (req, res, next) => {
        // TODO: Log user actions
        // Include: user, action, timestamp, IP, user agent
        // Store in database or file
    };
};
```

---

## 🏆 Mini Projects

### Project A: Blog API
Create a simple blog API with:
- Posts (title, content, author, tags)
- Comments on posts
- User authentication
- Like/dislike functionality

### Project B: Task Management API
Create a task management system with:
- Projects and tasks
- User assignments
- Due dates and priorities
- Status tracking

### Project C: E-learning Platform API
Create an e-learning API with:
- Courses and lessons
- User enrollment
- Progress tracking
- Quizzes and grades

---

## 📋 Evaluation Criteria

### Code Quality (25%)
- Clean, readable code
- Proper error handling
- Input validation
- Security considerations

### API Design (25%)
- RESTful conventions
- Appropriate HTTP methods
- Consistent response format
- Clear documentation

### Functionality (25%)
- All requirements met
- Edge cases handled
- Performance considerations
- Scalability

### Best Practices (25%)
- Security best practices
- Proper authentication
- Rate limiting
- Logging and monitoring

---

## 🚀 Next Steps

After completing these exercises:

1. **Learn Database Integration** (MongoDB/PostgreSQL)
2. **Implement Real-time Features** (WebSockets)
3. **Add Testing** (Unit & Integration tests)
4. **Learn Deployment** (Docker, AWS, Heroku)
5. **Study Microservices** (Service architecture)

## 📚 Additional Resources

- [Express.js Documentation](https://expressjs.com/)
- [Node.js Best Practices](https://github.com/goldbergyoni/nodebestpractices)
- [RESTful API Design](https://restfulapi.net/)
- [JWT.io](https://jwt.io/)
- [OWASP Security Guidelines](https://owasp.org/)
