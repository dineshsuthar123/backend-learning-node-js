# 🚀 Complete Backend Development Course Setup

## ⚠️ Prerequisites Required

Before you can run any projects, you need to install:

### 1. Install Node.js
- Download from [nodejs.org](https://nodejs.org/) (version 18 or higher)
- Verify installation: `node --version` and `npm --version`

### 2. Install MongoDB (for Project 4+)
- Download from [mongodb.com](https://www.mongodb.com/try/download/community)
- Or use MongoDB Atlas (cloud version)

### 3. Install Dependencies
```bash
npm install
```

## 🏃‍♂️ Quick Start

### Option 1: Start with Project 1 (Basic Server)
```bash
# Navigate to project 1
cd projects/01-basic-server

# Run the server
node server.js
```

### Option 2: Use VS Code Tasks
1. Press `Ctrl+Shift+P` (Windows) or `Cmd+Shift+P` (Mac)
2. Type "Tasks: Run Task"
3. Select "Start Development Server"

## 📚 Learning Path

### 🎯 Project 1: Basic Express Server
**Location:** `projects/01-basic-server/`
**What you'll learn:**
- Express.js setup
- Basic routing (GET, POST, PUT, DELETE)
- Middleware usage
- JSON handling
- Error handling

**Test it:**
```bash
node projects/01-basic-server/server.js
# Visit: http://localhost:3000
```

### 🎯 Project 2: Enhanced CRUD API
**Location:** `projects/02-crud-api/`
**What you'll learn:**
- Advanced validation
- Query parameters and filtering
- Pagination
- Environment variables
- Better error handling

**Test it:**
```bash
node projects/02-crud-api/server.js
# Visit: http://localhost:3000
```

### 🎯 Project 3: Authentication System
**Location:** `projects/03-authentication/`
**What you'll learn:**
- JWT authentication
- Password hashing with bcrypt
- Protected routes
- Role-based access control
- Rate limiting

**Test it:**
```bash
node projects/03-authentication/server.js
# Test credentials: admin@example.com / password
```

### 🎯 Project 4: Database Integration
**Location:** `projects/04-database-integration/`
**What you'll learn:**
- MongoDB with Mongoose
- Schema design and validation
- Database relationships
- Advanced queries
- Data aggregation

**Setup:**
1. Install MongoDB locally or use MongoDB Atlas
2. Set environment variables in `.env`
3. Run: `node projects/04-database-integration/server.js`

## 🧪 API Testing

### Using cURL
```bash
# Get all users
curl http://localhost:3000/api/users

# Create a user
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com"}'

# Login (Project 3+)
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "password"}'
```

### Using Postman
1. Import the collection from `docs/postman-collection.json`
2. Set up environment variables
3. Test all endpoints

## 📊 What Each Project Covers

| Project | Core Concepts | Difficulty | Time |
|---------|---------------|------------|------|
| 1 | Express basics, routing | Beginner | 2-3 hours |
| 2 | Validation, filtering | Beginner+ | 3-4 hours |
| 3 | Authentication, JWT | Intermediate | 4-5 hours |
| 4 | Database, MongoDB | Intermediate+ | 5-6 hours |

## 🎓 Practice Exercises

Each project includes:
- ✅ **Code examples** with comments
- ✅ **Practice exercises** to extend functionality
- ✅ **Interview questions** at different skill levels
- ✅ **Real-world scenarios** to solve

Check the `exercises/` folder for detailed practice problems.

## 🚨 Common Issues & Solutions

### Node.js not installed
```
Error: 'node' is not recognized as a command
```
**Solution:** Install Node.js from nodejs.org

### MongoDB connection error
```
Error: MongoNetworkError
```
**Solution:** 
1. Install MongoDB locally
2. Start MongoDB service
3. Or use MongoDB Atlas cloud database

### Port already in use
```
Error: EADDRINUSE
```
**Solution:** 
1. Kill process using the port: `npx kill-port 3000`
2. Or change PORT in environment variables

## 🎯 Next Steps

After completing all projects:

1. **Add Testing** - Learn Jest, Supertest
2. **Learn Docker** - Containerize your applications
3. **Deploy to Cloud** - AWS, Heroku, Vercel
4. **Microservices** - Break down monoliths
5. **GraphQL** - Alternative to REST APIs
6. **WebSockets** - Real-time communication

## 📞 Getting Help

- Check project-specific README files
- Review code comments for explanations
- Practice with the exercises
- Build your own variations

## 🏆 Certification Projects

Build these to demonstrate your skills:
1. **Blog API** with authentication
2. **E-commerce backend** with payments
3. **Chat application** with real-time features
4. **Social media API** with relationships

---

**Ready to start?** Run your first project:
```bash
node projects/01-basic-server/server.js
```

Then visit `http://localhost:3000` to see your API documentation! 🚀
