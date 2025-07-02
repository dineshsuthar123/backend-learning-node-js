# 📝 Project 1: Basic Express Server

## 🎯 Learning Objectives
- Set up Express.js server
- Create RESTful routes
- Use middleware
- Handle requests and responses
- Basic error handling

## 🚀 Getting Started

### **Option 1: Run from project root directory:**
```bash
# From: C:\Users\Naresh Suthar\vscode projects\p1
node projects/01-basic-server/server.js
```

### **Option 2: Run from this directory:**
```bash
# From: C:\Users\Naresh Suthar\vscode projects\p1\projects\01-basic-server
node server.js
```

2. **Test the API endpoints:**

### Available Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Welcome message |
| GET | `/api/users` | Get all users |
| GET | `/api/users/:id` | Get user by ID |
| POST | `/api/users` | Create new user |
| PUT | `/api/users/:id` | Update user |
| DELETE | `/api/users/:id` | Delete user |

## 🧪 Testing Examples

### 1. Get All Users
```bash
curl http://localhost:3000/api/users
```

### 2. Get Single User
```bash
curl http://localhost:3000/api/users/1
```

### 3. Create New User
```bash
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{"name": "Alice Brown", "email": "alice@example.com", "age": 28}'
```

### 4. Update User
```bash
curl -X PUT http://localhost:3000/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{"name": "John Updated", "age": 31}'
```

### 5. Delete User
```bash
curl -X DELETE http://localhost:3000/api/users/2
```

## 📋 Practice Exercises

### Exercise 1: Add Validation
Add more robust validation for user creation:
- Email format validation
- Age must be positive number
- Name minimum length

### Exercise 2: Query Parameters
Add support for query parameters:
- Filter users by age range
- Search users by name
- Pagination (limit, offset)

### Exercise 3: Status Endpoints
Add system endpoints:
- `/api/health` - Server health check
- `/api/stats` - User statistics

## 🤔 Interview Questions

1. **What is Express.js and why use it?**
2. **Explain middleware in Express**
3. **What are HTTP status codes?**
4. **Difference between PUT and PATCH?**
5. **How to handle errors in Express?**

## 🔍 Key Concepts Learned

- **Express.js setup and configuration**
- **RESTful API design principles**
- **Middleware functions and their order**
- **HTTP methods and status codes**
- **JSON request/response handling**
- **Basic error handling**
- **Route parameters and query strings**

## 🚀 Next Steps

Ready for Project 2? Learn about:
- Data validation with Joi
- Environment variables
- Better error handling
- API documentation
