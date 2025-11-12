# 🔐 MERN Secure Authentication System

Production-grade JWT authentication for MERN stack with refresh tokens, token revocation, and rate limiting.

## 🚀 Features

- **JWT Authentication** - Access tokens (15m) & refresh tokens (7d)
- **Token Revocation** - Redis blacklist + MongoDB persistence
- **Token Versioning** - Instant invalidation of all user sessions
- **Rate Limiting** - Brute-force protection with express-rate-limit
- **Secure Password** - Bcryptjs hashing with strength validation
- **Zod Validation** - Type-safe request validation
- **TypeScript** - Full type safety across the stack

## 📦 Tech Stack

- **Backend:** Node.js, Express.js, TypeScript
- **Database:** MongoDB (Mongoose)
- **Cache:** Redis
- **Auth:** JWT (jsonwebtoken)
- **Validation:** Zod
- **Security:** Helmet, CORS, bcryptjs

## 🛠️ Installation

Clone repository
git clone <your-repo-url>
cd mern-secure-auth

Install dependencies
npm install

Setup environment
cp .env.example .env

Edit .env with your configuration
Start MongoDB and Redis
docker-compose up -d # or start locally

Run development server
npm run dev



## 🔧 Environment Variables

PORT=3000
NODE_ENV=development

MONGODB_URI=mongodb://localhost:27017/auth_system
REDIS_URL=redis://localhost:6379

JWT_ACCESS_SECRET=your_access_secret_min_32_chars
JWT_REFRESH_SECRET=your_refresh_secret_min_32_chars

ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d

FRONTEND_URL=http://localhost:3000



## 📡 API Endpoints

### Public Routes
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/refresh-token` - Refresh access token

### Protected Routes
- `GET /api/auth/me` - Get current user
- `POST /api/auth/logout` - Logout user
- `POST /api/auth/change-password` - Change password

## 📝 Example Usage

### Register
curl -X POST http://localhost:3000/api/auth/register
-H "Content-Type: application/json"
-d '{"email":"user@example.com","password":"SecurePass123"}'



### Login
curl -X POST http://localhost:3000/api/auth/login
-H "Content-Type: application/json"
-d '{"email":"user@example.com","password":"SecurePass123"}'



### Access Protected Route
curl -X GET http://localhost:3000/api/auth/me
-H "Authorization: Bearer YOUR_ACCESS_TOKEN"



## 🏗️ Project Structure

src/
├── config/ # Database & Redis configuration
├── models/ # Mongoose models
├── controllers/ # Route controllers
├── middlewares/ # Auth, validation, rate limiting
├── services/ # Business logic
├── routes/ # API routes
├── types/ # TypeScript types
└── app.ts # Application entry point



## 🔒 Security Features

- **Short-lived access tokens** - 15-minute expiration
- **Refresh token rotation** - Automatic blacklisting
- **HTTP-only cookies** - XSS protection
- **Rate limiting** - Login (5 attempts/15m), Register (3/hour)
- **Password requirements** - 8+ chars, mixed case, numbers
- **Helmet & CORS** - Security headers
- **Anomaly detection** - Suspicious token usage tracking

## 🧪 Testing

npm test

text

## 📄 License

MIT

## 👤 Author

SUSHIL SATYARTHI