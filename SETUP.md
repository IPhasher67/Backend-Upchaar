# UPCHAAR Backend Setup Guide

## Environment Configuration

Create a `.env` file in the Backend directory with the following content:

```env
# Database Configuration
# Replace with your actual MongoDB connection string
connectionString=mongodb://localhost:27017/upchaar

# JWT Secret Key (Change this to a strong, random string in production)
JWT_SECRET=your-super-secret-jwt-key-change-in-production

# Server Configuration
PORT=3000

# Environment
NODE_ENV=development
```

## Database Setup

### Local MongoDB
1. Install MongoDB locally
2. Start MongoDB service
3. Use connection string: `mongodb://localhost:27017/upchaar`

### MongoDB Atlas (Cloud)
1. Create a MongoDB Atlas account
2. Create a new cluster
3. Get your connection string and replace in `.env`:
   ```
   connectionString=mongodb+srv://username:password@cluster.mongodb.net/upchaar?retryWrites=true&w=majority
   ```

## Installation & Running

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the server:
   ```bash
   # Development mode (with auto-restart)
   npm run dev
   
   # Production mode
   npm start
   ```

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `GET /api/auth/profile` - Get user profile (requires authentication)
- `PUT /api/auth/profile` - Update user profile (requires authentication)

### Frontend Routes
- `GET /` - Map Page
- `GET /user-login` - User Login Page
- `GET /user-dashboard` - User Dashboard
- `GET /admin-login` - Admin Login Page
- `GET /admin-dashboard` - Admin Dashboard

## Database Schema

### UserAuth Collection
- `name` (String, required)
- `email` (String, required, unique)
- `phone` (String, required, unique)
- `password` (String, required, hashed)
- `isActive` (Boolean, default: true)
- `lastLogin` (Date)
- `createdAt` (Date)
- `updatedAt` (Date)

### Ticket Collection (Future)
- `userId` (ObjectId, ref: UserAuth)
- `title` (String, required)
- `description` (String, required)
- `category` (String, enum)
- `priority` (String, enum)
- `status` (String, enum)
- `location` (GeoJSON Point)
- `images` (Array of Strings)
- `assignedTo` (ObjectId, ref: Admin)
- `resolution` (Object)
- `createdAt` (Date)
- `updatedAt` (Date)

## Security Features

- Password hashing with bcryptjs
- JWT token authentication
- Input validation with express-validator
- CORS enabled
- Environment variable configuration

## Next Steps

1. Set up MongoDB database
2. Create `.env` file with your configuration
3. Install dependencies: `npm install`
4. Start the server: `npm run dev`
5. Test the authentication endpoints
6. Integrate with frontend forms
