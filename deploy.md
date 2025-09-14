# UPCHAAR Backend Deployment Guide

## Prerequisites
- Node.js installed
- Vercel CLI installed (`npm i -g vercel`)
- Git repository (recommended)

## Deployment Steps

### 1. Deploy Backend to Vercel

#### Option A: Using Vercel CLI (Recommended)
```bash
# Navigate to Backend directory
cd Backend

# Deploy to Vercel
vercel

# Follow the prompts:
# - Link to existing project? (Y/n): n (for new project)
# - What's your project's name? upchaar-backend
# - In which directory is your code located? ./
# - Want to override the settings? n
```

#### Option B: Using Vercel Dashboard
1. Go to [vercel.com](https://vercel.com)
2. Click "New Project"
3. Import your GitHub repository
4. Set **Root Directory** to `Backend`
5. Click "Deploy"

### 2. Configure Environment Variables

After deployment, go to your Vercel project dashboard:

1. Navigate to **Settings** → **Environment Variables**
2. Add the following variables:

```
connectionString = mongodb+srv://Vismay:wKbuw3idOGbmHrYj@test.vxtkgty.mongodb.net/?retryWrites=true&w=majority&appName=Test
JWT_SECRET = your-super-secret-jwt-key-change-in-production-make-it-strong
GEMINI = AIzaSyAims7TTxPcVTMpEPbWRbjX8NPeDDq0ZPQ
eleven_labs = sk_386a5cdf4b9f487a2a03c1bd661c3b89e3a2183702681e68
```

3. Redeploy the project after adding environment variables

### 3. Update Frontend Configuration

After backend deployment, you'll get a URL like: `https://upchaar-backend-xyz.vercel.app`

Update `Frontend/config.js`:
```javascript
const API_CONFIG = {
    BACKEND_URL: 'https://your-actual-backend-url.vercel.app',
    API_BASE: 'https://your-actual-backend-url.vercel.app/api',
    // ... rest of the config
};
```

### 4. Test the Deployment

1. Visit your backend URL to ensure it's running
2. Test API endpoints:
   - `GET /api/auth/profile` (should return 401 without token)
   - `POST /api/admin/create-default` (creates default admin)

### 5. Deploy Frontend

Your frontend is already configured with the new API endpoints. Deploy it to Vercel as well:

```bash
cd Frontend
vercel
```

## Important Notes

- **CORS**: Already configured in your backend
- **Environment Variables**: Never commit sensitive data to Git
- **Database**: MongoDB Atlas connection is already configured
- **JWT Secret**: Change the default JWT secret for production

## Troubleshooting

- If API calls fail, check browser console for CORS errors
- Ensure environment variables are set correctly in Vercel dashboard
- Check Vercel function logs for backend errors
