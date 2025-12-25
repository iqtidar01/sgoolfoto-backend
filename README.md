# Power BI Backend API

Backend API for generating Power BI embed tokens using Service Principal authentication.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Configure environment variables:
   - Copy `.env.example` to `.env`
   - Fill in your Power BI credentials:
     - `AAD_TENANT_ID`: Your Azure AD Tenant ID
     - `SP_CLIENT_ID`: Service Principal Client ID
     - `SP_CLIENT_SECRET`: Service Principal Client Secret
     - `PBI_WORKSPACE_ID`: Power BI Workspace ID

3. Start the server:
```bash
npm start
```

For development with auto-restart:
```bash
npm run dev
```

## API Endpoints

### Health Check
```
GET /api/health
```
Returns server status.

### Get All Reports
```
GET /api/reports
```
Returns list of all reports in the workspace.

### Get Embed Token
```
POST /api/embed-token
Body: {
  "reportId": "your-report-id",
  "datasetId": "your-dataset-id",
  "userIdentity": {              // Optional: for RLS
    "username": "user@email.com",
    "roles": ["RoleName"]
  }
}
```
Generates an embed token for a specific report. Supports optional Row-Level Security (RLS) via `userIdentity`.

### Get Embed Config
```
POST /api/embed-config/:reportId
Body: {
  "userIdentity": {              // Optional: for RLS
    "username": "user@email.com",
    "roles": ["RoleName"]
  }
}
```
Returns complete embed configuration including report info and embed token. Supports Row-Level Security (RLS).

## Row-Level Security (RLS)

This API supports Power BI Row-Level Security for filtering data per user. See **[RLS-GUIDE.md](./RLS-GUIDE.md)** for complete documentation.

Quick example:
```javascript
POST /api/embed-token
{
  "reportId": "abc-123",
  "datasetId": "def-456",
  "userIdentity": {
    "username": "user@company.com",
    "roles": ["SalesManager"]
  }
}
```

## Security Notes

- Never commit the `.env` file to version control
- Keep your Service Principal credentials secure
- The embed token expires after 1 hour by default
- Use HTTPS in production
- Always validate user identity on backend before applying RLS
- Integrate with your authentication system (JWT, OAuth, etc.)

