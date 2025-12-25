# SMTP Email Setup Guide

## Fixing "535 Incorrect authentication data" Error

This error occurs when SMTP authentication fails. For Gmail, you need to use an **App Password** instead of your regular password.

---

## Step-by-Step: Gmail SMTP Setup

### Option 1: Using Gmail App Password (Recommended)

1. **Enable 2-Step Verification** (if not already enabled):
   - Go to: https://myaccount.google.com/security
   - Enable "2-Step Verification"

2. **Generate App Password**:
   - Go to: https://myaccount.google.com/apppasswords
   - Select "Mail" as the app
   - Select "Other (Custom name)" as the device
   - Enter a name like "Power BI Backend"
   - Click "Generate"
   - **Copy the 16-character password** (no spaces)

3. **Update your `.env` file**:
   ```env
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_SECURE=false
   SMTP_EMAIL=your-email@gmail.com
   SMTP_PASSWORD=your-16-character-app-password
   ```

4. **Restart your server**

---

### Option 2: Using Other Email Providers

#### Outlook/Hotmail
```env
SMTP_HOST=smtp-mail.outlook.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_EMAIL=your-email@outlook.com
SMTP_PASSWORD=your-password
```

#### Yahoo Mail
```env
SMTP_HOST=smtp.mail.yahoo.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_EMAIL=your-email@yahoo.com
SMTP_PASSWORD=your-app-password
```

#### Custom SMTP Server
```env
SMTP_HOST=your-smtp-server.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_EMAIL=your-email@domain.com
SMTP_PASSWORD=your-password
```

---

## Testing SMTP Connection

After updating your `.env` file, test the connection:

### Method 1: Using the Test Endpoint
```bash
GET http://localhost:3001/api/test-smtp
```

### Method 2: Send Test OTP
```bash
POST http://localhost:3001/api/send-otp
Content-Type: application/json

{
  "email": "sameerkhan.devpro@gmail.com"
}
```

---

## Common Issues & Solutions

### Error: "535 Incorrect authentication data"
- ✅ **Solution**: Use App Password for Gmail (not regular password)
- ✅ Make sure 2-Step Verification is enabled
- ✅ Copy the App Password exactly (no spaces)

### Error: "ECONNECTION" or Connection Failed
- ✅ Check `SMTP_HOST` is correct
- ✅ Check `SMTP_PORT` is correct (587 for TLS, 465 for SSL)
- ✅ Check firewall allows SMTP connections
- ✅ Try `SMTP_SECURE=false` for port 587

### Error: "ETIMEDOUT"
- ✅ Check your internet connection
- ✅ Verify SMTP server is accessible
- ✅ Try different SMTP port

### Email Not Arriving
- ✅ Check spam/junk folder
- ✅ Verify email address is correct
- ✅ Check server logs for errors
- ✅ Verify SMTP credentials are correct

---

## Environment Variables Checklist

Make sure your `.env` file has all required variables:

```env
# SMTP Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_EMAIL=your-email@gmail.com
SMTP_PASSWORD=your-app-password-here

# Power BI Configuration
AAD_TENANT_ID=your-tenant-id
SP_CLIENT_ID=your-client-id
SP_CLIENT_SECRET=your-client-secret
PBI_WORKSPACE_ID=your-workspace-id

# Server
PORT=3001
```

---

## Security Notes

⚠️ **Important**:
- Never commit your `.env` file to version control
- Use App Passwords instead of regular passwords
- Keep your SMTP credentials secure
- Use environment-specific credentials for production

---

## Quick Reference

### Gmail SMTP Settings
- **Host**: `smtp.gmail.com`
- **Port**: `587` (TLS) or `465` (SSL)
- **Secure**: `false` for port 587, `true` for port 465
- **Auth**: Required (use App Password)

### Generate Gmail App Password
🔗 https://myaccount.google.com/apppasswords

