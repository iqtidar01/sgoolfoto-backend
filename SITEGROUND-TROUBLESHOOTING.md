# SiteGround SMTP Troubleshooting Guide

## Fixing "535 Incorrect authentication data" Error

### Your SiteGround Settings:
- **SMTP Host**: `gukm1074.siteground.biz`
- **SMTP Port**: `465` (SSL)
- **Email**: `powerbi-admin@rspponderwijs.nl`
- **Password**: `(@D`#l%lk^l#`

---

## Step 1: Check Your .env File Format

The password contains special characters that need proper handling. Try these formats:

### Option 1: Without Quotes (if no spaces)
```env
SMTP_PASSWORD=(@D`#l%lk^l#
```

### Option 2: With Double Quotes
```env
SMTP_PASSWORD="(@D`#l%lk^l#"
```

### Option 3: With Single Quotes
```env
SMTP_PASSWORD='(@D`#l%lk^l#'
```

### Option 4: Escaped Special Characters
```env
SMTP_PASSWORD="(@D\`#l%lk^l#"
```

---

## Step 2: Verify Your Complete .env File

Make sure your `.env` file looks exactly like this:

```env
# Server Configuration
PORT=3001

# SMTP Email Configuration (SiteGround)
SMTP_HOST=gukm1074.siteground.biz
SMTP_PORT=465
SMTP_SECURE=true
SMTP_EMAIL=powerbi-admin@rspponderwijs.nl
SMTP_PASSWORD="(@D`#l%lk^l#"

# Power BI Configuration
AAD_TENANT_ID=your-azure-ad-tenant-id
SP_CLIENT_ID=your-service-principal-client-id
SP_CLIENT_SECRET=your-service-principal-client-secret
PBI_WORKSPACE_ID=your-power-bi-workspace-id
```

---

## Step 3: Common Issues & Solutions

### Issue 1: Password Has Special Characters
**Solution**: Wrap password in double quotes:
```env
SMTP_PASSWORD="(@D`#l%lk^l#"
```

### Issue 2: Password Has Backticks (`)
**Solution**: Escape the backtick or use single quotes:
```env
SMTP_PASSWORD='(@D`#l%lk^l#'
```

### Issue 3: Extra Spaces
**Solution**: Remove any spaces before/after password:
```env
SMTP_PASSWORD="(@D`#l%lk^l#"  # ❌ Wrong (space after quote)
SMTP_PASSWORD="(@D`#l%lk^l#"   # ✅ Correct
```

### Issue 4: Wrong Email Format
**Solution**: Use full email address:
```env
SMTP_EMAIL=powerbi-admin@rspponderwijs.nl  # ✅ Correct
SMTP_EMAIL=powerbi-admin                   # ❌ Wrong
```

---

## Step 4: Test Your Configuration

1. **Restart your server** after updating `.env`:
   ```bash
   npm start
   # or
   npm run dev
   ```

2. **Check server logs** - You should see:
   ```
   🔍 Verifying SMTP connection...
      Host: gukm1074.siteground.biz
      Port: 465
      Secure: true
      Email: powerbi-admin@rspponderwijs.nl
      Password: ***l#  (last 3 chars)
   ✅ SMTP server connection verified successfully
   ```

3. **Test SMTP connection**:
   ```bash
   GET http://localhost:3001/api/test-smtp
   ```

4. **Send test OTP**:
   ```bash
   POST http://localhost:3001/api/send-otp
   Content-Type: application/json
   
   {
     "email": "sameerkhan.devpro@gmail.com"
   }
   ```

---

## Step 5: Verify SiteGround Email Account

1. **Login to SiteGround cPanel**
2. **Go to Email Accounts**
3. **Verify**:
   - Email `powerbi-admin@rspponderwijs.nl` exists
   - Password is correct: `(@D`#l%lk^l#`
   - Account is active (not suspended)

4. **Test email login**:
   - Try logging into webmail: `https://gukm1074.siteground.biz:2096`
   - Use: `powerbi-admin@rspponderwijs.nl` / `(@D`#l%lk^l#`
   - If webmail login fails, the password is incorrect

---

## Step 6: Alternative: Use Port 587 (TLS)

If port 465 doesn't work, try port 587:

```env
SMTP_HOST=gukm1074.siteground.biz
SMTP_PORT=587
SMTP_SECURE=false
SMTP_EMAIL=powerbi-admin@rspponderwijs.nl
SMTP_PASSWORD="(@D`#l%lk^l#"
```

---

## Step 7: Enable Debug Mode

Add this to your `.env` to see detailed SMTP communication:

```env
SMTP_DEBUG=true
```

This will show you exactly what's being sent to the SMTP server.

---

## Still Not Working?

1. **Check server console logs** for detailed error messages
2. **Verify password** by logging into SiteGround webmail
3. **Contact SiteGround support** to verify:
   - SMTP is enabled for your account
   - Port 465 is not blocked
   - Account credentials are correct

---

## Quick Checklist

- [ ] `.env` file exists in `powerbi-backend` directory
- [ ] Password is wrapped in quotes (if has special chars)
- [ ] No extra spaces in `.env` file
- [ ] `SMTP_PORT=465` and `SMTP_SECURE=true`
- [ ] Email format is correct: `powerbi-admin@rspponderwijs.nl`
- [ ] Server restarted after `.env` changes
- [ ] Can login to SiteGround webmail with same credentials
- [ ] Checked server logs for detailed error messages

