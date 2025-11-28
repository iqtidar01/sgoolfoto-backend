# Render Deployment Guide - SMTP Configuration

## Problem: SMTP Connection Timeout on Render

When deploying to Render, you may encounter `ETIMEDOUT` errors when sending emails. This is because:

1. **Port 465 (SSL) is often blocked** on cloud platforms like Render
2. **SMTP servers may block connections** from cloud provider IP addresses
3. **Network restrictions** on outbound connections

## Solution: Use Port 587 (TLS) for Render

The backend has been updated to automatically retry with different ports, but for best results on Render, configure your environment variables as follows:

### Environment Variables for Render

In your Render dashboard, go to your service → Environment → Add Environment Variable:

```env
SMTP_HOST=gukm1074.siteground.biz
SMTP_PORT=587
SMTP_SECURE=false
SMTP_EMAIL=powerbi-admin@rspponderwijs.nl
SMTP_PASSWORD=(@D`#l%lk^l#
```

**Key Changes:**
- `SMTP_PORT=587` (instead of 465)
- `SMTP_SECURE=false` (TLS instead of SSL)

### Why Port 587?

- ✅ **Port 587 (TLS)** is more commonly allowed on cloud platforms
- ✅ **TLS (STARTTLS)** is preferred for cloud deployments
- ✅ **Better compatibility** with Render's network infrastructure
- ✅ **Less likely to be blocked** by firewalls

### Automatic Retry Logic

The backend now includes automatic retry logic that will:

1. Try the configured port first
2. Automatically fallback to port 587 (TLS) if the first attempt fails
3. Fallback to port 465 (SSL) as a last resort
4. Log which port successfully connected

### Testing After Deployment

1. **Test SMTP Connection:**
   ```bash
   GET https://your-app.onrender.com/api/test-smtp
   ```

2. **Send Test OTP:**
   ```bash
   POST https://your-app.onrender.com/api/send-otp
   Content-Type: application/json
   
   {
     "email": "your-email@example.com"
   }
   ```

### Troubleshooting

#### Still Getting Timeout Errors?

1. **Verify Environment Variables:**
   - Check that all SMTP variables are set correctly in Render dashboard
   - Ensure `SMTP_PORT=587` and `SMTP_SECURE=false`

2. **Check SiteGround Settings:**
   - Verify your SiteGround email account is active
   - Confirm SMTP is enabled for your email account
   - Check if SiteGround allows connections from external IPs

3. **Alternative: Use a Cloud-Friendly Email Service:**
   - Consider using SendGrid, Mailgun, or AWS SES
   - These services are designed for cloud deployments
   - Better reliability and deliverability

#### Error: "535 Incorrect authentication data"

- Verify `SMTP_EMAIL` and `SMTP_PASSWORD` are correct
- Check password doesn't have extra spaces
- For SiteGround, verify credentials in cPanel

#### Error: "ECONNECTION"

- Verify `SMTP_HOST` is correct
- Check that port 587 is not blocked
- Try testing SMTP connection from your local machine first

### Alternative: Using Gmail SMTP (If SiteGround Doesn't Work)

If SiteGround continues to have issues on Render, you can use Gmail SMTP:

1. **Enable 2-Step Verification** on your Gmail account
2. **Generate App Password**: https://myaccount.google.com/apppasswords
3. **Set Environment Variables:**
   ```env
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_SECURE=false
   SMTP_EMAIL=your-email@gmail.com
   SMTP_PASSWORD=your-16-character-app-password
   ```

### Monitoring

Check Render logs to see which port successfully connected:
- Look for: `✅ OTP sent successfully to: ... via port 587`
- Or: `✅ SMTP server connection verified successfully on port 587`

The backend will automatically use the working port for subsequent requests.

