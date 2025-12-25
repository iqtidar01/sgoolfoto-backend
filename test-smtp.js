/**
 * SMTP Connection Test Script
 * Run this to test your SMTP configuration independently
 * 
 * Usage: node test-smtp.js
 */

require("dotenv").config();
const nodemailer = require("nodemailer");

console.log("🧪 Testing SMTP Configuration...\n");

// Read environment variables
const smtpHost = process.env.SMTP_HOST;
const smtpPort = Number(process.env.SMTP_PORT) || 465;
const smtpSecure = smtpPort === 465 || process.env.SMTP_SECURE === "true";
const smtpEmail = process.env.SMTP_EMAIL;
const smtpPassword = process.env.SMTP_PASSWORD;

// Validate required variables
if (!smtpHost || !smtpEmail || !smtpPassword) {
  console.error("❌ Missing required environment variables:");
  console.error("   SMTP_HOST:", smtpHost || "NOT SET");
  console.error("   SMTP_EMAIL:", smtpEmail || "NOT SET");
  console.error("   SMTP_PASSWORD:", smtpPassword ? "SET (length: " + smtpPassword.length + ")" : "NOT SET");
  process.exit(1);
}

console.log("📧 Configuration:");
console.log("   Host:", smtpHost);
console.log("   Port:", smtpPort);
console.log("   Secure:", smtpSecure);
console.log("   Email:", smtpEmail);
console.log("   Password length:", smtpPassword.length);
console.log("   Password preview:", smtpPassword.substring(0, 3) + "..." + smtpPassword.substring(smtpPassword.length - 2));
console.log("   Password chars:", smtpPassword.split("").map(c => c.charCodeAt(0)).join(","));
console.log("");

// Create transporter
const transporter = nodemailer.createTransport({
  host: smtpHost,
  port: smtpPort,
  secure: smtpSecure,
  auth: {
    user: smtpEmail,
    pass: smtpPassword,
    method: 'LOGIN', // Try LOGIN method
  },
  tls: {
    rejectUnauthorized: false,
  },
  debug: true, // Enable debug output
  logger: true,
});

// Test connection
async function testConnection() {
  try {
    console.log("🔍 Verifying SMTP connection...");
    await transporter.verify();
    console.log("✅ SMTP connection verified successfully!\n");
    
    // Try sending a test email
    console.log("📧 Sending test email...");
    const info = await transporter.sendMail({
      from: smtpEmail,
      to: smtpEmail, // Send to yourself
      subject: "SMTP Test Email",
      text: "This is a test email from your SMTP configuration.",
      html: "<p>This is a test email from your SMTP configuration.</p>",
    });
    
    console.log("✅ Test email sent successfully!");
    console.log("   Message ID:", info.messageId);
    console.log("   Response:", info.response);
    
  } catch (error) {
    console.error("\n❌ SMTP Test Failed:");
    console.error("   Error:", error.message);
    console.error("   Code:", error.code);
    console.error("   Command:", error.command);
    console.error("   Response:", error.response);
    console.error("   ResponseCode:", error.responseCode);
    
    if (error.code === "EAUTH" || error.responseCode === 535) {
      console.error("\n💡 Authentication Failed (535):");
      console.error("   This means your email or password is incorrect.");
      console.error("   Steps to fix:");
      console.error("   1. Login to SiteGround cPanel");
      console.error("   2. Go to Email Accounts");
      console.error("   3. Verify email:", smtpEmail);
      console.error("   4. Reset password if needed");
      console.error("   5. Update .env file with correct password");
      console.error("   6. Make sure password is wrapped in quotes if it has special chars");
    }
    
    process.exit(1);
  }
}

testConnection();

