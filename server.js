require("dotenv").config();
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

let otpStore = {};

// const transporter = nodemailer.createTransport({
//   service: "gmail",
//   auth: {
//     user: process.env.SMTP_EMAIL,
//     pass: process.env.SMTP_PASSWORD
//   }
// });

// SMTP Configuration
// Helper to safely get password (handles special characters)
const getSMTPPassword = () => {
  const password = process.env.SMTP_PASSWORD;
  if (!password) {
    console.warn("⚠️  SMTP_PASSWORD is not set in .env");
    return "";
  }
  const cleanedPassword = password.trim();
  
  console.log(`🔐 Password length: ${cleanedPassword.length}`);
  console.log(`🔐 Password first char: ${cleanedPassword.charAt(0)}`);
  console.log(`🔐 Password last char: ${cleanedPassword.charAt(cleanedPassword.length - 1)}`);
  console.log(`🔐 Password has special chars: ${/[^a-zA-Z0-9]/.test(cleanedPassword)}`);
  
  return cleanedPassword;
};

// SMTP Configuration - Cloud-friendly settings
// For cloud deployments (like Render), prefer port 587 (TLS) over 465 (SSL)
const smtpPort = Number(process.env.SMTP_PORT) || (process.env.NODE_ENV === 'production' ? 587 : 465);
const isSecure = smtpPort === 465 || process.env.SMTP_SECURE === "true";

// Get credentials
const smtpEmail = process.env.SMTP_EMAIL;
const smtpPassword = getSMTPPassword();

// Log credentials (safely) for debugging
console.log("\n📧 SMTP Configuration:");
console.log(`   Email: ${smtpEmail}`);
console.log(`   Password set: ${smtpPassword ? "YES (length: " + smtpPassword.length + ")" : "NO"}`);
if (smtpPassword) {
  console.log(`   Password preview: ${smtpPassword.substring(0, 3)}...${smtpPassword.substring(smtpPassword.length - 2)}`);
  console.log(`   Password contains special chars: ${/[^a-zA-Z0-9]/.test(smtpPassword)}`);
}
console.log(`   Host: ${process.env.SMTP_HOST}`);
console.log(`   Port: ${smtpPort}`);
console.log(`   Secure: ${isSecure}`);
console.log(`   Environment: ${process.env.NODE_ENV || 'development'}\n`);

// Create transporter helper function
const createTransporter = (port, secure) => {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: port,
    secure: secure,
    auth: {
      user: smtpEmail,
      pass: smtpPassword,
      method: 'LOGIN',
    },
    tls: {
      rejectUnauthorized: false,
      ciphers: 'SSLv3',
    },
    connectionTimeout: 60000,
    greetingTimeout: 30000,
    socketTimeout: 60000,
    pool: true,
    maxConnections: 1,
    maxMessages: 3,
    debug: process.env.SMTP_DEBUG === "true",
    logger: process.env.SMTP_DEBUG === "true",
  });
};

// Create initial transporter with cloud-optimized settings
let transporter = createTransporter(smtpPort, isSecure);

// Verify SMTP connection on startup with fallback
const verifySMTPConnection = async () => {
  const portsToTry = [
    { port: smtpPort, secure: isSecure },
    // Fallback: Try port 587 (TLS) if 465 fails (common for cloud deployments)
    { port: 587, secure: false },
    // Fallback: Try port 465 (SSL) if 587 fails
    { port: 465, secure: true },
  ];

  // Remove duplicates
  const uniquePorts = portsToTry.filter((p, index, self) => 
    index === self.findIndex(t => t.port === p.port && t.secure === p.secure)
  );

  for (const config of uniquePorts) {
    try {
      console.log(`🔍 Verifying SMTP connection on port ${config.port} (secure: ${config.secure})...`);
      const testTransporter = createTransporter(config.port, config.secure);
      await testTransporter.verify();
      console.log(`✅ SMTP server connection verified successfully on port ${config.port}`);
      
      // Update the main transporter if we found a working port
      if (config.port !== smtpPort || config.secure !== isSecure) {
        console.log(`⚠️  Using fallback port ${config.port} instead of configured port ${smtpPort}`);
        // Note: We'll recreate transporter in send-otp if needed
      }
      
      return { success: true, port: config.port, secure: config.secure };
    } catch (error) {
      console.error(`❌ Port ${config.port} failed:`, error.message);
      if (config === uniquePorts[uniquePorts.length - 1]) {
        // Last attempt failed
        console.error("\n⚠️  All SMTP port attempts failed. Common issues:");
        console.error("   1. Check SMTP_HOST is correct");
        console.error("   2. Verify SMTP_EMAIL and SMTP_PASSWORD are correct");
        console.error("   3. For cloud deployments (Render, Heroku, etc.), try port 587 (TLS)");
        console.error("   4. Check if SMTP server allows connections from cloud IPs");
        console.error("   5. Verify firewall/network allows SMTP connections");
        
        if (error.code === "ETIMEDOUT" || error.code === "ECONNECTION") {
          console.error("\n💡 TIP: For Render deployments, set in environment variables:");
          console.error("   SMTP_PORT=587");
          console.error("   SMTP_SECURE=false");
        }
      }
    }
  }
  
  return { success: false, port: null, secure: null };
};

// Environment variables
const { AAD_TENANT_ID, SP_CLIENT_ID, SP_CLIENT_SECRET, PBI_WORKSPACE_ID } =
  process.env;

// Datasets that have RLS configured (from client specification)
const RLS_ENABLED_DATASETS = [
  "a48db15f-a2b5-41a9-a46d-67991ae69283", // Report 1: For users via RLS
  "1ca5fa8b-d1a9-4ce5-b740-d9f0a148ad62", // Report 2: For project team with school filter
  "7a7aa6bd-d65c-4a4c-9859-b9533f3cb974", // Report 3: New test report (524708e1-dfba-4d89-ab9b-40a520be203f)
];

// RLS Role name (from client: "Role in pbi report: RLS[Gebruiker]")
const RLS_ROLE_NAME = "Gebruiker"; // Dutch for "User"

// Validate environment variables
const validateEnvVars = () => {
  const required = {
    AAD_TENANT_ID,
    SP_CLIENT_ID,
    SP_CLIENT_SECRET,
    PBI_WORKSPACE_ID,
  };

  const missing = Object.entries(required)
    .filter(([, value]) => !value)
    .map(([key]) => key);

  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(", ")}`
    );
  }
};

// Get Azure AD access token
const getAccessToken = async () => {
  const url = `https://login.microsoftonline.com/${AAD_TENANT_ID}/oauth2/v2.0/token`;

  const params = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: SP_CLIENT_ID,
    client_secret: SP_CLIENT_SECRET,
    scope: "https://analysis.windows.net/powerbi/api/.default",
  });

  try {
    console.log("🔐 Requesting Azure AD access token...");
    const response = await axios.post(url, params.toString(), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });

    console.log("✅ Access token obtained successfully");
    return response.data.access_token;
  } catch (error) {
    console.error("❌ ERROR getting access token:");
    console.error("Status:", error.response?.status);
    console.error(
      "Error Details:",
      JSON.stringify(error.response?.data, null, 2)
    );
    console.error("Tenant ID:", AAD_TENANT_ID);
    console.error("Client ID:", SP_CLIENT_ID);
    console.error(
      "Client Secret:",
      SP_CLIENT_SECRET
        ? "PROVIDED (length: " + SP_CLIENT_SECRET.length + ")"
        : "MISSING"
    );
    throw new Error(
      `Failed to obtain access token: ${
        error.response?.data?.error_description || error.message
      }`
    );
  }
};

// Email validation helper
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// ---- SEND OTP ----
app.post("/api/send-otp", async (req, res) => {
  const { email } = req.body;

  // Validate email presence
  if (!email) {
    return res.status(400).json({ success: false, error: "Email required" });
  }

  // Validate email format
  if (!isValidEmail(email)) {
    return res.status(400).json({ success: false, error: "Invalid email format" });
  }

  // Normalize email (lowercase for consistency)
  const normalizedEmail = email.toLowerCase().trim();

  // Generate 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  // Store OTP with expiration (5 minutes)
  otpStore[normalizedEmail] = {
    otp,
    expiresAt: Date.now() + 5 * 60 * 1000,
  };

  // Try sending with retry logic for different ports
  const portsToTry = [
    { port: smtpPort, secure: isSecure },
    { port: 587, secure: false },
    { port: 465, secure: true },
  ];

  // Remove duplicates
  const uniquePorts = portsToTry.filter((p, index, self) => 
    index === self.findIndex(t => t.port === p.port && t.secure === p.secure)
  );

  let lastError = null;
  let emailSent = false;

  for (const config of uniquePorts) {
    try {
      console.log(`📧 Sending OTP to: ${normalizedEmail} (using port ${config.port})`);
      
      // Create transporter for this attempt
      const attemptTransporter = createTransporter(config.port, config.secure);
      
      await attemptTransporter.sendMail({
        from: process.env.SMTP_EMAIL,
        to: normalizedEmail,
        subject: "Your Verification Code",
        html: `
          <h2>Your OTP Code</h2>
          <p>Your verification code is:</p>
          <h1>${otp}</h1>
          <p>This code expires in 5 minutes.</p>
        `,
      });

      console.log(`✅ OTP sent successfully to: ${normalizedEmail} via port ${config.port}`);
      
      // Update main transporter if we used a different port
      if (config.port !== smtpPort || config.secure !== isSecure) {
        transporter = attemptTransporter;
        console.log(`ℹ️  Updated transporter to use port ${config.port}`);
      }
      
      emailSent = true;
      break; // Success, exit loop
    } catch (err) {
      lastError = err;
      console.error(`❌ Failed to send via port ${config.port}:`, err.message);
      
      // If this is not the last attempt, continue to next port
      if (config !== uniquePorts[uniquePorts.length - 1]) {
        console.log(`🔄 Retrying with different port...`);
        continue;
      }
    }
  }

  if (emailSent) {
    res.json({ success: true, message: "OTP sent to email" });
    return;
  }

  // All attempts failed
  if (lastError) {
    const err = lastError;
    console.error("\n❌ ERROR sending OTP:");
    console.error("   Email:", normalizedEmail);
    console.error("   Error:", err.message);
    console.error("   Code:", err.code);
    console.error("   Command:", err.command);
    console.error("   Response:", err.response);
    console.error("   ResponseCode:", err.responseCode);
    console.error("   Full error:", JSON.stringify(err, null, 2));
    
    // Provide more specific error messages
    let errorMessage = err.message;
    let statusCode = 500;
    
    // Check for authentication errors (535 is the SMTP error code for auth failure)
    if (err.code === "EAUTH" || err.responseCode === 535 || err.response?.includes?.("535") || err.message?.includes?.("535")) {
      statusCode = 401;
      console.error("\n🔍 DEBUGGING AUTH FAILURE:");
      console.error("   SMTP Email:", smtpEmail);
      console.error("   Password length:", smtpPassword?.length || 0);
      console.error("   Password first 3 chars:", smtpPassword?.substring(0, 3) || "N/A");
      console.error("   Password last 3 chars:", smtpPassword?.substring(smtpPassword?.length - 3) || "N/A");
      console.error("\n💡 TROUBLESHOOTING STEPS:");
      console.error("   1. Verify password in SiteGround cPanel");
      console.error("   2. Try logging into webmail: https://gukm1074.siteground.biz:2096");
      console.error("   3. Check .env file - password should be: SMTP_PASSWORD=\"(@D`#l%lk^l#\"");
      console.error("   4. Make sure no extra spaces in .env file");
      console.error("   5. Try resetting password in SiteGround if still failing");
      
      errorMessage = "SMTP authentication failed (535). Please verify your SMTP_EMAIL and SMTP_PASSWORD in .env file. Check server logs for detailed debugging info.";
    } else if (err.code === "ECONNECTION") {
      errorMessage = "Could not connect to SMTP server. Check SMTP_HOST and SMTP_PORT in your .env file.";
    } else if (err.code === "ETIMEDOUT") {
      statusCode = 503;
      errorMessage = "SMTP connection timed out. This is common on cloud platforms like Render. Try setting SMTP_PORT=587 and SMTP_SECURE=false in your environment variables.";
    } else if (err.code === "EENVELOPE") {
      errorMessage = "Invalid email address format.";
    } else if (err.message?.includes?.("535") || err.message?.includes?.("Invalid login")) {
      statusCode = 401;
      errorMessage = "Invalid login credentials (535). Check your SMTP_EMAIL and SMTP_PASSWORD in .env file. For SiteGround: Verify credentials in cPanel.";
    }
    
    res.status(statusCode).json({ success: false, error: errorMessage });
  } else {
    res.status(500).json({ success: false, error: "Failed to send OTP. Unknown error." });
  }
});

// ---- VERIFY OTP ----
app.post("/api/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ success: false, error: "Email and OTP are required" });
  }

  // Normalize email (lowercase for consistency)
  const normalizedEmail = email.toLowerCase().trim();

  const record = otpStore[normalizedEmail];

  if (!record) {
    return res.status(400).json({ success: false, error: "No OTP found for this email" });
  }

  if (Date.now() > record.expiresAt) {
    delete otpStore[normalizedEmail]; // Clean up expired OTP
    return res.status(400).json({ success: false, error: "OTP expired" });
  }

  if (record.otp !== otp) {
    return res.status(400).json({ success: false, error: "Invalid OTP" });
  }

  // OTP verified successfully - remove from store
  delete otpStore[normalizedEmail];
  console.log(`✅ OTP verified successfully for: ${normalizedEmail}`);

  res.json({ success: true, message: "OTP Verified" });
});

// Get all reports in workspace
const getReportsInWorkspace = async (accessToken) => {
  const url = `https://api.powerbi.com/v1.0/myorg/groups/${PBI_WORKSPACE_ID}/reports`;

  try {
    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
    });

    return response.data.value;
  } catch (error) {
    console.error(
      "Error getting reports:",
      error.response?.data || error.message
    );
    throw new Error("Failed to fetch reports");
  }
};

// Get embed token for a specific report
const getEmbedToken = async (
  accessToken,
  reportId,
  datasetIds,
  userIdentity = null
) => {
  const url = `https://api.powerbi.com/v1.0/myorg/GenerateToken`;

  const requestBody = {
    datasets: datasetIds.map((id) => ({ id })),
    reports: [{ id: reportId }],
  };

  // Add RLS (Row-Level Security) ONLY for datasets that have RLS configured
  if (userIdentity && userIdentity.username) {
    // Filter to only include datasets that have RLS enabled
    const rlsDatasets = datasetIds.filter((id) =>
      RLS_ENABLED_DATASETS.includes(id)
    );

    // Only add identities if there are RLS-enabled datasets
    if (rlsDatasets.length > 0) {
      // Use provided roles or default to RLS_ROLE_NAME
      const roles =
        userIdentity.roles && userIdentity.roles.length > 0
          ? userIdentity.roles
          : [RLS_ROLE_NAME];

      requestBody.identities = [
        {
          username: userIdentity.username,
          roles: roles, // Use role name from Power BI RLS configuration
          datasets: rlsDatasets, // Only RLS-enabled datasets
        },
      ];
      console.log(
        `🔒 RLS applied to ${rlsDatasets.length}/${datasetIds.length} datasets with roles:`,
        roles
      );
    } else {
      console.log(
        `ℹ️  No RLS-enabled datasets in this request (${datasetIds.length} total)`
      );
    }
  }

  try {
    console.log("🔑 Requesting embed token with:", {
      reportId,
      datasetIds,
      hasUserIdentity: !!userIdentity,
      username: userIdentity?.username,
    });

    const response = await axios.post(url, requestBody, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
    });

    return response.data;
  } catch (error) {
    console.error("❌ ERROR generating embed token:");
    console.error("Status:", error.response?.status);
    console.error(
      "Error Details:",
      JSON.stringify(error.response?.data, null, 2)
    );
    console.error("Request Body:", JSON.stringify(requestBody, null, 2));
    throw new Error(
      `Failed to generate embed token: ${
        error.response?.data?.error?.message || error.message
      }`
    );
  }
};

// Filter reports based on user roles and permissions
const filterReportsByUser = (reports, userIdentity) => {
  const { email, roles = [] } = userIdentity;

  // Report access control configuration
  // You can customize this based on your requirements
  const reportAccessControl = {
    // Example: Map report names to allowed roles
    // Leave empty array [] to allow all users
    // Add specific report names and their allowed roles:
    // 'Report Usage Metrics Report': ['Admin'],
    // 'RSPP onderwijsregio': ['Sales', 'Manager'],
    // 'RSPP onderwijsregio - ALL': ['Admin', 'Manager']
  };

  return reports.filter((report) => {
    const allowedRoles = reportAccessControl[report.name];

    // If no specific roles defined, allow all authenticated users
    if (!allowedRoles || allowedRoles.length === 0) {
      return true;
    }

    // Check if user has any of the allowed roles
    const hasAccess = roles.some((userRole) => allowedRoles.includes(userRole));

    // Store allowed roles in report object for frontend reference
    report.allowedRoles = allowedRoles;

    return hasAccess;
  });
};

// API Routes

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", message: "Power BI Backend API is running" });
});

// Get reports for a specific user (filtered by permissions)
app.post("/api/reports", async (req, res) => {
  try {
    const { userIdentity } = req.body;

    if (!userIdentity || !userIdentity.email) {
      return res.status(400).json({
        success: false,
        error: "User identity is required",
      });
    }

    const accessToken = await getAccessToken();
    const allReports = await getReportsInWorkspace(accessToken);

    // Filter reports based on user roles/permissions
    const filteredReports = filterReportsByUser(allReports, userIdentity);

    res.json({
      success: true,
      reports: filteredReports.map((report) => ({
        id: report.id,
        name: report.name,
        embedUrl: report.embedUrl,
        datasetId: report.datasetId,
        allowedRoles: report.allowedRoles || [],
      })),
      userInfo: {
        email: userIdentity.email,
        roles: userIdentity.roles,
      },
    });
  } catch (error) {
    console.error("Error in /api/reports:", error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Get embed token for a specific report
app.post("/api/embed-token", async (req, res) => {
  try {
    const { reportId, datasetId, userIdentity, bypassRLS } = req.body;

    if (!reportId || !datasetId) {
      return res.status(400).json({
        success: false,
        error: "reportId and datasetId are required",
      });
    }

    const accessToken = await getAccessToken();

    // Option to bypass RLS for testing (pass userIdentity only if NOT bypassing)
    const embedTokenData = await getEmbedToken(
      accessToken,
      reportId,
      [datasetId],
      bypassRLS ? null : userIdentity // Pass null to bypass RLS
    );

    res.json({
      success: true,
      embedToken: embedTokenData.token,
      tokenId: embedTokenData.tokenId,
      expiration: embedTokenData.expiration,
      rlsBypassed: bypassRLS || false,
    });
  } catch (error) {
    console.error("Error in /api/embed-token:", error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Get embed config for a specific report (combines report info + embed token)
app.post("/api/embed-config/:reportId", async (req, res) => {
  try {
    const { reportId } = req.params;
    const { userIdentity } = req.body; // Optional RLS

    const accessToken = await getAccessToken();
    const reports = await getReportsInWorkspace(accessToken);

    const report = reports.find((r) => r.id === reportId);

    if (!report) {
      return res.status(404).json({
        success: false,
        error: "Report not found",
      });
    }

    const embedTokenData = await getEmbedToken(
      accessToken,
      report.id,
      [report.datasetId],
      userIdentity
    );

    res.json({
      success: true,
      reportId: report.id,
      reportName: report.name,
      embedUrl: report.embedUrl,
      embedToken: embedTokenData.token,
      tokenId: embedTokenData.tokenId,
      expiration: embedTokenData.expiration,
    });
  } catch (error) {
    console.error("Error in /api/embed-config:", error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Test SMTP connection endpoint
app.get("/api/test-smtp", async (req, res) => {
  try {
    const isVerified = await verifySMTPConnection();
    if (isVerified) {
      res.json({ success: true, message: "SMTP connection verified successfully" });
    } else {
      res.status(500).json({ success: false, error: "SMTP connection verification failed. Check server logs for details." });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Start server
const startServer = async () => {
  try {
    validateEnvVars();

    // Verify SMTP connection (non-blocking)
    verifySMTPConnection().then((result) => {
      if (result.success) {
        // Update transporter if verification found a better port
        if (result.port !== smtpPort || result.secure !== isSecure) {
          transporter = createTransporter(result.port, result.secure);
          console.log(`✅ Updated transporter to use verified port ${result.port}`);
        }
      } else {
        console.warn("⚠️  SMTP verification failed, but server will continue. Emails may not work.");
        console.warn("💡 For Render deployments, try setting: SMTP_PORT=587 and SMTP_SECURE=false");
      }
    }).catch(() => {
      console.warn("⚠️  SMTP verification failed, but server will continue. Emails may not work.");
    });

    app.listen(PORT, () => {
      console.log(
        `🚀 Power BI Backend API running on http://localhost:${PORT}`
      );
      console.log(`📊 Workspace ID: ${PBI_WORKSPACE_ID}`);
      console.log(`🔐 Using Service Principal authentication`);
      console.log(`📧 SMTP Host: ${process.env.SMTP_HOST || "Not configured"}`);
      console.log(`📧 SMTP Email: ${process.env.SMTP_EMAIL || "Not configured"}`);
    });
  } catch (error) {
    console.error("❌ Failed to start server:", error.message);
    process.exit(1);
  }
};

startServer();
