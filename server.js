// require("dotenv").config();
// const express = require("express");
// const cors = require("cors");
// const axios = require("axios");
// const nodemailer = require("nodemailer");

// const app = express();
// const PORT = process.env.PORT || 3001;

// // Middleware
// app.use(cors());
// app.use(express.json());

// let otpStore = {};

// // const transporter = nodemailer.createTransport({
// //   service: "gmail",
// //   auth: {
// //     user: process.env.SMTP_EMAIL,
// //     pass: process.env.SMTP_PASSWORD
// //   }
// // });

// // SMTP Configuration
// // Helper to safely get password (handles special characters)
// const getSMTPPassword = () => {
//   const password = process.env.SMTP_PASSWORD;
//   if (!password) {
//     console.warn("⚠️  SMTP_PASSWORD is not set in .env");
//     return "";
//   }
//   const cleanedPassword = password.trim();
  
//   console.log(`🔐 Password length: ${cleanedPassword.length}`);
//   console.log(`🔐 Password first char: ${cleanedPassword.charAt(0)}`);
//   console.log(`🔐 Password last char: ${cleanedPassword.charAt(cleanedPassword.length - 1)}`);
//   console.log(`🔐 Password has special chars: ${/[^a-zA-Z0-9]/.test(cleanedPassword)}`);
  
//   return cleanedPassword;
// };

// const smtpPort = Number(process.env.SMTP_PORT) || 465;
// const isSecure = smtpPort === 465 || process.env.SMTP_SECURE === "true";

// // Get credentials
// const smtpEmail = process.env.SMTP_EMAIL;
// const smtpPassword = getSMTPPassword();

// // Log credentials (safely) for debugging
// console.log("\n📧 SMTP Configuration:");
// console.log(`   Email: ${smtpEmail}`);
// console.log(`   Password set: ${smtpPassword ? "YES (length: " + smtpPassword.length + ")" : "NO"}`);
// if (smtpPassword) {
//   console.log(`   Password preview: ${smtpPassword.substring(0, 3)}...${smtpPassword.substring(smtpPassword.length - 2)}`);
//   console.log(`   Password contains special chars: ${/[^a-zA-Z0-9]/.test(smtpPassword)}`);
// }
// console.log(`   Host: ${process.env.SMTP_HOST}`);
// console.log(`   Port: ${smtpPort}`);
// console.log(`   Secure: ${isSecure}\n`);

// // Try different authentication methods for SiteGround
// const transporter = nodemailer.createTransport({
//   host: process.env.SMTP_HOST,
//   port: smtpPort,
//   secure: isSecure, // true for 465 (SSL), false for 587 (TLS)
//   auth: {
//     user: smtpEmail,
//     pass: smtpPassword,
//     // Try LOGIN method instead of PLAIN (some servers prefer this)
//     method: 'LOGIN',
//   },
//   // Additional options for better compatibility with SiteGround
//   tls: {
//     rejectUnauthorized: false, // Accept self-signed certificates
//   },
//   // Connection timeout
//   connectionTimeout: 20000, // 20 seconds
//   greetingTimeout: 20000,
//   // Debug mode - enable to see full SMTP conversation
//   debug: process.env.SMTP_DEBUG === "true",
//   logger: process.env.SMTP_DEBUG === "true",
// });

// // Verify SMTP connection on startup
// const verifySMTPConnection = async () => {
//   try {
//     // Log configuration (without password)
//     console.log("🔍 Verifying SMTP connection...");
//     console.log(`   Host: ${process.env.SMTP_HOST}`);
//     console.log(`   Port: ${process.env.SMTP_PORT}`);
//     console.log(`   Secure: ${isSecure}`);
//     console.log(`   Email: ${process.env.SMTP_EMAIL}`);
//     console.log(`   Password: ${process.env.SMTP_PASSWORD ? "***" + process.env.SMTP_PASSWORD.slice(-3) : "NOT SET"}`);
    
//     await transporter.verify();
//     console.log("✅ SMTP server connection verified successfully");
//     return true;
//   } catch (error) {
//     console.error("❌ SMTP connection verification failed:", error.message);
//     console.error("   Error Code:", error.code);
//     console.error("   Response:", error.response);
    
//     if (error.code === "EAUTH" || error.responseCode === 535 || error.message?.includes?.("535")) {
//       console.error("\n⚠️  Authentication failed (535). Common issues:");
//       console.error("   1. Check SMTP_EMAIL and SMTP_PASSWORD are correct in .env");
//       console.error("   2. For passwords with special characters, try wrapping in quotes:");
//       console.error("      SMTP_PASSWORD=\"(@D`#l%lk^l#\"");
//       console.error("   3. Verify email account credentials in SiteGround cPanel");
//       console.error("   4. Check if password has any hidden characters or spaces");
//       console.error("   5. Try using the full email as username: powerbi-admin@rspponderwijs.nl");
//     } else if (error.code === "ECONNECTION") {
//       console.error("\n⚠️  Connection failed. Check:");
//       console.error("   1. SMTP_HOST is correct: gukm1074.siteground.biz");
//       console.error("   2. SMTP_PORT is correct: 465");
//       console.error("   3. SMTP_SECURE is true for port 465");
//       console.error("   4. Firewall/network allows SMTP connections on port 465");
//     }
    
//     return false;
//   }
// };

// // Environment variables
// const { AAD_TENANT_ID, SP_CLIENT_ID, SP_CLIENT_SECRET, PBI_WORKSPACE_ID } =
//   process.env;

// // Datasets that have RLS configured (from client specification)
// const RLS_ENABLED_DATASETS = [
//   "a48db15f-a2b5-41a9-a46d-67991ae69283", // Report 1: For users via RLS
//   "1ca5fa8b-d1a9-4ce5-b740-d9f0a148ad62", // Report 2: For project team with school filter
//   "7a7aa6bd-d65c-4a4c-9859-b9533f3cb974", // Report 3: New test report (524708e1-dfba-4d89-ab9b-40a520be203f)
// ];

// // RLS Role name (from client: "Role in pbi report: RLS[Gebruiker]")
// const RLS_ROLE_NAME = "Gebruiker"; // Dutch for "User"

// // Validate environment variables
// const validateEnvVars = () => {
//   const required = {
//     AAD_TENANT_ID,
//     SP_CLIENT_ID,
//     SP_CLIENT_SECRET,
//     PBI_WORKSPACE_ID,
//   };

//   const missing = Object.entries(required)
//     .filter(([, value]) => !value)
//     .map(([key]) => key);

//   if (missing.length > 0) {
//     throw new Error(
//       `Missing required environment variables: ${missing.join(", ")}`
//     );
//   }
// };

// // Get Azure AD access token
// const getAccessToken = async () => {
//   const url = `https://login.microsoftonline.com/${AAD_TENANT_ID}/oauth2/v2.0/token`;

//   const params = new URLSearchParams({
//     grant_type: "client_credentials",
//     client_id: SP_CLIENT_ID,
//     client_secret: SP_CLIENT_SECRET,
//     scope: "https://analysis.windows.net/powerbi/api/.default",
//   });

//   try {
//     console.log("🔐 Requesting Azure AD access token...");
//     const response = await axios.post(url, params.toString(), {
//       headers: {
//         "Content-Type": "application/x-www-form-urlencoded",
//       },
//     });

//     console.log("✅ Access token obtained successfully");
//     return response.data.access_token;
//   } catch (error) {
//     console.error("❌ ERROR getting access token:");
//     console.error("Status:", error.response?.status);
//     console.error(
//       "Error Details:",
//       JSON.stringify(error.response?.data, null, 2)
//     );
//     console.error("Tenant ID:", AAD_TENANT_ID);
//     console.error("Client ID:", SP_CLIENT_ID);
//     console.error(
//       "Client Secret:",
//       SP_CLIENT_SECRET
//         ? "PROVIDED (length: " + SP_CLIENT_SECRET.length + ")"
//         : "MISSING"
//     );
//     throw new Error(
//       `Failed to obtain access token: ${
//         error.response?.data?.error_description || error.message
//       }`
//     );
//   }
// };

// // Email validation helper
// const isValidEmail = (email) => {
//   const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//   return emailRegex.test(email);
// };

// // ---- SEND OTP ----
// app.post("/api/send-otp", async (req, res) => {
//   const { email } = req.body;

//   // Validate email presence
//   if (!email) {
//     return res.status(400).json({ success: false, error: "Email required" });
//   }

//   // Validate email format
//   if (!isValidEmail(email)) {
//     return res.status(400).json({ success: false, error: "Invalid email format" });
//   }

//   // Normalize email (lowercase for consistency)
//   const normalizedEmail = email.toLowerCase().trim();

//   // Generate 6-digit OTP
//   const otp = Math.floor(100000 + Math.random() * 900000).toString();

//   // Store OTP with expiration (5 minutes)
//   otpStore[normalizedEmail] = {
//     otp,
//     expiresAt: Date.now() + 5 * 60 * 1000,
//   };

//   try {
//     console.log(`📧 Sending OTP to: ${normalizedEmail}`);
    
//     await transporter.sendMail({
//       from: process.env.SMTP_EMAIL,
//       to: normalizedEmail,
//       subject: "Your Verification Code",
//       html: `
//         <h2>Your OTP Code</h2>
//         <p>Your verification code is:</p>
//         <h1>${otp}</h1>
//         <p>This code expires in 5 minutes.</p>
//       `,
//     });

//     console.log(`✅ OTP sent successfully to: ${normalizedEmail}`);
//     res.json({ success: true, message: "OTP sent to email" });
//   } catch (err) {
//     console.error("\n❌ ERROR sending OTP:");
//     console.error("   Email:", normalizedEmail);
//     console.error("   Error:", err.message);
//     console.error("   Code:", err.code);
//     console.error("   Command:", err.command);
//     console.error("   Response:", err.response);
//     console.error("   ResponseCode:", err.responseCode);
//     console.error("   Full error:", JSON.stringify(err, null, 2));
    
//     // Provide more specific error messages
//     let errorMessage = err.message;
//     let statusCode = 500;
    
//     // Check for authentication errors (535 is the SMTP error code for auth failure)
//     if (err.code === "EAUTH" || err.responseCode === 535 || err.response?.includes?.("535") || err.message?.includes?.("535")) {
//       statusCode = 401;
//       console.error("\n🔍 DEBUGGING AUTH FAILURE:");
//       console.error("   SMTP Email:", smtpEmail);
//       console.error("   Password length:", smtpPassword?.length || 0);
//       console.error("   Password first 3 chars:", smtpPassword?.substring(0, 3) || "N/A");
//       console.error("   Password last 3 chars:", smtpPassword?.substring(smtpPassword?.length - 3) || "N/A");
//       console.error("\n💡 TROUBLESHOOTING STEPS:");
//       console.error("   1. Verify password in SiteGround cPanel");
//       console.error("   2. Try logging into webmail: https://gukm1074.siteground.biz:2096");
//       console.error("   3. Check .env file - password should be: SMTP_PASSWORD=\"(@D`#l%lk^l#\"");
//       console.error("   4. Make sure no extra spaces in .env file");
//       console.error("   5. Try resetting password in SiteGround if still failing");
      
//       errorMessage = "SMTP authentication failed (535). Please verify your SMTP_EMAIL and SMTP_PASSWORD in .env file. Check server logs for detailed debugging info.";
//     } else if (err.code === "ECONNECTION") {
//       errorMessage = "Could not connect to SMTP server. Check SMTP_HOST and SMTP_PORT in your .env file.";
//     } else if (err.code === "ETIMEDOUT") {
//       errorMessage = "SMTP connection timed out. Check your network connection and SMTP settings.";
//     } else if (err.code === "EENVELOPE") {
//       errorMessage = "Invalid email address format.";
//     } else if (err.message?.includes?.("535") || err.message?.includes?.("Invalid login")) {
//       statusCode = 401;
//       errorMessage = "Invalid login credentials (535). Check your SMTP_EMAIL and SMTP_PASSWORD in .env file. For SiteGround: Verify credentials in cPanel.";
//     }
    
//     res.status(statusCode).json({ success: false, error: errorMessage });
//   }
// });

// // ---- VERIFY OTP ----
// app.post("/api/verify-otp", (req, res) => {
//   const { email, otp } = req.body;

//   if (!email || !otp) {
//     return res.status(400).json({ success: false, error: "Email and OTP are required" });
//   }

//   // Normalize email (lowercase for consistency)
//   const normalizedEmail = email.toLowerCase().trim();

//   const record = otpStore[normalizedEmail];

//   if (!record) {
//     return res.status(400).json({ success: false, error: "No OTP found for this email" });
//   }

//   if (Date.now() > record.expiresAt) {
//     delete otpStore[normalizedEmail]; // Clean up expired OTP
//     return res.status(400).json({ success: false, error: "OTP expired" });
//   }

//   if (record.otp !== otp) {
//     return res.status(400).json({ success: false, error: "Invalid OTP" });
//   }

//   // OTP verified successfully - remove from store
//   delete otpStore[normalizedEmail];
//   console.log(`✅ OTP verified successfully for: ${normalizedEmail}`);

//   res.json({ success: true, message: "OTP Verified" });
// });

// // Get all reports in workspace
// const getReportsInWorkspace = async (accessToken) => {
//   const url = `https://api.powerbi.com/v1.0/myorg/groups/${PBI_WORKSPACE_ID}/reports`;

//   try {
//     const response = await axios.get(url, {
//       headers: {
//         Authorization: `Bearer ${accessToken}`,
//         "Content-Type": "application/json",
//       },
//     });

//     return response.data.value;
//   } catch (error) {
//     console.error(
//       "Error getting reports:",
//       error.response?.data || error.message
//     );
//     throw new Error("Failed to fetch reports");
//   }
// };

// // Get embed token for a specific report
// const getEmbedToken = async (
//   accessToken,
//   reportId,
//   datasetIds,
//   userIdentity = null
// ) => {
//   const url = `https://api.powerbi.com/v1.0/myorg/GenerateToken`;

//   const requestBody = {
//     datasets: datasetIds.map((id) => ({ id })),
//     reports: [{ id: reportId }],
//   };

//   // Add RLS (Row-Level Security) ONLY for datasets that have RLS configured
//   if (userIdentity && userIdentity.username) {
//     // Filter to only include datasets that have RLS enabled
//     const rlsDatasets = datasetIds.filter((id) =>
//       RLS_ENABLED_DATASETS.includes(id)
//     );

//     // Only add identities if there are RLS-enabled datasets
//     if (rlsDatasets.length > 0) {
//       // Use provided roles or default to RLS_ROLE_NAME
//       const roles =
//         userIdentity.roles && userIdentity.roles.length > 0
//           ? userIdentity.roles
//           : [RLS_ROLE_NAME];

//       requestBody.identities = [
//         {
//           username: userIdentity.username,
//           roles: roles, // Use role name from Power BI RLS configuration
//           datasets: rlsDatasets, // Only RLS-enabled datasets
//         },
//       ];
//       console.log(
//         `🔒 RLS applied to ${rlsDatasets.length}/${datasetIds.length} datasets with roles:`,
//         roles
//       );
//     } else {
//       console.log(
//         `ℹ️  No RLS-enabled datasets in this request (${datasetIds.length} total)`
//       );
//     }
//   }

//   try {
//     console.log("🔑 Requesting embed token with:", {
//       reportId,
//       datasetIds,
//       hasUserIdentity: !!userIdentity,
//       username: userIdentity?.username,
//     });

//     const response = await axios.post(url, requestBody, {
//       headers: {
//         Authorization: `Bearer ${accessToken}`,
//         "Content-Type": "application/json",
//       },
//     });

//     return response.data;
//   } catch (error) {
//     console.error("❌ ERROR generating embed token:");
//     console.error("Status:", error.response?.status);
//     console.error(
//       "Error Details:",
//       JSON.stringify(error.response?.data, null, 2)
//     );
//     console.error("Request Body:", JSON.stringify(requestBody, null, 2));
//     throw new Error(
//       `Failed to generate embed token: ${
//         error.response?.data?.error?.message || error.message
//       }`
//     );
//   }
// };

// // Filter reports based on user roles and permissions
// const filterReportsByUser = (reports, userIdentity) => {
//   const { email, roles = [] } = userIdentity;

//   // Report access control configuration
//   // You can customize this based on your requirements
//   const reportAccessControl = {
//     // Example: Map report names to allowed roles
//     // Leave empty array [] to allow all users
//     // Add specific report names and their allowed roles:
//     // 'Report Usage Metrics Report': ['Admin'],
//     // 'RSPP onderwijsregio': ['Sales', 'Manager'],
//     // 'RSPP onderwijsregio - ALL': ['Admin', 'Manager']
//   };

//   return reports.filter((report) => {
//     const allowedRoles = reportAccessControl[report.name];

//     // If no specific roles defined, allow all authenticated users
//     if (!allowedRoles || allowedRoles.length === 0) {
//       return true;
//     }

//     // Check if user has any of the allowed roles
//     const hasAccess = roles.some((userRole) => allowedRoles.includes(userRole));

//     // Store allowed roles in report object for frontend reference
//     report.allowedRoles = allowedRoles;

//     return hasAccess;
//   });
// };

// // API Routes

// // Health check
// app.get("/api/health", (req, res) => {
//   res.json({ status: "ok", message: "Power BI Backend API is running" });
// });

// // Get reports for a specific user (filtered by permissions)
// app.post("/api/reports", async (req, res) => {
//   try {
//     const { userIdentity } = req.body;

//     if (!userIdentity || !userIdentity.email) {
//       return res.status(400).json({
//         success: false,
//         error: "User identity is required",
//       });
//     }

//     const accessToken = await getAccessToken();
//     const allReports = await getReportsInWorkspace(accessToken);

//     // Filter reports based on user roles/permissions
//     const filteredReports = filterReportsByUser(allReports, userIdentity);

//     res.json({
//       success: true,
//       reports: filteredReports.map((report) => ({
//         id: report.id,
//         name: report.name,
//         embedUrl: report.embedUrl,
//         datasetId: report.datasetId,
//         allowedRoles: report.allowedRoles || [],
//       })),
//       userInfo: {
//         email: userIdentity.email,
//         roles: userIdentity.roles,
//       },
//     });
//   } catch (error) {
//     console.error("Error in /api/reports:", error);
//     res.status(500).json({
//       success: false,
//       error: error.message,
//     });
//   }
// });

// // Get embed token for a specific report
// app.post("/api/embed-token", async (req, res) => {
//   try {
//     const { reportId, datasetId, userIdentity, bypassRLS } = req.body;

//     if (!reportId || !datasetId) {
//       return res.status(400).json({
//         success: false,
//         error: "reportId and datasetId are required",
//       });
//     }

//     const accessToken = await getAccessToken();

//     // Option to bypass RLS for testing (pass userIdentity only if NOT bypassing)
//     const embedTokenData = await getEmbedToken(
//       accessToken,
//       reportId,
//       [datasetId],
//       bypassRLS ? null : userIdentity // Pass null to bypass RLS
//     );

//     res.json({
//       success: true,
//       embedToken: embedTokenData.token,
//       tokenId: embedTokenData.tokenId,
//       expiration: embedTokenData.expiration,
//       rlsBypassed: bypassRLS || false,
//     });
//   } catch (error) {
//     console.error("Error in /api/embed-token:", error);
//     res.status(500).json({
//       success: false,
//       error: error.message,
//     });
//   }
// });

// // Get embed config for a specific report (combines report info + embed token)
// app.post("/api/embed-config/:reportId", async (req, res) => {
//   try {
//     const { reportId } = req.params;
//     const { userIdentity } = req.body; // Optional RLS

//     const accessToken = await getAccessToken();
//     const reports = await getReportsInWorkspace(accessToken);

//     const report = reports.find((r) => r.id === reportId);

//     if (!report) {
//       return res.status(404).json({
//         success: false,
//         error: "Report not found",
//       });
//     }

//     const embedTokenData = await getEmbedToken(
//       accessToken,
//       report.id,
//       [report.datasetId],
//       userIdentity
//     );

//     res.json({
//       success: true,
//       reportId: report.id,
//       reportName: report.name,
//       embedUrl: report.embedUrl,
//       embedToken: embedTokenData.token,
//       tokenId: embedTokenData.tokenId,
//       expiration: embedTokenData.expiration,
//     });
//   } catch (error) {
//     console.error("Error in /api/embed-config:", error);
//     res.status(500).json({
//       success: false,
//       error: error.message,
//     });
//   }
// });

// // Test SMTP connection endpoint
// app.get("/api/test-smtp", async (req, res) => {
//   try {
//     const isVerified = await verifySMTPConnection();
//     if (isVerified) {
//       res.json({ success: true, message: "SMTP connection verified successfully" });
//     } else {
//       res.status(500).json({ success: false, error: "SMTP connection verification failed. Check server logs for details." });
//     }
//   } catch (error) {
//     res.status(500).json({ success: false, error: error.message });
//   }
// });

// // Start server
// const startServer = async () => {
//   try {
//     validateEnvVars();

//     // Verify SMTP connection (non-blocking)
//     verifySMTPConnection().catch(() => {
//       console.warn("⚠️  SMTP verification failed, but server will continue. Emails may not work.");
//     });

//     app.listen(PORT, () => {
//       console.log(
//         `🚀 Power BI Backend API running on http://localhost:${PORT}`
//       );
//       console.log(`📊 Workspace ID: ${PBI_WORKSPACE_ID}`);
//       console.log(`🔐 Using Service Principal authentication`);
//       console.log(`📧 SMTP Host: ${process.env.SMTP_HOST || "Not configured"}`);
//       console.log(`📧 SMTP Email: ${process.env.SMTP_EMAIL || "Not configured"}`);
//     });
//   } catch (error) {
//     console.error("❌ Failed to start server:", error.message);
//     process.exit(1);
//   }
// };

// startServer();



require("dotenv").config();
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const nodemailer = require("nodemailer");

const app = express();
const PORT = Number(process.env.PORT) || 3001;

// ---------- Middleware ----------
app.use(cors());
app.use(express.json());

// In-memory OTP store (use Redis if you scale to multiple instances)
const otpStore = {};

// ---------- Helpers ----------
function readEnvNoQuotes(key, { trimStartEnd = false } = {}) {
  const raw = process.env[key];
  if (raw == null) return "";
  // Remove one leading and one trailing single/double quote if present
  let val = raw.replace(/^['"]/, "").replace(/['"]$/, "");
  if (trimStartEnd) val = val.trim();
  return val;
}

function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// ---------- SMTP (Nodemailer) ----------
const SMTP_HOST = readEnvNoQuotes("SMTP_HOST", { trimStartEnd: true });
const SMTP_PORT = Number(process.env.SMTP_PORT) || 587; // 587 STARTTLS recommended
const SMTP_SECURE = process.env.SMTP_SECURE === "true" || SMTP_PORT === 465; // 465 -> true
const SMTP_EMAIL = readEnvNoQuotes("SMTP_EMAIL", { trimStartEnd: true });
const SMTP_PASSWORD = readEnvNoQuotes("SMTP_PASSWORD"); // DON'T trim; spaces may be valid

if (!SMTP_HOST || !SMTP_EMAIL || !SMTP_PASSWORD) {
  console.warn("⚠️  SMTP env missing. Please set SMTP_HOST/SMTP_EMAIL/SMTP_PASSWORD.");
}

const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_SECURE, // true for 465, false for 587/2525
  auth: {
    user: SMTP_EMAIL,
    pass: SMTP_PASSWORD,
  },
  // SiteGround has valid certs; keep strict verification on
  tls: {
    rejectUnauthorized: true,
    minVersion: "TLSv1.2",
  },
  // Encourage STARTTLS on 587
  requireTLS: SMTP_PORT === 587,
  connectionTimeout: 20000,
  greetingTimeout: 20000,
  socketTimeout: 20000,
});

async function verifySMTPConnection() {
  try {
    await transporter.verify();
    console.log("✅ SMTP server connection verified");
    return true;
  } catch (error) {
    console.error("❌ SMTP verification failed", {
      code: error.code,
      responseCode: error.responseCode,
      message: error.message,
    });
    return false;
  }
}

async function sendEmail({ to, subject, html }) {
  // Uses authenticated mailbox as sender
  await transporter.sendMail({
    from: SMTP_EMAIL,
    to,
    subject,
    html,
  });
}

// ---------- Power BI (Service Principal) ----------
const {
  AAD_TENANT_ID,
  SP_CLIENT_ID,
  SP_CLIENT_SECRET,
  PBI_WORKSPACE_ID,
} = process.env;

const RLS_ENABLED_DATASETS = [
  "a48db15f-a2b5-41a9-a46d-67991ae69283",
  "1ca5fa8b-d1a9-4ce5-b740-d9f0a148ad62",
  "7a7aa6bd-d65c-4a4c-9859-b9533f3cb974",
];

const RLS_ROLE_NAME = "Gebruiker";

function validateEnvVars() {
  const required = {
    AAD_TENANT_ID,
    SP_CLIENT_ID,
    SP_CLIENT_SECRET,
    PBI_WORKSPACE_ID,
  };

  const missing = Object.entries(required)
    .filter(([, v]) => !v)
    .map(([k]) => k);

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }
}

async function getAccessToken() {
  const url = `https://login.microsoftonline.com/${AAD_TENANT_ID}/oauth2/v2.0/token`;

  const params = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: SP_CLIENT_ID,
    client_secret: SP_CLIENT_SECRET,
    scope: "https://analysis.windows.net/powerbi/api/.default",
  });

  try {
    const response = await axios.post(url, params.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    return response.data.access_token;
  } catch (error) {
    const status = error.response?.status;
    const details = error.response?.data?.error_description || error.message;
    throw new Error(`Failed to obtain access token (status ${status || "n/a"}): ${details}`);
  }
}

async function getReportsInWorkspace(accessToken) {
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
    throw new Error(
      `Failed to fetch reports: ${error.response?.data?.error?.message || error.message}`
    );
  }
}

async function getEmbedToken(accessToken, reportId, datasetIds, userIdentity = null) {
  const url = `https://api.powerbi.com/v1.0/myorg/GenerateToken`;

  const body = {
    datasets: datasetIds.map((id) => ({ id })),
    reports: [{ id: reportId }],
  };

  if (userIdentity && userIdentity.username) {
    const rlsDatasets = datasetIds.filter((id) => RLS_ENABLED_DATASETS.includes(id));
    if (rlsDatasets.length > 0) {
      const roles =
        userIdentity.roles && userIdentity.roles.length > 0
          ? userIdentity.roles
          : [RLS_ROLE_NAME];

      body.identities = [
        {
          username: userIdentity.username,
          roles,
          datasets: rlsDatasets,
        },
      ];
    }
  }

  try {
    const response = await axios.post(url, body, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
    });
    return response.data;
  } catch (error) {
    const msg = error.response?.data?.error?.message || error.message;
    throw new Error(`Failed to generate embed token: ${msg}`);
  }
}

function filterReportsByUser(reports, userIdentity) {
  const { roles = [] } = userIdentity;

  const reportAccessControl = {
    // 'Report Name': ['Admin', 'Manager'],
  };

  return reports.filter((report) => {
    const allowedRoles = reportAccessControl[report.name];
    if (!allowedRoles || allowedRoles.length === 0) return true;
    const hasAccess = roles.some((r) => allowedRoles.includes(r));
    report.allowedRoles = allowedRoles;
    return hasAccess;
  });
}

// ---------- Routes ----------
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", message: "Power BI Backend API is running" });
});

app.get("/api/test-smtp", async (_req, res) => {
  try {
    const ok = await verifySMTPConnection();
    if (ok) return res.json({ success: true, message: "SMTP connection verified successfully" });
    return res
      .status(500)
      .json({ success: false, error: "SMTP connection verification failed. Check server logs." });
  } catch (e) {
    return res.status(500).json({ success: false, error: e.message });
  }
});

app.post("/api/send-otp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, error: "Email required" });
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, error: "Invalid email format" });
    }
    const normalizedEmail = email.toLowerCase().trim();

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[normalizedEmail] = {
      otp,
      expiresAt: Date.now() + 5 * 60 * 1000,
    };

    await sendEmail({
      to: normalizedEmail,
      subject: "Your Verification Code",
      html: `
        <h2>Your OTP Code</h2>
        <p>Your verification code is:</p>
        <h1>${otp}</h1>
        <p>This code expires in 5 minutes.</p>
      `,
    });

    res.json({ success: true, message: "OTP sent to email" });
  } catch (err) {
    // Map common Nodemailer errors to friendly messages
    let statusCode = 500;
    let errorMessage = err.message || "Failed to send email";

    if (err.code === "EAUTH" || err.responseCode === 535 || /(^|[^0-9])535([^0-9]|$)/.test(err.message)) {
      statusCode = 401;
      errorMessage =
        "SMTP authentication failed (535). Verify SMTP_EMAIL/SMTP_PASSWORD and remove any quotes in env.";
    } else if (err.code === "ECONNECTION") {
      errorMessage = "Could not connect to SMTP server. Check SMTP_HOST/SMTP_PORT.";
    } else if (err.code === "ETIMEDOUT" || /timed out/i.test(err.message)) {
      errorMessage = "SMTP connection timed out. Check network and SMTP settings.";
    } else if (err.code === "EENVELOPE") {
      errorMessage = "Invalid email address format.";
    }

    res.status(statusCode).json({ success: false, error: errorMessage });
  }
});

app.post("/api/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ success: false, error: "Email and OTP are required" });
  }
  const normalizedEmail = email.toLowerCase().trim();
  const record = otpStore[normalizedEmail];
  if (!record) return res.status(400).json({ success: false, error: "No OTP found for this email" });

  if (Date.now() > record.expiresAt) {
    delete otpStore[normalizedEmail];
    return res.status(400).json({ success: false, error: "OTP expired" });
  }
  if (record.otp !== otp) {
    return res.status(400).json({ success: false, error: "Invalid OTP" });
  }
  delete otpStore[normalizedEmail];
  res.json({ success: true, message: "OTP Verified" });
});

app.post("/api/reports", async (req, res) => {
  try {
    const { userIdentity } = req.body;
    if (!userIdentity || !userIdentity.email) {
      return res.status(400).json({ success: false, error: "User identity is required" });
    }
    const accessToken = await getAccessToken();
    const allReports = await getReportsInWorkspace(accessToken);
    const filteredReports = filterReportsByUser(allReports, userIdentity);

    res.json({
      success: true,
      reports: filteredReports.map((r) => ({
        id: r.id,
        name: r.name,
        embedUrl: r.embedUrl,
        datasetId: r.datasetId,
        allowedRoles: r.allowedRoles || [],
      })),
      userInfo: {
        email: userIdentity.email,
        roles: userIdentity.roles || [],
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/api/embed-token", async (req, res) => {
  try {
    const { reportId, datasetId, userIdentity, bypassRLS } = req.body;
    if (!reportId || !datasetId) {
      return res.status(400).json({ success: false, error: "reportId and datasetId are required" });
    }
    const accessToken = await getAccessToken();
    const token = await getEmbedToken(
      accessToken,
      reportId,
      [datasetId],
      bypassRLS ? null : userIdentity
    );

    res.json({
      success: true,
      embedToken: token.token,
      tokenId: token.tokenId,
      expiration: token.expiration,
      rlsBypassed: !!bypassRLS,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/api/embed-config/:reportId", async (req, res) => {
  try {
    const { reportId } = req.params;
    const { userIdentity } = req.body;
    const accessToken = await getAccessToken();
    const reports = await getReportsInWorkspace(accessToken);
    const report = reports.find((r) => r.id === reportId);
    if (!report) return res.status(404).json({ success: false, error: "Report not found" });

    const token = await getEmbedToken(accessToken, report.id, [report.datasetId], userIdentity);

    res.json({
      success: true,
      reportId: report.id,
      reportName: report.name,
      embedUrl: report.embedUrl,
      embedToken: token.token,
      tokenId: token.tokenId,
      expiration: token.expiration,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ---------- Start ----------
async function startServer() {
  try {
    validateEnvVars();
    // Non-blocking SMTP verify
    verifySMTPConnection().catch(() => {
      console.warn("⚠️  SMTP verification failed; emails may not send.");
    });

    app.listen(PORT, () => {
      console.log(`🚀 API running on http://localhost:${PORT}`);
      console.log(`📊 Workspace ID: ${PBI_WORKSPACE_ID}`);
      console.log(`📧 SMTP Host: ${SMTP_HOST || "Not configured"}`);
      console.log(`📧 SMTP Port: ${SMTP_PORT} Secure: ${SMTP_SECURE}`);
    });
  } catch (e) {
    console.error("❌ Failed to start server:", e.message);
    process.exit(1);
  }
}

startServer();

