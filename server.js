require("dotenv").config();
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const nodemailer = require("nodemailer");
const fs = require("fs");
const path = require("path");
const csv = require("csv-parser");
const createCsvWriter = require("csv-writer").createObjectCsvWriter;

const app = express();
const PORT = Number(process.env.PORT) || 3001;

// ---------- Middleware ----------
app.use(cors());
app.use(express.json());

// In-memory OTP store (use Redis if you scale to multiple instances)
const otpStore = {};

// CSV file path
const CSV_FILE_PATH = path.join(__dirname, "emails.csv");

// ---------- CSV Helper Functions ----------

// Initialize CSV file if it doesn't exist
function initializeCsvFile() {
  if (!fs.existsSync(CSV_FILE_PATH)) {
    // Create empty CSV with just headers
    const headers = "id,email,createdAt,updatedAt\n";
    fs.writeFileSync(CSV_FILE_PATH, headers);
  }
}

// Read emails from CSV file
async function readEmailsFromCsv() {
  return new Promise((resolve, reject) => {
    const emails = [];
    
    if (!fs.existsSync(CSV_FILE_PATH)) {
      resolve([]);
      return;
    }

    fs.createReadStream(CSV_FILE_PATH)
      .pipe(csv())
      .on("data", (row) => {
        emails.push({
          id: parseInt(row.id),
          email: row.email,
          createdAt: row.createdAt,
          updatedAt: row.updatedAt,
        });
      })
      .on("end", () => {
        resolve(emails);
      })
      .on("error", (error) => {
        reject(error);
      });
  });
}

// Write emails to CSV file
async function writeEmailsToCsv(emails) {
  const csvWriter = createCsvWriter({
    path: CSV_FILE_PATH,
    header: [
      { id: "id", title: "id" },
      { id: "email", title: "email" },
      { id: "createdAt", title: "createdAt" },
      { id: "updatedAt", title: "updatedAt" },
    ],
  });

  try {
    await csvWriter.writeRecords(emails);
    return true;
  } catch (error) {
    throw error;
  }
}

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
  // SMTP env missing
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
const { AAD_TENANT_ID, SP_CLIENT_ID, SP_CLIENT_SECRET, PBI_WORKSPACE_ID } =
  process.env;

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
    throw new Error(
      `Missing required environment variables: ${missing.join(", ")}`
    );
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
    throw new Error(
      `Failed to obtain access token (status ${status || "n/a"}): ${details}`
    );
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
      `Failed to fetch reports: ${
        error.response?.data?.error?.message || error.message
      }`
    );
  }
}

async function getEmbedToken(
  accessToken,
  reportId,
  datasetIds,
  userIdentity = null
) {
  const url = `https://api.powerbi.com/v1.0/myorg/GenerateToken`;

  const body = {
    datasets: datasetIds.map((id) => ({ id })),
    reports: [{ id: reportId }],
  };

  if (userIdentity && userIdentity.username) {
    const rlsDatasets = datasetIds.filter((id) =>
      RLS_ENABLED_DATASETS.includes(id)
    );
    
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
    if (ok)
      return res.json({
        success: true,
        message: "SMTP connection verified successfully",
      });
    return res
      .status(500)
      .json({
        success: false,
        error: "SMTP connection verification failed. Check server logs.",
      });
  } catch (e) {
    return res.status(500).json({ success: false, error: e.message });
  }
});

app.post("/api/send-otp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res.status(400).json({ success: false, error: "Email required" });
    if (!isValidEmail(email)) {
      return res
        .status(400)
        .json({ success: false, error: "Invalid email format" });
    }
    const normalizedEmail = email.toLowerCase().trim();

    // CRUCIAL: Read emails from CSV file to check authorization
    const authorizedEmails = await readEmailsFromCsv();

    // Check if email exists in authorized email list from CSV
    const isAuthorized = authorizedEmails.find(e => e.email === normalizedEmail);

    if (!isAuthorized) {
      return res.status(403).json({ 
        success: false, 
        error: "Dit e-mailadres is niet geautoriseerd. Neem contact op met de beheerder om uw e-mailadres aan het systeem toe te voegen."
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[normalizedEmail] = {
      otp,
      expiresAt: Date.now() + 5 * 60 * 1000,
    };

    await sendEmail({
      to: normalizedEmail,
      subject: "Uw Verificatie code voor RSPP",
      html: `
        <p>Uw Verificatie code voor het RSPP Dashboard:</p>
        <h1>${otp}</h1>
        <p>Deze code verloopt over 5 minuten.</p>
      `,
    });

    res.json({ success: true, message: "OTP sent to email" });
  } catch (err) {
    // Map common Nodemailer errors to friendly messages
    let statusCode = 500;
    let errorMessage = err.message || "Failed to send email";

    if (
      err.code === "EAUTH" ||
      err.responseCode === 535 ||
      /(^|[^0-9])535([^0-9]|$)/.test(err.message)
    ) {
      statusCode = 401;
      errorMessage =
        "SMTP authentication failed (535). Verify SMTP_EMAIL/SMTP_PASSWORD and remove any quotes in env.";
    } else if (err.code === "ECONNECTION") {
      errorMessage =
        "Could not connect to SMTP server. Check SMTP_HOST/SMTP_PORT.";
    } else if (err.code === "ETIMEDOUT" || /timed out/i.test(err.message)) {
      errorMessage =
        "SMTP connection timed out. Check network and SMTP settings.";
    } else if (err.code === "EENVELOPE") {
      errorMessage = "Invalid email address format.";
    }

    res.status(statusCode).json({ success: false, error: errorMessage });
  }
});

app.post("/api/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res
      .status(400)
      .json({ success: false, error: "Email and OTP are required" });
  }
  const normalizedEmail = email.toLowerCase().trim();
  const record = otpStore[normalizedEmail];
  if (!record)
    return res
      .status(400)
      .json({ success: false, error: "No OTP found for this email" });

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

app.post("/api/admin/login", (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: "Email and password are required" 
      });
    }

    // Static admin credentials
    const ADMIN_EMAIL = "info@rspp.com";
    const ADMIN_PASSWORD = "info@rspp.com";

    // Normalize email for comparison
    const normalizedEmail = email.toLowerCase().trim();

    // Check credentials
    if (normalizedEmail === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
      return res.json({ 
        success: true, 
        message: "Admin login successful",
        user: {
          email: ADMIN_EMAIL,
          role: "admin"
        }
      });
    }

    // Invalid credentials
    return res.status(401).json({ 
      success: false, 
      error: "Invalid email or password" 
    });
  } catch (err) {
    return res.status(500).json({ 
      success: false, 
      error: "An error occurred during login" 
    });
  }
});

// ---------- Email Management APIs ----------

// Helper function to add serial numbers to emails
function addSerialNumbers(emails) {
  return emails.map((email, index) => ({
    ...email,
    serialNumber: index + 1
  }));
}

// Create a new email
app.post("/api/admin/emails", async (req, res) => {
  try {
    const { email } = req.body;
    
    // Validate required fields
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        error: "Email is required" 
      });
    }

    // Validate email format
    if (!isValidEmail(email)) {
      return res.status(400).json({ 
        success: false, 
        error: "Invalid email format" 
      });
    }

    // Read existing emails from CSV
    const emails = await readEmailsFromCsv();

    // Check if email already exists
    const normalizedEmail = email.toLowerCase().trim();
    const existingEmail = emails.find(e => e.email === normalizedEmail);
    if (existingEmail) {
      return res.status(409).json({ 
        success: false, 
        error: "Email already exists" 
      });
    }

    // Create new email entry with unique ID using Date.now()
    const newEmail = {
      id: Date.now(),
      email: normalizedEmail,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    // Add to emails array and write to CSV
    emails.push(newEmail);
    await writeEmailsToCsv(emails);

    // Add serial number for response
    const emailsWithSerial = addSerialNumbers(emails);
    const newEmailWithSerial = emailsWithSerial.find(e => e.id === newEmail.id);

    return res.status(201).json({ 
      success: true, 
      message: "Email created successfully",
      data: newEmailWithSerial
    });
  } catch (err) {
    return res.status(500).json({ 
      success: false, 
      error: "An error occurred while creating email" 
    });
  }
});

// Get all emails
app.get("/api/admin/emails", async (req, res) => {
  try {
    // Read emails from CSV
    const emails = await readEmailsFromCsv();
    
    // Add serial numbers
    const emailsWithSerial = addSerialNumbers(emails);
    
    return res.json({ 
      success: true, 
      message: "Emails retrieved successfully",
      count: emails.length,
      data: emailsWithSerial
    });
  } catch (err) {
    return res.status(500).json({ 
      success: false, 
      error: "An error occurred while retrieving emails" 
    });
  }
});

// Get single email by ID
app.get("/api/admin/emails/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const emailId = parseInt(id);

    if (isNaN(emailId)) {
      return res.status(400).json({ 
        success: false, 
        error: "Invalid email ID" 
      });
    }

    // Read emails from CSV
    const emails = await readEmailsFromCsv();
    const email = emails.find(e => e.id === emailId);
    
    if (!email) {
      return res.status(404).json({ 
        success: false, 
        error: "Email not found" 
      });
    }

    // Add serial numbers
    const emailsWithSerial = addSerialNumbers(emails);
    const emailWithSerial = emailsWithSerial.find(e => e.id === emailId);

    return res.json({ 
      success: true, 
      message: "Email retrieved successfully",
      data: emailWithSerial
    });
  } catch (err) {
    return res.status(500).json({ 
      success: false, 
      error: "An error occurred while retrieving email" 
    });
  }
});

// Update email by ID
app.put("/api/admin/emails/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { email } = req.body;
    const emailId = parseInt(id);

    if (isNaN(emailId)) {
      return res.status(400).json({ 
        success: false, 
        error: "Invalid email ID" 
      });
    }

    // Read emails from CSV
    const emails = await readEmailsFromCsv();
    const emailIndex = emails.findIndex(e => e.id === emailId);
    
    if (emailIndex === -1) {
      return res.status(404).json({ 
        success: false, 
        error: "Email not found" 
      });
    }

    // Validate required field
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        error: "Email is required" 
      });
    }

    // Validate email format
    if (!isValidEmail(email)) {
      return res.status(400).json({ 
        success: false, 
        error: "Invalid email format" 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    
    // Check for duplicates
    const duplicateEmail = emails.find(
      e => e.email === normalizedEmail && e.id !== emailId
    );
    
    if (duplicateEmail) {
      return res.status(409).json({ 
        success: false, 
        error: "Email already exists" 
      });
    }

    // Update email
    emails[emailIndex].email = normalizedEmail;
    emails[emailIndex].updatedAt = new Date().toISOString();

    // Write updated emails to CSV
    await writeEmailsToCsv(emails);

    // Add serial numbers for response
    const emailsWithSerial = addSerialNumbers(emails);
    const updatedEmail = emailsWithSerial.find(e => e.id === emailId);

    return res.json({ 
      success: true, 
      message: "Email updated successfully",
      data: updatedEmail
    });
  } catch (err) {
    return res.status(500).json({ 
      success: false, 
      error: "An error occurred while updating email" 
    });
  }
});

// Delete email by ID
app.delete("/api/admin/emails/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const emailId = parseInt(id);

    if (isNaN(emailId)) {
      return res.status(400).json({ 
        success: false, 
        error: "Invalid email ID" 
      });
    }

    // Read emails from CSV
    const emails = await readEmailsFromCsv();
    const emailIndex = emails.findIndex(e => e.id === emailId);
    
    if (emailIndex === -1) {
      return res.status(404).json({ 
        success: false, 
        error: "Email not found" 
      });
    }

    // Get the deleted email before removal
    const deletedEmail = { ...emails[emailIndex], serialNumber: emailIndex + 1 };
    
    // Remove email from array
    emails.splice(emailIndex, 1);

    // Write updated emails to CSV
    await writeEmailsToCsv(emails);

    return res.json({ 
      success: true, 
      message: "Email deleted successfully",
      data: deletedEmail
    });
  } catch (err) {
    return res.status(500).json({ 
      success: false, 
      error: "An error occurred while deleting email" 
    });
  }
});

app.post("/api/reports", async (req, res) => {
  try {
    const { userIdentity } = req.body;
    if (!userIdentity || !userIdentity.email) {
      return res
        .status(400)
        .json({ success: false, error: "User identity is required" });
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
      return res
        .status(400)
        .json({ success: false, error: "reportId and datasetId are required" });
    }
    
    // Get access token for Power BI API
    const accessToken = await getAccessToken();
    
    // Get all reports to find embedUrl
    const reports = await getReportsInWorkspace(accessToken);
    const report = reports.find((r) => r.id === reportId);
    
    if (!report) {
      return res
        .status(404)
        .json({ success: false, error: "Report not found" });
    }
    
    // Generate embed token
    const token = await getEmbedToken(
      accessToken,
      reportId,
      [datasetId],
      bypassRLS ? null : userIdentity
    );

    // Return complete embed configuration
    res.json({
      success: true,
      accessToken: token.token,  // This is the embed token (Power BI calls it accessToken in the SDK)
      embedToken: token.token,    // Also return as embedToken for backward compatibility
      embedUrl: report.embedUrl,
      reportId: report.id,
      tokenExpiry: token.expiration,
      expiration: token.expiration,  // Backward compatibility
      tokenId: token.tokenId,
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
    if (!report)
      return res
        .status(404)
        .json({ success: false, error: "Report not found" });

    const token = await getEmbedToken(
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
      embedToken: token.token,
      accessToken: token.token,  // Also include accessToken
      tokenId: token.tokenId,
      expiration: token.expiration,
      tokenExpiry: token.expiration,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Debug endpoint to test full embed flow
app.post("/api/debug-embed", async (req, res) => {
  try {
    const { reportId, datasetId, userEmail } = req.body;
    
    // Step 1: Get access token
    const accessToken = await getAccessToken();
    
    // Step 2: Get reports
    const reports = await getReportsInWorkspace(accessToken);
    
    // Step 3: Find the specific report
    const report = reports.find((r) => r.id === reportId);
    if (!report) {
      return res.status(404).json({ 
        success: false, 
        error: "Report not found",
        availableReports: reports.map(r => ({ id: r.id, name: r.name }))
      });
    }
    
    // Step 4: Generate embed token
    const userIdentity = userEmail ? {
      username: userEmail,
      roles: ["Gebruiker"]
    } : null;
    
    const token = await getEmbedToken(
      accessToken,
      reportId,
      datasetId ? [datasetId] : [report.datasetId],
      userIdentity
    );
    
    // Step 5: Return full config
    const config = {
      success: true,
      embedConfig: {
        type: 'report',
        id: report.id,
        embedUrl: report.embedUrl,
        accessToken: token.token,
        tokenType: 'Embed',
        expiration: token.expiration,
      },
      reportDetails: {
        reportId: report.id,
        reportName: report.name,
        datasetId: report.datasetId,
        webUrl: report.webUrl,
      },
      rlsInfo: {
        enabled: RLS_ENABLED_DATASETS.includes(datasetId || report.datasetId),
        username: userIdentity?.username || null,
        roles: userIdentity?.roles || [],
      },
      debug: {
        tokenLength: token.token.length,
        expiresIn: new Date(token.expiration).toLocaleString(),
      }
    };
    
    res.json(config);
    
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// ---------- Start ----------
async function startServer() {
  try {
    validateEnvVars();
    
    // Initialize CSV file for email storage
    initializeCsvFile();
    console.log("📄 CSV email storage initialized");
    
    // Non-blocking SMTP verify
    verifySMTPConnection().catch(() => {
      // SMTP verification failed
    });

    app.listen(PORT, () => {
      console.log(`🚀 API running on http://localhost:${PORT}`);
      console.log(`📊 Workspace ID: ${PBI_WORKSPACE_ID}`);
      console.log(`📧 SMTP Host: ${SMTP_HOST || "Not configured"}`);
      console.log(`📧 SMTP Port: ${SMTP_PORT} Secure: ${SMTP_SECURE}`);
    });
  } catch (e) {
    process.exit(1);
  }
}

startServer();
