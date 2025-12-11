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
  console.warn(
    "⚠️  SMTP env missing. Please set SMTP_HOST/SMTP_EMAIL/SMTP_PASSWORD."
  );
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

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[normalizedEmail] = {
      otp,
      expiresAt: Date.now() + 5 * 60 * 1000,
    };

    await sendEmail({
      to: normalizedEmail,
      subject: "De e-mail, kun je die ook aanpanseen?",
      html: `
        <h2>Uw RSPP Verificatie Code</h2>
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
