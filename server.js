

require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const path = require("path");
const db = require("./database/database");

const app = express();
const PORT = process.env.PORT || 3000;

if (
  !process.env.SESSION_SECRET ||
  process.env.SESSION_SECRET.length < 32
) {
  throw new Error(
    "Set SESSION_SECRET to at least 32 characters in .env"
  );
}


app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(helmet());
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

// Local development session configuration.
// The default MemoryStore is for local development only.
app.use(
  session({
    name: "secureweb.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 30 * 60 * 1000
    }
  })
);

// Security event logging.
function logEvent(type, details) {
  db.prepare(
    `INSERT INTO security_events (event_type, details)
     VALUES (?, ?)`
  ).run(type, details);
}

// Authentication middleware.
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }

  next();
}

// Generate a CSRF token stored in the session.
function createCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }

  return req.session.csrfToken;
}

// Verify CSRF tokens on state-changing requests.
function verifyCsrf(req, res, next) {
  const token = req.body._csrf;
  const expected = req.session.csrfToken;

  if (
    typeof token !== "string" ||
    typeof expected !== "string"
  ) {
    logEvent("CSRF_BLOCKED", "Missing CSRF token");

    return res.status(403).send(
      "Request blocked: missing or invalid CSRF token."
    );
  }

  const tokenBuffer = Buffer.from(token);
  const expectedBuffer = Buffer.from(expected);

  if (
    tokenBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(tokenBuffer, expectedBuffer)
  ) {
    logEvent("CSRF_BLOCKED", "Invalid CSRF token");

    return res.status(403).send(
      "Request blocked: missing or invalid CSRF token."
    );
  }

  next();
}

// Home page.
app.get("/", (req, res) => {
  res.render("index");
});

// Registration page.
app.get("/register", (req, res) => {
  res.render("register", {
    error: null,
    csrfToken: createCsrfToken(req)
  });
});

// Registration submission.
app.post("/register", verifyCsrf, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    const password = String(req.body.password || "");

    if (
      username.length < 3 ||
      username.length > 30 ||
      !/^[a-zA-Z0-9_]+$/.test(username) ||
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      password.length < 10 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).render("register", {
        error: "Enter a valid username and email, and a password of 10–72 bytes.",
        csrfToken: createCsrfToken(req)
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    db.prepare(
      `INSERT INTO users (username, email, password_hash)
       VALUES (?, ?, ?)`
    ).run(username, email, passwordHash);

    logEvent("REGISTER_SUCCESS", "A new account was created");

    // Rotate the token after successful registration.
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");

    res.redirect("/login");
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).render("register", {
        error: "That username or email is already registered.",
        csrfToken: createCsrfToken(req)
      });
    }

    next(err);
  }
});

// Login page.
app.get("/login", (req, res) => {
  res.render("login", {
    error: null,
    csrfToken: createCsrfToken(req)
  });
});

// Login submission.
app.post("/login", verifyCsrf, async (req, res, next) => {
  try {
    const login = String(req.body.login || "").trim();
    const password = String(req.body.password || "");

    const user = db.prepare(
      `SELECT id, username, email, password_hash
       FROM users
       WHERE username = ? OR email = ?`
    ).get(login, login.toLowerCase());

    const valid = user
      ? await bcrypt.compare(password, user.password_hash)
      : false;

    if (!valid) {
      logEvent("LOGIN_FAILED", "An unsuccessful login occurred");

      return res.status(401).render("login", {
        error: "Invalid username/email or password.",
        csrfToken: createCsrfToken(req)
      });
    }

    // Regenerate the session after login to prevent session fixation.
    req.session.regenerate((err) => {
      if (err) return next(err);

      req.session.user = {
        id: user.id,
        username: user.username
      };

      req.session.csrfToken = crypto.randomBytes(32).toString("hex");

      logEvent("LOGIN_SUCCESS", "A user logged in");

      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);
        res.redirect("/dashboard");
      });
    });
  } catch (err) {
    next(err);
  }
});

// Authenticated dashboard.
app.get("/dashboard", requireLogin, (req, res) => {
  res.render("dashboard", {
    username: req.session.user.username,
    csrfToken: createCsrfToken(req)
  });
});

// Logout requires a valid CSRF token.
app.post("/logout", requireLogin, verifyCsrf, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);

    res.clearCookie("secureweb.sid");
    res.redirect("/");
  });
});

// Security learning lab.
app.get("/security-lab", requireLogin, (req, res) => {
  res.render("security-lab", {
    username: req.session.user.username,
    csrfToken: createCsrfToken(req)
  });
});

// Demonstration of a CSRF-protected action.
app.post(
  "/security-lab/action",
  requireLogin,
  verifyCsrf,
  (req, res) => {
    logEvent(
      "CSRF_VALID_ACTION",
      "A protected demonstration action succeeded"
    );

    res.send("Success: the server accepted a valid CSRF token.");
  }
);

// Authenticated security-event viewer.
 // Authenticated security-event viewer.
app.get("/events", requireLogin, (req, res) => {
  res.render("events");
});

app.get("/events-data", requireLogin, (req, res) => {
  const events = db.prepare(
    `SELECT event_type, details, created_at
     FROM security_events
     ORDER BY id DESC
     LIMIT 50`
  ).all();

  res.json(events);
});

// Error handler.
app.use((err, req, res, next) => {
  console.error(err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).send("An unexpected server error occurred.");
});

// Start server.
app.listen(PORT, () => {
  console.log(
    `SecureWeb Shield running at http://localhost:${PORT}`
  );
});
