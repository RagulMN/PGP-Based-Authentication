const express = require("express");
const bcrypt = require("bcryptjs");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const path = require("path");
const openpgp = require("openpgp");


const app = express();
app.use(bodyParser.json());

// Set up MySQL database connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "root",
    database: "pgp"
});

db.connect((err) => {
  if (err) throw err;
  console.log("Connected to MySQL database.");
});

app.use(express.static(path.join(__dirname, 'public')));
// Homepage route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public'));
});

// Registration Endpoint
app.post("/register", async (req, res) => {
    const { username, email, password, publicKey } = req.body;
  
    console.log("Received registration data:", req.body); // Debugging log
  
    // Hash the password
    const passwordHash = await bcrypt.hash(password, 10);
  
    // Insert user into database
    const query = "INSERT INTO users (username, email, password, public_key) VALUES (?, ?, ?, ?)";
    db.query(query, [username, email, passwordHash, publicKey], (err, results) => {
      if (err) {
        console.error("Error inserting data:", err); // Debugging log
        res.json({ success: false, message: "Registration failed" });
      } else {
        console.log("User registered successfully.");
        res.json({ success: true, message: "User registered successfully" });
      }
    });
  });
  

// Login Endpoint (Initial Challenge)
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  console.log("Login attempt for username:", username);

  try {
    // Retrieve user data
    db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ success: false, message: "Internal server error." });
      }

      if (results.length === 0) {
        console.log("Login failed: User not found for username:", username);
        return res.status(404).json({ success: false, message: "User not found." });
      }

      const user = results[0];

      // Check password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        console.log("Login failed: Invalid password for username:", username);
        return res.status(401).json({ success: false, message: "Invalid password." });
      }

      // Generate and send challenge
      const challenge = "PGP_LOGIN_CHALLENGE";
      console.log("Login successful: Challenge sent for username:", username);
      res.json({ success: true, challenge });
    });
  } catch (error) {
    console.error("Unexpected error during login:", error);
    res.status(500).json({ success: false, message: "Internal server error." });
  }
});

// Log invalid private key attempts
app.post("/invalid-key", (req, res) => {
  const { username, error } = req.body;

  // Log the error to the terminal
  console.error(`Invalid private key attempt for user "${username}": ${error}`);

  res.status(200).json({ success: true, message: "Invalid key logged successfully." });
});


// Function to verify PGP challenge
async function verifyPGPChallenge(publicKeyArmored, signedChallenge) {
    try {
      console.log("Verifying PGP challenge...");
      console.log("Public Key:", publicKeyArmored);
      console.log("Signed Challenge:", signedChallenge);
  
      // Read the armored public key
      const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
      console.log("Parsed Public Key:", publicKey);
  
      // Verify the signed message
      const verified = await openpgp.verify({
        message: await openpgp.createMessage({ text: "PGP_LOGIN_CHALLENGE" }), // The original challenge message
        signature: await openpgp.readSignature({ armoredSignature: signedChallenge }),
        verificationKeys: publicKey
      });
  
      // Check if the verification was successful
      const validity = await verified.signatures[0].verified;
      console.log("Signature validity:", validity);
  
      return validity; // true if valid, false if invalid
    } catch (error) {
      console.log("Error in verifyPGPChallenge:", error);
      console.error("Error in verifyPGPChallenge:", error);
      return false;
    }
}
  
  // `/verify` endpoint to handle challenge-response verification
  app.post("/verify", async (req, res) => {
    const { username, signedChallenge } = req.body;
  
    console.log("Received verify request:", req.body);
  
    // Retrieve user data from the database
    db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.json({ success: false, message: "Database error" });
      }
      
      if (results.length === 0) {
        console.log("User not found for username:", username);
        return res.json({ success: false, message: "User not found" });
      }
  
      const user = results[0];
      console.log("User found:", user);
  
      // Verify the signed challenge using the `verifyPGPChallenge` function
      const isVerified = await verifyPGPChallenge(user.public_key, signedChallenge);
      console.log("Verification result:", isVerified);
  
      if (isVerified) {
        res.json({ success: true, message: "Verification successful" });
      } else {
        res.json({ success: false, message: "Verification failed" });
      }
    });
});

app.get("/dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "dashboard.html"));
  });
  

// Start server
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
