# PhishGuard — AI-Based Phishing Detection System
**Created by: Hasnain Mushtaq (SAP 45822) & Tayyab Ayub (SAP 51599)**
**Subject: Vulnerability Assessment | Submitted to: Yawar Abbas**
**Riphah International University**

---

## 📌 WHAT IS THIS PROJECT?

PhishGuard is an AI-powered web application that analyzes URLs and email
content to detect phishing attacks in real time. It uses a weighted
feature-scoring engine (25+ features) to classify threats as:

  ☠  PHISHING      → Score 70-100  (Critical threat)
  ⚠  SUSPICIOUS    → Score 45-69   (High risk)
  ⚡  MODERATE RISK → Score 25-44   (Be cautious)
  ✓  LEGITIMATE    → Score 0-24    (Safe)

---

## 🛠 SOFTWARE REQUIRED

You need to install these programs on your computer:

  1. Python 3.10 or newer     → https://www.python.org/downloads/
  2. pip (comes with Python)
  3. A web browser (Chrome, Firefox, Edge — any)

That's it! No extra software needed.

---

## 🚀 HOW TO RUN — BABY STEP BY STEP

### STEP 1: Install Python
  - Go to: https://www.python.org/downloads/
  - Click "Download Python 3.x.x"
  - Run the installer
  - ✅ IMPORTANT: Check the box "Add Python to PATH"
  - Click Install Now

### STEP 2: Open Terminal / Command Prompt
  Windows: Press Win+R → type "cmd" → press Enter
  Mac:     Press Cmd+Space → type "terminal" → press Enter

### STEP 3: Go to the Project Folder
  Type this command (change the path to where you saved PhishGuard):

      cd C:\Users\YourName\Desktop\PhishGuard

  (On Mac/Linux):
      cd ~/Desktop/PhishGuard

### STEP 4: Install Flask (One-Time Only)
  Type this and press Enter:

      pip install flask

  Wait for it to finish. You will see "Successfully installed flask"

### STEP 5: Run the Project
  Type this and press Enter:

      python app.py

  You will see this in the terminal:
  ═══════════════════════════════════════════════════════
    PhishGuard — AI Phishing Detection System
    Created by: Hasnain Mushtaq | SAP: 45822
  ═══════════════════════════════════════════════════════
    Starting server at: http://127.0.0.1:5000
  ═══════════════════════════════════════════════════════

### STEP 6: Open the App in Browser
  Open your browser and type in the address bar:

      http://127.0.0.1:5000

  🎉 PhishGuard is now running!

### STEP 7: Stop the Server (when done)
  Press Ctrl+C in the terminal

---

## 🔬 HOW THE PROJECT ACTUALLY WORKS

### Phase 1 — You Enter a URL or Email
  The user types a URL (like http://secure-login-bank.xyz/verify)
  or pastes an email into the web interface.

### Phase 2 — Feature Extraction Engine
  The system extracts 25+ features automatically:

  URL Features:
  • URL length            • Presence of '@' symbol
  • Subdomain count       • IP address instead of domain
  • HTTPS or not          • Suspicious keywords count
  • Dot count             • Special character count
  • Suspicious TLD (.tk, .xyz, .ml, etc.)
  • URL entropy (randomness score)
  • Hex-encoded characters (obfuscation detection)
  • Port number presence  • Double-slash redirects

  Email Features:
  • Urgency language score
  • Threat language detection
  • Number of embedded links
  • HTML forms (credential harvesting)
  • Spelling errors
  • ALL CAPS word count

### Phase 3 — Weighted Scoring Engine
  Each feature is given a risk weight:
  • IP address used          → +20 points
  • '@' symbol in URL        → +15 points
  • Suspicious keywords      → +6 points each (max 25)
  • No HTTPS                 → +10 points
  • Suspicious TLD           → +12 points
  • Trusted domain found     → -20 points (reduces score)
  ...and many more rules

### Phase 4 — Verdict
  Final score 0-100 determines the verdict:
  70-100 → PHISHING (Critical)
  45-69  → SUSPICIOUS (High)
  25-44  → MODERATE RISK (Medium)
  0-24   → LEGITIMATE (Low)

### Phase 5 — Results Displayed
  The GUI shows:
  ✅ Threat score bar (animated)
  ✅ All threat indicators found
  ✅ All safe indicators found
  ✅ Every extracted feature and its value
  ✅ Scan history table
  ✅ Live statistics dashboard

---

## 📁 PROJECT STRUCTURE

  PhishGuard/
  ├── app.py              ← Main Python file (Flask server + AI engine)
  ├── requirements.txt    ← Python packages needed
  ├── README.md           ← This guide
  └── templates/
      └── index.html      ← Professional GUI (Dark Cybersecurity Theme)

---

## 🧪 TEST EXAMPLES

Try these URLs to see the system in action:

  Likely PHISHING:
  • http://192.168.1.1/login/verify?account=secure&bank=update
  • http://paypal-secure-login.tk/confirm?user=123@gmail.com
  • http://www.free-prize-winner.xyz/claim?verify=true

  Likely SAFE:
  • https://google.com
  • https://github.com
  • https://microsoft.com/en-us/windows

---

## ⚠ NOTES

• This system uses heuristic/rule-based AI scoring, not a pre-trained ML model.
  It is fully functional for academic demonstration purposes.
• No internet connection needed after Flask is installed.
• Data stays local — nothing is sent to external servers.

---

**© 2026 Hasnain Mushtaq & Tayyab Ayub — Riphah International University**
