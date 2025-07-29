# Cybersecurity_Incident_Resopnse_Assistant 

FalconCyber Scan is a comprehensive web security application that allows users to scan websites for vulnerabilities, view detailed scan reports, track scan history, and interact with an AI-powered security assistant for insights and recommendations.

✨ Features
- User Authentication: Secure login and registration.
- Website Scanning: Perform passive and active security scans on specified URLs.
- Real-time Scan Progress: Track the status and progress of ongoing scans with detailed stage information.
- Detailed Alerts: View a comprehensive list of vulnerabilities detected, including risk levels, descriptions, and solutions.
- Scan History: Access a complete history of all past scans with filtering and search capabilities.
- PDF Report Generation: Download detailed scan reports in PDF format.
- AI Security Assistant: Get instant answers and advice on cybersecurity topics.
- Dashboard Metrics: Overview of total scans, active threats, system health, and security alerts.
- Security News Feed: Stay updated with the latest cybersecurity news.

🚀 Technologies Used
Frontend:
- HTML5: Structure of the web pages.
- Tailwind CSS: Utility-first CSS framework for styling.
- Remixicon: Open-source icon library.
- JavaScript: For dynamic client-side interactions and API calls.

Backend:
- Node.js: Asynchronous event-driven JavaScript runtime.
- Express.js: Web application framework for Node.js.
- MongoDB: NoSQL database for storing user data, scan history, and alerts.
- Mongoose: MongoDB object data modeling (ODM) for Node.js.
- dotenv: To load environment variables from a .env file.
- express-session & connect-mongo: For managing user sessions.
- bcryptjs: For hashing passwords.
- axios: Promise-based HTTP client for making API requests.
- zaproxy: Node.js client for interacting with OWASP ZAP for security scans.
- pdfkit: For generating PDF reports.
- groq: For integrating with the Groq AI API for the security assistant.

🔧 Installation and Setup
Prerequisites
- Node.js (LTS version recommended)
- MongoDB
- OWASP ZAP (running and accessible, default port 8080)

Steps
1. Clone the repository:
```Bash
git clone <repository_url>
cd CyberGuard-AI
```
`
2. Install backend dependencies:
```bash
npm install
```
3. Configure Environment Variables:
```bash
Create a .env file in the root directory and add the following:
PORT=3000
MONGODB_URI=mongodb://localhost:27017/cyberguard
SESSION_SECRET=your_secret_key_here
SESSION_TTL=86400
COOKIE_SECURE=false
GEMINI_API_KEY=your_api_key
```

- PORT: The port your server will run on (default: 3000).
- MONGODB_URI: Connection string for your MongoDB instance.
- SESSION_SECRET: A strong, random string for session encryption.
- SESSION_TTL: Session time-to-live in seconds (default: 24 hours).
- COOKIE_SECURE: Set to true in production with HTTPS.
- GEMINI_API_KEY: Your Groq API key for the AI Assistant.

4. Start MongoDB:
Ensure your MongoDB instance is running, typically on mongodb://localhost:27017.

5. Start OWASP ZAP:
Ensure OWASP ZAP is running. By default, the application expects ZAP to be accessible on http://localhost:8080.

6. Run the application:
```Bash
npm start
```
7. Access the application:
Open your web browser and navigate to 
```bash 
http://localhost:3000.
```

📂 Project Structure
```bash
├── public/
│   ├── cyber.html            # Dashboard page 
│   ├── login.html            # User login page
│   ├── signup.html           # User registration page
│   ├── scan-history.html     # Scan history page
│   ├── detailed-alerts.html  # Detailed alerts for a specific scan
│   ├── chatbot.html          # AI security assistant page
│   └── progress-tracker.js   # Frontend script for scan progress
├── server.js                 # Backend server entry point
├── models/
│   └── User.js               # Mongoose model for User
│   └── Scan.js               # Mongoose model for Scan results
├── routes/
│   └── auth.js               # Authentication routes
│   └── scan.js               # Scan-related routes
│   └── chat.js               # Chatbot routes
│   └── dashboard.js          # Dashboard data routes
├── utils/
│   └── zap-scanner.js        # OWASP ZAP integration logic
│   └── pdf-generator.js      # PDF report generation logic
├── .env                      # Environment variables
├── package.json              # Project dependencies and scripts
└── package-lock.json         # Locked dependencies versions
```

🚦 Usage
Register and Login
Navigate to http://localhost:3000/signup.html to create a new account, then log in at http://localhost:3000/login.html.

Dashboard (cyber.html)
After logging in, you'll land on the dashboard.
- Website Security Scanner: Enter a URL and choose between Passive Scan or Active Scan. The progress will be displayed in real-time.
- Dashboard Metrics: View summaries of your scans, threats, and system health.
- Recent Scan Alerts: See a summary of alerts from your latest scan.
- Latest Security News: Get updates on cybersecurity news.

Scan History (scan-history.html)

Access the "Scan History" from the sidebar to view a list of all your past scans. You can filter by status, scan type, and search by URL.

Detailed Alerts (detailed-alerts.html)

From the Scan History, click on "Details" for a completed scan to see all detected alerts, sortable by risk level. You can also download a PDF report here.

AI Security Assistant (chatbot.html)

Click on "AI Assistant" from the dashboard to open the chatbot. Ask cybersecurity-related questions and receive expert advice.
