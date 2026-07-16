# RAVN AI — Enterprise Security Platform

Python Flask application for automated website security monitoring, vulnerability scanning, and threat management, powered by AI.

## Overview
RAVN AI acts as an automated Security Operations Center (SOC). It allows administrators to monitor web assets continuously. The system performs background checks every 5 minutes to detect:
- SSL certificate expirations and misconfigurations.
- Missing HTTP security headers.
- DNS configurations (like SPF records).
- Website defacements and content anomalies.

It leverages **Groq API (Llama 3)** to analyze raw scan data and intelligently determine vulnerabilities, severities, and remediation steps. A fallback static rule engine ensures the system remains operational even if the AI service is unreachable.

## Quick Start

### Prerequisites
- Python 3.8+
- Groq API Key (Optional, for AI Analysis)
- Google Client ID (Optional, for Google SSO)

### Installation
```bash
git clone https://github.com/Abimanyu123-1505/RAVN-AI.git
cd RAVN-AI
python -m venv venv

# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

### Configuration
Create a `.env` file in the root directory and add the following variables:
```ini
RAVN_SECRET_KEY=your_secure_random_key
GROQ_API_KEY=your_groq_api_key_here
GOOGLE_CLIENT_ID=your_google_sso_client_id_here
```

### Run the Application
```bash
python app.py
```
Open **http://localhost:5000** in your browser.

## Demo Credentials

| Email | Password | Role |
|-------|----------|------|
| admin@ravn.ai | admin123 | Admin |

## Features

- **Continuous Monitoring** — APScheduler runs background jobs every 5 minutes to detect content defacements.
- **AI-Powered Vulnerability Analysis** — Uses Groq API (Llama-3.3-70b-versatile) to dynamically categorize threats.
- **Dashboard** — Real-time security metrics with Chart.js visualizations.
- **Websites** — Add, monitor, and scan web assets with live SSL/header/DNS checks.
- **Alerting** — Webhook dispatcher for Slack notifications on critical alerts.
- **Authentication** — Local authentication and Google SSO.

## Tech Stack

- **Backend:** Python 3, Flask, APScheduler
- **AI Integration:** Groq API (Llama 3)
- **Database:** SQLite
- **Frontend:** Jinja2 templates, Custom CSS
- **Charts:** Chart.js

---

## Contributing 🤝

We welcome contributions from the community! Whether it's fixing bugs, improving documentation, or adding new features, your help is appreciated.

### How to Contribute

1. **Fork the Repository:** Click the "Fork" button at the top right of this page.
2. **Clone your Fork:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/RAVN-AI.git
   cd RAVN-AI
   ```
3. **Create a Branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Make your Changes:** Implement your feature or bug fix.
5. **Commit your Changes:**
   ```bash
   git commit -m "Add some feature"
   ```
6. **Push to your Fork:**
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Open a Pull Request:** Go to the original repository and click "New Pull Request".

### Contribution Guidelines
- Ensure your code follows standard Python PEP 8 conventions.
- Update the `README.md` if your changes add new features or require new environment variables.
- Be respectful and constructive in pull request reviews and issues.

## License
This project is open-source and available under the MIT License.
