# CyberSec Bot - Web Frontend

A modern React.js web interface for the CyberSec Bot API security scanner, built with Material UI and TypeScript.

## Features

- Interactive Curl Input: Paste curl commands or URLs to scan
- Real-time Progress: WebSocket-powered live scan updates  
- Beautiful Reports: Markdown rendering with syntax highlighting
- Security Score: Visual security scoring and vulnerability breakdown
- Scan History: View all previous scans and reports
- Material UI: Modern, responsive design
- TypeScript: Type-safe development

## Quick Start

### 1. Install Backend Dependencies

```bash
cd web-frontend/backend
pip install -r requirements.txt
```

### 2. Install Frontend Dependencies

```bash
cd web-frontend/frontend
npm install
```

### 3. Start the Backend API Server

```bash
cd web-frontend/backend
python app.py
```

The Flask API will be available at http://localhost:8000

### 4. Start the Frontend Development Server

```bash
cd web-frontend/frontend
npm start
```

The React app will be available at http://localhost:3000

## Usage

1. Navigate to the Dashboard (http://localhost:3000)
2. Enter a curl command or URL in the input field
3. Select severity level (Critical, High, Medium, All)
4. Click "Start Security Scan"
5. Monitor real-time progress
6. View detailed reports with attack/fix code
7. Download reports as markdown files 