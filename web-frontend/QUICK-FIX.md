# Quick Fix for "Failed to start scan" Error

## 🚨 Problem
Getting "Failed to start scan" error when clicking "Start Security Scan" button.

## ✅ Solution

### Step 1: Set Up Backend Properly
```bash
cd web-frontend/backend

# Create virtual environment
python3 -m venv venv

# Activate virtual environment  
source venv/bin/activate

# Install dependencies
pip install -r requirements-minimal.txt
```

### Step 2: Start Backend Server
```bash
# Make sure you're in web-frontend/backend directory
# and virtual environment is activated
source venv/bin/activate
python3 app.py
```

**Expected output:**
```
Starting CyberSec Bot API server...
API will be available at: http://localhost:8000
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8000
 * Running on http://localhost:8000
```

### Step 3: Test Backend (Optional)
```bash
# In a new terminal
cd web-frontend
python3 test-backend.py
```

### Step 4: Start Frontend
```bash
# In a new terminal
cd web-frontend/frontend
npm install
npm start
```

## 🔧 Alternative: Use Updated Startup Script
```bash
cd web-frontend
./start.sh
```

## ✅ Verification

1. **Backend running**: Visit http://localhost:8000/api/health
   - Should show: `{"status": "healthy", "message": "CyberSec Bot API is running"}`

2. **Frontend running**: Visit http://localhost:3000
   - Should show the CyberSec Bot dashboard

3. **Test a scan**: 
   - Enter: `https://httpbin.org/get`
   - Select: "Critical" severity
   - Click: "Start Security Scan"

## 🐛 Still Having Issues?

### Check Backend Logs
Look for these error messages:
- `ModuleNotFoundError: No module named 'scraper'` → Scanner modules not found
- `ModuleNotFoundError: No module named 'requests'` → Dependencies not installed
- `AssertionError: write() before start_response` → SocketIO issue (can be ignored)

### Manual API Test
```bash
# Test health endpoint
curl http://localhost:8000/api/health

# Test scan start
curl -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target":"https://httpbin.org/get","severity":"critical"}'
```

### Common Fixes
1. **Kill existing processes**:
   ```bash
   pkill -f "python.*app.py"
   pkill -f "npm start"
   ```

2. **Clean restart**:
   ```bash
   cd web-frontend/backend
   rm -rf venv
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements-minimal.txt
   python3 app.py
   ```

## 📋 What Was Fixed

1. **Dependencies**: Created `requirements-minimal.txt` without problematic database libraries
2. **Virtual Environment**: Proper isolation from system Python
3. **Import Path**: Correctly configured to find scanner modules
4. **Startup Scripts**: Updated to use virtual environment
5. **Testing**: Added test script to verify backend functionality

The main issue was that the backend dependencies weren't properly installed in a virtual environment, which is required on modern macOS systems. 