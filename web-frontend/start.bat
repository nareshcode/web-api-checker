@echo off
echo 🚀 Starting CyberSec Bot Web Frontend...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is required but not installed.
    pause
    exit /b 1
)

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Node.js is required but not installed.
    pause
    exit /b 1
)

REM Check if npm is installed
npm --version >nul 2>&1
if errorlevel 1 (
    echo ❌ npm is required but not installed.
    pause
    exit /b 1
)

echo ✅ All dependencies found!
echo.

REM Install backend dependencies
echo 📦 Installing backend dependencies...
cd backend
if not exist "requirements_installed.flag" (
    pip install -r requirements.txt
    echo. > requirements_installed.flag
    echo ✅ Backend dependencies installed!
) else (
    echo ✅ Backend dependencies already installed!
)
cd ..
echo.

REM Install frontend dependencies
echo 📦 Installing frontend dependencies...
cd frontend
if not exist "node_modules" (
    npm install
    echo ✅ Frontend dependencies installed!
) else (
    echo ✅ Frontend dependencies already installed!
    echo 🔄 Checking for new dependencies...
    npm install --silent
)
cd ..
echo.

echo 🔧 Starting Flask backend server...
cd backend
start "CyberSec Bot Backend" cmd /k python app.py
cd ..

echo 🎨 Starting React frontend server...
timeout /t 3 /nobreak >nul
cd frontend
start "CyberSec Bot Frontend" cmd /k npm start
cd ..

echo.
echo 🎉 CyberSec Bot Web Frontend is now starting!
echo.
echo 📱 Open your browser and navigate to:
echo    http://localhost:3000
echo.
echo 🔗 Backend API will be available at:
echo    http://localhost:8000
echo.
echo 💡 Both servers will open in separate command windows
echo 💡 Close those windows to stop the servers
echo.

pause 