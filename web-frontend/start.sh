#!/bin/bash

echo "🚀 Starting CyberSec Bot Web Frontend..."
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check dependencies
echo "📋 Checking dependencies..."

if ! command_exists python3; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

if ! command_exists node; then
    echo "❌ Node.js is required but not installed."
    exit 1
fi

if ! command_exists npm; then
    echo "❌ npm is required but not installed."
    exit 1
fi

echo "✅ All dependencies found!"
echo ""

# Install backend dependencies
echo "📦 Installing backend dependencies..."
cd backend

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "🔧 Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment and install dependencies
source venv/bin/activate
if [ ! -f "requirements_installed.flag" ]; then
    pip install -r requirements-minimal.txt
    touch requirements_installed.flag
    echo "✅ Backend dependencies installed!"
else
    echo "✅ Backend dependencies already installed!"
    echo "🔄 Checking for new dependencies..."
    pip install -r requirements-minimal.txt --quiet
fi
cd ..
echo ""

# Install frontend dependencies
echo "📦 Installing frontend dependencies..."
cd frontend
if [ ! -d "node_modules" ]; then
    npm install
    echo "✅ Frontend dependencies installed!"
else
    echo "✅ Frontend dependencies already installed!"
    echo "🔄 Checking for new dependencies..."
    npm install --silent
fi
cd ..
echo ""

# Function to start backend
start_backend() {
    echo "🔧 Starting Flask backend server..."
    cd backend
    source venv/bin/activate && python3 app.py &
    BACKEND_PID=$!
    cd ..
    echo "✅ Backend server started (PID: $BACKEND_PID)"
    echo "   API available at: http://localhost:8000"
}

# Function to start frontend
start_frontend() {
    echo "🎨 Starting React frontend server..."
    cd frontend
    npm start &
    FRONTEND_PID=$!
    cd ..
    echo "✅ Frontend server started (PID: $FRONTEND_PID)"
    echo "   Web app available at: http://localhost:3000"
}

# Start both servers
start_backend
sleep 3  # Give backend time to start
start_frontend

echo ""
echo "🎉 CyberSec Bot Web Frontend is now running!"
echo ""
echo "📱 Open your browser and navigate to:"
echo "   http://localhost:3000"
echo ""
echo "🔗 Backend API is available at:"
echo "   http://localhost:8000"
echo ""
echo "💡 Press Ctrl+C to stop both servers"
echo ""

# Wait for interrupt signal
trap 'echo ""; echo "🛑 Shutting down servers..."; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0' INT

# Keep script running
wait 