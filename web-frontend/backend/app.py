from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
import uuid
import threading
import time
import sys
import os
import json
from datetime import datetime

# Add the parent directory to sys.path to import from the existing scanner
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from scraper import api_scanner
from report import report_generator
from utils.curl_parser import parse_curl_command

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cybersec-bot-secret-key'
CORS(app, origins=["http://localhost:3000"])

# Improved SocketIO configuration
socketio = SocketIO(
    app, 
    cors_allowed_origins="http://localhost:3000",
    logger=False,  # Disable verbose logging
    engineio_logger=False,  # Disable engine.io logging
    async_mode='threading',  # Use threading mode for better compatibility
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=1000000,  # 1MB buffer
    allow_upgrades=True,
    transports=['websocket', 'polling']
)

# In-memory storage for scans (session-based)
active_scans = {}
completed_scans = {}

class ScanProgress:
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.status = 'initializing'
        self.progress = 0
        self.current_step = 'Preparing scan...'
        self.start_time = datetime.now()
        self.end_time = None
        self.findings = {}
        self.report_content = None
        self.error = None

def emit_progress(scan_id, status, progress, step, findings=None):
    """Emit scan progress to connected clients"""
    try:
        progress_data = {
            'scan_id': scan_id,
            'status': status,
            'progress': progress,
            'current_step': step,
            'timestamp': datetime.now().isoformat()
        }
        if findings:
            progress_data['findings'] = findings
        
        socketio.emit('scan_progress', progress_data, room=f'scan_{scan_id}')
        print(f"BE is sending progress: {progress}%")
    except Exception as e:
        print(f"[ERROR] Failed to emit progress: {e}")

def run_scan_async(scan_id, target, curl_info, severity):
    """Run the scan asynchronously and emit progress updates"""
    print(f"[DEBUG] Starting scan thread for {scan_id}")
    try:
        scan_progress = active_scans[scan_id]
        print(f"[DEBUG] Found scan progress object for {scan_id}")
        
        # Step 1: Initialize
        print(f"[DEBUG] Step 1: Initializing scan {scan_id}")
        scan_progress.status = 'running'
        scan_progress.progress = 10
        scan_progress.current_step = 'Initializing security scanner...'
        emit_progress(scan_id, 'running', 10, 'Initializing security scanner...')
        time.sleep(1)
        
        # Step 2: Parse input
        print(f"[DEBUG] Step 2: Parsing input for {scan_id}")
        scan_progress.progress = 20
        scan_progress.current_step = 'Parsing target and configuration...'
        emit_progress(scan_id, 'running', 20, 'Parsing target and configuration...')
        time.sleep(1)
        
        # Step 3: Start scanning with incremental progress
        print(f"[DEBUG] Step 3: Starting security checks for {scan_id}")
        scan_progress.progress = 30
        scan_progress.current_step = 'Running security checks...'
        emit_progress(scan_id, 'running', 30, 'Running security checks...')
        
        # Step 4: Add incremental progress during scanning
        print(f"[DEBUG] Step 4: Running actual scan for {scan_id} with severity {severity}")
        
        # Break scanning into smaller progress increments
        scan_progress.progress = 35
        scan_progress.current_step = 'Testing HTTPS and authentication...'
        emit_progress(scan_id, 'running', 35, 'Testing HTTPS and authentication...')
        time.sleep(0.5)
        
        scan_progress.progress = 40
        scan_progress.current_step = 'Checking for injection vulnerabilities...'
        emit_progress(scan_id, 'running', 40, 'Checking for injection vulnerabilities...')
        time.sleep(0.5)
        
        scan_progress.progress = 45
        scan_progress.current_step = 'Testing for XSS vulnerabilities...'
        emit_progress(scan_id, 'running', 45, 'Testing for XSS vulnerabilities...')
        time.sleep(0.5)
        
        scan_progress.progress = 50
        scan_progress.current_step = 'Analyzing security headers...'
        emit_progress(scan_id, 'running', 50, 'Analyzing security headers...')
        time.sleep(0.5)
        
        scan_progress.progress = 55
        scan_progress.current_step = 'Testing authentication bypass...'
        emit_progress(scan_id, 'running', 55, 'Testing authentication bypass...')
        time.sleep(0.5)
        
        scan_progress.progress = 60
        scan_progress.current_step = 'Performing deep security analysis...'
        emit_progress(scan_id, 'running', 60, 'Performing deep security analysis...')
        
        # Perform the actual scan
        findings = {'api': api_scanner.scan_api(target, curl_info=curl_info, severity=severity)}
        print(f"[DEBUG] Scan completed for {scan_id}, found {len(findings.get('api', {}))} findings")
        
        scan_progress.progress = 70
        scan_progress.current_step = 'Analyzing vulnerabilities...'
        scan_progress.findings = findings
        emit_progress(scan_id, 'running', 70, 'Analyzing vulnerabilities...', findings)
        time.sleep(1)
        
        # Step 5: Generate report
        print(f"[DEBUG] Step 5: Generating report for {scan_id}")
        scan_progress.progress = 85
        scan_progress.current_step = 'Generating security report...'
        emit_progress(scan_id, 'running', 85, 'Generating security report...')
        
        # Generate report content
        report_path = f'/tmp/report_{scan_id}.md'
        report_generator.generate_report(
            findings, 
            report_path, 
            api_url=target, 
            curl_cmd=None, 
            curl_info=curl_info, 
            severity=severity
        )
        
        # Read the generated report
        with open(report_path, 'r') as f:
            report_content = f.read()
        
        # Clean up temp file
        os.remove(report_path)
        
        # Complete the scan
        print(f"[DEBUG] Step 6: Completing scan {scan_id}")
        scan_progress.status = 'completed'
        scan_progress.progress = 100
        scan_progress.current_step = 'Scan completed successfully!'
        scan_progress.end_time = datetime.now()
        scan_progress.findings = findings
        scan_progress.report_content = report_content
        
        # Move to completed scans
        completed_scans[scan_id] = scan_progress
        del active_scans[scan_id]
        
        emit_progress(scan_id, 'completed', 100, 'Scan completed successfully!', findings)
        print(f"[DEBUG] Scan {scan_id} completed successfully!")
        
    except Exception as e:
        # Handle errors
        print(f"[ERROR] Scan {scan_id} failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        
        scan_progress = active_scans.get(scan_id)
        if scan_progress:
            scan_progress.status = 'error'
            scan_progress.error = str(e)
            scan_progress.end_time = datetime.now()
            
            completed_scans[scan_id] = scan_progress
            if scan_id in active_scans:
                del active_scans[scan_id]
            
            emit_progress(scan_id, 'error', 100, f'Scan failed: {str(e)}')

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'message': 'CyberSec Bot API is running'})

@app.route('/api/test-scan', methods=['POST'])
def test_scan():
    """Test endpoint to verify real-time updates work"""
    scan_id = str(uuid.uuid4())
    
    def test_progress():
        for i in range(0, 101, 20):
            emit_progress(scan_id, 'running', i, f'Test step {i}%')
            time.sleep(1)
        emit_progress(scan_id, 'completed', 100, 'Test completed!')
    
    thread = threading.Thread(target=test_progress)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'message': 'Test scan started'
    })

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    try:
        data = request.get_json()
        
        # Validate input
        if not data or not data.get('target'):
            return jsonify({'error': 'Target URL or curl command is required'}), 400
        
        target_input = data['target'].strip()
        severity = data.get('severity', 'all')
        
        # Parse curl command or URL
        if target_input.lower().startswith('curl'):
            curl_info = parse_curl_command(target_input)
            target = curl_info['url']
            curl_cmd = target_input
        else:
            target = target_input
            curl_info = {'url': target, 'method': 'GET', 'headers': {}, 'data': None}
            curl_cmd = None
        
        if not target:
            return jsonify({'error': 'Invalid target URL'}), 400
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scan progress tracker
        scan_progress = ScanProgress(scan_id)
        active_scans[scan_id] = scan_progress
        
        # Start scan in background thread
        print(f"[DEBUG] Creating thread for scan {scan_id}")
        thread = threading.Thread(
            target=run_scan_async, 
            args=(scan_id, target, curl_info, severity)
        )
        thread.daemon = True
        thread.start()
        print(f"[DEBUG] Thread started for scan {scan_id}")
        
        # Give the thread a moment to start
        time.sleep(0.1)
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'target': target,
            'severity': severity,
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to start scan: {str(e)}'}), 500

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """Get the status of a specific scan"""
    try:
        # Check active scans
        if scan_id in active_scans:
            scan = active_scans[scan_id]
            return jsonify({
                'scan_id': scan_id,
                'status': scan.status,
                'progress': scan.progress,
                'current_step': scan.current_step,
                'start_time': scan.start_time.isoformat(),
                'findings': scan.findings
            })
        
        # Check completed scans
        if scan_id in completed_scans:
            scan = completed_scans[scan_id]
            result = {
                'scan_id': scan_id,
                'status': scan.status,
                'progress': scan.progress,
                'current_step': scan.current_step,
                'start_time': scan.start_time.isoformat(),
                'end_time': scan.end_time.isoformat() if scan.end_time else None,
                'findings': scan.findings
            }
            
            if scan.error:
                result['error'] = scan.error
            
            return jsonify(result)
        
        return jsonify({'error': 'Scan not found'}), 404
        
    except Exception as e:
        return jsonify({'error': f'Failed to get scan status: {str(e)}'}), 500

@app.route('/api/report/<scan_id>', methods=['GET'])
def get_report(scan_id):
    """Get the full report for a completed scan"""
    try:
        if scan_id not in completed_scans:
            return jsonify({'error': 'Report not found'}), 404
        
        scan = completed_scans[scan_id]
        
        if scan.status != 'completed':
            return jsonify({'error': 'Scan not completed yet'}), 400
        
        return jsonify({
            'scan_id': scan_id,
            'report_content': scan.report_content,
            'findings': scan.findings,
            'start_time': scan.start_time.isoformat(),
            'end_time': scan.end_time.isoformat(),
            'duration': (scan.end_time - scan.start_time).total_seconds()
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get report: {str(e)}'}), 500

@app.route('/api/scans', methods=['GET'])
def list_scans():
    """List all scans (active and completed)"""
    try:
        scans = []
        
        # Add active scans
        for scan_id, scan in active_scans.items():
            scans.append({
                'scan_id': scan_id,
                'status': scan.status,
                'progress': scan.progress,
                'start_time': scan.start_time.isoformat(),
                'current_step': scan.current_step
            })
        
        # Add completed scans
        for scan_id, scan in completed_scans.items():
            scans.append({
                'scan_id': scan_id,
                'status': scan.status,
                'progress': scan.progress,
                'start_time': scan.start_time.isoformat(),
                'end_time': scan.end_time.isoformat() if scan.end_time else None,
                'error': scan.error if scan.error else None
            })
        
        # Sort by start time (newest first)
        scans.sort(key=lambda x: x['start_time'], reverse=True)
        
        return jsonify({'scans': scans})
        
    except Exception as e:
        return jsonify({'error': f'Failed to list scans: {str(e)}'}), 500

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    try:
        print(f'Client connected: {request.sid}')
        emit('connected', {'message': 'Connected to CyberSec Bot'})
    except Exception as e:
        print(f"[ERROR] Connect handler failed: {e}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    try:
        print(f'Client disconnected: {request.sid}')
    except Exception as e:
        print(f"[ERROR] Disconnect handler failed: {e}")

@socketio.on('join_scan')
def handle_join_scan(data):
    """Join a specific scan room for updates"""
    try:
        scan_id = data.get('scan_id')
        if scan_id:
            join_room(f'scan_{scan_id}')
            emit('joined_scan', {'scan_id': scan_id})
            print(f'Client {request.sid} joined scan room: {scan_id}')
    except Exception as e:
        print(f"[ERROR] Join scan handler failed: {e}")

@socketio.on_error_default
def default_error_handler(e):
    """Default error handler for Socket.IO events"""
    print(f"[ERROR] Socket.IO error: {e}")
    return False

if __name__ == '__main__':
    print("Starting CyberSec Bot API server...")
    print("API will be available at: http://localhost:8000")
    print("WebSocket endpoint: ws://localhost:8000/socket.io/")
    try:
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=8000, 
            debug=True,
            use_reloader=False,  # Prevent double initialization
            log_output=False     # Reduce verbose logging
        )
    except Exception as e:
        print(f"[ERROR] Failed to start server: {e}")
        raise 