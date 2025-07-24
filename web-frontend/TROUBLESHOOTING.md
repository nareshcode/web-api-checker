# Troubleshooting Guide

## Common Issues and Solutions

### ❌ Proxy Error: Could not proxy request from localhost:3000 to localhost:8000

**Problem**: Getting proxy errors for favicon.ico or other static assets.

**Solution**: 
1. Make sure you have the latest version of the code with `setupProxy.js`
2. Restart both servers:
   ```bash
   # Stop both servers (Ctrl+C)
   cd web-frontend
   ./start.sh  # or start.bat on Windows
   ```

**What was fixed**: 
- Configured proxy to only handle `/api` and `/socket.io` requests
- Disabled favicon to prevent proxy conflicts
- Added `http-proxy-middleware` dependency

### ❌ Backend Import Errors

**Problem**: 
```
ModuleNotFoundError: No module named 'scraper'
```

**Solution**:
1. Make sure you're running the backend from the correct directory:
   ```bash
   cd web-frontend/backend
   python app.py
   ```
2. The backend looks for scanner modules in the parent directory
3. Ensure the original scanner code is in the project root

### ❌ Frontend Dependencies Missing

**Problem**: 
```
Module not found: Can't resolve '@mui/material'
```

**Solution**:
```bash
cd web-frontend/frontend
npm install
```

### ❌ WebSocket Connection Failed

**Problem**: Real-time updates not working, console shows WebSocket errors.

**Solutions**:
1. **Check Backend is Running**: Ensure Flask server is running on port 8000
2. **Check Ports**: Make sure ports 3000 and 8000 are not in use by other applications
3. **Restart Servers**: Stop and restart both frontend and backend
4. **Fallback Mode**: The app automatically falls back to polling if WebSocket fails

### ❌ CORS Errors

**Problem**: 
```
Access to XMLHttpRequest blocked by CORS policy
```

**Solution**: The backend is configured with CORS for localhost:3000. If you're running on different ports:
1. Update CORS configuration in `backend/app.py`:
   ```python
   CORS(app, origins=["http://localhost:YOUR_PORT"])
   ```

### ❌ Port Already in Use

**Problem**: 
```
Error: listen EADDRINUSE: address already in use :::3000
```

**Solutions**:
1. **Kill existing processes**:
   ```bash
   # Find and kill process on port 3000
   lsof -ti:3000 | xargs kill -9
   
   # Find and kill process on port 8000  
   lsof -ti:8000 | xargs kill -9
   ```
2. **Use different ports**: Modify the ports in the configuration files

### ❌ Scan Not Starting

**Problem**: Clicking "Start Security Scan" doesn't work.

**Checklist**:
1. ✅ Backend server running on port 8000
2. ✅ Valid URL or curl command entered
3. ✅ No console errors in browser dev tools
4. ✅ Network tab shows API request being made

**Debug Steps**:
1. Open browser dev tools (F12)
2. Check Console tab for errors
3. Check Network tab to see if API requests are being made
4. Verify backend logs for error messages

### ❌ Report Not Loading

**Problem**: Clicking "View Report" shows loading indefinitely.

**Solutions**:
1. **Check Scan Status**: Ensure scan completed successfully
2. **Backend Logs**: Check Flask server logs for errors
3. **Browser Cache**: Try hard refresh (Ctrl+Shift+R)
4. **API Check**: Verify `/api/report/{scanId}` endpoint works

### ❌ Real-time Updates Not Working

**Problem**: Progress bar doesn't update during scan.

**Solutions**:
1. **WebSocket Connection**: Check browser console for WebSocket errors
2. **Fallback Polling**: App should automatically fall back to polling
3. **Backend Logs**: Check if progress events are being emitted
4. **Restart**: Try restarting both servers

## Advanced Debugging

### Enable Debug Mode

**Frontend**:
```bash
export REACT_APP_DEBUG=true
npm start
```

**Backend**:
```bash
export FLASK_DEBUG=1
python app.py
```

### Check API Endpoints Manually

Test backend endpoints directly:

```bash
# Health check
curl http://localhost:8000/api/health

# Start a scan
curl -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target":"https://httpbin.org/get","severity":"critical"}'

# Check scan status
curl http://localhost:8000/api/scan/{SCAN_ID}
```

### Browser Developer Tools

1. **Console Tab**: Check for JavaScript errors
2. **Network Tab**: Monitor API requests and responses
3. **Application Tab**: Check WebSocket connections
4. **Sources Tab**: Set breakpoints for debugging

## Performance Issues

### Slow Scans

**Causes**:
- Using "All" severity level (20+ minutes)
- Target server is slow to respond
- Network connectivity issues

**Solutions**:
- Use "Critical" severity for faster testing
- Test with fast endpoints like httpbin.org
- Check network connectivity

### Memory Usage

**High Memory Usage**:
- Large reports with many vulnerabilities
- Multiple concurrent scans

**Solutions**:
- Limit to one scan at a time
- Restart browsers/servers periodically
- Use lower severity levels for testing

## Getting Help

If you're still experiencing issues:

1. **Check Browser Console**: Look for error messages
2. **Check Backend Logs**: Look at Flask server output
3. **Test Simple Cases**: Try with `https://httpbin.org/get`
4. **Restart Everything**: Stop and restart all servers
5. **Clean Install**: Delete `node_modules` and reinstall

### Useful Commands

```bash
# Clean frontend install
cd web-frontend/frontend
rm -rf node_modules package-lock.json
npm install

# Clean backend install  
cd web-frontend/backend
pip uninstall -y -r requirements.txt
pip install -r requirements.txt

# Check processes
ps aux | grep python
ps aux | grep node

# Kill processes
pkill -f "python app.py"
pkill -f "npm start"
``` 