# Demo Commands for CyberSec Bot Web Frontend

Here are some sample curl commands you can use to test the web frontend:

## Basic GET Request
```bash
curl https://httpbin.org/get
```

## POST with JSON Data
```bash
curl -X POST https://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password123"}'
```

## Request with Authentication Header
```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" \
  -H "Content-Type: application/json" \
  https://httpbin.org/bearer
```

## Complex Request with Multiple Headers
```bash
curl --location 'https://api.example.com/v1/users' \
  --header 'Authorization: Bearer token123' \
  --header 'X-API-Key: abc123' \
  --header 'Content-Type: application/json' \
  --data '{"email":"test@example.com","role":"admin"}'
```

## Banking API Example (From Your Existing Report)
```bash
curl --location 'https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false' \
  --header 'u-session-token: 01K0YJ2HRAQHKEBFV5DQY8BDS8' \
  --header 'traceparent: 00-B2F2C5F047404E1A9CDA9C23DF82DD59-00000000684373b1-01' \
  --header 'x-slice-checksum: 2f30cd7962868f8ae7a1cbcff58e4a9f36db1fd3d8a832e98482f20e07d09fcc|1753372255827|IST' \
  --header 'Platform: ios:89376' \
  --header 'device-id: D8CBA312-59C8-4CF3-9475-A5E9CDBA514E' \
  --header 'Content-Type: application/json'
```

## Simple URLs for Quick Testing

You can also just paste these URLs without curl syntax:

- `https://httpbin.org/get`
- `https://httpbin.org/json`
- `https://jsonplaceholder.typicode.com/posts/1`
- `https://reqres.in/api/users`

## Testing Different Severity Levels

Try these commands with different severity levels:

### Critical (fastest, ~5 minutes)
- Only tests for SQL injection, command injection, XXE, SSRF

### High (~10 minutes)  
- Adds XSS, NoSQL injection, LDAP injection, path traversal

### Medium (~15 minutes)
- Adds security headers, CORS configuration

### All (~20 minutes)
- Complete comprehensive security assessment

## Expected Results

When you run these commands through the web frontend, you should see:

1. **Real-time Progress**: Live updates as the scan progresses
2. **Security Score**: Calculated based on findings
3. **Detailed Report**: Markdown-formatted with attack/fix code
4. **Vulnerability Breakdown**: Categorized by severity
5. **Download Options**: Save reports as markdown files

## Tips for Testing

- Start with simple URLs to test the basic functionality
- Use the "Critical" severity level for faster testing
- Try the Banking API example to see a real-world scan
- Check the Network tab in browser dev tools to see API calls
- Monitor the browser console for WebSocket connection status 