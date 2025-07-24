import re
import json

def parse_curl_command(curl_cmd):
    """
    Parse a curl command string and return a dict with url, method, headers, and data.
    Supports: -X, -H, -d, and URL at the end.
    Handles complex JSON data properly.
    """
    # Remove 'curl' from the beginning
    curl_cmd = curl_cmd.strip()
    if curl_cmd.startswith('curl'):
        curl_cmd = curl_cmd[4:].strip()
    
    method = 'GET'
    headers = {}
    data = None
    url = None
    
    # Split by lines to handle multi-line curl commands
    lines = curl_cmd.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        # Handle --location (same as -L)
        if line.startswith('--location'):
            continue
            
        # Handle method
        if line.startswith('-X ') or line.startswith('--request '):
            method = line.split(' ', 1)[1].strip().upper()
            continue
            
        # Handle headers
        if line.startswith('-H ') or line.startswith('--header '):
            header_part = line.split(' ', 1)[1].strip()
            # Remove quotes if present
            if header_part.startswith("'") and header_part.endswith("'"):
                header_part = header_part[1:-1]
            elif header_part.startswith('"') and header_part.endswith('"'):
                header_part = header_part[1:-1]
                
            if ':' in header_part:
                k, v = header_part.split(':', 1)
                headers[k.strip()] = v.strip()
            continue
            
        # Handle data
        if line.startswith('-d ') or line.startswith('--data '):
            data_part = line.split(' ', 1)[1].strip()
            # Remove quotes if present
            if data_part.startswith("'") and data_part.endswith("'"):
                data_part = data_part[1:-1]
            elif data_part.startswith('"') and data_part.endswith('"'):
                data_part = data_part[1:-1]
            data = data_part
            continue
            
        # Handle URL (if it's not a flag)
        if not line.startswith('-') and not line.startswith('--'):
            # Remove quotes if present
            if line.startswith("'") and line.endswith("'"):
                line = line[1:-1]
            elif line.startswith('"') and line.endswith('"'):
                line = line[1:-1]
            url = line
            continue
    
    # If no URL found, look for it in the original command
    if not url:
        # Try to find URL pattern
        url_match = re.search(r"'(https?://[^']+)'", curl_cmd)
        if url_match:
            url = url_match.group(1)
        else:
            # Look for URL without quotes
            url_match = re.search(r'https?://[^\s]+', curl_cmd)
            if url_match:
                url = url_match.group(0)
    
    # Try to parse data as JSON if it looks like JSON
    if data and (data.startswith('{') or data.startswith('[')):
        try:
            # Clean up the data string
            data = data.replace("\\'", "'").replace('\\"', '"')
            json.loads(data)  # Validate JSON
        except:
            # If JSON parsing fails, keep as string
            pass
    
    return {'url': url, 'method': method, 'headers': headers, 'data': data} 