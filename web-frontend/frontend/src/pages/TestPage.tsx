import React, { useState, useEffect } from 'react';
import {
  Container,
  Typography,
  Button,
  Card,
  CardContent,
  Alert,
  Box,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import { useWebSocket } from '../hooks/useWebSocket';
import { apiClient } from '../utils/apiClient';

const TestPage: React.FC = () => {
  const [messages, setMessages] = useState<string[]>([]);
  const [scanId, setScanId] = useState<string>('');
  const [connected, setConnected] = useState(false);

  const { isConnected, sendMessage } = useWebSocket('http://localhost:8000', {
    onConnect: () => {
      addMessage('✅ WebSocket Connected!');
      setConnected(true);
    },
    onDisconnect: () => {
      addMessage('❌ WebSocket Disconnected');
      setConnected(false);
    },
    onMessage: (data) => {
      addMessage(`📨 Received: ${JSON.stringify(data)}`);
    },
    onError: (error) => {
      addMessage(`❌ WebSocket Error: ${error}`);
    }
  });

  const addMessage = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setMessages(prev => [`[${timestamp}] ${message}`, ...prev.slice(0, 19)]);
  };

  const testBackendHealth = async () => {
    try {
      const response = await apiClient.get('/api/health');
      addMessage(`✅ Backend Health: ${response.data.message}`);
    } catch (error) {
      addMessage(`❌ Backend Health Failed: ${error}`);
    }
  };

  const startTestScan = async () => {
    try {
      const response = await apiClient.post('/api/scan/start', {
        target: 'https://httpbin.org/get',
        severity: 'critical'
      });
      const newScanId = response.data.scan_id;
      setScanId(newScanId);
      addMessage(`🚀 Started scan: ${newScanId}`);
      
      // Join the scan room if WebSocket is connected
      if (isConnected) {
        sendMessage('join_scan', { scan_id: newScanId });
        addMessage(`🔗 Joined scan room: ${newScanId}`);
      }
    } catch (error: any) {
      addMessage(`❌ Scan Start Failed: ${error.response?.data?.error || error.message}`);
    }
  };

  const checkScanStatus = async () => {
    if (!scanId) {
      addMessage('❌ No scan ID to check');
      return;
    }
    
    try {
      const response = await apiClient.get(`/api/scan/${scanId}`);
      addMessage(`📊 Scan Status: ${response.data.status} (${response.data.progress}%) - ${response.data.current_step}`);
    } catch (error: any) {
      addMessage(`❌ Status Check Failed: ${error.response?.data?.error || error.message}`);
    }
  };

  useEffect(() => {
    addMessage('🔄 Test page loaded');
    testBackendHealth();
  }, []);

  return (
    <Container maxWidth="lg">
      <Typography variant="h4" gutterBottom>
        🧪 Real-time Updates Test Page
      </Typography>
      
      <Box sx={{ mb: 3 }}>
        <Alert severity={connected ? 'success' : 'warning'}>
          WebSocket Status: {connected ? '✅ Connected' : '❌ Disconnected'}
        </Alert>
      </Box>

      <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
        <Button variant="contained" onClick={testBackendHealth}>
          Test Backend Health
        </Button>
        <Button variant="contained" onClick={startTestScan} color="secondary">
          Start Test Scan
        </Button>
        <Button variant="outlined" onClick={checkScanStatus} disabled={!scanId}>
          Check Scan Status
        </Button>
        <Button variant="outlined" onClick={() => setMessages([])}>
          Clear Messages
        </Button>
      </Box>

      {scanId && (
        <Alert severity="info" sx={{ mb: 2 }}>
          Current Scan ID: {scanId}
        </Alert>
      )}

      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Debug Messages
          </Typography>
          <List sx={{ maxHeight: 400, overflow: 'auto' }}>
            {messages.map((message, index) => (
              <ListItem key={index} sx={{ py: 0.5 }}>
                <ListItemText 
                  primary={message}
                  sx={{ 
                    fontFamily: 'monospace',
                    fontSize: '0.875rem',
                    color: message.includes('❌') ? 'error.main' : 
                           message.includes('✅') ? 'success.main' : 'text.primary'
                  }}
                />
              </ListItem>
            ))}
          </List>
        </CardContent>
      </Card>
    </Container>
  );
};

export default TestPage; 