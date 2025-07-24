import React, { useEffect, useState } from 'react';
import {
  Box,
  Typography,
  LinearProgress,
  Card,
  CardContent,
  Chip,
  Alert,
  Button,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from '@mui/material';
import {
  Security as SecurityIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Visibility as ViewIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useWebSocket } from '../hooks/useWebSocket';
import { scanAPI } from '../utils/apiClient';

interface ScanProgressProps {
  scanId: string;
  onUpdate: (status: any) => void;
  onComplete: () => void;
}

const ScanProgress: React.FC<ScanProgressProps> = ({ scanId, onUpdate, onComplete }) => {
  const [status, setStatus] = useState<any>(null);
  const [findings, setFindings] = useState<any>(null);
  const [error, setError] = useState('');
  const [debugMessages, setDebugMessages] = useState<string[]>([]);
  const navigate = useNavigate();

  const addDebugMessage = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setDebugMessages(prev => [`[${timestamp}] ${message}`, ...prev.slice(0, 4)]);
  };

  // WebSocket connection for real-time updates
  const { isConnected, lastMessage, sendMessage } = useWebSocket(`http://localhost:8000`, {
    onConnect: () => {
      console.log('Connected to WebSocket');
      addDebugMessage('🔌 WebSocket Connected');
      // Join the specific scan room for updates with a shorter delay
      setTimeout(() => {
        sendMessage('join_scan', { scan_id: scanId });
        addDebugMessage(`📡 Joined scan room: ${scanId.slice(0, 8)}...`);
      }, 100);
    },
    onMessage: (data) => {
      if (data.scan_id === scanId) {
        addDebugMessage(`📨 WebSocket update: ${data.status} ${data.progress}%`);
        setStatus(data);
        onUpdate(data);
        
        if (data.findings) {
          setFindings(data.findings);
        }
        
        if (data.status === 'completed') {
          setTimeout(onComplete, 2000); // Wait 2 seconds before clearing
        } else if (data.status === 'error') {
          setError(data.current_step);
          setTimeout(onComplete, 5000); // Wait 5 seconds before clearing
        }
      }
    },
    onError: (error) => {
      console.error('WebSocket error:', error);
      addDebugMessage('❌ WebSocket error');
      setError('Connection lost. Using polling...');
    }
  });

  // Polling for scan status (always active as primary method)
  useEffect(() => {
    const pollInterval = setInterval(async () => {
      try {
        const response = await scanAPI.getScanStatus(scanId);
        const data = response.data;
        
        // Only update if we got new data
        if (!status || data.progress !== status.progress || data.status !== status.status) {
          addDebugMessage(`📊 Poll update: ${data.status} ${data.progress}% - ${data.current_step}`);
          setStatus(data);
          onUpdate(data);
        }
        
        if (data.findings) {
          setFindings(data.findings);
        }
        
        if (data.status === 'completed' || data.status === 'error') {
          clearInterval(pollInterval);
          if (data.status === 'completed') {
            addDebugMessage('✅ Scan completed!');
            setTimeout(onComplete, 2000);
          } else {
            setError(data.error || 'Scan failed');
            addDebugMessage(`❌ Scan failed: ${data.error}`);
            setTimeout(onComplete, 5000);
          }
        }
      } catch (err) {
        console.error('Failed to poll scan status:', err);
        addDebugMessage('❌ Polling failed');
        setError('Connection lost. Retrying...');
      }
    }, 1000); // Poll every 1 second for better responsiveness

    return () => clearInterval(pollInterval);
  }, [scanId, onUpdate, onComplete, status]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'success';
      case 'error':
        return 'error';
      case 'running':
        return 'primary';
      default:
        return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckIcon color="success" />;
      case 'error':
        return <ErrorIcon color="error" />;
      case 'running':
        return <SecurityIcon color="primary" />;
      default:
        return <InfoIcon />;
    }
  };

  const handleViewReport = () => {
    navigate(`/report/${scanId}`);
  };

  if (!status) {
    return (
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            <SecurityIcon color="primary" />
            <Typography variant="h6">Initializing Scan...</Typography>
          </Box>
          <LinearProgress />
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Connecting to scanner...
          </Typography>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            {getStatusIcon(status.status)}
            <Typography variant="h6">
              Security Scan Progress
            </Typography>
          </Box>
          <Chip
            label={status.status.toUpperCase()}
            sx={{
              color: `${getStatusColor(status.status)}.main`,
              borderColor: `${getStatusColor(status.status)}.main`
            }}
            variant="outlined"
          />
        </Box>

        <Typography variant="body2" color="text.secondary" gutterBottom>
          Scan ID: {scanId.slice(0, 8)}...
        </Typography>

        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
            <Typography variant="body2">{status.current_step}</Typography>
            <Typography variant="body2">{status.progress}%</Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={status.progress}
            sx={{
              '& .MuiLinearProgress-bar': {
                backgroundColor: `${getStatusColor(status.status)}.main`
              }
            }}
          />
        </Box>

        {/* Debug Messages */}
        {debugMessages.length > 0 && (
          <Box sx={{ mb: 2 }}>
            <Typography variant="caption" color="text.secondary">
              Debug Info:
            </Typography>
            {debugMessages.map((msg, index) => (
              <Typography 
                key={index} 
                variant="caption" 
                sx={{ 
                  display: 'block', 
                  fontFamily: 'monospace', 
                  fontSize: '0.7rem',
                  color: 'text.secondary'
                }}
              >
                {msg}
              </Typography>
            ))}
          </Box>
        )}

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {findings && findings.api && (
          <Box sx={{ mb: 2 }}>
            <Typography variant="subtitle2" gutterBottom>
              Preliminary Findings:
            </Typography>
            <List dense>
              {Object.entries(findings.api).map(([key, value]: [string, any]) => {
                if (key === 'https') {
                  return (
                    <ListItem key={key}>
                      <ListItemIcon>
                        {value ? <CheckIcon color="success" /> : <ErrorIcon color="error" />}
                      </ListItemIcon>
                      <ListItemText
                        primary={`HTTPS: ${value ? 'Enabled' : 'Not Enabled'}`}
                      />
                    </ListItem>
                  );
                } else if (Array.isArray(value) && value.length > 0) {
                  return (
                    <ListItem key={key}>
                      <ListItemIcon>
                        <ErrorIcon color="error" />
                      </ListItemIcon>
                      <ListItemText
                        primary={`${key.replace('_', ' ').toUpperCase()}: ${value.length} issue(s) found`}
                      />
                    </ListItem>
                  );
                }
                return null;
              })}
            </List>
          </Box>
        )}

        {status.status === 'completed' && (
          <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
            <Button
              variant="contained"
              startIcon={<ViewIcon />}
              onClick={handleViewReport}
              size="large"
            >
              View Full Report
            </Button>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default ScanProgress; 