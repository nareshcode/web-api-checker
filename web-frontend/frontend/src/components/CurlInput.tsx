import React, { useState } from 'react';
import {
  Box,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Typography,
  Alert,
  Chip,
  Stack,
} from '@mui/material';
import { Send as SendIcon, Code as CodeIcon } from '@mui/icons-material';
import { apiClient } from '../utils/apiClient';

interface CurlInputProps {
  onScanStart: (scanId: string) => void;
  disabled?: boolean;
}

const CurlInput: React.FC<CurlInputProps> = ({ onScanStart, disabled = false }) => {
  const [target, setTarget] = useState('');
  const [severity, setSeverity] = useState('all');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const sampleCurls = [
    {
      name: 'Basic GET Request',
      value: 'curl https://api.example.com/users'
    },
    {
      name: 'POST with Authentication',
      value: 'curl -X POST https://api.example.com/auth/login -H "Content-Type: application/json" -d \'{"username":"admin","password":"password"}\''
    },
    {
      name: 'API with Headers',
      value: 'curl -H "Authorization: Bearer token123" -H "Content-Type: application/json" https://api.example.com/protected'
    }
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!target.trim()) {
      setError('Please enter a URL or curl command');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const response = await apiClient.post('/api/scan/start', {
        target: target.trim(),
        severity
      });

      if (response.data.scan_id) {
        onScanStart(response.data.scan_id);
        setTarget('');
      } else {
        setError('Failed to start scan');
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  const handleSampleClick = (sampleValue: string) => {
    setTarget(sampleValue);
  };

  return (
    <Box>
      <Typography variant="h5" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <CodeIcon />
        Enter Target for Scanning
      </Typography>
      
      <Box component="form" onSubmit={handleSubmit}>
        <TextField
          fullWidth
          multiline
          rows={4}
          label="Curl Command or URL"
          placeholder="Enter a curl command or just a URL to scan..."
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          disabled={disabled || loading}
          sx={{ mb: 2 }}
          helperText="Example: curl -H 'Authorization: Bearer token' https://api.example.com/users"
        />

        <Box sx={{ display: 'flex', gap: 2, mb: 2, alignItems: 'center' }}>
          <FormControl sx={{ minWidth: 200 }}>
            <InputLabel>Severity Level</InputLabel>
            <Select
              value={severity}
              label="Severity Level"
              onChange={(e) => setSeverity(e.target.value)}
              disabled={disabled || loading}
            >
              <MenuItem value="critical">🔴 Critical (~5 min)</MenuItem>
              <MenuItem value="high">🟠 High (~10 min)</MenuItem>
              <MenuItem value="medium">🟡 Medium (~15 min)</MenuItem>
              <MenuItem value="all">🔵 All (~20 min)</MenuItem>
            </Select>
          </FormControl>

          <Button
            type="submit"
            variant="contained"
            size="large"
            startIcon={<SendIcon />}
            disabled={disabled || loading || !target.trim()}
            sx={{ height: 56 }}
          >
            {loading ? 'Starting Scan...' : 'Start Security Scan'}
          </Button>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Box>
          <Typography variant="subtitle2" gutterBottom>
            Sample Commands:
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            {sampleCurls.map((sample, index) => (
              <Chip
                key={index}
                label={sample.name}
                onClick={() => handleSampleClick(sample.value)}
                variant="outlined"
                clickable
                size="small"
                disabled={disabled || loading}
              />
            ))}
          </Stack>
        </Box>
      </Box>
    </Box>
  );
};

export default CurlInput; 