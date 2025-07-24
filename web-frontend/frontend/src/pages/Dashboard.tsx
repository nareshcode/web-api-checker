import React, { useState } from 'react';
import {
  Container,
  Paper,
  Typography,
  Box,
  Grid,
} from '@mui/material';
import CurlInput from '../components/CurlInput';
import ScanProgress from '../components/ScanProgress';
import SecurityScore from '../components/SecurityScore';

const Dashboard: React.FC = () => {
  const [currentScan, setCurrentScan] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<any>(null);

  const handleScanStart = (scanId: string) => {
    setCurrentScan(scanId);
    setScanStatus(null);
  };

  const handleScanUpdate = (status: any) => {
    setScanStatus(status);
  };

  const handleScanComplete = () => {
    setCurrentScan(null);
  };

  return (
    <Container maxWidth="lg">
      <Box sx={{ mb: 4 }}>
        <Typography variant="h3" component="h1" gutterBottom>
          API Security Scanner
        </Typography>
        <Typography variant="h6" color="text.secondary" gutterBottom>
          Enter a curl command or URL to scan for security vulnerabilities
        </Typography>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} lg={8}>
          <Paper sx={{ p: 3, mb: 3 }}>
            <CurlInput onScanStart={handleScanStart} disabled={!!currentScan} />
          </Paper>

          {currentScan && (
            <Paper sx={{ p: 3 }}>
              <ScanProgress
                scanId={currentScan}
                onUpdate={handleScanUpdate}
                onComplete={handleScanComplete}
              />
            </Paper>
          )}
        </Grid>

        <Grid item xs={12} lg={4}>
          <SecurityScore scanStatus={scanStatus} />
        </Grid>
      </Grid>
    </Container>
  );
};

export default Dashboard; 