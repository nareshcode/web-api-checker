import React, { useEffect, useState } from 'react';
import {
  Container,
  Typography,
  Box,
  Card,
  CardContent,
  Chip,
  Button,
  Alert,
  CircularProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  IconButton,
} from '@mui/material';
import {
  History as HistoryIcon,
  Visibility as ViewIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  PlayArrow as RunningIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { scanAPI } from '../utils/apiClient';

interface Scan {
  scan_id: string;
  status: string;
  progress: number;
  start_time: string;
  end_time?: string;
  current_step?: string;
  error?: string;
}

const ScanHistory: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const fetchScans = async () => {
    try {
      setLoading(true);
      const response = await scanAPI.listScans();
      setScans(response.data.scans || []);
      setError('');
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to load scan history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

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
        return <RunningIcon color="primary" />;
      default:
        return <HistoryIcon />;
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const getDuration = (startTime: string, endTime?: string) => {
    const start = new Date(startTime);
    const end = endTime ? new Date(endTime) : new Date();
    const duration = Math.round((end.getTime() - start.getTime()) / 1000);
    
    if (duration < 60) return `${duration}s`;
    if (duration < 3600) return `${Math.round(duration / 60)}m`;
    return `${Math.round(duration / 3600)}h`;
  };

  const handleViewReport = (scanId: string) => {
    navigate(`/report/${scanId}`);
  };

  if (loading) {
    return (
      <Container maxWidth="lg">
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
          <CircularProgress />
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg">
      <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h3" component="h1" gutterBottom>
            Scan History
          </Typography>
          <Typography variant="h6" color="text.secondary" gutterBottom>
            View all your security scan results
          </Typography>
        </Box>
        <IconButton onClick={fetchScans} color="primary" size="large">
          <RefreshIcon />
        </IconButton>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {scans.length === 0 ? (
        <Card>
          <CardContent sx={{ textAlign: 'center', py: 6 }}>
            <HistoryIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No scans found
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Start your first security scan from the dashboard
            </Typography>
            <Button
              variant="contained"
              onClick={() => navigate('/')}
            >
              Go to Dashboard
            </Button>
          </CardContent>
        </Card>
      ) : (
        <List sx={{ gap: 2, display: 'flex', flexDirection: 'column' }}>
          {scans.map((scan) => (
            <Card key={scan.scan_id} sx={{ mb: 2 }}>
              <CardContent>
                <ListItem sx={{ p: 0 }}>
                  <ListItemIcon>
                    {getStatusIcon(scan.status)}
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <Typography variant="h6">
                          Scan {scan.scan_id.slice(0, 8)}...
                        </Typography>
                                                 <Chip
                           label={scan.status.toUpperCase()}
                           sx={{
                             color: `${getStatusColor(scan.status)}.main`,
                             borderColor: `${getStatusColor(scan.status)}.main`
                           }}
                           variant="outlined"
                           size="small"
                         />
                        {scan.status === 'running' && (
                          <Chip
                            label={`${scan.progress}%`}
                            color="primary"
                            variant="outlined"
                            size="small"
                          />
                        )}
                      </Box>
                    }
                    secondary={
                      <Box sx={{ mt: 1 }}>
                        <Typography variant="body2" color="text.secondary">
                          Started: {formatDate(scan.start_time)}
                        </Typography>
                        {scan.end_time && (
                          <Typography variant="body2" color="text.secondary">
                            Completed: {formatDate(scan.end_time)} ({getDuration(scan.start_time, scan.end_time)})
                          </Typography>
                        )}
                        {scan.status === 'running' && scan.current_step && (
                          <Typography variant="body2" color="primary">
                            {scan.current_step}
                          </Typography>
                        )}
                        {scan.error && (
                          <Typography variant="body2" color="error">
                            Error: {scan.error}
                          </Typography>
                        )}
                      </Box>
                    }
                  />
                  {scan.status === 'completed' && (
                    <Button
                      variant="outlined"
                      startIcon={<ViewIcon />}
                      onClick={() => handleViewReport(scan.scan_id)}
                    >
                      View Report
                    </Button>
                  )}
                </ListItem>
              </CardContent>
            </Card>
          ))}
        </List>
      )}
    </Container>
  );
};

export default ScanHistory; 