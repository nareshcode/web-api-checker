import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Card,
  CardContent,
  Typography,
  LinearProgress,
  Box,
  Chip,
  Alert,
  Button,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Grid,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  useTheme,
  useMediaQuery,
  Paper,
  Stepper,
  Step,
  StepLabel,
  CircularProgress,
  Fade,
  Zoom,
  Collapse,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import {
  Security as SecurityIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Assessment as ViewIcon,
  Shield as ShieldIcon,
  Warning as WarningIcon,
  ExpandMore as ExpandMoreIcon,
  Timeline as TimelineIcon,
  BugReport as BugIcon,
  Visibility as VisibilityIcon,
  Speed as SpeedIcon,
  PlayArrow as PlayIcon,
  Pause as PauseIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  TrendingUp as TrendingUpIcon,
  AccountBalance as BankIcon,
  VpnLock as VpnIcon,
  DataObject as DataIcon,
  Web as WebIcon,
  Settings as SettingsIcon,
  Code as CodeIcon,
  Timer as TimerIcon,
  Download as DownloadIcon,
  Close as CloseIcon,
} from '@mui/icons-material';
import { useWebSocket } from '../hooks/useWebSocket';
import { scanAPI } from '../utils/apiClient';

interface ScanProgressProps {
  scanId: string;
  onUpdate: (status: any) => void;
  onComplete: () => void;
}

interface SecurityFindingsSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
  categories: {
    [key: string]: {
      count: number;
      issues: string[];
    };
  };
}

interface SecurityLayerSummary {
  totalBlocked: number;
  wafDetected: boolean;
  rateLimitDetected: boolean;
  authBlocksDetected: boolean;
  captchaDetected: boolean;
  challengeDetected: boolean;
  securityLayers: string[];
}

const ScanProgress: React.FC<ScanProgressProps> = ({ scanId, onUpdate, onComplete }) => {
  const [status, setStatus] = useState<any>(null);
  const [findings, setFindings] = useState<any>(null);
  const [error, setError] = useState('');
  const [debugMessages, setDebugMessages] = useState<string[]>([]);
  const [showFindings, setShowFindings] = useState(false);
  const [showDebug, setShowDebug] = useState(false);
  const [elapsedTime, setElapsedTime] = useState(0);
  const [currentStage, setCurrentStage] = useState('Initializing');
  const [estimatedTimeRemaining, setEstimatedTimeRemaining] = useState('');
  const [progressValue, setProgressValue] = useState(0); // Separate progress state for better tracking
  const [isInitialized, setIsInitialized] = useState(false);
  const [reportContent, setReportContent] = useState<string>('');
  const [showReportDialog, setShowReportDialog] = useState(false);
  const lastProgressRef = useRef(0);
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));

  // Timer for elapsed time
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (status?.status === 'running') {
      timer = setInterval(() => {
        setElapsedTime(prev => prev + 1);
      }, 1000);
    }
    return () => {
      if (timer) {
        clearInterval(timer);
      }
    };
  }, [status]);

  const addDebugMessage = useCallback((message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setDebugMessages(prev => [`[${timestamp}] ${message}`, ...prev.slice(0, 19)]);
    console.log(`[ScanProgress] ${message}`);
  }, []);

  // Enhanced status update handler with better progress tracking
  const updateStatus = useCallback((data: any) => {
    console.log('[ScanProgress] Updating status:', data);
    
    // Ensure progress is a valid number
    const newProgress = typeof data.progress === 'number' ? Math.max(0, Math.min(100, data.progress)) : lastProgressRef.current;
    
    addDebugMessage(`📊 Raw Progress Data: ${JSON.stringify({ progress: data.progress, status: data.status, step: data.current_step })}`);
    console.log(`FE is receiving progress: ${newProgress}%`);
    
    // Force progress update even if it's the same value to ensure UI updates
    if (newProgress !== lastProgressRef.current || !status || data.status !== status?.status || data.current_step !== currentStage) {
      lastProgressRef.current = newProgress;
      
      // Use setTimeout to ensure state updates happen in the next tick
      setTimeout(() => {
        setProgressValue(newProgress);
        setStatus(data);
        setCurrentStage(data.current_step || 'Processing');
        
        addDebugMessage(`📊 Progress Updated: ${newProgress}% | Status: ${data.status} | Stage: ${data.current_step}`);
        
        // Calculate estimated time remaining
        if (newProgress > 0 && newProgress < 100 && elapsedTime > 0) {
          const timePerPercent = elapsedTime / newProgress;
          const remainingPercent = 100 - newProgress;
          const estimatedSeconds = timePerPercent * remainingPercent;
          setEstimatedTimeRemaining(formatTime(estimatedSeconds));
        }
        
        // Update findings if available
        if (data.findings) {
          setFindings(data.findings);
          addDebugMessage(`🔍 Findings updated - ${Object.keys(data.findings).length} categories analyzed`);
        }
        
        // Handle completion
        if (data.status === 'completed') {
          setProgressValue(100);
          addDebugMessage('✅ Scan completed successfully - Redirecting to report...');
          onComplete(); // Notify parent
          navigate(`/report/${scanId}`); // Redirect to report page
          return; // Stop further processing
        } else if (data.status === 'error') {
          addDebugMessage(`❌ Scan failed: ${data.current_step}`);
          setError(data.current_step || 'Scan failed');
          setTimeout(onComplete, 5000);
        }
        
        // Notify parent component
        onUpdate(data);
      }, 0);
    }
  }, [status, elapsedTime, addDebugMessage, onUpdate, onComplete, currentStage, scanId, navigate]);

  // Fetch completed report
  const fetchCompletedReport = useCallback(async (scanId: string) => {
    try {
      addDebugMessage('📄 Fetching completed report...');
      const response = await scanAPI.getReport(scanId);
      const reportData = response.data;
      
      setReportContent(reportData.report_content || '');
      addDebugMessage('📄 Report fetched successfully');
      
      // Show report dialog after a short delay
      setTimeout(() => {
        setShowReportDialog(true);
      }, 1000);
      
      // Auto-close scan progress after showing report
      setTimeout(() => {
        onComplete();
      }, 3000);
      
    } catch (err) {
      console.error('Failed to fetch report:', err);
      addDebugMessage('❌ Failed to fetch report');
      // Fallback to showing completion
      setTimeout(onComplete, 2000);
    }
  }, [addDebugMessage, onComplete]);

  // Initial status fetch - only run once
  useEffect(() => {
    const fetchInitialStatus = async () => {
      if (scanId && !isInitialized) {
        try {
          addDebugMessage('🔍 Fetching initial scan status...');
          const response = await scanAPI.getScanStatus(scanId);
          const data = response.data;
          
          addDebugMessage(`📨 Initial Status: ${data.status} | Progress: ${data.progress}%`);
          updateStatus(data);
          setIsInitialized(true);
        } catch (err) {
          console.error('Failed to fetch initial status:', err);
          addDebugMessage('❌ Failed to fetch initial status');
          setIsInitialized(true); // Mark as initialized even on error to prevent retry loops
        }
      }
    };

    fetchInitialStatus();
  }, [scanId, isInitialized, updateStatus, addDebugMessage]);

  // Enhanced WebSocket connection for real-time updates
  const { isConnected, lastMessage, sendMessage, reconnect } = useWebSocket(`http://localhost:8000`, {
    onConnect: () => {
      console.log('Connected to WebSocket');
      addDebugMessage('🔌 WebSocket Connected - Real-time updates enabled');
      setTimeout(() => {
        if (scanId) {
          sendMessage('join_scan', { scan_id: scanId });
          addDebugMessage(`📡 Joined scan room: ${scanId.slice(0, 8)}...`);
        }
      }, 100);
    },
    onMessage: (data) => {
      console.log('[WebSocket] Received data:', data);
      addDebugMessage(`📡 WebSocket Message: ${JSON.stringify(data)}`);
      if (data.scan_id === scanId) {
        updateStatus(data);
      }
    },
    onError: (error) => {
      console.error('WebSocket error:', error);
      addDebugMessage('❌ WebSocket connection lost - Switching to polling mode');
    }
  });

  // Fallback polling mechanism with improved logic
  useEffect(() => {
    let pollInterval: NodeJS.Timeout;
    
    if (!isConnected && scanId && isInitialized) {
      addDebugMessage('🔄 Starting polling mode (WebSocket unavailable)');
      
      pollInterval = setInterval(async () => {
        try {
          const response = await scanAPI.getScanStatus(scanId);
          const data = response.data;
          
          addDebugMessage(`🔄 Polled Status: ${data.status} | Progress: ${data.progress}%`);
          updateStatus(data);
          
          // Stop polling if scan is completed or errored
          if (data.status === 'completed' || data.status === 'error') {
            clearInterval(pollInterval);
          }
        } catch (err) {
          console.error('Polling failed:', err);
          addDebugMessage('❌ Polling request failed');
        }
      }, 1000); // Poll every 1 second for more responsive updates
    }

    return () => {
      if (pollInterval) {
        clearInterval(pollInterval);
      }
    };
  }, [isConnected, scanId, isInitialized, updateStatus, addDebugMessage]);

  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'success';
      case 'error':
        return 'error';
      case 'running':
        return 'primary';
      default:
        return 'info';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckIcon color="success" />;
      case 'error':
        return <ErrorIcon color="error" />;
      case 'running':
        return <PlayIcon color="primary" />;
      default:
        return <SecurityIcon />;
    }
  };

  const getScanStages = () => {
    return [
      'Initializing Scanner',
      'Testing HTTPS Configuration', 
      'Analyzing Security Headers',
      'Testing Injection Vulnerabilities',
      'Banking Security Checks',
      'Authentication Testing',
      'Rate Limiting Analysis',
      'Security Layer Detection',
      'Generating Report',
      'Completed'
    ];
  };

  const getCurrentStageIndex = () => {
    const stages = getScanStages();
    const currentIndex = stages.findIndex(stage => 
      currentStage.toLowerCase().includes(stage.toLowerCase().split(' ')[0].toLowerCase())
    );
    return currentIndex >= 0 ? currentIndex : Math.floor(progressValue / 10);
  };

  const handleViewReport = () => {
    navigate(`/report/${scanId}`);
  };

  const handleDownloadReport = () => {
    if (reportContent) {
      const blob = new Blob([reportContent], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security-report-${scanId}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  };

  const handleReconnect = () => {
    addDebugMessage('🔄 Manual reconnection attempt...');
    reconnect();
  };

  // Enhanced findings analysis
  const getFindingsSummary = (): SecurityFindingsSummary => {
    if (!findings?.api) {
      return {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        total: 0,
        categories: {}
      };
    }

    const api = findings.api;
    let critical = 0, high = 0, medium = 0, low = 0;

    // Handle new structure with vulnerabilities
    const vulnerabilities = api.vulnerabilities || api;
    
    // Handle severity-based structure
    if (vulnerabilities.critical && Array.isArray(vulnerabilities.critical)) {
      critical = vulnerabilities.critical.length;
    }
    if (vulnerabilities.high && Array.isArray(vulnerabilities.high)) {
      high = vulnerabilities.high.length;
    }
    if (vulnerabilities.medium && Array.isArray(vulnerabilities.medium)) {
      medium = vulnerabilities.medium.length;
    }
    if (vulnerabilities.low && Array.isArray(vulnerabilities.low)) {
      low = vulnerabilities.low.length;
    }

    // Handle legacy type-based structure
    const categoryMapping = {
      'Injection Attacks': ['sql_injection', 'command_injection', 'xss', 'xxe', 'ssrf'],
      'Banking Security': ['double_spending', 'race_conditions', 'privilege_escalation', 'bola_attacks', 'transaction_manipulation'],
      'Authentication': ['auth_bypass', 'session_fixation', 'jwt_attacks'],
      'Information Disclosure': ['metadata_leakage', 'verbose_errors', 'open_endpoints'],
      'Configuration': ['security_headers', 'cors', 'rate_limiting']
    };

    const categories: any = {};
    
    Object.entries(categoryMapping).forEach(([category, types]) => {
      categories[category] = {
        count: 0,
        issues: []
      };
      
      types.forEach(type => {
        if (vulnerabilities[type] && Array.isArray(vulnerabilities[type]) && vulnerabilities[type].length > 0) {
          categories[category].count += vulnerabilities[type].length;
          categories[category].issues.push(type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()));
          
          // Add to severity counts if not already counted
          if (!vulnerabilities.critical && !vulnerabilities.high && !vulnerabilities.medium) {
            if (['sql_injection', 'command_injection', 'double_spending', 'race_conditions'].includes(type)) {
              critical += vulnerabilities[type].length;
            } else if (['xss', 'privilege_escalation', 'bola_attacks', 'auth_bypass'].includes(type)) {
              high += vulnerabilities[type].length;
            } else {
              medium += vulnerabilities[type].length;
            }
          }
        }
      });
    });

    return {
      critical,
      high,
      medium,
      low,
      total: critical + high + medium + low,
      categories
    };
  };

  const getSecurityLayerSummary = (): SecurityLayerSummary | null => {
    if (!findings?.api?.security_layers) return null;
    
    const securityLayers = findings.api.security_layers;
    const blockedRequests = securityLayers.blocked_requests || [];
    
    return {
      totalBlocked: blockedRequests.length,
      wafDetected: securityLayers.waf_detected || false,
      rateLimitDetected: securityLayers.rate_limiting_detected || false,
      authBlocksDetected: securityLayers.auth_blocks_detected || false,
      captchaDetected: securityLayers.captcha_detected || false,
      challengeDetected: securityLayers.challenge_detected || false,
      securityLayers: securityLayers.security_layers || []
    };
  };

  const findingsSummary = getFindingsSummary();
  const securityLayerSummary = getSecurityLayerSummary();

  if (!status) {
    return (
      <Card elevation={3} sx={{ borderRadius: 3 }}>
        <CardContent sx={{ p: 4 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
            <CircularProgress size={40} />
            <Box>
              <Typography variant="h5">Initializing Security Scanner...</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Establishing connection and preparing scan environment
              </Typography>
            </Box>
          </Box>
          <LinearProgress variant="indeterminate" sx={{ borderRadius: 2, height: 8 }} />
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2, textAlign: 'center' }}>
            Scan ID: {scanId?.slice(0, 8)}...
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1, textAlign: 'center' }}>
            Progress: {progressValue}%
          </Typography>
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      <Card elevation={3} sx={{ borderRadius: 3, overflow: 'visible' }}>
        <CardContent sx={{ p: isMobile ? 3 : 4 }}>
          {/* Enhanced Header */}
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Zoom in={true}>
                <Box sx={{ position: 'relative' }}>
                  {getStatusIcon(status.status)}
                  {status.status === 'running' && (
                    <CircularProgress
                      size={40}
                      sx={{
                        position: 'absolute',
                        top: -8,
                        left: -8,
                        zIndex: 1,
                      }}
                    />
                  )}
                </Box>
              </Zoom>
              <Box>
                <Typography variant="h5" sx={{ fontWeight: 'bold' }}>
                  Security Scan in Progress
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Real-time vulnerability assessment and analysis
                </Typography>
              </Box>
            </Box>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Chip
                label={status.status.toUpperCase()}
                color={getStatusColor(status.status)}
                variant="filled"
                sx={{ fontWeight: 'bold' }}
              />
              <Chip
                label={`${elapsedTime}s`}
                variant="outlined"
                icon={<TimerIcon />}
              />
            </Box>
          </Box>

          {/* Progress Section - Enhanced with real-time updates */}
          <Paper elevation={1} sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: 'grey.50' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                Scan Progress
              </Typography>
              <Typography variant="h4" color="primary" sx={{ fontWeight: 'bold' }}>
                {progressValue}%
              </Typography>
            </Box>
            
            <LinearProgress
              variant="determinate"
              value={progressValue}
              sx={{
                height: 12,
                borderRadius: 6,
                mb: 2,
                '& .MuiLinearProgress-bar': {
                  borderRadius: 6,
                  background: `linear-gradient(90deg, ${theme.palette.primary.main}, ${theme.palette.primary.light})`,
                  transition: 'transform 0.4s ease-in-out' // Smooth animation for progress updates
                }
              }}
            />
            
            {/* Real-time progress indicator */}
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 1 }}>
              <Typography variant="body2" color="text.secondary">
                <PlayIcon fontSize="small" sx={{ mr: 1, verticalAlign: 'middle' }} />
                {currentStage}
              </Typography>
              {estimatedTimeRemaining && (
                <Typography variant="body2" color="text.secondary">
                  <SpeedIcon fontSize="small" sx={{ mr: 1, verticalAlign: 'middle' }} />
                  Est. {estimatedTimeRemaining} remaining
                </Typography>
              )}
            </Box>
            
            {/* Progress steps indicator */}
            <Box sx={{ mt: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
              {[10, 20, 30, 40, 50, 60, 70, 80, 90, 100].map((milestone) => (
                <Box
                  key={milestone}
                  sx={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    bgcolor: progressValue >= milestone ? 'primary.main' : 'grey.300',
                    transition: 'background-color 0.3s ease'
                  }}
                />
              ))}
            </Box>
          </Paper>

          {/* Scan Stages Stepper */}
          <Paper elevation={1} sx={{ p: 3, mb: 3, borderRadius: 2 }}>
            <Typography variant="h6" gutterBottom sx={{ fontWeight: 'bold', mb: 2 }}>
              Scan Stages
            </Typography>
            <Stepper activeStep={getCurrentStageIndex()} orientation={isMobile ? 'vertical' : 'horizontal'}>
              {getScanStages().slice(0, 6).map((stage, index) => (
                <Step key={stage}>
                  <StepLabel>
                    <Typography variant="body2">{stage}</Typography>
                  </StepLabel>
                </Step>
              ))}
            </Stepper>
          </Paper>

          {/* Enhanced Security Analysis Results */}
          {findingsSummary.total > 0 && (
            <Fade in={true}>
              <Paper elevation={2} sx={{ p: 3, mb: 3, borderRadius: 2, border: '2px solid', borderColor: 'primary.light' }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: 1 }}>
                    <TrendingUpIcon color="primary" />
                    Security Analysis Results
                  </Typography>
                  <Button
                    size="small"
                    startIcon={<VisibilityIcon />}
                    onClick={() => setShowFindings(!showFindings)}
                    variant="outlined"
                  >
                    {showFindings ? 'Hide' : 'Show'} Details
                  </Button>
                </Box>

                {/* Risk Overview Cards */}
                <Grid container spacing={2} sx={{ mb: 3 }}>
                  <Grid item xs={6} sm={3}>
                    <Card variant="outlined" sx={{ p: 2, textAlign: 'center', bgcolor: 'error.light', color: 'error.contrastText' }}>
                      <Typography variant="h4" sx={{ fontWeight: 'bold' }}>
                        {findingsSummary.critical}
                      </Typography>
                      <Typography variant="caption">Critical</Typography>
                    </Card>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Card variant="outlined" sx={{ p: 2, textAlign: 'center', bgcolor: 'warning.light', color: 'warning.contrastText' }}>
                      <Typography variant="h4" sx={{ fontWeight: 'bold' }}>
                        {findingsSummary.high}
                      </Typography>
                      <Typography variant="caption">High</Typography>
                    </Card>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Card variant="outlined" sx={{ p: 2, textAlign: 'center', bgcolor: 'info.light', color: 'info.contrastText' }}>
                      <Typography variant="h4" sx={{ fontWeight: 'bold' }}>
                        {findingsSummary.medium}
                      </Typography>
                      <Typography variant="caption">Medium</Typography>
                    </Card>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Card variant="outlined" sx={{ p: 2, textAlign: 'center', bgcolor: 'primary.light', color: 'primary.contrastText' }}>
                      <Typography variant="h4" sx={{ fontWeight: 'bold' }}>
                        {findingsSummary.total}
                      </Typography>
                      <Typography variant="caption">Total</Typography>
                    </Card>
                  </Grid>
                </Grid>

                {/* Vulnerability Categories */}
                <Collapse in={showFindings}>
                  <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 'bold', mt: 2 }}>
                    Vulnerability Categories
                  </Typography>
                  <Grid container spacing={2}>
                    {Object.entries(findingsSummary.categories).map(([category, data]: [string, any]) => {
                      if (data.count === 0) return null;
                      
                      const categoryIcons: any = {
                        'Injection Attacks': <BugIcon />,
                        'Banking Security': <BankIcon />,
                        'Authentication': <VpnIcon />,
                        'Information Disclosure': <InfoIcon />,
                        'Configuration': <SettingsIcon />
                      };
                      
                      return (
                        <Grid item xs={12} sm={6} md={4} key={category}>
                          <Card variant="outlined" sx={{ p: 2, height: '100%' }}>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                              {categoryIcons[category]}
                              <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>
                                {category}
                              </Typography>
                            </Box>
                            <Typography variant="h5" color="error" gutterBottom>
                              {data.count}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                              {data.issues.slice(0, 2).join(', ')}
                              {data.issues.length > 2 && '...'}
                            </Typography>
                          </Card>
                        </Grid>
                      );
                    })}
                  </Grid>
                </Collapse>
              </Paper>
            </Fade>
          )}

          {/* Security Layer Protection Status */}
          {securityLayerSummary && (
            <Fade in={true}>
              <Paper elevation={2} sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: 'success.light', color: 'success.contrastText' }}>
                <Typography variant="h6" gutterBottom sx={{ fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: 1 }}>
                  <ShieldIcon />
                  Security Layer Protection Status
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6} sm={3}>
                    <Typography variant="body2" sx={{ opacity: 0.9 }}>Blocked Attacks</Typography>
                    <Typography variant="h5" sx={{ fontWeight: 'bold' }}>{securityLayerSummary.totalBlocked}</Typography>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Typography variant="body2" sx={{ opacity: 0.9 }}>WAF Protection</Typography>
                    <Typography variant="h5" sx={{ fontWeight: 'bold' }}>{securityLayerSummary.wafDetected ? '✅' : '❌'}</Typography>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Typography variant="body2" sx={{ opacity: 0.9 }}>Rate Limiting</Typography>
                    <Typography variant="h5" sx={{ fontWeight: 'bold' }}>{securityLayerSummary.rateLimitDetected ? '✅' : '❌'}</Typography>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Typography variant="body2" sx={{ opacity: 0.9 }}>Auth Blocks</Typography>
                    <Typography variant="h5" sx={{ fontWeight: 'bold' }}>{securityLayerSummary.authBlocksDetected ? '✅' : '❌'}</Typography>
                  </Grid>
                </Grid>
              </Paper>
            </Fade>
          )}

          {/* Real-time Debug Messages with enhanced connection status */}
          {/* This section has been removed as per user request */}

          {/* Error Alert */}
          {error && (
            <Alert severity="error" sx={{ mt: 2 }}>
              <Typography variant="body2">
                <strong>Scan Error:</strong> {error}
              </Typography>
            </Alert>
          )}

          {/* Action Button */}
          {status.status === 'completed' && (
            <Fade in={true}>
              <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, mt: 3 }}>
                <Button
                  variant="contained"
                  startIcon={<ViewIcon />}
                  onClick={handleViewReport}
                  size="large"
                  sx={{
                    borderRadius: 3,
                    py: 1.5,
                    px: 4,
                    fontSize: '1.1rem',
                    fontWeight: 'bold',
                    background: 'linear-gradient(45deg, #1976d2, #42a5f5)',
                    '&:hover': {
                      background: 'linear-gradient(45deg, #1565c0, #1976d2)',
                    }
                  }}
                >
                  View Detailed Report
                </Button>
                {reportContent && (
                  <Button
                    variant="outlined"
                    startIcon={<DownloadIcon />}
                    onClick={handleDownloadReport}
                    size="large"
                    sx={{
                      borderRadius: 3,
                      py: 1.5,
                      px: 4,
                    }}
                  >
                    Download Report
                  </Button>
                )}
              </Box>
            </Fade>
          )}

          {/* Scan Metadata */}
          <Box sx={{ mt: 3, pt: 2, borderTop: '1px solid', borderColor: 'divider' }}>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <Typography variant="caption" color="text.secondary">Scan ID</Typography>
                <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{scanId}</Typography>
              </Grid>
            </Grid>
          </Box>
        </CardContent>
      </Card>

      {/* Report Dialog - Show report directly when scan completes */}
      <Dialog
        open={showReportDialog}
        onClose={() => setShowReportDialog(false)}
        maxWidth="lg"
        fullWidth
        fullScreen={isMobile}
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
            🎉 Security Scan Completed Successfully!
          </Typography>
          <IconButton onClick={() => setShowReportDialog(false)}>
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent>
          <Alert severity="success" sx={{ mb: 3 }}>
            <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
              Scan completed in {formatTime(elapsedTime)}
            </Typography>
            <Typography variant="body2">
              {findingsSummary.total} security issues found across {Object.keys(findingsSummary.categories).length} categories
            </Typography>
          </Alert>
          
          {/* Quick Summary */}
          <Paper elevation={1} sx={{ p: 2, mb: 3, bgcolor: 'grey.50' }}>
            <Typography variant="h6" gutterBottom>Quick Summary</Typography>
            <Grid container spacing={2}>
              <Grid item xs={6} sm={3}>
                <Typography variant="body2" color="text.secondary">Critical</Typography>
                <Typography variant="h5" color="error">{findingsSummary.critical}</Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="body2" color="text.secondary">High</Typography>
                <Typography variant="h5" color="warning.main">{findingsSummary.high}</Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="body2" color="text.secondary">Medium</Typography>
                <Typography variant="h5" color="info.main">{findingsSummary.medium}</Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="body2" color="text.secondary">Total</Typography>
                <Typography variant="h5" color="primary.main">{findingsSummary.total}</Typography>
              </Grid>
            </Grid>
          </Paper>

          {reportContent && (
            <Paper variant="outlined" sx={{ p: 2, maxHeight: 400, overflow: 'auto', bgcolor: 'grey.50' }}>
              <Typography variant="body2" sx={{ fontFamily: 'monospace', whiteSpace: 'pre-line' }}>
                {reportContent.substring(0, 2000)}...
                {reportContent.length > 2000 && (
                  <Typography variant="caption" color="primary" sx={{ display: 'block', mt: 1 }}>
                    (Preview - Click "View Full Report" to see complete details)
                  </Typography>
                )}
              </Typography>
            </Paper>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 3 }}>
          <Button onClick={() => setShowReportDialog(false)}>
            Close
          </Button>
          <Button
            variant="outlined"
            startIcon={<DownloadIcon />}
            onClick={handleDownloadReport}
          >
            Download Report
          </Button>
          <Button
            variant="contained"
            startIcon={<ViewIcon />}
            onClick={() => {
              setShowReportDialog(false);
              handleViewReport();
            }}
          >
            View Full Report
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ScanProgress; 